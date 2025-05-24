// Modified from: https://github.com/Qv2ray/gun-lite
// License: MIT

package gun

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/eyslce/routune/common/pool"

	"go.uber.org/atomic"
	"golang.org/x/net/http2"
)

var (
	// ErrInvalidLength 表示读取到的长度无效
	ErrInvalidLength = errors.New("invalid length")
	// ErrSmallBuffer 表示提供的缓冲区太小
	ErrSmallBuffer = errors.New("buffer too small")
)

// defaultHeader 是 gRPC 请求的默认 HTTP 头部
var defaultHeader = http.Header{
	"content-type": []string{"application/grpc"},
	"user-agent":   []string{"grpc-go/1.36.0"},
}

// DialFn 定义了用于建立网络连接的函数类型
type DialFn = func(network, addr string) (net.Conn, error)

// Conn 封装了 gRPC-over-HTTP/2 的连接
type Conn struct {
	response  *http.Response   // HTTP 响应
	request   *http.Request    // HTTP 请求
	transport *http2.Transport // HTTP/2 传输层
	writer    *io.PipeWriter   // 用于写入请求体的管道写入器
	once      sync.Once        // 用于确保 initRequest 只执行一次
	close     *atomic.Bool     // 标记连接是否已关闭
	err       error            // 连接过程中发生的错误
	remain    int              // 上次读取操作后剩余未读取的字节数
	br        *bufio.Reader    // 用于读取响应体的缓冲读取器

	// deadlines
	deadline *time.Timer // 连接的截止时间定时器
}

// Config 包含 Gun 连接的配置信息
type Config struct {
	ServiceName string // gRPC 服务名称
	Host        string // 目标主机名
}

// initRequest 初始化并发送 HTTP/2 请求。
// 它在第一次调用 Read 或 Write 时通过 once.Do 执行。
func (g *Conn) initRequest() {
	response, err := g.transport.RoundTrip(g.request)
	if err != nil {
		g.err = err
		g.writer.Close() // 关闭写入管道，通知读取端请求失败
		return
	}

	if !g.close.Load() { // 如果连接未关闭
		g.response = response
		g.br = bufio.NewReader(response.Body) // 初始化响应体读取器
	} else {
		response.Body.Close() // 如果连接已关闭，则关闭响应体
	}
}

// Read 从连接中读取数据。
// 它实现了 io.Reader 接口。
func (g *Conn) Read(b []byte) (n int, err error) {
	g.once.Do(g.initRequest) // 确保请求已初始化
	if g.err != nil {        // 如果初始化过程中发生错误，则返回错误
		return 0, g.err
	}

	// 如果上次读取有剩余数据，则先读取剩余数据
	if g.remain > 0 {
		size := g.remain
		if len(b) < size { // 如果提供的缓冲区小于剩余数据量
			size = len(b) // 则只读取缓冲区大小的数据
		}

		n, err = io.ReadFull(g.br, b[:size]) // 从缓冲读取器中读取数据
		g.remain -= n                        // 更新剩余数据量
		return
	} else if g.response == nil { // 如果响应为空（可能在 initRequest 失败后），则表示连接已关闭
		return 0, net.ErrClosed
	}

	// gRPC-Web 帧格式:
	// - 1 byte: 0x00 (表示非压缩数据)
	// - 4 bytes: 长度前缀 (消息长度，大端序)
	// - N bytes: Protobuf 消息
	// 此处我们处理的是 gRPC over HTTP/2，其帧格式略有不同，
	// 包含一个标记 (0x0A) 和一个 ULEB128 编码的 Protobuf 载荷长度。
	// 我们首先丢弃前6个字节 (标记和长度信息的一部分，或者可能是一个固定的头部)。
	// 0x00 grpclength(uint32) 0x0A uleb128 payload
	_, err = g.br.Discard(6) // 丢弃 gRPC 帧头部的固定部分
	if err != nil {
		return 0, err
	}

	// 读取 ULEB128 编码的 Protobuf 载荷长度
	protobufPayloadLen, err := binary.ReadUvarint(g.br)
	if err != nil {
		return 0, ErrInvalidLength // 如果读取长度失败，返回长度无效错误
	}

	size := int(protobufPayloadLen)
	if len(b) < size { // 如果提供的缓冲区小于载荷长度
		size = len(b) // 则只读取缓冲区大小的数据
	}

	n, err = io.ReadFull(g.br, b[:size]) // 从缓冲读取器中读取载荷数据
	if err != nil {
		return
	}

	// 计算剩余未读取的载荷数据量
	remain := int(protobufPayloadLen) - n
	if remain > 0 {
		g.remain = remain // 如果有剩余，则记录下来以便下次 Read 操作读取
	}

	return n, nil
}

// Write 向连接中写入数据。
// 它实现了 io.Writer 接口。
func (g *Conn) Write(b []byte) (n int, err error) {
	// 构造 gRPC 消息头部:
	// - 1 byte: 0x0A (标记)
	// - variable bytes: ULEB128 编码的 Protobuf 消息长度
	protobufHeader := [binary.MaxVarintLen64 + 1]byte{0x0A}
	varuintSize := binary.PutUvarint(protobufHeader[1:], uint64(len(b)))

	// 构造 gRPC 帧头部:
	// - 1 byte: 0x00 (表示非压缩)
	// - 4 bytes: 整个 gRPC 帧的长度 (包括标记、ULEB128长度、Protobuf消息本身)
	grpcHeader := make([]byte, 5) // 0x00 + 长度 (4字节)
	// grpcPayloadLen 是 protobufHeader (标记 + ULEB128长度) 和实际数据 b 的总长度
	grpcPayloadLen := uint32(varuintSize + 1 + len(b))
	binary.BigEndian.PutUint32(grpcHeader[1:5], grpcPayloadLen) // 写入总长度，大端序

	// 从 buffer pool 获取一个字节缓冲区以提高性能
	buf := pool.GetBytesBuffer()
	defer pool.PutBytesBuffer(buf)               // 确保缓冲区在使用后被放回池中
	buf.PutSlice(grpcHeader)                     // 写入 gRPC 帧头
	buf.PutSlice(protobufHeader[:varuintSize+1]) // 写入 Protobuf 消息头 (标记 + ULEB128长度)
	buf.PutSlice(b)                              // 写入实际的 Protobuf 数据

	// 将构造好的数据写入请求体的管道
	_, err = g.writer.Write(buf.Bytes())
	if err == io.ErrClosedPipe && g.err != nil { // 如果管道已关闭且存在连接错误
		err = g.err // 则返回连接错误
	}

	return len(b), err // 返回写入的字节数和错误状态
}

// Close 关闭连接。
// 它实现了 io.Closer 接口。
func (g *Conn) Close() error {
	g.close.Store(true) // 标记连接已关闭
	if r := g.response; r != nil {
		r.Body.Close() // 关闭 HTTP 响应体
	}

	return g.writer.Close() // 关闭请求体的写入管道
}

// LocalAddr 返回本地网络地址。
func (g *Conn) LocalAddr() net.Addr { return &net.TCPAddr{IP: net.IPv4zero, Port: 0} }

// RemoteAddr 返回远程网络地址。
func (g *Conn) RemoteAddr() net.Addr { return &net.TCPAddr{IP: net.IPv4zero, Port: 0} }

// SetReadDeadline 设置读取操作的截止时间。
func (g *Conn) SetReadDeadline(t time.Time) error { return g.SetDeadline(t) }

// SetWriteDeadline 设置写入操作的截止时间。
func (g *Conn) SetWriteDeadline(t time.Time) error { return g.SetDeadline(t) }

// SetDeadline 设置连接的读取和写入操作的截止时间。
// 如果截止时间到达，连接将被关闭。
func (g *Conn) SetDeadline(t time.Time) error {
	d := time.Until(t)     // 计算距离截止时间的时长
	if g.deadline != nil { // 如果已存在定时器
		g.deadline.Reset(d) // 则重置定时器
		return nil
	}
	// 创建一个新的定时器，在截止时间到达时关闭连接
	g.deadline = time.AfterFunc(d, func() {
		g.Close()
	})
	return nil
}

// NewHTTP2Client 创建一个新的 HTTP/2 传输客户端。
// dialFn 用于自定义拨号逻辑，tlsConfig 用于 TLS 配置。
func NewHTTP2Client(dialFn DialFn, tlsConfig *tls.Config) *http2.Transport {
	// dialFunc 是 http2.Transport 需要的 DialTLSContext 函数
	dialFunc := func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
		// 使用提供的 dialFn 建立底层 TCP 连接
		pconn, err := dialFn(network, addr)
		if err != nil {
			return nil, err
		}

		// 在 TCP 连接之上建立 TLS 连接
		cn := tls.Client(pconn, cfg)
		if err := cn.HandshakeContext(ctx); err != nil { // 执行 TLS 握手
			pconn.Close() // 握手失败则关闭底层连接
			return nil, err
		}
		state := cn.ConnectionState()
		// 检查 ALPN 协商的协议是否为 h2 (HTTP/2)
		if p := state.NegotiatedProtocol; p != http2.NextProtoTLS {
			cn.Close() // 如果协议不匹配，则关闭连接
			return nil, fmt.Errorf("http2: unexpected ALPN protocol %s, want %s", p, http2.NextProtoTLS)
		}
		return cn, nil // 返回 TLS 连接
	}

	return &http2.Transport{
		DialTLSContext:     dialFunc,  // 自定义 TLS 拨号函数
		TLSClientConfig:    tlsConfig, // TLS 客户端配置
		AllowHTTP:          false,     // 不允许 HTTP/1.1 (强制 HTTP/2)
		DisableCompression: true,      // 禁用传输层压缩
		PingTimeout:        0,         // Ping 超时时间，0 表示使用默认值
	}
}

// StreamGunWithTransport 使用给定的 HTTP/2 传输层和配置创建一个新的 Gun 连接。
// Gun 连接是一种基于 HTTP/2 的 gRPC 流。
func StreamGunWithTransport(transport *http2.Transport, cfg *Config) (net.Conn, error) {
	serviceName := "GunService" // 默认服务名
	if cfg.ServiceName != "" {  // 如果配置中指定了服务名，则使用配置的名称
		serviceName = cfg.ServiceName
	}

	// 创建一个管道，reader 端作为请求体，writer 端用于写入数据到请求体
	reader, writer := io.Pipe()
	request := &http.Request{
		Method: http.MethodPost, // gRPC 通常使用 POST 方法
		Body:   reader,          // 请求体是管道的读取端
		URL: &url.URL{
			Scheme: "https",                             // gRPC over TLS 使用 https
			Host:   cfg.Host,                            // 目标主机
			Path:   fmt.Sprintf("/%s/Tun", serviceName), // gRPC 请求路径格式
			// Opaque 用于确保路径中的特殊字符不被转义，
			// 这里的格式 "//host/service/method" 是 gRPC-Go 的一种典型路径表示。
			Opaque: fmt.Sprintf("//%s/%s/Tun", cfg.Host, serviceName),
		},
		Proto:      "HTTP/2", // 显式指定协议版本
		ProtoMajor: 2,
		ProtoMinor: 0,
		Header:     defaultHeader, // 使用默认的 gRPC 请求头
	}

	// 创建 Gun 连接实例
	conn := &Conn{
		request:   request,               // HTTP 请求
		transport: transport,             // HTTP/2 传输层
		writer:    writer,                // 请求体写入管道
		close:     atomic.NewBool(false), // 初始化关闭状态为 false
	}

	// 异步启动请求初始化过程
	// once.Do 确保 conn.initRequest() 只被执行一次
	go conn.once.Do(conn.initRequest)
	return conn, nil // 返回 Gun 连接实例
}

// StreamGunWithConn 使用一个已有的 net.Conn (通常是 TCP 连接) 创建一个新的 Gun 连接。
// 它会在此 net.Conn 之上建立 TLS 和 HTTP/2。
func StreamGunWithConn(conn net.Conn, tlsConfig *tls.Config, cfg *Config) (net.Conn, error) {
	// 创建一个 DialFn，它总是返回提供的 conn
	dialFn := func(network, addr string) (net.Conn, error) {
		return conn, nil
	}

	// 使用这个 dialFn 创建一个新的 HTTP/2 客户端传输层
	transport := NewHTTP2Client(dialFn, tlsConfig)
	// 使用创建的传输层和配置来建立 Gun 流连接
	return StreamGunWithTransport(transport, cfg)
}
