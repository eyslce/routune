package socks

import (
	"io"
	"net"

	"github.com/eyslce/routune/adapter/inbound"
	N "github.com/eyslce/routune/common/net"
	C "github.com/eyslce/routune/constant"
	authStore "github.com/eyslce/routune/listener/auth"
	"github.com/eyslce/routune/transport/socks4"
	"github.com/eyslce/routune/transport/socks5"
)

// Listener 结构体封装了 SOCKS TCP 监听器的基本信息和操作
type Listener struct {
	listener net.Listener // 底层的 net.Listener
	addr     string       // 监听的原始地址字符串，例如 ":7890"
	closed   bool         // 标记监听器是否已关闭
}

// RawAddress 返回监听器配置时使用的原始地址字符串。
// 实现 C.Listener 接口。
func (l *Listener) RawAddress() string {
	return l.addr
}

// Address 返回监听器实际监听的地址字符串，可能包含动态分配的端口。
// 实现 C.Listener 接口。
func (l *Listener) Address() string {
	return l.listener.Addr().String()
}

// Close 关闭监听器。
// 实现 C.Listener 接口。
func (l *Listener) Close() error {
	l.closed = true           // 标记为已关闭
	return l.listener.Close() // 关闭底层的 net.Listener
}

// New 创建一个新的 SOCKS TCP 监听器。
// addr: 监听地址字符串，例如 ":7890" 或 "127.0.0.1:7890"。
// in: 用于将新接受的连接（包装为 C.ConnContext）发送到 Tunnel 处理的通道。
// 返回创建的监听器实例 (C.Listener) 和可能发生的错误。
func New(addr string, in chan<- C.ConnContext) (C.Listener, error) {
	l, err := net.Listen("tcp", addr) // 在指定地址上开始监听 TCP 连接
	if err != nil {
		return nil, err
	}

	// 创建 Listener 结构体实例
	sl := &Listener{
		listener: l,
		addr:     addr,
	}
	// 启动一个 goroutine 来接受新的连接
	go func() {
		for {
			c, err := l.Accept() // 接受新的 TCP 连接
			if err != nil {
				if sl.closed { // 如果监听器已关闭，则退出循环
					break
				}
				continue // 其他错误则继续尝试接受连接
			}
			// 为每个新连接启动一个 goroutine 进行 SOCKS 协议处理
			go handleSocks(c, in)
		}
	}()

	return sl, nil
}

// handleSocks 处理单个 SOCKS TCP 连接。
// conn: 接受到的 net.Conn TCP 连接。
// in: 用于将处理后的连接发送到 Tunnel 的通道。
// 该函数会检测连接是 SOCKS4 还是 SOCKS5 协议，并调用相应的处理函数。
func handleSocks(conn net.Conn, in chan<- C.ConnContext) {
	conn.(*net.TCPConn).SetKeepAlive(true) // 为 TCP 连接启用 KeepAlive
	// 将原始连接包装成带缓冲的连接，以支持 Peek 操作
	bufConn := N.NewBufferedConn(conn)
	// 尝试读取第一个字节以判断 SOCKS 版本
	head, err := bufConn.Peek(1)
	if err != nil {
		conn.Close() // 读取失败则关闭连接
		return
	}

	// 根据第一个字节判断 SOCKS 版本
	switch head[0] {
	case socks4.Version: // SOCKS4 协议版本号
		HandleSocks4(bufConn, in)
	case socks5.Version: // SOCKS5 协议版本号
		HandleSocks5(bufConn, in)
	default: // 未知协议版本
		conn.Close() // 关闭连接
	}
}

// HandleSocks4 处理 SOCKS4 协议的连接。
// conn: 传入的 net.Conn 连接。
// in: 用于将处理后的连接发送到 Tunnel 的通道。
func HandleSocks4(conn net.Conn, in chan<- C.ConnContext) {
	// 执行 SOCKS4 服务端握手，并获取目标地址和认证信息
	addr, _, err := socks4.ServerHandshake(conn, authStore.Authenticator())
	if err != nil {
		conn.Close() // 握手失败则关闭连接
		return
	}
	// 将 SOCKS4 连接包装成 C.ConnContext 并发送到 Tunnel
	in <- inbound.NewSocket(socks5.ParseAddr(addr), conn, C.SOCKS4)
}

// HandleSocks5 处理 SOCKS5 协议的连接。
// conn: 传入的 net.Conn 连接。
// in: 用于将处理后的连接发送到 Tunnel 的通道。
func HandleSocks5(conn net.Conn, in chan<- C.ConnContext) {
	// 执行 SOCKS5 服务端握手，并获取目标地址、命令和认证信息
	target, command, err := socks5.ServerHandshake(conn, authStore.Authenticator())
	if err != nil {
		conn.Close() // 握手失败则关闭连接
		return
	}
	// 如果是 UDP Associate 命令
	if command == socks5.CmdUDPAssociate {
		defer conn.Close()        // 确保连接最终关闭
		io.Copy(io.Discard, conn) // 丢弃所有后续数据，因为 UDP Associate 本身不传输应用数据
		return
	}
	// 将 SOCKS5 连接包装成 C.ConnContext 并发送到 Tunnel
	in <- inbound.NewSocket(target, conn, C.SOCKS5)
}
