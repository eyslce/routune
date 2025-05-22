// Package outbound 实现了 Clash 的出站代理适配器
package outbound

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strconv"

	"github.com/eyslce/clash/component/dialer"
	C "github.com/eyslce/clash/constant"
	"github.com/eyslce/clash/transport/gun"
	"github.com/eyslce/clash/transport/trojan"

	"golang.org/x/net/http2"
)

// Trojan 实现了 Trojan 代理适配器
// 支持 TCP、UDP、WebSocket 和 gRPC 传输
type Trojan struct {
	*Base
	instance *trojan.Trojan // Trojan 实例
	option   *TrojanOption  // 配置选项

	// for gun mux
	gunTLSConfig *tls.Config      // gRPC TLS 配置
	gunConfig    *gun.Config      // gRPC 配置
	transport    *http2.Transport // HTTP/2 传输
}

// TrojanOption 包含创建 Trojan 代理适配器所需的配置选项
type TrojanOption struct {
	BasicOption
	Name           string      `proxy:"name"`                       // 代理名称
	Server         string      `proxy:"server"`                     // 代理服务器地址
	Port           int         `proxy:"port"`                       // 代理服务器端口
	Password       string      `proxy:"password"`                   // 密码
	ALPN           []string    `proxy:"alpn,omitempty"`             // ALPN 协议列表
	SNI            string      `proxy:"sni,omitempty"`              // TLS SNI
	SkipCertVerify bool        `proxy:"skip-cert-verify,omitempty"` // 是否跳过证书验证
	UDP            bool        `proxy:"udp,omitempty"`              // 是否支持 UDP
	Network        string      `proxy:"network,omitempty"`          // 传输网络类型
	GrpcOpts       GrpcOptions `proxy:"grpc-opts,omitempty"`        // gRPC 选项
	WSOpts         WSOptions   `proxy:"ws-opts,omitempty"`          // WebSocket 选项
}

// plainStream 创建一个普通的 Trojan 流连接
// 支持 WebSocket 和普通 TCP 连接
func (t *Trojan) plainStream(c net.Conn) (net.Conn, error) {
	if t.option.Network == "ws" {
		host, port, _ := net.SplitHostPort(t.addr)
		wsOpts := &trojan.WebsocketOption{
			Host: host,
			Port: port,
			Path: t.option.WSOpts.Path,
		}

		if t.option.SNI != "" {
			wsOpts.Host = t.option.SNI
		}

		if len(t.option.WSOpts.Headers) != 0 {
			header := http.Header{}
			for key, value := range t.option.WSOpts.Headers {
				header.Add(key, value)
			}
			wsOpts.Headers = header
		}

		return t.instance.StreamWebsocketConn(c, wsOpts)
	}

	return t.instance.StreamConn(c)
}

// StreamConn 实现 C.ProxyAdapter 接口
// 将普通连接转换为 Trojan 代理连接
func (t *Trojan) StreamConn(c net.Conn, metadata *C.Metadata) (net.Conn, error) {
	var err error
	if t.transport != nil {
		c, err = gun.StreamGunWithConn(c, t.gunTLSConfig, t.gunConfig)
	} else {
		c, err = t.plainStream(c)
	}

	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", t.addr, err)
	}

	err = t.instance.WriteHeader(c, trojan.CommandTCP, serializesSocksAddr(metadata))
	return c, err
}

// DialContext 实现 C.ProxyAdapter 接口
// 创建一个到代理服务器的连接
func (t *Trojan) DialContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (_ C.Conn, err error) {
	// gun transport
	if t.transport != nil && len(opts) == 0 {
		c, err := gun.StreamGunWithTransport(t.transport, t.gunConfig)
		if err != nil {
			return nil, err
		}

		if err = t.instance.WriteHeader(c, trojan.CommandTCP, serializesSocksAddr(metadata)); err != nil {
			c.Close()
			return nil, err
		}

		return NewConn(c, t), nil
	}

	c, err := dialer.DialContext(ctx, "tcp", t.addr, t.Base.DialOptions(opts...)...)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", t.addr, err)
	}
	tcpKeepAlive(c)

	defer func(c net.Conn) {
		safeConnClose(c, err)
	}(c)

	c, err = t.StreamConn(c, metadata)
	if err != nil {
		return nil, err
	}

	return NewConn(c, t), err
}

// ListenPacketContext 实现 C.ProxyAdapter 接口
// 创建一个 UDP 数据包连接
func (t *Trojan) ListenPacketContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (_ C.PacketConn, err error) {
	var c net.Conn

	// grpc transport
	if t.transport != nil && len(opts) == 0 {
		c, err = gun.StreamGunWithTransport(t.transport, t.gunConfig)
		if err != nil {
			return nil, fmt.Errorf("%s connect error: %w", t.addr, err)
		}
		defer func(c net.Conn) {
			safeConnClose(c, err)
		}(c)
	} else {
		c, err = dialer.DialContext(ctx, "tcp", t.addr, t.Base.DialOptions(opts...)...)
		if err != nil {
			return nil, fmt.Errorf("%s connect error: %w", t.addr, err)
		}
		defer func(c net.Conn) {
			safeConnClose(c, err)
		}(c)
		tcpKeepAlive(c)
		c, err = t.plainStream(c)
		if err != nil {
			return nil, fmt.Errorf("%s connect error: %w", t.addr, err)
		}
	}

	err = t.instance.WriteHeader(c, trojan.CommandUDP, serializesSocksAddr(metadata))
	if err != nil {
		return nil, err
	}

	pc := t.instance.PacketConn(c)
	return newPacketConn(pc, t), err
}

// NewTrojan 创建一个新的 Trojan 代理适配器
func NewTrojan(option TrojanOption) (*Trojan, error) {
	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))

	tOption := &trojan.Option{
		Password:       option.Password,
		ALPN:           option.ALPN,
		ServerName:     option.Server,
		SkipCertVerify: option.SkipCertVerify,
	}

	if option.SNI != "" {
		tOption.ServerName = option.SNI
	}

	t := &Trojan{
		Base: &Base{
			name:  option.Name,
			addr:  addr,
			tp:    C.Trojan,
			udp:   option.UDP,
			iface: option.Interface,
			rmark: option.RoutingMark,
		},
		instance: trojan.New(tOption),
		option:   &option,
	}

	if option.Network == "grpc" {
		dialFn := func(network, addr string) (net.Conn, error) {
			c, err := dialer.DialContext(context.Background(), "tcp", t.addr, t.Base.DialOptions()...)
			if err != nil {
				return nil, fmt.Errorf("%s connect error: %s", t.addr, err.Error())
			}
			tcpKeepAlive(c)
			return c, nil
		}

		tlsConfig := &tls.Config{
			NextProtos:         option.ALPN,
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: tOption.SkipCertVerify,
			ServerName:         tOption.ServerName,
		}

		t.transport = gun.NewHTTP2Client(dialFn, tlsConfig)
		t.gunTLSConfig = tlsConfig
		t.gunConfig = &gun.Config{
			ServiceName: option.GrpcOpts.GrpcServiceName,
			Host:        tOption.ServerName,
		}
	}

	return t, nil
}
