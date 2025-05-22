// Package outbound 实现了 Clash 的出站代理适配器
package outbound

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"

	"github.com/eyslce/clash/common/structure"
	"github.com/eyslce/clash/component/dialer"
	C "github.com/eyslce/clash/constant"
	"github.com/eyslce/clash/transport/shadowsocks/core"
	obfs "github.com/eyslce/clash/transport/simple-obfs"
	"github.com/eyslce/clash/transport/socks5"
	v2rayObfs "github.com/eyslce/clash/transport/v2ray-plugin"
)

// ShadowSocks 实现了 Shadowsocks 代理适配器
// 支持多种加密方式和混淆插件
type ShadowSocks struct {
	*Base
	cipher core.Cipher // Shadowsocks 加密器

	// obfs
	obfsMode    string            // 混淆模式
	obfsOption  *simpleObfsOption // simple-obfs 选项
	v2rayOption *v2rayObfs.Option // v2ray-plugin 选项
}

// ShadowSocksOption 包含创建 Shadowsocks 代理适配器所需的配置选项
type ShadowSocksOption struct {
	BasicOption
	Name       string         `proxy:"name"`                  // 代理名称
	Server     string         `proxy:"server"`                // 代理服务器地址
	Port       int            `proxy:"port"`                  // 代理服务器端口
	Password   string         `proxy:"password"`              // 加密密码
	Cipher     string         `proxy:"cipher"`                // 加密方式
	UDP        bool           `proxy:"udp,omitempty"`         // 是否支持 UDP
	Plugin     string         `proxy:"plugin,omitempty"`      // 混淆插件
	PluginOpts map[string]any `proxy:"plugin-opts,omitempty"` // 混淆插件选项
}

// simpleObfsOption 包含 simple-obfs 插件的配置选项
type simpleObfsOption struct {
	Mode string `obfs:"mode,omitempty"` // 混淆模式
	Host string `obfs:"host,omitempty"` // 混淆主机名
}

// v2rayObfsOption 包含 v2ray-plugin 插件的配置选项
type v2rayObfsOption struct {
	Mode           string            `obfs:"mode"`                       // 混淆模式
	Host           string            `obfs:"host,omitempty"`             // 混淆主机名
	Path           string            `obfs:"path,omitempty"`             // WebSocket 路径
	TLS            bool              `obfs:"tls,omitempty"`              // 是否启用 TLS
	Headers        map[string]string `obfs:"headers,omitempty"`          // 自定义请求头
	SkipCertVerify bool              `obfs:"skip-cert-verify,omitempty"` // 是否跳过证书验证
	Mux            bool              `obfs:"mux,omitempty"`              // 是否启用多路复用
}

// StreamConn 实现 C.ProxyAdapter 接口
// 将普通连接转换为 Shadowsocks 代理连接
func (ss *ShadowSocks) StreamConn(c net.Conn, metadata *C.Metadata) (net.Conn, error) {
	switch ss.obfsMode {
	case "tls":
		c = obfs.NewTLSObfs(c, ss.obfsOption.Host)
	case "http":
		_, port, _ := net.SplitHostPort(ss.addr)
		c = obfs.NewHTTPObfs(c, ss.obfsOption.Host, port)
	case "websocket":
		var err error
		c, err = v2rayObfs.NewV2rayObfs(c, ss.v2rayOption)
		if err != nil {
			return nil, fmt.Errorf("%s connect error: %w", ss.addr, err)
		}
	}
	c = ss.cipher.StreamConn(c)
	_, err := c.Write(serializesSocksAddr(metadata))
	return c, err
}

// DialContext 实现 C.ProxyAdapter 接口
// 创建一个到代理服务器的连接
func (ss *ShadowSocks) DialContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (_ C.Conn, err error) {
	c, err := dialer.DialContext(ctx, "tcp", ss.addr, ss.Base.DialOptions(opts...)...)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", ss.addr, err)
	}
	tcpKeepAlive(c)

	defer func(c net.Conn) {
		safeConnClose(c, err)
	}(c)

	c, err = ss.StreamConn(c, metadata)
	return NewConn(c, ss), err
}

// ListenPacketContext 实现 C.ProxyAdapter 接口
// 创建一个 UDP 数据包连接
func (ss *ShadowSocks) ListenPacketContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (C.PacketConn, error) {
	pc, err := dialer.ListenPacket(ctx, "udp", "", ss.Base.DialOptions(opts...)...)
	if err != nil {
		return nil, err
	}

	addr, err := resolveUDPAddr("udp", ss.addr)
	if err != nil {
		pc.Close()
		return nil, err
	}

	pc = ss.cipher.PacketConn(pc)
	return newPacketConn(&ssPacketConn{PacketConn: pc, rAddr: addr}, ss), nil
}

// NewShadowSocks 创建一个新的 Shadowsocks 代理适配器
func NewShadowSocks(option ShadowSocksOption) (*ShadowSocks, error) {
	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))
	cipher := option.Cipher
	password := option.Password
	ciph, err := core.PickCipher(cipher, nil, password)
	if err != nil {
		return nil, fmt.Errorf("ss %s initialize error: %w", addr, err)
	}

	var v2rayOption *v2rayObfs.Option
	var obfsOption *simpleObfsOption
	obfsMode := ""

	decoder := structure.NewDecoder(structure.Option{TagName: "obfs", WeaklyTypedInput: true})
	if option.Plugin == "obfs" {
		opts := simpleObfsOption{Host: "bing.com"}
		if err := decoder.Decode(option.PluginOpts, &opts); err != nil {
			return nil, fmt.Errorf("ss %s initialize obfs error: %w", addr, err)
		}

		if opts.Mode != "tls" && opts.Mode != "http" {
			return nil, fmt.Errorf("ss %s obfs mode error: %s", addr, opts.Mode)
		}
		obfsMode = opts.Mode
		obfsOption = &opts
	} else if option.Plugin == "v2ray-plugin" {
		opts := v2rayObfsOption{Host: "bing.com", Mux: true}
		if err := decoder.Decode(option.PluginOpts, &opts); err != nil {
			return nil, fmt.Errorf("ss %s initialize v2ray-plugin error: %w", addr, err)
		}

		if opts.Mode != "websocket" {
			return nil, fmt.Errorf("ss %s obfs mode error: %s", addr, opts.Mode)
		}
		obfsMode = opts.Mode
		v2rayOption = &v2rayObfs.Option{
			Host:    opts.Host,
			Path:    opts.Path,
			Headers: opts.Headers,
			Mux:     opts.Mux,
		}

		if opts.TLS {
			v2rayOption.TLS = true
			v2rayOption.SkipCertVerify = opts.SkipCertVerify
		}
	}

	return &ShadowSocks{
		Base: &Base{
			name:  option.Name,
			addr:  addr,
			tp:    C.Shadowsocks,
			udp:   option.UDP,
			iface: option.Interface,
			rmark: option.RoutingMark,
		},
		cipher: ciph,

		obfsMode:    obfsMode,
		v2rayOption: v2rayOption,
		obfsOption:  obfsOption,
	}, nil
}

// ssPacketConn 是一个 Shadowsocks UDP 数据包连接包装器
type ssPacketConn struct {
	net.PacketConn
	rAddr net.Addr // 远程地址
}

// WriteTo 实现 net.PacketConn 接口
// 将数据包发送到指定地址
func (spc *ssPacketConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	packet, err := socks5.EncodeUDPPacket(socks5.ParseAddrToSocksAddr(addr), b)
	if err != nil {
		return
	}
	return spc.PacketConn.WriteTo(packet[3:], spc.rAddr)
}

// ReadFrom 实现 net.PacketConn 接口
// 从连接读取数据包
func (spc *ssPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, _, e := spc.PacketConn.ReadFrom(b)
	if e != nil {
		return 0, nil, e
	}

	addr := socks5.SplitAddr(b[:n])
	if addr == nil {
		return 0, nil, errors.New("parse addr error")
	}

	udpAddr := addr.UDPAddr()
	if udpAddr == nil {
		return 0, nil, errors.New("parse addr error")
	}

	copy(b, b[len(addr):])
	return n - len(addr), udpAddr, e
}
