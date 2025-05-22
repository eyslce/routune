// Package outbound 实现了 Clash 的出站代理适配器
package outbound

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"

	"github.com/eyslce/clash/component/dialer"
	C "github.com/eyslce/clash/constant"
	"github.com/eyslce/clash/transport/socks5"
)

// Socks5 实现了 SOCKS5 代理适配器
// 支持 TCP 和 UDP 代理，可配置认证信息和 TLS
type Socks5 struct {
	*Base
	user           string      // 代理认证用户名
	pass           string      // 代理认证密码
	tls            bool        // 是否启用 TLS
	skipCertVerify bool        // 是否跳过证书验证
	tlsConfig      *tls.Config // TLS 配置
}

// Socks5Option 包含创建 SOCKS5 代理适配器所需的配置选项
type Socks5Option struct {
	BasicOption
	Name           string `proxy:"name"`                       // 代理名称
	Server         string `proxy:"server"`                     // 代理服务器地址
	Port           int    `proxy:"port"`                       // 代理服务器端口
	UserName       string `proxy:"username,omitempty"`         // 认证用户名
	Password       string `proxy:"password,omitempty"`         // 认证密码
	TLS            bool   `proxy:"tls,omitempty"`              // 是否启用 TLS
	UDP            bool   `proxy:"udp,omitempty"`              // 是否支持 UDP
	SkipCertVerify bool   `proxy:"skip-cert-verify,omitempty"` // 是否跳过证书验证
}

// StreamConn 实现 C.ProxyAdapter 接口
// 将普通连接转换为 SOCKS5 代理连接
func (ss *Socks5) StreamConn(c net.Conn, metadata *C.Metadata) (net.Conn, error) {
	if ss.tls {
		cc := tls.Client(c, ss.tlsConfig)
		ctx, cancel := context.WithTimeout(context.Background(), C.DefaultTLSTimeout)
		defer cancel()
		err := cc.HandshakeContext(ctx)
		c = cc
		if err != nil {
			return nil, fmt.Errorf("%s connect error: %w", ss.addr, err)
		}
	}

	var user *socks5.User
	if ss.user != "" {
		user = &socks5.User{
			Username: ss.user,
			Password: ss.pass,
		}
	}
	if _, err := socks5.ClientHandshake(c, serializesSocksAddr(metadata), socks5.CmdConnect, user); err != nil {
		return nil, err
	}
	return c, nil
}

// DialContext 实现 C.ProxyAdapter 接口
// 创建一个到代理服务器的连接
func (ss *Socks5) DialContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (_ C.Conn, err error) {
	c, err := dialer.DialContext(ctx, "tcp", ss.addr, ss.Base.DialOptions(opts...)...)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", ss.addr, err)
	}
	tcpKeepAlive(c)

	defer func(c net.Conn) {
		safeConnClose(c, err)
	}(c)

	c, err = ss.StreamConn(c, metadata)
	if err != nil {
		return nil, err
	}

	return NewConn(c, ss), nil
}

// ListenPacketContext 实现 C.ProxyAdapter 接口
// 创建一个 UDP 数据包连接
func (ss *Socks5) ListenPacketContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (_ C.PacketConn, err error) {
	c, err := dialer.DialContext(ctx, "tcp", ss.addr, ss.Base.DialOptions(opts...)...)
	if err != nil {
		err = fmt.Errorf("%s connect error: %w", ss.addr, err)
		return
	}

	if ss.tls {
		cc := tls.Client(c, ss.tlsConfig)
		ctx, cancel := context.WithTimeout(context.Background(), C.DefaultTLSTimeout)
		defer cancel()
		err = cc.HandshakeContext(ctx)
		c = cc
	}

	defer func(c net.Conn) {
		safeConnClose(c, err)
	}(c)

	tcpKeepAlive(c)
	var user *socks5.User
	if ss.user != "" {
		user = &socks5.User{
			Username: ss.user,
			Password: ss.pass,
		}
	}

	udpAssocateAddr := socks5.AddrFromStdAddrPort(netip.AddrPortFrom(netip.IPv4Unspecified(), 0))
	bindAddr, err := socks5.ClientHandshake(c, udpAssocateAddr, socks5.CmdUDPAssociate, user)
	if err != nil {
		err = fmt.Errorf("client hanshake error: %w", err)
		return
	}

	pc, err := dialer.ListenPacket(ctx, "udp", "", ss.Base.DialOptions(opts...)...)
	if err != nil {
		return
	}

	go func() {
		io.Copy(io.Discard, c)
		c.Close()
		// A UDP association terminates when the TCP connection that the UDP
		// ASSOCIATE request arrived on terminates. RFC1928
		pc.Close()
	}()

	// Support unspecified UDP bind address.
	bindUDPAddr := bindAddr.UDPAddr()
	if bindUDPAddr == nil {
		err = errors.New("invalid UDP bind address")
		return
	} else if bindUDPAddr.IP.IsUnspecified() {
		serverAddr, err := resolveUDPAddr("udp", ss.Addr())
		if err != nil {
			return nil, err
		}

		bindUDPAddr.IP = serverAddr.IP
	}

	return newPacketConn(&socksPacketConn{PacketConn: pc, rAddr: bindUDPAddr, tcpConn: c}, ss), nil
}

// NewSocks5 创建一个新的 SOCKS5 代理适配器
func NewSocks5(option Socks5Option) *Socks5 {
	var tlsConfig *tls.Config
	if option.TLS {
		tlsConfig = &tls.Config{
			InsecureSkipVerify: option.SkipCertVerify,
			ServerName:         option.Server,
		}
	}

	return &Socks5{
		Base: &Base{
			name:  option.Name,
			addr:  net.JoinHostPort(option.Server, strconv.Itoa(option.Port)),
			tp:    C.Socks5,
			udp:   option.UDP,
			iface: option.Interface,
			rmark: option.RoutingMark,
		},
		user:           option.UserName,
		pass:           option.Password,
		tls:            option.TLS,
		skipCertVerify: option.SkipCertVerify,
		tlsConfig:      tlsConfig,
	}
}

// socksPacketConn 是一个 SOCKS5 UDP 数据包连接包装器
type socksPacketConn struct {
	net.PacketConn
	rAddr   net.Addr // 远程地址
	tcpConn net.Conn // 关联的 TCP 连接
}

// WriteTo 实现 net.PacketConn 接口
// 将数据包发送到指定地址
func (uc *socksPacketConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	packet, err := socks5.EncodeUDPPacket(socks5.ParseAddrToSocksAddr(addr), b)
	if err != nil {
		return
	}
	return uc.PacketConn.WriteTo(packet, uc.rAddr)
}

// ReadFrom 实现 net.PacketConn 接口
// 从连接读取数据包
func (uc *socksPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, _, e := uc.PacketConn.ReadFrom(b)
	if e != nil {
		return 0, nil, e
	}
	addr, payload, err := socks5.DecodeUDPPacket(b)
	if err != nil {
		return 0, nil, err
	}

	udpAddr := addr.UDPAddr()
	if udpAddr == nil {
		return 0, nil, errors.New("parse udp addr error")
	}

	// due to DecodeUDPPacket is mutable, record addr length
	copy(b, payload)
	return n - len(addr) - 3, udpAddr, nil
}

// Close 关闭连接
// 同时关闭 UDP 和关联的 TCP 连接
func (uc *socksPacketConn) Close() error {
	uc.tcpConn.Close()
	return uc.PacketConn.Close()
}
