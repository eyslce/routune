// Package outbound 实现了 Clash 的出站代理适配器
package outbound

import (
	"context"
	"fmt"
	"net"
	"strconv"

	"github.com/eyslce/clash/component/dialer"
	C "github.com/eyslce/clash/constant"
	"github.com/eyslce/clash/transport/shadowsocks/core"
	"github.com/eyslce/clash/transport/shadowsocks/shadowaead"
	"github.com/eyslce/clash/transport/shadowsocks/shadowstream"
	"github.com/eyslce/clash/transport/ssr/obfs"
	"github.com/eyslce/clash/transport/ssr/protocol"
)

// ShadowSocksR 实现了 ShadowsocksR 代理适配器
// 支持多种加密方式、混淆和协议
type ShadowSocksR struct {
	*Base
	cipher   core.Cipher       // Shadowsocks 加密器
	obfs     obfs.Obfs         // 混淆器
	protocol protocol.Protocol // 协议
}

// ShadowSocksROption 包含创建 ShadowsocksR 代理适配器所需的配置选项
type ShadowSocksROption struct {
	BasicOption
	Name          string `proxy:"name"`                     // 代理名称
	Server        string `proxy:"server"`                   // 代理服务器地址
	Port          int    `proxy:"port"`                     // 代理服务器端口
	Password      string `proxy:"password"`                 // 加密密码
	Cipher        string `proxy:"cipher"`                   // 加密方式
	Obfs          string `proxy:"obfs"`                     // 混淆方式
	ObfsParam     string `proxy:"obfs-param,omitempty"`     // 混淆参数
	Protocol      string `proxy:"protocol"`                 // 协议
	ProtocolParam string `proxy:"protocol-param,omitempty"` // 协议参数
	UDP           bool   `proxy:"udp,omitempty"`            // 是否支持 UDP
}

// StreamConn 实现 C.ProxyAdapter 接口
// 将普通连接转换为 ShadowsocksR 代理连接
func (ssr *ShadowSocksR) StreamConn(c net.Conn, metadata *C.Metadata) (net.Conn, error) {
	c = ssr.obfs.StreamConn(c)
	c = ssr.cipher.StreamConn(c)
	var (
		iv  []byte
		err error
	)
	switch conn := c.(type) {
	case *shadowstream.Conn:
		iv, err = conn.ObtainWriteIV()
		if err != nil {
			return nil, err
		}
	case *shadowaead.Conn:
		return nil, fmt.Errorf("invalid connection type")
	}
	c = ssr.protocol.StreamConn(c, iv)
	_, err = c.Write(serializesSocksAddr(metadata))
	return c, err
}

// DialContext 实现 C.ProxyAdapter 接口
// 创建一个到代理服务器的连接
func (ssr *ShadowSocksR) DialContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (_ C.Conn, err error) {
	c, err := dialer.DialContext(ctx, "tcp", ssr.addr, ssr.Base.DialOptions(opts...)...)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", ssr.addr, err)
	}
	tcpKeepAlive(c)

	defer func(c net.Conn) {
		safeConnClose(c, err)
	}(c)

	c, err = ssr.StreamConn(c, metadata)
	return NewConn(c, ssr), err
}

// ListenPacketContext 实现 C.ProxyAdapter 接口
// 创建一个 UDP 数据包连接
func (ssr *ShadowSocksR) ListenPacketContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (C.PacketConn, error) {
	pc, err := dialer.ListenPacket(ctx, "udp", "", ssr.Base.DialOptions(opts...)...)
	if err != nil {
		return nil, err
	}

	addr, err := resolveUDPAddr("udp", ssr.addr)
	if err != nil {
		pc.Close()
		return nil, err
	}

	pc = ssr.cipher.PacketConn(pc)
	pc = ssr.protocol.PacketConn(pc)
	return newPacketConn(&ssPacketConn{PacketConn: pc, rAddr: addr}, ssr), nil
}

// NewShadowSocksR 创建一个新的 ShadowsocksR 代理适配器
func NewShadowSocksR(option ShadowSocksROption) (*ShadowSocksR, error) {
	// SSR protocol compatibility
	// https://github.com/eyslce/clash/pull/2056
	if option.Cipher == "none" {
		option.Cipher = "dummy"
	}

	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))
	cipher := option.Cipher
	password := option.Password
	coreCiph, err := core.PickCipher(cipher, nil, password)
	if err != nil {
		return nil, fmt.Errorf("ssr %s initialize error: %w", addr, err)
	}
	var (
		ivSize int
		key    []byte
	)

	if option.Cipher == "dummy" {
		ivSize = 0
		key = core.Kdf(option.Password, 16)
	} else {
		ciph, ok := coreCiph.(*core.StreamCipher)
		if !ok {
			return nil, fmt.Errorf("%s is not none or a supported stream cipher in ssr", cipher)
		}
		ivSize = ciph.IVSize()
		key = ciph.Key
	}

	obfs, obfsOverhead, err := obfs.PickObfs(option.Obfs, &obfs.Base{
		Host:   option.Server,
		Port:   option.Port,
		Key:    key,
		IVSize: ivSize,
		Param:  option.ObfsParam,
	})
	if err != nil {
		return nil, fmt.Errorf("ssr %s initialize obfs error: %w", addr, err)
	}

	protocol, err := protocol.PickProtocol(option.Protocol, &protocol.Base{
		Key:      key,
		Overhead: obfsOverhead,
		Param:    option.ProtocolParam,
	})
	if err != nil {
		return nil, fmt.Errorf("ssr %s initialize protocol error: %w", addr, err)
	}

	return &ShadowSocksR{
		Base: &Base{
			name:  option.Name,
			addr:  addr,
			tp:    C.ShadowsocksR,
			udp:   option.UDP,
			iface: option.Interface,
			rmark: option.RoutingMark,
		},
		cipher:   coreCiph,
		obfs:     obfs,
		protocol: protocol,
	}, nil
}
