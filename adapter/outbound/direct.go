// Package outbound 实现了 Clash 的出站代理适配器
package outbound

import (
	"context"
	"net"

	"github.com/eyslce/clash/component/dialer"
	C "github.com/eyslce/clash/constant"
)

// Direct 实现了直连代理适配器
// 直接使用系统网络进行连接，不经过任何代理
type Direct struct {
	*Base
}

// DialContext 实现 C.ProxyAdapter 接口
// 创建一个直连的 TCP 连接
func (d *Direct) DialContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (C.Conn, error) {
	c, err := dialer.DialContext(ctx, "tcp", metadata.RemoteAddress(), d.Base.DialOptions(opts...)...)
	if err != nil {
		return nil, err
	}
	tcpKeepAlive(c)
	return NewConn(c, d), nil
}

// ListenPacketContext 实现 C.ProxyAdapter 接口
// 创建一个直连的 UDP 数据包连接
func (d *Direct) ListenPacketContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (C.PacketConn, error) {
	pc, err := dialer.ListenPacket(ctx, "udp", "", d.Base.DialOptions(opts...)...)
	if err != nil {
		return nil, err
	}
	return newPacketConn(&directPacketConn{pc}, d), nil
}

// directPacketConn 是一个直连的 UDP 数据包连接包装器
type directPacketConn struct {
	net.PacketConn
}

// NewDirect 创建一个新的直连代理适配器
func NewDirect() *Direct {
	return &Direct{
		Base: &Base{
			name: "DIRECT",
			tp:   C.Direct,
			udp:  true,
		},
	}
}
