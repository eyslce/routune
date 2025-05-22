// Package outbound 实现了 Clash 的出站代理适配器
package outbound

import (
	"context"
	"encoding/json"
	"errors"
	"net"

	"github.com/eyslce/clash/component/dialer"
	C "github.com/eyslce/clash/constant"
)

// Base 是出站代理适配器的基础结构体
// 包含了所有代理适配器共有的基本属性
type Base struct {
	name  string        // 代理名称
	addr  string        // 代理服务器地址
	iface string        // 网络接口名称
	tp    C.AdapterType // 代理类型
	udp   bool          // 是否支持 UDP
	rmark int           // 路由标记
}

// Name 返回代理适配器的名称
// 实现 C.ProxyAdapter 接口
func (b *Base) Name() string {
	return b.name
}

// Type 返回代理适配器的类型
// 实现 C.ProxyAdapter 接口
func (b *Base) Type() C.AdapterType {
	return b.tp
}

// StreamConn 创建一个流式连接
// 实现 C.ProxyAdapter 接口
func (b *Base) StreamConn(c net.Conn, metadata *C.Metadata) (net.Conn, error) {
	return c, errors.New("no support")
}

// ListenPacketContext 创建一个数据包连接
// 实现 C.ProxyAdapter 接口
func (b *Base) ListenPacketContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (C.PacketConn, error) {
	return nil, errors.New("no support")
}

// SupportUDP 返回是否支持 UDP
// 实现 C.ProxyAdapter 接口
func (b *Base) SupportUDP() bool {
	return b.udp
}

// MarshalJSON 将代理适配器信息序列化为 JSON
// 实现 C.ProxyAdapter 接口
func (b *Base) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]string{
		"type": b.Type().String(),
	})
}

// Addr 返回代理服务器地址
// 实现 C.ProxyAdapter 接口
func (b *Base) Addr() string {
	return b.addr
}

// Unwrap 返回底层代理
// 实现 C.ProxyAdapter 接口
func (b *Base) Unwrap(metadata *C.Metadata) C.Proxy {
	return nil
}

// DialOptions 返回拨号选项
// 根据结构体中的配置生成拨号选项
func (b *Base) DialOptions(opts ...dialer.Option) []dialer.Option {
	if b.iface != "" {
		opts = append(opts, dialer.WithInterface(b.iface))
	}

	if b.rmark != 0 {
		opts = append(opts, dialer.WithRoutingMark(b.rmark))
	}

	return opts
}

// BasicOption 包含基本的代理选项
type BasicOption struct {
	Interface   string `proxy:"interface-name,omitempty" group:"interface-name,omitempty"` // 网络接口名称
	RoutingMark int    `proxy:"routing-mark,omitempty" group:"routing-mark,omitempty"`     // 路由标记
}

// BaseOption 包含创建基础代理适配器所需的选项
type BaseOption struct {
	Name        string        // 代理名称
	Addr        string        // 代理服务器地址
	Type        C.AdapterType // 代理类型
	UDP         bool          // 是否支持 UDP
	Interface   string        // 网络接口名称
	RoutingMark int           // 路由标记
}

// NewBase 创建一个新的基础代理适配器
func NewBase(opt BaseOption) *Base {
	return &Base{
		name:  opt.Name,
		addr:  opt.Addr,
		tp:    opt.Type,
		udp:   opt.UDP,
		iface: opt.Interface,
		rmark: opt.RoutingMark,
	}
}

// conn 是一个包装了 net.Conn 的连接结构体
// 实现了 C.Connection 接口
type conn struct {
	net.Conn
	chain C.Chain // 代理链
}

// Chains 返回代理链
// 实现 C.Connection 接口
func (c *conn) Chains() C.Chain {
	return c.chain
}

// AppendToChains 将代理适配器添加到代理链中
// 实现 C.Connection 接口
func (c *conn) AppendToChains(a C.ProxyAdapter) {
	c.chain = append(c.chain, a.Name())
}

// NewConn 创建一个新的连接
func NewConn(c net.Conn, a C.ProxyAdapter) C.Conn {
	return &conn{c, []string{a.Name()}}
}

// packetConn 是一个包装了 net.PacketConn 的数据包连接结构体
// 实现了 C.PacketConn 接口
type packetConn struct {
	net.PacketConn
	chain C.Chain // 代理链
}

// Chains 返回代理链
// 实现 C.Connection 接口
func (c *packetConn) Chains() C.Chain {
	return c.chain
}

// AppendToChains 将代理适配器添加到代理链中
// 实现 C.Connection 接口
func (c *packetConn) AppendToChains(a C.ProxyAdapter) {
	c.chain = append(c.chain, a.Name())
}

// newPacketConn 创建一个新的数据包连接
func newPacketConn(pc net.PacketConn, a C.ProxyAdapter) C.PacketConn {
	return &packetConn{pc, []string{a.Name()}}
}
