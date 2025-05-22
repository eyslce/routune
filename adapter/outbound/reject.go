// Package outbound 实现了 Clash 的出站代理适配器
package outbound

import (
	"context"
	"io"
	"net"
	"time"

	"github.com/eyslce/clash/component/dialer"
	C "github.com/eyslce/clash/constant"
)

// Reject 实现了拒绝连接的代理适配器
// 用于拒绝所有连接请求
type Reject struct {
	*Base
}

// DialContext 实现 C.ProxyAdapter 接口
// 返回一个空连接，所有读写操作都会立即返回 EOF
func (r *Reject) DialContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (C.Conn, error) {
	return NewConn(&nopConn{}, r), nil
}

// ListenPacketContext 实现 C.ProxyAdapter 接口
// 返回一个空的数据包连接，所有读写操作都会立即返回 EOF
func (r *Reject) ListenPacketContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (C.PacketConn, error) {
	return newPacketConn(&nopPacketConn{}, r), nil
}

// NewReject 创建一个新的拒绝连接代理适配器
func NewReject() *Reject {
	return &Reject{
		Base: &Base{
			name: "REJECT",
			tp:   C.Reject,
			udp:  true,
		},
	}
}

// nopConn 是一个空连接实现
// 所有操作都会立即返回 EOF 或成功
type nopConn struct{}

// Read 实现 io.Reader 接口
// 总是返回 EOF
func (rw *nopConn) Read(b []byte) (int, error) {
	return 0, io.EOF
}

// Write 实现 io.Writer 接口
// 总是返回 EOF
func (rw *nopConn) Write(b []byte) (int, error) {
	return 0, io.EOF
}

// Close 实现 io.Closer 接口
func (rw *nopConn) Close() error { return nil }

// LocalAddr 返回本地地址
func (rw *nopConn) LocalAddr() net.Addr { return nil }

// RemoteAddr 返回远程地址
func (rw *nopConn) RemoteAddr() net.Addr { return nil }

// SetDeadline 设置读写超时
func (rw *nopConn) SetDeadline(time.Time) error { return nil }

// SetReadDeadline 设置读超时
func (rw *nopConn) SetReadDeadline(time.Time) error { return nil }

// SetWriteDeadline 设置写超时
func (rw *nopConn) SetWriteDeadline(time.Time) error { return nil }

// nopPacketConn 是一个空的数据包连接实现
// 所有操作都会立即返回 EOF 或成功
type nopPacketConn struct{}

// WriteTo 实现 net.PacketConn 接口
// 总是返回成功
func (npc *nopPacketConn) WriteTo(b []byte, addr net.Addr) (n int, err error) { return len(b), nil }

// ReadFrom 实现 net.PacketConn 接口
// 总是返回 EOF
func (npc *nopPacketConn) ReadFrom(b []byte) (int, net.Addr, error) { return 0, nil, io.EOF }

// Close 实现 net.PacketConn 接口
func (npc *nopPacketConn) Close() error { return nil }

// LocalAddr 返回本地地址
func (npc *nopPacketConn) LocalAddr() net.Addr { return &net.UDPAddr{IP: net.IPv4zero, Port: 0} }

// SetDeadline 设置读写超时
func (npc *nopPacketConn) SetDeadline(time.Time) error { return nil }

// SetReadDeadline 设置读超时
func (npc *nopPacketConn) SetReadDeadline(time.Time) error { return nil }

// SetWriteDeadline 设置写超时
func (npc *nopPacketConn) SetWriteDeadline(time.Time) error { return nil }
