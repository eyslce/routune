package socks

import (
	"net"

	"github.com/eyslce/clash/adapter/inbound"
	"github.com/eyslce/clash/common/pool"
	"github.com/eyslce/clash/common/sockopt"
	C "github.com/eyslce/clash/constant"
	"github.com/eyslce/clash/log"
	"github.com/eyslce/clash/transport/socks5"
)

// UDPListener 结构体封装了 SOCKS UDP 监听器的基本信息和操作
type UDPListener struct {
	packetConn net.PacketConn // 底层的 net.PacketConn，用于收发 UDP 包
	addr       string         // 监听的原始地址字符串，例如 ":7890"
	closed     bool           // 标记监听器是否已关闭
}

// RawAddress 返回监听器配置时使用的原始地址字符串。
// 实现 C.Listener 接口。
func (l *UDPListener) RawAddress() string {
	return l.addr
}

// Address 返回监听器实际监听的地址字符串，可能包含动态分配的端口。
// 实现 C.Listener 接口。
func (l *UDPListener) Address() string {
	return l.packetConn.LocalAddr().String()
}

// Close 关闭 UDP 监听器。
// 实现 C.Listener 接口。
func (l *UDPListener) Close() error {
	l.closed = true             // 标记为已关闭
	return l.packetConn.Close() // 关闭底层的 net.PacketConn
}

// NewUDP 创建一个新的 SOCKS UDP 监听器。
// addr: 监听地址字符串，例如 ":7890" 或 "127.0.0.1:7890"。
// in: 用于将新接收的 UDP 包（包装为 inbound.PacketAdapter）发送到 Tunnel 处理的通道。
// 返回创建的监听器实例 (C.Listener) 和可能发生的错误。
func NewUDP(addr string, in chan<- *inbound.PacketAdapter) (C.Listener, error) {
	l, err := net.ListenPacket("udp", addr) // 在指定地址上开始监听 UDP 包
	if err != nil {
		return nil, err
	}

	// 尝试为 UDP 连接设置 SO_REUSEADDR 选项，允许多个进程绑定到同一地址和端口
	// 这在某些情况下可以避免 "address already in use" 错误，尤其是在快速重启应用时
	if err := sockopt.UDPReuseaddr(l.(*net.UDPConn)); err != nil {
		log.Warnln("Failed to Reuse UDP Address: %s", err)
	}

	// 创建 UDPListener 结构体实例
	sl := &UDPListener{
		packetConn: l,
		addr:       addr,
	}
	// 启动一个 goroutine 来接收和处理 UDP 包
	go func() {
		for {
			buf := pool.Get(pool.UDPBufferSize) // 从 buffer pool 获取一个字节切片用于接收数据
			// 从 PacketConn 读取 UDP 包，n 为读取的字节数，remoteAddr 为发送方的地址
			n, remoteAddr, err := l.ReadFrom(buf)
			if err != nil {
				pool.Put(buf)  // 将 buffer 放回 pool
				if sl.closed { // 如果监听器已关闭，则退出循环
					break
				}
				continue // 其他错误则继续尝试读取
			}
			// 处理接收到的 SOCKS UDP 包
			handleSocksUDP(l, in, buf[:n], remoteAddr)
		}
	}()

	return sl, nil
}

// handleSocksUDP 处理单个 SOCKS UDP 包。
// pc: 用于发送响应的 net.PacketConn。
// in: 用于将解码后的包发送到 Tunnel 的通道。
// buf: 包含 UDP 包数据的字节切片。
// addr: UDP 包的发送方地址。
func handleSocksUDP(pc net.PacketConn, in chan<- *inbound.PacketAdapter, buf []byte, addr net.Addr) {
	// 解码 SOCKS5 UDP 包头，获取目标地址和实际的负载数据
	target, payload, err := socks5.DecodeUDPPacket(buf)
	if err != nil {
		// 如果解码失败（例如，不是有效的 SOCKS5 UDP 包），则将 buffer 放回 pool
		pool.Put(buf)
		return
	}
	// 创建一个 packet 实例，它实现了 C.UDPPacket 接口
	packet := &packet{
		pc:      pc,      // 用于回写数据的 PacketConn
		rAddr:   addr,    // 原始 UDP 包的源地址
		payload: payload, // SOCKS5 UDP 包中的实际负载数据
		bufRef:  buf,     // 对原始 buffer 的引用，用于在 Drop 时归还到 pool
	}
	// 尝试将包装好的 PacketAdapter 发送到 Tunnel 的处理队列
	// 使用 select 以避免在队列满时阻塞
	select {
	case in <- inbound.NewPacket(target, pc.LocalAddr(), packet, C.SOCKS5):
	default: // 如果队列已满，则丢弃该包（packet.Drop() 会在 inbound.NewPacket 内部处理失败时被调用，或在此处显式调用）
	}
}
