package socks

import (
	"net"

	"github.com/eyslce/clash/common/pool"
	"github.com/eyslce/clash/transport/socks5"
)

// packet 结构体实现了 C.UDPPacket 接口，用于包装 SOCKS5 UDP 包。
// 它包含了发送响应所需的 PacketConn、原始请求的源地址、实际的负载数据以及对原始缓冲区的引用。
type packet struct {
	pc      net.PacketConn // 用于发送响应的 PacketConn
	rAddr   net.Addr       // UDP 包的原始发送方地址 (remote address)
	payload []byte         // SOCKS5 UDP 包中解码后的实际负载数据
	bufRef  []byte         // 对原始接收缓冲区的引用，用于在处理完毕后归还到池中
}

// Data 返回 UDP 包的实际负载数据。
// 实现 C.UDPPacket 接口。
func (c *packet) Data() []byte {
	return c.payload
}

// WriteBack 将数据写回 UDP 包的原始发送方。
// b: 要发送的负载数据。
// addr: 此次回写操作中，作为 SOCKS5 UDP 包头中的源地址 (rsv + atyp + dst.addr + dst.port)。
//
//	注意：这里的 addr 是 SOCKS5 协议层面的源地址，而不是网络层面的。
//	实际的网络层面的目标地址是 c.rAddr (即原始请求的发送方)。
//
// 实现 C.UDPPacket 接口。
func (c *packet) WriteBack(b []byte, addr net.Addr) (n int, err error) {
	// 将传入的负载数据 b 和 SOCKS5 源地址 addr 编码成一个完整的 SOCKS5 UDP 包
	encodedPacket, err := socks5.EncodeUDPPacket(socks5.ParseAddrToSocksAddr(addr), b)
	if err != nil {
		return // 编码失败则返回错误
	}
	// 通过底层的 PacketConn (c.pc) 将编码后的 SOCKS5 UDP 包发送到原始请求的源地址 (c.rAddr)
	return c.pc.WriteTo(encodedPacket, c.rAddr)
}

// LocalAddr 返回 UDP 包的原始发送方地址。
// 注意：虽然方法名叫 LocalAddr，但在这里它返回的是远端（客户端）的地址，
// 因为这是从服务器监听的角度来看的"本地"对端地址，即 UDP 请求的来源。
// 实现 C.UDPPacket 接口。
func (c *packet) LocalAddr() net.Addr {
	return c.rAddr
}

// Drop 用于在处理完 UDP 包后（例如，发送到 Tunnel 失败或处理完毕），
// 将原始接收时使用的缓冲区归还到 buffer pool，以供复用。
// 实现 C.UDPPacket 接口。
func (c *packet) Drop() {
	pool.Put(c.bufRef) // 将 bufRef 引用的缓冲区放回池中
}
