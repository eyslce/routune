// Package inbound 提供了处理入站连接的相关功能
package inbound

import (
	"net"
	"net/netip"

	C "github.com/eyslce/routune/constant"
	"github.com/eyslce/routune/transport/socks5"
)

// PacketAdapter 是用于 socks/redir/tun 的 UDP 数据包适配器
// 它实现了 UDP 数据包的包装，并添加了元数据信息
type PacketAdapter struct {
	C.UDPPacket
	metadata *C.Metadata
}

// Metadata 返回目标元数据信息
// 返回值:
//   - *C.Metadata: 包含连接元数据的对象
func (s *PacketAdapter) Metadata() *C.Metadata {
	return s.metadata
}

// NewPacket 创建一个新的 PacketAdapter 实例
// 参数说明:
//   - target: SOCKS5 格式的目标地址
//   - originTarget: 原始目标地址（可能为 nil）
//   - packet: UDP 数据包对象
//   - source: 连接类型
//
// 返回值:
//   - *PacketAdapter: 新创建的 UDP 数据包适配器
func NewPacket(target socks5.Addr, originTarget net.Addr, packet C.UDPPacket, source C.Type) *PacketAdapter {
	// 解析目标地址信息
	metadata := parseSocksAddr(target)
	// 设置网络类型为 UDP
	metadata.NetWork = C.UDP
	// 设置连接类型
	metadata.Type = source
	// 解析并设置源 IP 和端口
	if ip, port, err := parseAddr(packet.LocalAddr()); err == nil {
		metadata.SrcIP = ip
		metadata.SrcPort = C.Port(port)
	}
	// 如果存在原始目标地址，解析并设置
	if originTarget != nil {
		if addrPort, err := netip.ParseAddrPort(originTarget.String()); err == nil {
			metadata.OriginDst = addrPort
		}
	}
	// 创建并返回新的数据包适配器
	return &PacketAdapter{
		UDPPacket: packet,
		metadata:  metadata,
	}
}
