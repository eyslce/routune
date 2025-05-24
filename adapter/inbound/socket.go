// Package inbound 提供了处理入站连接的相关功能
package inbound

import (
	"net"
	"net/netip"

	C "github.com/eyslce/routune/constant"
	"github.com/eyslce/routune/context"
	"github.com/eyslce/routune/transport/socks5"
)

// NewSocket 创建一个新的 Socket 连接上下文
// 参数说明:
//   - target: SOCKS5 格式的目标地址
//   - conn: 网络连接对象
//   - source: 连接类型
//
// 返回值:
//   - *context.ConnContext: 包含连接元数据的上下文对象
func NewSocket(target socks5.Addr, conn net.Conn, source C.Type) *context.ConnContext {
	// 解析目标地址信息
	metadata := parseSocksAddr(target)
	// 设置网络类型为 TCP
	metadata.NetWork = C.TCP
	// 设置连接类型
	metadata.Type = source
	// 解析并设置源 IP 和端口
	if ip, port, err := parseAddr(conn.RemoteAddr()); err == nil {
		metadata.SrcIP = ip
		metadata.SrcPort = C.Port(port)
	}
	// 解析并设置本地地址（原始目标地址）
	if addrPort, err := netip.ParseAddrPort(conn.LocalAddr().String()); err == nil {
		metadata.OriginDst = addrPort
	}
	// 创建并返回新的连接上下文
	return context.NewConnContext(conn, metadata)
}
