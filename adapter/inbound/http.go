// Package inbound 提供了处理入站连接的相关功能
package inbound

import (
	"net"
	"net/netip"

	C "github.com/eyslce/routune/constant"
	"github.com/eyslce/routune/context"
	"github.com/eyslce/routune/transport/socks5"
)

// NewHTTP 创建一个新的 HTTP 连接上下文
// 参数说明:
//   - target: SOCKS5 格式的目标地址
//   - source: 连接的源地址
//   - originTarget: 原始目标地址（可能为 nil）
//   - conn: 网络连接对象
//
// 返回值:
//   - *context.ConnContext: 包含连接元数据的上下文对象
func NewHTTP(target socks5.Addr, source net.Addr, originTarget net.Addr, conn net.Conn) *context.ConnContext {
	// 解析目标地址信息
	metadata := parseSocksAddr(target)
	// 设置网络类型为 TCP
	metadata.NetWork = C.TCP
	// 设置连接类型为 HTTP
	metadata.Type = C.HTTP
	// 解析并设置源 IP 和端口
	if ip, port, err := parseAddr(source); err == nil {
		metadata.SrcIP = ip
		metadata.SrcPort = C.Port(port)
	}
	// 如果存在原始目标地址，解析并设置
	if originTarget != nil {
		if addrPort, err := netip.ParseAddrPort(originTarget.String()); err == nil {
			metadata.OriginDst = addrPort
		}
	}
	// 创建并返回新的连接上下文
	return context.NewConnContext(conn, metadata)
}
