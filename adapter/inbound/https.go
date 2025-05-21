// Package inbound 提供了处理入站连接的相关功能
package inbound

import (
	"net"
	"net/http"
	"net/netip"

	C "github.com/eyslce/clash/constant"
	"github.com/eyslce/clash/context"
)

// NewHTTPS 创建一个新的 HTTPS 连接上下文
// 参数说明:
//   - request: HTTP CONNECT 请求对象
//   - conn: 网络连接对象
//
// 返回值:
//   - *context.ConnContext: 包含连接元数据的上下文对象
func NewHTTPS(request *http.Request, conn net.Conn) *context.ConnContext {
	// 解析 HTTP 请求中的目标地址信息
	metadata := parseHTTPAddr(request)
	// 设置连接类型为 HTTP CONNECT
	metadata.Type = C.HTTPCONNECT
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
