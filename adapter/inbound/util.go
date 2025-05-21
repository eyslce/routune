// Package inbound 提供了处理入站连接的相关功能
package inbound

import (
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/eyslce/clash/common/util"
	C "github.com/eyslce/clash/constant"
	"github.com/eyslce/clash/transport/socks5"
)

// parseSocksAddr 解析 SOCKS5 地址格式并返回元数据
// 参数说明:
//   - target: SOCKS5 格式的目标地址
//
// 返回值:
//   - *C.Metadata: 包含解析后的地址信息的元数据对象
func parseSocksAddr(target socks5.Addr) *C.Metadata {
	metadata := &C.Metadata{}

	switch target[0] {
	case socks5.AtypDomainName:
		// 处理域名类型地址，移除 FQDN 末尾的点
		metadata.Host = strings.TrimRight(string(target[2:2+target[1]]), ".")
		metadata.DstPort = C.Port((int(target[2+target[1]]) << 8) | int(target[2+target[1]+1]))
	case socks5.AtypIPv4:
		// 处理 IPv4 类型地址
		ip := net.IP(target[1 : 1+net.IPv4len])
		metadata.DstIP = ip
		metadata.DstPort = C.Port((int(target[1+net.IPv4len]) << 8) | int(target[1+net.IPv4len+1]))
	case socks5.AtypIPv6:
		// 处理 IPv6 类型地址
		ip := net.IP(target[1 : 1+net.IPv6len])
		metadata.DstIP = ip
		metadata.DstPort = C.Port((int(target[1+net.IPv6len]) << 8) | int(target[1+net.IPv6len+1]))
	}

	return metadata
}

// parseHTTPAddr 解析 HTTP 请求中的地址信息并返回元数据
// 参数说明:
//   - request: HTTP 请求对象
//
// 返回值:
//   - *C.Metadata: 包含解析后的地址信息的元数据对象
func parseHTTPAddr(request *http.Request) *C.Metadata {
	// 获取主机名和端口
	host := request.URL.Hostname()
	port, _ := strconv.ParseUint(util.EmptyOr(request.URL.Port(), "80"), 10, 16)

	// 移除 FQDN 末尾的点
	host = strings.TrimRight(host, ".")

	metadata := &C.Metadata{
		NetWork: C.TCP,
		Host:    host,
		DstIP:   nil,
		DstPort: C.Port(port),
	}

	// 如果主机名是 IP 地址，则设置 DstIP
	if ip := net.ParseIP(host); ip != nil {
		metadata.DstIP = ip
	}

	return metadata
}

// parseAddr 解析网络地址并返回 IP 和端口
// 参数说明:
//   - addr: 网络地址对象
//
// 返回值:
//   - net.IP: IP 地址
//   - int: 端口号
//   - error: 错误信息（如果解析失败）
func parseAddr(addr net.Addr) (net.IP, int, error) {
	switch a := addr.(type) {
	case *net.TCPAddr:
		return a.IP, a.Port, nil
	case *net.UDPAddr:
		return a.IP, a.Port, nil
	default:
		return nil, 0, fmt.Errorf("unknown address type %s", addr.String())
	}
}
