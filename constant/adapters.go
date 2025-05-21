package constant

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/eyslce/clash/component/dialer"
)

// AdapterType 定义了不同代理适配器的类型。
// Adapter Type
const (
	Direct AdapterType = iota // Direct 表示直连适配器。
	Reject                    // Reject 表示拒绝连接适配器。

	Shadowsocks  // Shadowsocks 协议适配器。
	ShadowsocksR // ShadowsocksR 协议适配器。
	Snell        // Snell 协议适配器。
	Socks5       // SOCKS5 协议适配器。
	Http         // HTTP 代理适配器。
	Vmess        // VMess 协议适配器。
	Trojan       // Trojan 协议适配器。

	Relay       // Relay 表示一个代理组，用于转发流量到其他代理。
	Selector    // Selector 表示一个可选择的代理组。
	Fallback    // Fallback 表示一个故障转移代理组。
	URLTest     // URLTest 表示一个基于 URL 测试结果选择代理的组。
	LoadBalance // LoadBalance 表示一个负载均衡代理组。
)

// 定义了默认的网络超时时间。
const (
	DefaultTCPTimeout = 5 * time.Second   // DefaultTCPTimeout 是 TCP 连接的默认超时时间。
	DefaultUDPTimeout = DefaultTCPTimeout // DefaultUDPTimeout 是 UDP 连接的默认超时时间，与 TCP 相同。
	DefaultTLSTimeout = DefaultTCPTimeout // DefaultTLSTimeout 是 TLS 握手的默认超时时间，与 TCP 相同。
)

// Connection 接口定义了连接链的操作。
// 连接链记录了数据包或连接通过的代理序列。
type Connection interface {
	Chains() Chain                       // Chains 返回当前的连接链。
	AppendToChains(adapter ProxyAdapter) // AppendToChains 将给定的代理适配器添加到连接链的末尾。
}

// Chain 是一个字符串切片，表示一个连接链。
// 通常，链中的第一个元素是入口代理，最后一个元素是出口代理或目标地址。
type Chain []string

// String 方法返回连接链的字符串表示形式。
// 如果链为空，返回空字符串。
// 如果链中只有一个元素，返回该元素。
// 如果链中有多个元素，返回格式为 "最后一个元素[第一个元素]"。
func (c Chain) String() string {
	switch len(c) {
	case 0:
		return ""
	case 1:
		return c[0]
	default:
		return fmt.Sprintf("%s[%s]", c[len(c)-1], c[0])
	}
}

// Last 方法返回连接链中的第一个元素（通常是入口代理或最初的适配器）。
// 如果链为空，返回空字符串。
func (c Chain) Last() string {
	switch len(c) {
	case 0:
		return ""
	default:
		return c[0]
	}
}

// Conn 接口扩展了 net.Conn 接口，并嵌入了 Connection 接口。
// 它代表一个具有连接链跟踪功能的网络连接。
type Conn interface {
	net.Conn
	Connection
}

// PacketConn 接口扩展了 net.PacketConn 接口，并嵌入了 Connection 接口。
// 它代表一个具有连接链跟踪功能的面向数据包的网络连接。
type PacketConn interface {
	net.PacketConn
	Connection
	// Deprecate WriteWithMetadata because of remote resolve DNS cause TURN failed
	// WriteWithMetadata(p []byte, metadata *Metadata) (n int, err error)
}

// ProxyAdapter 接口定义了一个代理适配器的基本行为。
// 适配器负责处理特定协议的连接建立和数据转发。
type ProxyAdapter interface {
	Name() string                 // Name 返回适配器的名称。
	Type() AdapterType            // Type 返回适配器的类型 (例如 Shadowsocks, HTTP 等)。
	Addr() string                 // Addr 返回适配器的地址 (例如 "127.0.0.1:1080")。
	SupportUDP() bool             // SupportUDP 返回适配器是否支持 UDP 转发。
	MarshalJSON() ([]byte, error) // MarshalJSON 返回适配器的 JSON 表示形式，通常用于 API 输出。

	// StreamConn 在 net.Conn 的基础上封装一层特定协议，并附带元数据。
	// 例如：
	//	conn, _ := net.DialContext(context.Background(), "tcp", "host:port")
	//	conn, _ = adapter.StreamConn(conn, metadata)
	//
	// 它返回一个 C.Conn，该连接带有协议，并（如果适用）启动一个新的会话。
	StreamConn(c net.Conn, metadata *Metadata) (net.Conn, error)

	// DialContext 返回一个带有协议的 C.Conn。
	// 此连接（如果适用）包含与多路复用相关的重用逻辑。
	DialContext(ctx context.Context, metadata *Metadata, opts ...dialer.Option) (Conn, error)

	// ListenPacketContext 建立一个 UDP 包连接，并附带元数据。
	// 此连接（如果适用）包含与多路复用相关的重用逻辑。
	ListenPacketContext(ctx context.Context, metadata *Metadata, opts ...dialer.Option) (PacketConn, error)

	// Unwrap 从代理组中提取底层的单个代理。如果无法提取（例如，适配器本身不是代理组，或者代理组为空），则返回 nil。
	Unwrap(metadata *Metadata) Proxy
}

// DelayHistory 结构体用于存储延迟测试的历史记录。
type DelayHistory struct {
	Time      time.Time `json:"time"`      // Time 是进行延迟测试的时间。
	Delay     uint16    `json:"delay"`     // Delay 是测试记录的延迟时间，单位通常是毫秒。
	MeanDelay uint16    `json:"meanDelay"` // MeanDelay 是多次测试的平均延迟时间，单位通常是毫秒。
}

// Proxy 接口扩展了 ProxyAdapter 接口，增加了与代理健康状况和性能相关的方法。
type Proxy interface {
	ProxyAdapter
	Alive() bool                                                     // Alive 返回代理当前是否被认为是存活的。
	DelayHistory() []DelayHistory                                    // DelayHistory 返回最近的延迟测试历史记录。
	LastDelay() uint16                                               // LastDelay 返回最后一次记录的延迟时间。
	URLTest(ctx context.Context, url string) (uint16, uint16, error) // URLTest 测试到指定 URL 的连接延迟，返回单次延迟和平均延迟。

	// Deprecated: 请改用 DialContext。
	Dial(metadata *Metadata) (Conn, error)

	// Deprecated: 请改用 ListenPacketContext。
	DialUDP(metadata *Metadata) (PacketConn, error)
}

// AdapterType 是代理适配器类型的枚举。
// AdapterType is enum of adapter type
type AdapterType int

// String 方法为 AdapterType 提供字符串表示。
func (at AdapterType) String() string {
	switch at {
	case Direct:
		return "Direct"
	case Reject:
		return "Reject"

	case Shadowsocks:
		return "Shadowsocks"
	case ShadowsocksR:
		return "ShadowsocksR"
	case Snell:
		return "Snell"
	case Socks5:
		return "Socks5"
	case Http:
		return "Http"
	case Vmess:
		return "Vmess"
	case Trojan:
		return "Trojan"

	case Relay:
		return "Relay"
	case Selector:
		return "Selector"
	case Fallback:
		return "Fallback"
	case URLTest:
		return "URLTest"
	case LoadBalance:
		return "LoadBalance"

	default:
		return "Unknown"
	}
}

// UDPPacket 接口定义了对 UDP 数据包的操作。
// 它提供了获取数据包内容、将数据写回源地址以及管理数据包生命周期的方法。
// UDPPacket contains the data of UDP packet, and offers control/info of UDP packet's source
type UDPPacket interface {
	// Data 获取 UDP 数据包的有效负载。
	// Data get the payload of UDP Packet
	Data() []byte

	// WriteBack 将有效负载写回指定的源地址。
	// - 可变的源 IP/端口对于 STUN 非常重要。
	// - 如果未提供 addr，WriteBack 将使用原始目标作为源 IP/端口来写出 UDP 数据包，
	//   这在使用 Fake-IP 时非常重要。
	// WriteBack writes the payload with source IP/Port equals addr
	// - variable source IP/Port is important to STUN
	// - if addr is not provided, WriteBack will write out UDP packet with SourceIP/Port equals to original Target,
	//   this is important when using Fake-IP.
	WriteBack(b []byte, addr net.Addr) (n int, err error)

	// Drop 在数据包使用完毕后调用，可以在此函数中回收缓冲区。
	// Drop call after packet is used, could recycle buffer in this function.
	Drop()

	// LocalAddr 返回数据包的源 IP/端口。
	// LocalAddr returns the source IP/Port of packet
	LocalAddr() net.Addr
}
