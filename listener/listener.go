package listener

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/eyslce/routune/adapter/inbound"
	"github.com/eyslce/routune/config"
	C "github.com/eyslce/routune/constant"
	"github.com/eyslce/routune/listener/http"
	"github.com/eyslce/routune/listener/mixed"
	"github.com/eyslce/routune/listener/redir"
	"github.com/eyslce/routune/listener/socks"
	"github.com/eyslce/routune/listener/tproxy"
	"github.com/eyslce/routune/listener/tunnel"
	"github.com/eyslce/routune/log"

	"github.com/samber/lo"
)

var (
	allowLan    = false // 是否允许局域网连接
	bindAddress = "*"   // 默认监听地址，"*" 表示监听所有网络接口

	tcpListeners = make(map[C.Inbound]C.Listener) // 存储 TCP 监听器，键为入站配置，值为监听器实例
	udpListeners = make(map[C.Inbound]C.Listener) // 存储 UDP 监听器，键为入站配置，值为监听器实例

	tunnelTCPListeners = make(map[string]*tunnel.Listener)   // 存储 Tunnel TCP 监听器，键为 "address/target/proxy"
	tunnelUDPListeners = make(map[string]*tunnel.PacketConn) // 存储 Tunnel UDP PacketConn，键为 "address/target/proxy"

	// lock for recreate function
	recreateMux sync.Mutex // 用于保护监听器重新创建过程的互斥锁
	tunnelMux   sync.Mutex // 用于保护 Tunnel 监听器操作的互斥锁
)

// Ports 结构体定义了各种代理协议的监听端口
type Ports struct {
	Port       int `json:"port"`        // HTTP 代理端口
	SocksPort  int `json:"socks-port"`  // SOCKS5 代理端口
	RedirPort  int `json:"redir-port"`  // 透明代理（重定向）端口
	TProxyPort int `json:"tproxy-port"` // TProxy 代理端口 (Linux)
	MixedPort  int `json:"mixed-port"`  // 混合代理端口 (HTTP 和 SOCKS)
}

// tcpListenerCreators 存储了不同入站类型的 TCP 监听器创建函数
var tcpListenerCreators = map[C.InboundType]tcpListenerCreator{
	C.InboundTypeHTTP:   http.New,   // HTTP 监听器创建函数
	C.InboundTypeSocks:  socks.New,  // SOCKS 监听器创建函数
	C.InboundTypeRedir:  redir.New,  // Redir 监听器创建函数
	C.InboundTypeTproxy: tproxy.New, // TProxy 监听器创建函数
	C.InboundTypeMixed:  mixed.New,  // Mixed 监听器创建函数
}

// udpListenerCreators 存储了不同入站类型的 UDP 监听器创建函数
var udpListenerCreators = map[C.InboundType]udpListenerCreator{
	C.InboundTypeSocks:  socks.NewUDP,  // SOCKS UDP 监听器创建函数
	C.InboundTypeRedir:  tproxy.NewUDP, // Redir UDP 监听器创建函数 (实际使用 TProxy 的 UDP)
	C.InboundTypeTproxy: tproxy.NewUDP, // TProxy UDP 监听器创建函数
	C.InboundTypeMixed:  socks.NewUDP,  // Mixed UDP 监听器创建函数 (实际使用 SOCKS 的 UDP)
}

// tcpListenerCreator 定义了 TCP 监听器创建函数的类型签名
type (
	tcpListenerCreator func(addr string, tcpIn chan<- C.ConnContext) (C.Listener, error)
	// udpListenerCreator 定义了 UDP 监听器创建函数的类型签名
	udpListenerCreator func(addr string, udpIn chan<- *inbound.PacketAdapter) (C.Listener, error)
)

// AllowLan 返回当前是否允许局域网连接
func AllowLan() bool {
	return allowLan
}

// BindAddress 返回当前配置的监听地址
func BindAddress() string {
	return bindAddress
}

// SetAllowLan 设置是否允许局域网连接
// al: true 表示允许，false 表示不允许
func SetAllowLan(al bool) {
	allowLan = al
}

// SetBindAddress 设置监听地址
// host: 新的监听地址，例如 "*", "127.0.0.1"
func SetBindAddress(host string) {
	bindAddress = host
}

// createListener 根据入站配置创建 TCP 和/或 UDP 监听器
// inbound: 入站配置
// tcpIn: TCP 连接上下文的发送通道，用于将新的 TCP 连接传递给 Tunnel 处理
// udpIn: UDP 包适配器的发送通道，用于将新的 UDP 包传递给 Tunnel 处理
func createListener(inbound C.Inbound, tcpIn chan<- C.ConnContext, udpIn chan<- *inbound.PacketAdapter) {
	addr := inbound.BindAddress // 获取入站配置中指定的监听地址
	// 如果端口号为 0 或无效，则不创建监听器
	if portIsZero(addr) {
		return
	}
	tcpCreator := tcpListenerCreators[inbound.Type] // 获取对应入站类型的 TCP 监听器创建函数
	udpCreator := udpListenerCreators[inbound.Type] // 获取对应入站类型的 UDP 监听器创建函数
	// 如果该入站类型既不支持 TCP 也不支持 UDP，则记录错误并返回
	if tcpCreator == nil && udpCreator == nil {
		log.Errorln("inbound type %s not support.", inbound.Type)
		return
	}
	// 如果支持 TCP，则创建 TCP 监听器
	if tcpCreator != nil {
		tcpListener, err := tcpCreator(addr, tcpIn)
		if err != nil {
			log.Errorln("create addr %s tcp listener error. err:%v", addr, err)
			return
		}
		tcpListeners[inbound] = tcpListener // 将创建的 TCP 监听器存入映射
	}
	// 如果支持 UDP，则创建 UDP 监听器
	if udpCreator != nil {
		udpListener, err := udpCreator(addr, udpIn)
		if err != nil {
			log.Errorln("create addr %s udp listener error. err:%v", addr, err)
			return
		}
		udpListeners[inbound] = udpListener // 将创建的 UDP 监听器存入映射
	}
	log.Infoln("inbound %s create success.", inbound.ToAlias()) // 记录监听器创建成功的日志
}

// closeListener 关闭指定入站配置对应的 TCP 和 UDP 监听器
// inbound: 需要关闭监听器的入站配置
func closeListener(inbound C.Inbound) {
	listener := tcpListeners[inbound] // 获取 TCP 监听器
	if listener != nil {
		if err := listener.Close(); err != nil {
			log.Errorln("close tcp address `%s` error. err:%s", inbound.ToAlias(), err.Error())
		}
		delete(tcpListeners, inbound) // 从映射中移除
	}
	listener = udpListeners[inbound] // 获取 UDP 监听器
	if listener != nil {
		if err := listener.Close(); err != nil {
			log.Errorln("close udp address `%s` error. err:%s", inbound.ToAlias(), err.Error())
		}
		delete(udpListeners, inbound) // 从映射中移除
	}
}

// getNeedCloseAndCreateInbound 比较原始入站配置和新的入站配置，
// 返回需要关闭的旧监听器配置列表和需要创建的新监听器配置列表。
// originInbounds: 原始的入站配置列表。
// newInbounds: 新的入站配置列表。
func getNeedCloseAndCreateInbound(originInbounds []C.Inbound, newInbounds []C.Inbound) ([]C.Inbound, []C.Inbound) {
	needCloseMap := map[C.Inbound]bool{} // 用于快速查找需要关闭的入站配置
	needClose := []C.Inbound{}           // 需要关闭的入站配置列表
	needCreate := []C.Inbound{}          // 需要创建的入站配置列表

	// 将所有原始入站配置加入 needCloseMap
	for _, inbound := range originInbounds {
		needCloseMap[inbound] = true
	}
	// 遍历新的入站配置
	for _, inbound := range newInbounds {
		if needCloseMap[inbound] { // 如果新的入站配置也在原始配置中，则不需要关闭
			delete(needCloseMap, inbound)
		} else { // 如果新的入站配置不在原始配置中，则需要创建
			needCreate = append(needCreate, inbound)
		}
	}
	// needCloseMap 中剩余的即为需要关闭的入站配置
	for inbound := range needCloseMap {
		needClose = append(needClose, inbound)
	}
	return needClose, needCreate
}

// ReCreateListeners 仅重新创建通过 `inbounds` 配置项指定的监听器。
// 它会保留通过 `port`, `socks-port` 等传统端口配置方式创建的监听器。
// inbounds: 新的 `inbounds` 配置列表。
// tcpIn: TCP 连接上下文的发送通道。
// udpIn: UDP 包适配器的发送通道。
func ReCreateListeners(inbounds []C.Inbound, tcpIn chan<- C.ConnContext, udpIn chan<- *inbound.PacketAdapter) {
	newInbounds := []C.Inbound{}
	newInbounds = append(newInbounds, inbounds...) // 复制一份新的 inbounds 配置
	// 将当前由端口配置生成的入站配置也加入到 newInbounds 中，以进行比较和可能的关闭操作
	for _, inbound := range getInbounds() {
		if inbound.IsFromPortCfg { // IsFromPortCfg 标记此入站配置是否来自传统的端口配置
			newInbounds = append(newInbounds, inbound)
		}
	}
	reCreateListeners(newInbounds, tcpIn, udpIn) // 调用通用的监听器重新创建逻辑
}

// ReCreatePortsListeners 仅重新创建通过传统端口配置（如 `port`, `socks-port`）指定的监听器。
// 它会保留通过 `inbounds` 配置项创建的监听器。
// ports: 包含新端口配置的 Ports 结构体。
// tcpIn: TCP 连接上下文的发送通道。
// udpIn: UDP 包适配器的发送通道。
func ReCreatePortsListeners(ports Ports, tcpIn chan<- C.ConnContext, udpIn chan<- *inbound.PacketAdapter) {
	newInbounds := []C.Inbound{}
	newInbounds = append(newInbounds, GetInbounds()...) // 获取当前所有非端口配置生成的入站配置
	// 根据新的端口配置生成对应的入站配置，并添加到 newInbounds 列表中
	newInbounds = addPortInbound(newInbounds, C.InboundTypeHTTP, ports.Port)
	newInbounds = addPortInbound(newInbounds, C.InboundTypeSocks, ports.SocksPort)
	newInbounds = addPortInbound(newInbounds, C.InboundTypeRedir, ports.RedirPort)
	newInbounds = addPortInbound(newInbounds, C.InboundTypeTproxy, ports.TProxyPort)
	newInbounds = addPortInbound(newInbounds, C.InboundTypeMixed, ports.MixedPort)
	reCreateListeners(newInbounds, tcpIn, udpIn) // 调用通用的监听器重新创建逻辑
}

// addPortInbound 根据给定的入站类型和端口号，生成一个入站配置并添加到列表中。
// inbounds: 当前的入站配置列表。
// inboundType: 入站类型 (HTTP, SOCKS 等)。
// port: 监听端口号。
// 返回更新后的入站配置列表。
func addPortInbound(inbounds []C.Inbound, inboundType C.InboundType, port int) []C.Inbound {
	if port != 0 { // 仅当端口号非零时创建
		inbounds = append(inbounds, C.Inbound{
			Type:          inboundType,                          // 设置入站类型
			BindAddress:   genAddr(bindAddress, port, allowLan), // 生成监听地址
			IsFromPortCfg: true,                                 // 标记此配置来自传统端口设置
		})
	}
	return inbounds
}

// reCreateListeners 是一个通用的函数，用于根据新的入站配置列表重新创建监听器。
// 它会比较当前活动的监听器和新的配置，关闭不再需要的监听器，并创建新的监听器。
// inbounds: 最新的完整入站配置列表（包括来自 `inbounds` 和传统端口配置的）。
// tcpIn: TCP 连接上下文的发送通道。
// udpIn: UDP 包适配器的发送通道。
func reCreateListeners(inbounds []C.Inbound, tcpIn chan<- C.ConnContext, udpIn chan<- *inbound.PacketAdapter) {
	recreateMux.Lock()         // 加锁，防止并发重新创建
	defer recreateMux.Unlock() // 函数结束时解锁
	// 获取需要关闭的旧监听器和需要创建的新监听器
	needClose, needCreate := getNeedCloseAndCreateInbound(getInbounds(), inbounds)
	// 关闭不再需要的监听器
	for _, inbound := range needClose {
		closeListener(inbound)
	}
	// 创建新的监听器
	for _, inbound := range needCreate {
		createListener(inbound, tcpIn, udpIn)
	}
}

// PatchTunnel 根据新的 Tunnel 配置列表，更新活动的 Tunnel 监听器。
// tunnels: 新的 Tunnel 配置列表。
// tcpIn: TCP 连接上下文的发送通道。
// udpIn: UDP 包适配器的发送通道。
func PatchTunnel(tunnels []config.Tunnel, tcpIn chan<- C.ConnContext, udpIn chan<- *inbound.PacketAdapter) {
	tunnelMux.Lock()         // 加锁，防止并发操作 Tunnel 监听器
	defer tunnelMux.Unlock() // 函数结束时解锁

	// addrProxy 结构体用于统一表示 TCP 或 UDP Tunnel 的关键信息
	type addrProxy struct {
		network string // "tcp" 或 "udp"
		addr    string // 监听地址
		target  string // 目标地址
		proxy   string // 使用的代理名称
	}

	// 获取当前活动的 TCP Tunnel 监听器的信息
	tcpOld := lo.Map(
		lo.Keys(tunnelTCPListeners), // 获取所有 TCP Tunnel 的键 ("address/target/proxy")
		func(key string, _ int) addrProxy {
			parts := strings.Split(key, "/")
			return addrProxy{
				network: "tcp",
				addr:    parts[0],
				target:  parts[1],
				proxy:   parts[2],
			}
		},
	)
	// 获取当前活动的 UDP Tunnel 监听器的信息
	udpOld := lo.Map(
		lo.Keys(tunnelUDPListeners), // 获取所有 UDP Tunnel 的键 ("address/target/proxy")
		func(key string, _ int) addrProxy {
			parts := strings.Split(key, "/")
			return addrProxy{
				network: "udp",
				addr:    parts[0],
				target:  parts[1],
				proxy:   parts[2],
			}
		},
	)
	oldElm := lo.Union(tcpOld, udpOld) // 合并 TCP 和 UDP 的旧 Tunnel 信息

	// 根据新的 Tunnel 配置列表生成新的 Tunnel 信息
	newElm := lo.FlatMap(
		tunnels,
		func(tunnel config.Tunnel, _ int) []addrProxy {
			return lo.Map(
				tunnel.Network, // 遍历 Tunnel 配置中支持的网络类型 ("tcp", "udp")
				func(network string, _ int) addrProxy {
					return addrProxy{
						network: network,
						addr:    tunnel.Address,
						target:  tunnel.Target,
						proxy:   tunnel.Proxy,
					}
				},
			)
		},
	)

	// 计算需要关闭的旧 Tunnel 和需要创建的新 Tunnel
	needClose, needCreate := lo.Difference(oldElm, newElm)

	// 关闭不再需要的 Tunnel 监听器
	for _, elm := range needClose {
		key := fmt.Sprintf("%s/%s/%s", elm.addr, elm.target, elm.proxy)
		if elm.network == "tcp" {
			tunnelTCPListeners[key].Close()
			delete(tunnelTCPListeners, key)
		} else {
			tunnelUDPListeners[key].Close()
			delete(tunnelUDPListeners, key)
		}
	}

	// 创建新的 Tunnel 监听器
	for _, elm := range needCreate {
		key := fmt.Sprintf("%s/%s/%s", elm.addr, elm.target, elm.proxy)
		if elm.network == "tcp" {
			l, err := tunnel.New(elm.addr, elm.target, elm.proxy, tcpIn)
			if err != nil {
				log.Errorln("Start tunnel %s error: %s", elm.target, err.Error())
				continue
			}
			tunnelTCPListeners[key] = l
			log.Infoln("Tunnel(tcp/%s) proxy %s listening at: %s", elm.target, elm.proxy, tunnelTCPListeners[key].Address())
		} else {
			l, err := tunnel.NewUDP(elm.addr, elm.target, elm.proxy, udpIn)
			if err != nil {
				log.Errorln("Start tunnel %s error: %s", elm.target, err.Error())
				continue
			}
			tunnelUDPListeners[key] = l
			log.Infoln("Tunnel(udp/%s) proxy %s listening at: %s", elm.target, elm.proxy, tunnelUDPListeners[key].Address())
		}
	}
}

// GetInbounds 返回当前通过 `inbounds` 配置项创建的入站配置列表（不包括来自传统端口配置的）。
func GetInbounds() []C.Inbound {
	return lo.Filter(getInbounds(), func(inbound C.Inbound, idx int) bool {
		return !inbound.IsFromPortCfg // 过滤掉 IsFromPortCfg 为 true 的配置
	})
}

// getInbounds 返回当前所有活动的入站配置列表（包括来自 `inbounds` 和传统端口配置的）。
// GetInbounds return the inbounds of proxy servers
func getInbounds() []C.Inbound {
	var inbounds []C.Inbound
	// 添加所有 TCP 监听器对应的入站配置
	for inbound := range tcpListeners {
		inbounds = append(inbounds, inbound)
	}
	// 添加所有 UDP 监听器对应的入站配置，但要避免重复添加（如果 TCP 和 UDP 使用相同的入站配置）
	for inbound := range udpListeners {
		if _, ok := tcpListeners[inbound]; !ok { // 如果该入站配置没有对应的 TCP 监听器
			inbounds = append(inbounds, inbound)
		}
	}
	return inbounds
}

// GetPorts 返回一个 Ports 结构体，包含了当前各种代理协议的监听端口号。
// GetPorts return the ports of proxy servers
func GetPorts() *Ports {
	ports := &Ports{}
	// 遍历所有活动的入站配置
	for _, inbound := range getInbounds() {
		fillPort(inbound, ports) // 填充端口信息到 Ports 结构体
	}
	return ports
}

// fillPort 根据单个入站配置，将其端口信息填充到 Ports 结构体中。
// 仅处理来自传统端口配置的入站配置 (inbound.IsFromPortCfg 为 true)。
func fillPort(inbound C.Inbound, ports *Ports) {
	if inbound.IsFromPortCfg { // 确保是来自传统端口配置
		port := getPort(inbound.BindAddress) // 从监听地址中提取端口号
		switch inbound.Type {                // 根据入站类型填充到对应的 Ports 字段
		case C.InboundTypeHTTP:
			ports.Port = port
		case C.InboundTypeSocks:
			ports.SocksPort = port
		case C.InboundTypeTproxy:
			ports.TProxyPort = port
		case C.InboundTypeRedir:
			ports.RedirPort = port
		case C.InboundTypeMixed:
			ports.MixedPort = port
		default:
			// do nothing
		}
	}
}

// portIsZero 检查监听地址中的端口号是否为零或无效。
// addr: 监听地址字符串，例如 ":7890", "127.0.0.1:7890"。
// 返回 true 如果端口号为零、为空或解析错误，否则返回 false。
func portIsZero(addr string) bool {
	_, port, err := net.SplitHostPort(addr)      // 分割主机和端口
	if port == "0" || port == "" || err != nil { // 检查端口是否为 "0"、空字符串或发生错误
		return true
	}
	return false
}

// genAddr 根据主机、端口和是否允许局域网连接的设置，生成标准的监听地址字符串。
// host: 主机地址 ("*" 或具体 IP)。
// port: 端口号。
// allowLan: 是否允许局域网连接。
// 返回生成的监听地址字符串，例如 ":7890", "127.0.0.1:7890"。
func genAddr(host string, port int, allowLan bool) string {
	if allowLan { // 如果允许局域网连接
		if host == "*" { // 如果主机是 "*"，表示监听所有接口
			return fmt.Sprintf(":%d", port) // 返回 ":port"
		}
		return fmt.Sprintf("%s:%d", host, port) // 返回 "host:port"
	}

	// 如果不允许局域网连接，则强制监听 127.0.0.1
	return fmt.Sprintf("127.0.0.1:%d", port)
}

// getPort 从监听地址字符串中提取端口号。
// addr: 监听地址字符串。
// 返回提取到的端口号，如果解析失败则返回 0。
func getPort(addr string) int {
	_, portStr, err := net.SplitHostPort(addr) // 分割主机和端口
	if err != nil {
		return 0 // 解析失败返回 0
	}
	port, err := strconv.Atoi(portStr) // 将端口字符串转换为整数
	if err != nil {
		return 0 // 转换失败返回 0
	}
	return port
}
