package tunnel

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"time"

	"github.com/eyslce/clash/adapter/inbound"
	"github.com/eyslce/clash/component/nat"
	P "github.com/eyslce/clash/component/process"
	"github.com/eyslce/clash/component/resolver"
	C "github.com/eyslce/clash/constant"
	"github.com/eyslce/clash/constant/provider"
	icontext "github.com/eyslce/clash/context"
	"github.com/eyslce/clash/log"
	"github.com/eyslce/clash/tunnel/statistic"

	"go.uber.org/atomic"
)

var (
	tcpQueue  = make(chan C.ConnContext, 200)         // TCP 连接上下文队列，用于异步处理 TCP 连接
	udpQueue  = make(chan *inbound.PacketAdapter, 200) // UDP 包适配器队列，用于异步处理 UDP 包
	natTable  = nat.New()                               // NAT 表，用于跟踪 UDP 会话
	rules     []C.Rule                                  // 规则列表
	proxies   = make(map[string]C.Proxy)                // 代理映射，存储所有可用的代理
	providers map[string]provider.ProxyProvider         // 代理提供者映射
	configMux sync.RWMutex                              // 用于保护 rules, proxies, providers 的读写锁

	// Outbound Rule
	mode = Rule // 当前的隧道模式 (Rule, Global, Direct)

	// default timeout for UDP session
	udpTimeout = 60 * time.Second // UDP 会话的默认超时时间

	// experimental feature
	UDPFallbackMatch = atomic.NewBool(false) // 实验性功能：当代理不支持 UDP 时，是否尝试匹配下一个规则
)

// init 函数在包初始化时启动后台处理 goroutine
func init() {
	go process() // 启动处理 TCP 和 UDP 请求的 goroutine
}

// TCPIn 返回 TCP 连接上下文的接收通道。
// 其他模块可以通过此通道将新的 TCP 连接发送到 Tunnel 进行处理。
func TCPIn() chan<- C.ConnContext {
	return tcpQueue
}

// UDPIn 返回 UDP 包适配器的接收通道。
// 其他模块可以通过此通道将新的 UDP 包发送到 Tunnel 进行处理。
func UDPIn() chan<- *inbound.PacketAdapter {
	return udpQueue
}

// Rules 返回当前的规则列表。
func Rules() []C.Rule {
	configMux.RLock()         // 加读锁保护规则列表的并发访问
	defer configMux.RUnlock() // 解读锁
	return rules
}

// UpdateRules 更新规则列表。
// newRules: 新的规则列表。
func UpdateRules(newRules []C.Rule) {
	configMux.Lock()         // 加写锁保护规则列表的并发访问
	rules = newRules           // 更新规则列表
	configMux.Unlock()       // 解写锁
}

// Proxies 返回当前的代理映射。
func Proxies() map[string]C.Proxy {
	configMux.RLock()         // 加读锁保护代理映射的并发访问
	defer configMux.RUnlock() // 解读锁
	return proxies
}

// Providers 返回当前的代理提供者映射。
func Providers() map[string]provider.ProxyProvider {
	configMux.RLock()         // 加读锁保护代理提供者映射的并发访问
	defer configMux.RUnlock() // 解读锁
	return providers
}

// UpdateProxies 更新代理和代理提供者映射。
// newProxies: 新的代理映射。
// newProviders: 新的代理提供者映射。
func UpdateProxies(newProxies map[string]C.Proxy, newProviders map[string]provider.ProxyProvider) {
	configMux.Lock()         // 加写锁保护代理和提供者映射的并发访问
	proxies = newProxies       // 更新代理映射
	providers = newProviders   // 更新代理提供者映射
	configMux.Unlock()       // 解写锁
}

// Mode 返回当前的隧道模式。
func Mode() TunnelMode {
	return mode
}

// SetMode 设置隧道的模式。
// m: 新的隧道模式 (Rule, Global, Direct)。
func SetMode(m TunnelMode) {
	mode = m
}

// processUDP 是一个处理 UDP 包的 goroutine。
// 它从 udpQueue 中读取 UDP 包并调用 handleUDPConn 进行处理。
func processUDP() {
	queue := udpQueue
	for conn := range queue { // 不断从队列中读取 UDP 包
		handleUDPConn(conn)    // 处理 UDP 连接（包）
	}
}

// process 是 Tunnel 的主处理 goroutine。
// 它启动多个 processUDP goroutine 来并发处理 UDP 包，
// 并从 tcpQueue 中读取 TCP 连接上下文，为每个连接启动一个 handleTCPConn goroutine 进行处理。
func process() {
	numUDPWorkers := 4 // 默认启动 4 个 UDP 处理 worker
	// 根据 GOMAXPROCS 的值调整 UDP worker 的数量，但不超过 GOMAXPROCS
	if num := runtime.GOMAXPROCS(0); num > numUDPWorkers {
		numUDPWorkers = num
	}
	// 启动指定数量的 UDP 处理 goroutine
	for i := 0; i < numUDPWorkers; i++ {
		go processUDP()
	}

	queue := tcpQueue
	for conn := range queue { // 不断从队列中读取 TCP 连接
		go handleTCPConn(conn) // 为每个 TCP 连接启动一个新的 goroutine 进行处理
	}
}

// needLookupIP 判断是否需要根据目标 IP 地址查找主机名。
// 当启用了 IP 到主机名的映射 (resolver.MappingEnabled())，
// 且元数据中没有主机名 (metadata.Host == "")，但有目标 IP 地址 (metadata.DstIP != nil) 时返回 true。
func needLookupIP(metadata *C.Metadata) bool {
	return resolver.MappingEnabled() && metadata.Host == "" && metadata.DstIP != nil
}

// preHandleMetadata 对连接的元数据进行预处理。
// - 如果 metadata.Host 是一个 IP 地址字符串，则将其解析并填充到 metadata.DstIP，同时清空 metadata.Host。
// - 如果需要进行 IP 反查主机名 (needLookupIP 返回 true)：
//   - 尝试通过 resolver.FindHostByIP 查找主机名。
//   - 如果找到主机名，则更新 metadata.Host 和 metadata.DNSMode。
//   - 如果启用了 FakeIP，则将 metadata.DstIP 清空，并将 metadata.DNSMode 设置为 C.DNSFakeIP。
//   - 如果主机在自定义 Hosts 中，则更新 metadata.DstIP。
// - 如果 metadata.DstIP 是一个 FakeIP 但无法找到对应的主机名，则返回错误。
func preHandleMetadata(metadata *C.Metadata) error {
	// 如果 Host 字段是 IP 地址字符串，则解析为 IP 地址
	if ip := net.ParseIP(metadata.Host); ip != nil {
		metadata.DstIP = ip
		metadata.Host = "" // 清空 Host 字段，因为已经有了 DstIP
	}

	// 如果需要根据 IP 反查域名（通常在增强模式下）
	if needLookupIP(metadata) {
		host, exist := resolver.FindHostByIP(metadata.DstIP) // 尝试通过 IP 查找主机名
		if exist {
			metadata.Host = host // 找到了主机名，更新 metadata
			metadata.DNSMode = C.DNSMapping // 标记 DNS 解析模式为 IP->Host 映射
			if resolver.FakeIPEnabled() { // 如果启用了 FakeIP
				metadata.DstIP = nil             // 清除 DstIP，因为将通过 FakeIP 机制处理
				metadata.DNSMode = C.DNSFakeIP // 标记 DNS 解析模式为 FakeIP
			} else if node := resolver.DefaultHosts.Search(host); node != nil { // 如果主机在自定义 Hosts 中
				// redir-host (透明代理 Host 模式) 需要查找 hosts 文件
				metadata.DstIP = node.Data.(net.IP) // 使用 Hosts 文件中的 IP
			}
		} else if resolver.IsFakeIP(metadata.DstIP) { // 如果 DstIP 是 FakeIP 但没有找到映射
			return fmt.Errorf("fake DNS record %s missing", metadata.DstIP)
		}
	}

	return nil
}

// resolveMetadata 根据当前的隧道模式和元数据，解析出需要使用的代理和匹配的规则。
// ctx: 连接的上下文信息。
// metadata: 连接的元数据。
// 返回选定的代理 (C.Proxy)，匹配的规则 (C.Rule)，以及可能发生的错误。
// - 如果 metadata.SpecialProxy 不为空，则直接使用指定的代理。
// - 根据当前的隧道模式 (Direct, Global, Rule) 选择代理：
//   - Direct 模式：使用名为 "DIRECT" 的代理。
//   - Global 模式：使用名为 "GLOBAL" 的代理。
//   - Rule 模式：调用 match 函数匹配规则并获取代理。
func resolveMetadata(ctx C.PlainContext, metadata *C.Metadata) (proxy C.Proxy, rule C.Rule, err error) {
	// 如果元数据中指定了特殊的代理名称
	if metadata.SpecialProxy != "" {
		var exist bool
		proxy, exist = proxies[metadata.SpecialProxy] // 从代理映射中查找
		if !exist {
			err = fmt.Errorf("proxy %s not found", metadata.SpecialProxy) // 未找到则报错
		}
		return // 直接返回
	}

	// 根据当前的隧道模式选择代理
	switch mode {
	case Direct:
		proxy = proxies["DIRECT"] // Direct 模式，使用 DIRECT 代理
	case Global:
		proxy = proxies["GLOBAL"] // Global 模式，使用 GLOBAL 代理
	case Rule:
		proxy, rule, err = match(metadata) // Rule 模式，进行规则匹配
	default:
		panic(fmt.Sprintf("unknown mode: %s", mode)) // 未知模式，抛出 panic
	}

	return
}

// handleUDPConn 处理单个 UDP 包（适配器）。
// packet: 包含 UDP 包及其元数据的适配器。
// 主要流程：
// 1. 验证元数据有效性。
// 2. 如果目标 IP 是 FakeIP，记录其原始未映射的地址。
// 3. 调用 preHandleMetadata 对元数据进行预处理。
// 4. 如果元数据中的主机名未解析，进行 DNS 解析获取目标 IP。
// 5. 使用 NAT 表 (natTable) 管理 UDP 会话：
//    - 如果当前源地址的会话已存在，则直接将包转发到远端。
//    - 如果会话不存在，则创建新的会话：
//      - 使用锁确保同一源地址的会话创建过程是串行的。
//      - 调用 resolveMetadata 解析代理和规则。
//      - 使用选定的代理建立到目标地址的 UDP 连接 (ListenPacketContext)。
//      - 创建 UDP 流量追踪器 (statistic.NewUDPTracker)。
//      - 记录日志。
//      - 启动 handleUDPToLocal goroutine 处理从远端返回给本地的数据。
//      - 将新创建的 UDP 连接存入 NAT 表。
//      - 将当前包转发到远端。
func handleUDPConn(packet *inbound.PacketAdapter) {
	metadata := packet.Metadata() // 获取元数据
	// 校验元数据是否有效
	if !metadata.Valid() {
		packet.Drop() // 无效则丢弃包
		log.Warnln("[Metadata] not valid: %#v", metadata)
		return
	}

	// 如果目标 IP 是 FakeIP，记录其未映射的地址
	var fAddr netip.Addr
	if resolver.IsExistFakeIP(metadata.DstIP) {
		fAddr, _ = netip.AddrFromSlice(metadata.DstIP)
		fAddr = fAddr.Unmap() // 转换为 IPv4 地址（如果它是 IPv4 映射的 IPv6 地址）
	}

	// 预处理元数据
	if err := preHandleMetadata(metadata); err != nil {
		packet.Drop() // 预处理失败则丢弃包
		log.Debugln("[Metadata PreHandle] error: %s", err)
		return
	}

	// 如果目标主机名未解析为 IP（例如，直接使用域名进行连接时）
	if !metadata.Resolved() {
		ips, err := resolver.LookupIP(context.Background(), metadata.Host) // 进行 DNS 解析
		if err != nil {
			packet.Drop()
			return
		} else if len(ips) == 0 { // 没有解析到 IP
			packet.Drop()
			return
		}
		metadata.DstIP = ips[0] // 使用解析到的第一个 IP 地址
	}

	key := packet.LocalAddr().String() // 使用本地地址作为 NAT 表的键

	// 定义一个闭包，尝试从 NAT 表获取现有连接并处理
	handle := func() bool {
		pc := natTable.Get(key) // 从 NAT 表获取连接
		if pc != nil { // 如果连接已存在
			handleUDPToRemote(packet, pc, metadata) // 将包发送到远端
			return true
		}
		return false
	}

	// 尝试处理现有连接
	if handle() {
		packet.Drop() // 处理完后丢弃原始包（因为它已经被发送或复制）
		return
	}

	// 如果 NAT 表中没有现有连接，需要创建新连接
	// 使用 lockKey 来同步对特定源地址的连接创建过程
	lockKey := key + "-lock"
	cond, loaded := natTable.GetOrCreateLock(lockKey) // 获取或创建锁

	// 启动一个新的 goroutine 来处理连接的建立和后续的数据转发
	// 这是为了避免阻塞 processUDP goroutine
	go func() {
		defer packet.Drop() // 确保在 goroutine 退出时丢弃包

		// 如果 loaded 为 true，表示当前 goroutine 不是创建者，而是等待者
		if loaded {
			cond.L.Lock()   // 获取锁
			cond.Wait()     // 等待创建者完成并发出通知
			handle()         // 再次尝试处理（此时连接应该已经创建好了）
			cond.L.Unlock() // 释放锁
			return
		}

		// 当前 goroutine 是创建者
		defer func() {
			natTable.Delete(lockKey) // 删除锁
			cond.Broadcast()         // 通知所有等待者
		}()

		pCtx := icontext.NewPacketConnContext(metadata) // 创建 UDP 连接上下文
		// 解析元数据以确定使用哪个代理和规则
		proxy, rule, err := resolveMetadata(pCtx, metadata)
		if err != nil {
			log.Warnln("[UDP] Parse metadata failed: %s", err.Error())
			return
		}

		// 创建带有超时的上下文，用于代理的 ListenPacketContext 调用
		ctx, cancel := context.WithTimeout(context.Background(), C.DefaultUDPTimeout)
		defer cancel()
		// 使用选定的代理与目标地址建立 UDP 连接
		rawPc, err := proxy.ListenPacketContext(ctx, metadata.Pure())
		if err != nil {
			// 记录拨号错误日志
			if rule == nil {
				log.Warnln(
					"[UDP] dial %s %s --> %s error: %s",
					proxy.Name(),
					metadata.SourceAddress(),
					metadata.RemoteAddress(),
					err.Error(),
				)
			} else {
				log.Warnln("[UDP] dial %s (match %s/%s) %s --> %s error: %s", proxy.Name(), rule.RuleType().String(), rule.Payload(), metadata.SourceAddress(), metadata.RemoteAddress(), err.Error())
			}
			return
		}
		pCtx.InjectPacketConn(rawPc) // 将底层的 PacketConn 注入到上下文中
		// 创建 UDP 流量追踪器
		pc := statistic.NewUDPTracker(rawPc, statistic.DefaultManager, metadata, rule)

		// 记录连接日志
		switch true {
		case metadata.SpecialProxy != "": // 使用了特殊代理
			log.Infoln("[UDP] %s --> %s using %s", metadata.SourceAddress(), metadata.RemoteAddress(), metadata.SpecialProxy)
		case rule != nil: // 匹配到规则
			log.Infoln(
				"[UDP] %s --> %s match %s(%s) using %s",
				metadata.SourceAddress(),
				metadata.RemoteAddress(),
				rule.RuleType().String(),
				rule.Payload(),
				rawPc.Chains().String(), // 打印代理链
			)
		case mode == Global: // 全局模式
			log.Infoln("[UDP] %s --> %s using GLOBAL", metadata.SourceAddress(), metadata.RemoteAddress())
		case mode == Direct: // 直连模式
			log.Infoln("[UDP] %s --> %s using DIRECT", metadata.SourceAddress(), metadata.RemoteAddress())
		default: // 未匹配到任何规则，默认使用 DIRECT
			log.Infoln(
				"[UDP] %s --> %s doesn't match any rule using DIRECT",
				metadata.SourceAddress(),
				metadata.RemoteAddress(),
			)
		}

		oAddr, _ := netip.AddrFromSlice(metadata.DstIP) // 原始目标地址
		oAddr = oAddr.Unmap()
		// 启动一个 goroutine 处理从远端返回给本地的数据
		go handleUDPToLocal(packet.UDPPacket, pc, key, oAddr, fAddr)

		natTable.Set(key, pc) // 将新创建的连接存入 NAT 表
		handle()               // 再次调用 handle，将当前的第一个包发送出去
	}()
}

// handleTCPConn 处理单个 TCP 连接上下文。
// connCtx: 包含 TCP 连接及其元数据的上下文。
// 主要流程：
// 1. 确保连接最终被关闭。
// 2. 验证元数据有效性。
// 3. 调用 preHandleMetadata 对元数据进行预处理。
// 4. 调用 resolveMetadata 解析代理和规则。
// 5. 使用选定的代理与目标地址建立 TCP 连接 (DialContext)。
// 6. 创建 TCP 流量追踪器 (statistic.NewTCPTracker)。
// 7. 记录日志。
// 8. 调用 handleSocket 在本地连接和远端连接之间进行双向数据转发。
func handleTCPConn(connCtx C.ConnContext) {
	defer connCtx.Conn().Close() // 确保连接在函数结束时关闭

	metadata := connCtx.Metadata() // 获取元数据
	// 校验元数据是否有效
	if !metadata.Valid() {
		log.Warnln("[Metadata] not valid: %#v", metadata)
		return
	}

	// 预处理元数据
	if err := preHandleMetadata(metadata); err != nil {
		log.Debugln("[Metadata PreHandle] error: %s", err)
		return
	}

	// 解析元数据以确定使用哪个代理和规则
	proxy, rule, err := resolveMetadata(connCtx, metadata)
	if err != nil {
		log.Warnln("[Metadata] parse failed: %s", err.Error())
		return
	}

	// 创建带有超时的上下文，用于代理的 DialContext 调用
	ctx, cancel := context.WithTimeout(context.Background(), C.DefaultTCPTimeout)
	defer cancel()
	// 使用选定的代理与目标地址建立 TCP 连接
	remoteConn, err := proxy.DialContext(ctx, metadata.Pure())
	if err != nil {
		// 记录拨号错误日志
		if rule == nil {
			log.Warnln(
				"[TCP] dial %s %s --> %s error: %s",
				proxy.Name(),
				metadata.SourceAddress(),
				metadata.RemoteAddress(),
				err.Error(),
			)
		} else {
			log.Warnln("[TCP] dial %s (match %s/%s) %s --> %s error: %s", proxy.Name(), rule.RuleType().String(), rule.Payload(), metadata.SourceAddress(), metadata.RemoteAddress(), err.Error())
		}
		return
	}
	// 创建 TCP 流量追踪器
	remoteConn = statistic.NewTCPTracker(remoteConn, statistic.DefaultManager, metadata, rule)
	defer remoteConn.Close() // 确保远端连接在函数结束时关闭

	// 记录连接日志
	switch true {
	case metadata.SpecialProxy != "": // 使用了特殊代理
		log.Infoln("[TCP] %s --> %s using %s", metadata.SourceAddress(), metadata.RemoteAddress(), metadata.SpecialProxy)
	case rule != nil: // 匹配到规则
		log.Infoln(
			"[TCP] %s --> %s match %s(%s) using %s",
			metadata.SourceAddress(),
			metadata.RemoteAddress(),
			rule.RuleType().String(),
			rule.Payload(),
			remoteConn.Chains().String(), // 打印代理链
		)
	case mode == Global: // 全局模式
		log.Infoln("[TCP] %s --> %s using GLOBAL", metadata.SourceAddress(), metadata.RemoteAddress())
	case mode == Direct: // 直连模式
		log.Infoln("[TCP] %s --> %s using DIRECT", metadata.SourceAddress(), metadata.RemoteAddress())
	default: // 未匹配到任何规则，默认使用 DIRECT
		log.Infoln(
			"[TCP] %s --> %s doesn't match any rule using DIRECT",
			metadata.SourceAddress(),
			metadata.RemoteAddress(),
		)
	}

	// 在本地连接和远端连接之间进行双向数据转发
	handleSocket(connCtx, remoteConn)
}

// shouldResolveIP 判断是否应该为当前规则解析 IP 地址。
// 当规则指定需要解析 IP (rule.ShouldResolveIP() 返回 true)，
// 且元数据中有主机名 (metadata.Host != "")，但没有目标 IP (metadata.DstIP == nil) 时返回 true。
func shouldResolveIP(rule C.Rule, metadata *C.Metadata) bool {
	return rule.ShouldResolveIP() && metadata.Host != "" && metadata.DstIP == nil
}

// match 根据元数据匹配规则，并返回相应的代理和规则。
// metadata: 连接的元数据。
// 返回选定的代理 (C.Proxy)，匹配的规则 (C.Rule)，以及可能发生的错误（当前版本总是返回 nil 错误）。
// 匹配逻辑：
// 1. 加读锁保护规则和代理的并发访问。
// 2. 如果元数据中的主机名在自定义 Hosts 中，则使用 Hosts 中的 IP 更新 metadata.DstIP。
// 3. 遍历规则列表：
//    - 如果当前规则需要解析 IP (shouldResolveIP 返回 true) 且 IP 尚未解析，则进行 DNS 解析并更新 metadata.DstIP。
//    - 如果当前规则需要查找进程信息 (rule.ShouldFindProcess()) 且尚未查找，则尝试查找并更新 metadata.ProcessPath。
//    - 调用 rule.Match(metadata) 进行匹配。
//    - 如果匹配成功：
//      - 获取规则指定的代理适配器。
//      - 如果是 UDP 连接，且代理不支持 UDP，并且启用了 UDPFallbackMatch，则跳过此规则，继续匹配下一条。
//      - 返回匹配到的代理和规则。
// 4. 如果没有匹配到任何规则，则返回名为 "DIRECT" 的代理。
func match(metadata *C.Metadata) (C.Proxy, C.Rule, error) {
	configMux.RLock()         // 加读锁
	defer configMux.RUnlock() // 解读锁

	var resolved bool     // 标记 IP 是否已解析
	var processFound bool // 标记进程信息是否已查找

	// 检查 Hosts 文件中是否有匹配的域名
	if node := resolver.DefaultHosts.Search(metadata.Host); node != nil {
		ip := node.Data.(net.IP)
		metadata.DstIP = ip // 使用 Hosts 文件中的 IP
		resolved = true       // 标记已解析
	}

	// 遍历所有规则
	for _, rule := range rules {
		// 如果规则需要解析 IP 且尚未解析
		if !resolved && shouldResolveIP(rule, metadata) {
			ip, err := resolver.ResolveIP(metadata.Host) // 解析 IP
			if err != nil {
				log.Debugln("[DNS] resolve %s error: %s", metadata.Host, err.Error())
			} else {
				log.Debugln("[DNS] %s --> %s", metadata.Host, ip.String())
				metadata.DstIP = ip // 更新元数据中的目标 IP
			}
			resolved = true // 标记已解析
		}

		// 如果规则需要查找进程信息且尚未查找
		if !processFound && rule.ShouldFindProcess() {
			processFound = true // 标记已查找

			srcIP, ok := netip.AddrFromSlice(metadata.SrcIP) // 获取源 IP
			// 确保源 IP 有效且原始目标地址有效 (用于查找连接)
			if ok && metadata.OriginDst.IsValid() {
				srcIP = srcIP.Unmap()
				// 查找进程路径
				path, err := P.FindProcessPath(metadata.NetWork.String(), netip.AddrPortFrom(srcIP, uint16(metadata.SrcPort)), metadata.OriginDst)
				if err != nil {
					log.Debugln("[Process] find process %s: %v", metadata.String(), err)
				} else {
					log.Debugln("[Process] %s from process %s", metadata.String(), path)
					metadata.ProcessPath = path // 更新元数据中的进程路径
				}
			}
		}

		// 规则匹配
		if rule.Match(metadata) {
			adapter, ok := proxies[rule.Adapter()] // 获取规则指定的代理名称对应的代理实例
			if !ok { // 如果代理不存在，则跳过此规则
				continue
			}

			// 如果是 UDP 连接，代理不支持 UDP，并且启用了 UDPFallbackMatch
			if metadata.NetWork == C.UDP && !adapter.SupportUDP() && UDPFallbackMatch.Load() {
				log.Debugln("[Matcher] %s UDP is not supported, skip match", adapter.Name())
				continue // 跳过此规则，尝试匹配下一条
			}
			return adapter, rule, nil // 返回匹配的代理和规则
		}
	}

	// 如果没有匹配到任何规则，则返回 DIRECT 代理
	return proxies["DIRECT"], nil, nil
}
