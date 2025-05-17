package executor

import (
	"fmt"
	"os"
	"sync"

	"github.com/eyslce/clash/adapter"
	"github.com/eyslce/clash/adapter/outboundgroup"
	"github.com/eyslce/clash/component/auth"
	"github.com/eyslce/clash/component/dialer"
	"github.com/eyslce/clash/component/iface"
	"github.com/eyslce/clash/component/profile"
	"github.com/eyslce/clash/component/profile/cachefile"
	"github.com/eyslce/clash/component/resolver"
	"github.com/eyslce/clash/component/trie"
	"github.com/eyslce/clash/config"
	C "github.com/eyslce/clash/constant"
	"github.com/eyslce/clash/constant/provider"
	"github.com/eyslce/clash/dns"
	"github.com/eyslce/clash/listener"
	authStore "github.com/eyslce/clash/listener/auth"
	"github.com/eyslce/clash/log"
	"github.com/eyslce/clash/tunnel"
)

var mux sync.Mutex // mux 用于保护对全局配置的并发访问

// readConfig 从指定路径读取配置文件内容。
// path: 配置文件的路径。
// 返回文件内容的字节切片和可能发生的错误。
func readConfig(path string) ([]byte, error) {
	// 检查文件是否存在
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, err
	}
	// 读取文件内容
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// 检查文件是否为空
	if len(data) == 0 {
		return nil, fmt.Errorf("configuration file %s is empty", path)
	}

	return data, err
}

// Parse 使用默认配置文件路径解析配置。
// 返回解析后的配置对象和可能发生的错误。
func Parse() (*config.Config, error) {
	return ParseWithPath(C.Path.Config())
}

// ParseWithPath 使用自定义配置文件路径解析配置。
// path: 自定义配置文件的路径。
// 返回解析后的配置对象和可能发生的错误。
func ParseWithPath(path string) (*config.Config, error) {
	// 读取配置文件内容
	buf, err := readConfig(path)
	if err != nil {
		return nil, err
	}

	// 使用读取到的字节流解析配置
	return ParseWithBytes(buf)
}

// ParseWithBytes 使用字节流解析配置。
// buf: 包含配置信息的字节切片。
// 返回解析后的配置对象和可能发生的错误。
func ParseWithBytes(buf []byte) (*config.Config, error) {
	return config.Parse(buf)
}

// ApplyConfig 将配置分发到所有相关的部分。
// cfg: 要应用的配置对象。
// force: 是否强制应用配置，即使某些部分未更改。
func ApplyConfig(cfg *config.Config, force bool) {
	mux.Lock()         // 加锁以保证并发安全
	defer mux.Unlock() // 在函数返回时解锁

	// 按顺序更新各个部分的配置
	updateUsers(cfg.Users)                             // 更新用户认证信息
	updateProxies(cfg.Proxies, cfg.Providers)          // 更新代理和代理提供者
	updateRules(cfg.Rules)                             // 更新规则
	updateHosts(cfg.Hosts)                             // 更新 Hosts
	updateProfile(cfg)                                 // 更新 Profile 设置
	updateGeneral(cfg.General, force)                  // 更新通用设置
	updateInbounds(cfg.Inbounds, force)                // 更新入站连接监听器
	updateDNS(cfg.DNS)                                 // 更新 DNS 设置
	updateExperimental(cfg)                            // 更新实验性功能设置
	updateTunnels(cfg.Tunnels)                         // 更新隧道设置
}

// GetGeneral 获取当前的通用配置信息。
// 返回一个包含当前通用配置的 config.General 对象。
func GetGeneral() *config.General {
	ports := listener.GetPorts() // 获取当前监听的端口信息
	authenticator := []string{}  // 初始化认证用户列表
	// 获取当前的认证器并提取用户列表
	if auth := authStore.Authenticator(); auth != nil {
		authenticator = auth.Users()
	}

	// 构建并返回 General 配置对象
	general := &config.General{
		LegacyInbound: config.LegacyInbound{
			Port:        ports.Port,       // HTTP 代理端口
			SocksPort:   ports.SocksPort,  // SOCKS5 代理端口
			RedirPort:   ports.RedirPort,  // 透明代理（重定向）端口
			TProxyPort:  ports.TProxyPort, // TProxy 代理端口 (Linux)
			MixedPort:   ports.MixedPort,  // 混合代理端口 (HTTP 和 SOCKS)
			AllowLan:    listener.AllowLan(),   // 是否允许局域网连接
			BindAddress: listener.BindAddress(), // 监听地址
		},
		Authentication: authenticator,        // 认证用户列表
		Mode:           tunnel.Mode(),        // 代理模式 (Rule, Global, Direct)
		LogLevel:       log.Level(),          // 日志级别
		IPv6:           !resolver.DisableIPv6, // 是否启用 IPv6
	}

	return general
}

// updateExperimental 更新实验性功能相关的配置。
// c: 包含实验性功能配置的 config.Config 对象。
func updateExperimental(c *config.Config) {
	// 更新 UDP 回退匹配设置
	tunnel.UDPFallbackMatch.Store(c.Experimental.UDPFallbackMatch)
}

// updateDNS 更新 DNS相关的配置。
// c: 包含 DNS 配置的 config.DNS 对象。
func updateDNS(c *config.DNS) {
	// 如果未启用 DNS 服务
	if !c.Enable {
		resolver.DefaultResolver = nil    // 清除默认解析器
		resolver.DefaultHostMapper = nil // 清除默认主机映射器
		dns.ReCreateServer("", nil, nil) // 重新创建 DNS 服务（实际上是停止）
		return
	}

	// 构建 DNS 配置对象
	cfg := dns.Config{
		Main:         c.NameServer,       // 主 DNS 服务器
		Fallback:     c.Fallback,         // 备用 DNS 服务器
		IPv6:         c.IPv6,             // 是否启用 IPv6 DNS 解析
		EnhancedMode: c.EnhancedMode,     // DNS 增强模式
		Pool:         c.FakeIPRange,      // Fake IP 地址池
		Hosts:        c.Hosts,            // 自定义 Hosts 记录
		FallbackFilter: dns.FallbackFilter{ // 备用 DNS 过滤器配置
			GeoIP:     c.FallbackFilter.GeoIP,     // 是否启用 GeoIP 过滤
			GeoIPCode: c.FallbackFilter.GeoIPCode, // GeoIP 国家代码
			IPCIDR:    c.FallbackFilter.IPCIDR,    // IP CIDR 过滤列表
			Domain:    c.FallbackFilter.Domain,    // 域名过滤列表
		},
		Default:       c.DefaultNameserver, // 默认 DNS 服务器（用于 Bootstrap）
		Policy:        c.NameServerPolicy,  // DNS 服务器策略
		SearchDomains: c.SearchDomains,     // 搜索域
	}

	r := dns.NewResolver(cfg) // 创建新的 DNS 解析器
	m := dns.NewEnhancer(cfg) // 创建新的 DNS 增强器（用于 Fake IP 等）

	// 复用旧的 HostMapper 的缓存
	if old := resolver.DefaultHostMapper; old != nil {
		m.PatchFrom(old.(*dns.ResolverEnhancer))
	}

	resolver.DefaultResolver = r    // 设置新的默认解析器
	resolver.DefaultHostMapper = m // 设置新的默认主机映射器

	dns.ReCreateServer(c.Listen, r, m) // 根据新配置重新创建 DNS 服务
}

// updateHosts 更新自定义 Hosts 记录。
// tree: 包含域名和对应 IP 的 Trie 树。
func updateHosts(tree *trie.DomainTrie) {
	resolver.DefaultHosts = tree // 设置默认的 Hosts Trie 树
}

// updateProxies 更新代理和代理提供者。
// proxies: 代理名称到代理实例的映射。
// providers: 代理提供者名称到代理提供者实例的映射。
func updateProxies(proxies map[string]C.Proxy, providers map[string]provider.ProxyProvider) {
	tunnel.UpdateProxies(proxies, providers) // 更新 Tunnel 使用的代理和提供者
}

// updateRules 更新规则列表。
// rules: 规则列表。
func updateRules(rules []C.Rule) {
	tunnel.UpdateRules(rules) // 更新 Tunnel 使用的规则
}

// updateTunnels 更新隧道（通常指本地 SOCKS/HTTP 等）监听配置。
// tunnels: 隧道配置列表。
func updateTunnels(tunnels []config.Tunnel) {
	// 使用当前的 TCP 和 UDP 入站处理器更新隧道监听器
	listener.PatchTunnel(tunnels, tunnel.TCPIn(), tunnel.UDPIn())
}

// updateInbounds 更新入站连接监听器配置。
// inbounds: 入站配置列表。
// force: 是否强制重新创建监听器。
func updateInbounds(inbounds []C.Inbound, force bool) {
	// 如果不是强制更新，则直接返回
	if !force {
		return
	}
	tcpIn := tunnel.TCPIn() // 获取当前的 TCP 入站处理器
	udpIn := tunnel.UDPIn() // 获取当前的 UDP 入站处理器

	// 根据新的入站配置重新创建监听器
	listener.ReCreateListeners(inbounds, tcpIn, udpIn)
}

// updateGeneral 更新通用配置。
// general: 通用配置对象。
// force: 是否强制应用需要重启监听器的配置。
func updateGeneral(general *config.General, force bool) {
	log.SetLevel(general.LogLevel) // 设置日志级别
	tunnel.SetMode(general.Mode)   // 设置代理模式
	resolver.DisableIPv6 = !general.IPv6 // 设置是否禁用 IPv6 DNS 解析

	// 更新默认出站网络接口和路由标记
	dialer.DefaultInterface.Store(general.Interface)
	dialer.DefaultRoutingMark.Store(int32(general.RoutingMark))

	iface.FlushCache() // 清除网络接口缓存

	// 如果不是强制更新，则不处理需要重启监听器的配置
	if !force {
		return
	}

	allowLan := general.AllowLan // 是否允许局域网连接
	listener.SetAllowLan(allowLan) // 应用设置

	bindAddress := general.BindAddress // 监听地址
	listener.SetBindAddress(bindAddress) // 应用设置

	// 更新传统入站监听器的端口
	ports := listener.Ports{
		Port:       general.Port,       // HTTP 代理端口
		SocksPort:  general.SocksPort,  // SOCKS5 代理端口
		RedirPort:  general.RedirPort,  // 透明代理（重定向）端口
		TProxyPort: general.TProxyPort, // TProxy 代理端口 (Linux)
		MixedPort:  general.MixedPort,  // 混合代理端口 (HTTP 和 SOCKS)
	}
	// 使用新的端口配置重新创建传统监听器
	listener.ReCreatePortsListeners(ports, tunnel.TCPIn(), tunnel.UDPIn())
}

// updateUsers 更新用户认证信息。
// users: 用户认证信息列表。
func updateUsers(users []auth.AuthUser) {
	authenticator := auth.NewAuthenticator(users) // 创建新的认证器
	authStore.SetAuthenticator(authenticator)      // 设置全局认证器
	// 如果认证器不为空，则记录日志
	if authenticator != nil {
		log.Infoln("Authentication of local server updated")
	}
}

// updateProfile 更新 Profile 相关的配置。
// cfg: 完整的配置对象。
func updateProfile(cfg *config.Config) {
	profileCfg := cfg.Profile // 获取 Profile 配置部分

	// 更新是否在切换选择组时存储选择的配置
	profile.StoreSelected.Store(profileCfg.StoreSelected)
	// 如果启用了存储选择，则尝试恢复之前的选择组状态
	if profileCfg.StoreSelected {
		patchSelectGroup(cfg.Proxies)
	}
}

// patchSelectGroup 用于在加载配置时，如果启用了 profile.StoreSelected，
// 则尝试从缓存中恢复上一次选择组（如 Selector 类型）的选择。
// proxies: 当前配置中的代理映射。
func patchSelectGroup(proxies map[string]C.Proxy) {
	mapping := cachefile.Cache().SelectedMap() // 从缓存文件获取已保存的选择组状态
	// 如果缓存为空，则直接返回
	if mapping == nil {
		return
	}

	// 遍历当前配置中的所有代理
	for name, proxy := range proxies {
		// 检查代理是否为 adapter.Proxy 类型（通常的出站代理）
		outbound, ok := proxy.(*adapter.Proxy)
		if !ok {
			continue
		}

		// 检查代理内部的实际适配器是否为 outboundgroup.Selector 类型
		selector, ok := outbound.ProxyAdapter.(*outboundgroup.Selector)
		if !ok {
			continue
		}

		// 从缓存的映射中查找当前选择组是否保存了之前的选择
		selected, exist := mapping[name]
		if !exist {
			continue
		}

		// 如果找到了，则将选择组的状态设置为之前保存的选择
		selector.Set(selected)
	}
}
