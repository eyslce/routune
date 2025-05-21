package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"

	"github.com/eyslce/clash/adapter"
	"github.com/eyslce/clash/adapter/outbound"
	"github.com/eyslce/clash/adapter/outboundgroup"
	"github.com/eyslce/clash/adapter/provider"
	"github.com/eyslce/clash/component/auth"
	"github.com/eyslce/clash/component/fakeip"
	"github.com/eyslce/clash/component/trie"
	C "github.com/eyslce/clash/constant"
	providerTypes "github.com/eyslce/clash/constant/provider"
	"github.com/eyslce/clash/dns"
	"github.com/eyslce/clash/log"
	R "github.com/eyslce/clash/rule"
	T "github.com/eyslce/clash/tunnel"

	"github.com/samber/lo"
	"gopkg.in/yaml.v3"
)

// General 结构体定义了Clash的通用配置项。
// General config
type General struct {
	LegacyInbound
	Controller
	Authentication []string     `json:"authentication"`
	Mode           T.TunnelMode `json:"mode"`
	LogLevel       log.LogLevel `json:"log-level"`
	IPv6           bool         `json:"ipv6"`
	Interface      string       `json:"-"`
	RoutingMark    int          `json:"-"`
}

// Controller 结构体定义了外部控制器相关的配置项。
// Controller
type Controller struct {
	ExternalController string `json:"-"`
	ExternalUI         string `json:"-"`
	Secret             string `json:"-"`
}

// LegacyInbound 结构体定义了旧版的各种入站代理端口配置。
// 这些端口配置未来可能会被 `Inbounds` 字段取代。
type LegacyInbound struct {
	Port        int    `json:"port"`
	SocksPort   int    `json:"socks-port"`
	RedirPort   int    `json:"redir-port"`
	TProxyPort  int    `json:"tproxy-port"`
	MixedPort   int    `json:"mixed-port"`
	AllowLan    bool   `json:"allow-lan"`
	BindAddress string `json:"bind-address"`
}

// DNS 结构体定义了Clash的DNS相关配置。
// DNS config
type DNS struct {
	Enable            bool             `yaml:"enable"`
	IPv6              bool             `yaml:"ipv6"`
	NameServer        []dns.NameServer `yaml:"nameserver"`
	Fallback          []dns.NameServer `yaml:"fallback"`
	FallbackFilter    FallbackFilter   `yaml:"fallback-filter"`
	Listen            string           `yaml:"listen"`
	EnhancedMode      C.DNSMode        `yaml:"enhanced-mode"`
	DefaultNameserver []dns.NameServer `yaml:"default-nameserver"`
	FakeIPRange       *fakeip.Pool
	Hosts             *trie.DomainTrie
	NameServerPolicy  map[string]dns.NameServer
	SearchDomains     []string
}

// FallbackFilter 结构体定义了触发备用DNS服务器的条件。
// FallbackFilter config
type FallbackFilter struct {
	GeoIP     bool         `yaml:"geoip"`
	GeoIPCode string       `yaml:"geoip-code"`
	IPCIDR    []*net.IPNet `yaml:"ipcidr"`
	Domain    []string     `yaml:"domain"`
}

// Profile 结构体定义了与用户配置文件持久化相关的设置。
// Profile config
type Profile struct {
	StoreSelected bool `yaml:"store-selected"`
	StoreFakeIP   bool `yaml:"store-fake-ip"`
}

// Experimental 结构体定义了一些实验性功能的开关。
// Experimental config
type Experimental struct {
	UDPFallbackMatch bool `yaml:"udp-fallback-match"`
}

// Config 结构体是Clash配置的顶层容器，包含了所有解析后的配置信息。
// Config is clash config manager
type Config struct {
	General      *General
	DNS          *DNS
	Experimental *Experimental
	Hosts        *trie.DomainTrie
	Profile      *Profile
	Inbounds     []C.Inbound
	Rules        []C.Rule
	Users        []auth.AuthUser
	Proxies      map[string]C.Proxy
	Providers    map[string]providerTypes.ProxyProvider
	Tunnels      []Tunnel
}

// RawDNS 是从配置文件中直接读取的DNS配置的原始结构。
// 在解析阶段，它会被转换为DNS结构体。
type RawDNS struct {
	Enable            bool              `yaml:"enable"`
	IPv6              *bool             `yaml:"ipv6"`
	UseHosts          bool              `yaml:"use-hosts"`
	NameServer        []string          `yaml:"nameserver"`
	Fallback          []string          `yaml:"fallback"`
	FallbackFilter    RawFallbackFilter `yaml:"fallback-filter"`
	Listen            string            `yaml:"listen"`
	EnhancedMode      C.DNSMode         `yaml:"enhanced-mode"`
	FakeIPRange       string            `yaml:"fake-ip-range"`
	FakeIPFilter      []string          `yaml:"fake-ip-filter"`
	DefaultNameserver []string          `yaml:"default-nameserver"`
	NameServerPolicy  map[string]string `yaml:"nameserver-policy"`
	SearchDomains     []string          `yaml:"search-domains"`
}

// RawFallbackFilter 是从配置文件中直接读取的FallbackFilter的原始结构。
type RawFallbackFilter struct {
	GeoIP     bool     `yaml:"geoip"`
	GeoIPCode string   `yaml:"geoip-code"`
	IPCIDR    []string `yaml:"ipcidr"`
	Domain    []string `yaml:"domain"`
}

// tunnel 是Tunnel配置的内部表示，用于YAML反序列化。
type tunnel struct {
	Network []string `yaml:"network"`
	Address string   `yaml:"address"`
	Target  string   `yaml:"target"`
	Proxy   string   `yaml:"proxy"`
}

// Tunnel 是本地端口转发配置的公开类型。
// 它可以从字符串或映射形式的YAML中解析。
type Tunnel tunnel

// UnmarshalYAML 实现了 yaml.Unmarshaler 接口，允许Tunnel配置支持两种格式：
// 1. 字符串形式: "network,address,target,proxy" (例如 "tcp/udp,0.0.0.0:80,example.com:80,PROXY_NAME")
// 2. 映射形式: 如tunnel结构体定义的字段。
// UnmarshalYAML implements yaml.Unmarshaler
func (t *Tunnel) UnmarshalYAML(unmarshal func(any) error) error {
	var tp string
	// 尝试按字符串格式解析
	if err := unmarshal(&tp); err != nil {
		// 如果字符串解析失败，尝试按映射格式解析
		var inner tunnel
		if err := unmarshal(&inner); err != nil {
			return err // 两种格式都解析失败
		}

		*t = Tunnel(inner)
		return nil
	}

	// 解析逗号分隔的字符串 "network,address,target,proxy"
	parts := lo.Map(strings.Split(tp, ","), func(s string, _ int) string {
		return strings.TrimSpace(s)
	})
	if len(parts) != 4 {
		return fmt.Errorf("invalid tunnel config %s", tp)
	}
	network := strings.Split(parts[0], "/")

	// 验证网络类型
	for _, n := range network {
		switch n {
		case "tcp", "udp":
		default:
			return fmt.Errorf("invalid tunnel network %s", n)
		}
	}

	// 验证监听地址和目标地址的格式
	address := parts[1]
	target := parts[2]
	for _, addr := range []string{address, target} {
		if _, _, err := net.SplitHostPort(addr); err != nil {
			return fmt.Errorf("invalid tunnel target or address %s", addr)
		}
	}

	*t = Tunnel(tunnel{
		Network: network,
		Address: address,
		Target:  target,
		Proxy:   parts[3],
	})
	return nil
}

// RawConfig 是从YAML配置文件中直接反序列化得到的原始配置结构。
// 它包含了所有可能的配置项，并带有默认值。
// 后续会被ParseRawConfig函数处理成更结构化的Config类型。
type RawConfig struct {
	Port               int          `yaml:"port"`
	SocksPort          int          `yaml:"socks-port"`
	RedirPort          int          `yaml:"redir-port"`
	TProxyPort         int          `yaml:"tproxy-port"`
	MixedPort          int          `yaml:"mixed-port"`
	Authentication     []string     `yaml:"authentication"`
	AllowLan           bool         `yaml:"allow-lan"`
	BindAddress        string       `yaml:"bind-address"`
	Mode               T.TunnelMode `yaml:"mode"`
	LogLevel           log.LogLevel `yaml:"log-level"`
	IPv6               bool         `yaml:"ipv6"`
	ExternalController string       `yaml:"external-controller"`
	ExternalUI         string       `yaml:"external-ui"`
	Secret             string       `yaml:"secret"`
	Interface          string       `yaml:"interface-name"`
	RoutingMark        int          `yaml:"routing-mark"`
	Tunnels            []Tunnel     `yaml:"tunnels"`

	ProxyProvider map[string]map[string]any `yaml:"proxy-providers"`
	Hosts         map[string]string         `yaml:"hosts"`
	Inbounds      []C.Inbound               `yaml:"inbounds"`
	DNS           RawDNS                    `yaml:"dns"`
	Experimental  Experimental              `yaml:"experimental"`
	Profile       Profile                   `yaml:"profile"`
	Proxy         []map[string]any          `yaml:"proxies"`
	ProxyGroup    []map[string]any          `yaml:"proxy-groups"`
	Rule          []string                  `yaml:"rules"`
}

// Parse 函数接收配置文件内容的字节切片，解析并返回一个Config结构体指针。
// 它首先调用UnmarshalRawConfig将字节反序列化为RawConfig，然后调用ParseRawConfig进行进一步处理。
// Parse config
func Parse(buf []byte) (*Config, error) {
	rawCfg, err := UnmarshalRawConfig(buf)
	if err != nil {
		return nil, err
	}

	return ParseRawConfig(rawCfg)
}

// UnmarshalRawConfig 函数将YAML配置文件的字节切片反序列化为RawConfig结构体。
// 它会为RawConfig中的一些字段设置默认值。
func UnmarshalRawConfig(buf []byte) (*RawConfig, error) {
	// config with default value
	rawCfg := &RawConfig{
		AllowLan:       false,
		BindAddress:    "*",
		Mode:           T.Rule,
		Authentication: []string{},
		LogLevel:       log.INFO,
		Hosts:          map[string]string{},
		Rule:           []string{},
		Proxy:          []map[string]any{},
		ProxyGroup:     []map[string]any{},
		DNS: RawDNS{
			Enable:      false,
			UseHosts:    true,
			FakeIPRange: "198.18.0.1/16",
			FallbackFilter: RawFallbackFilter{
				GeoIP:     true,
				GeoIPCode: "CN",
				IPCIDR:    []string{},
			},
			DefaultNameserver: []string{
				"114.114.114.114",
				"8.8.8.8",
			},
		},
		Profile: Profile{
			StoreSelected: true,
		},
	}

	if err := yaml.Unmarshal(buf, rawCfg); err != nil {
		return nil, err
	}

	return rawCfg, nil
}

// ParseRawConfig 函数将RawConfig结构体转换为最终的Config结构体。
// 这个过程包括解析各个部分的配置，例如General, Proxies, Rules, DNS等，
// 并进行必要的验证和转换。
func ParseRawConfig(rawCfg *RawConfig) (*Config, error) {
	config := &Config{}

	config.Experimental = &rawCfg.Experimental
	config.Profile = &rawCfg.Profile

	general, err := parseGeneral(rawCfg)
	if err != nil {
		return nil, err
	}
	config.General = general

	config.Inbounds = rawCfg.Inbounds

	proxies, providers, err := parseProxies(rawCfg)
	if err != nil {
		return nil, err
	}
	config.Proxies = proxies
	config.Providers = providers

	rules, err := parseRules(rawCfg, proxies)
	if err != nil {
		return nil, err
	}
	config.Rules = rules

	hosts, err := parseHosts(rawCfg)
	if err != nil {
		return nil, err
	}
	config.Hosts = hosts

	dnsCfg, err := parseDNS(rawCfg, hosts)
	if err != nil {
		return nil, err
	}
	config.DNS = dnsCfg

	config.Users = parseAuthentication(rawCfg.Authentication)

	config.Tunnels = rawCfg.Tunnels
	// 验证Tunnel配置中的代理是否存在
	for _, t := range config.Tunnels {
		if _, ok := config.Proxies[t.Proxy]; !ok {
			return nil, fmt.Errorf("tunnel proxy %s not found", t.Proxy)
		}
	}

	return config, nil
}

// parseGeneral 函数从RawConfig中提取并解析通用配置项，返回一个General结构体。
// 它还会检查ExternalUI路径的有效性。
func parseGeneral(cfg *RawConfig) (*General, error) {
	externalUI := cfg.ExternalUI

	// 检查 external-ui 路径是否存在
	if externalUI != "" {
		externalUI = C.Path.Resolve(externalUI)

		if _, err := os.Stat(externalUI); os.IsNotExist(err) {
			return nil, fmt.Errorf("external-ui: %s not exist", externalUI)
		}
	}

	return &General{
		LegacyInbound: LegacyInbound{
			Port:        cfg.Port,
			SocksPort:   cfg.SocksPort,
			RedirPort:   cfg.RedirPort,
			TProxyPort:  cfg.TProxyPort,
			MixedPort:   cfg.MixedPort,
			AllowLan:    cfg.AllowLan,
			BindAddress: cfg.BindAddress,
		},
		Controller: Controller{
			ExternalController: cfg.ExternalController,
			ExternalUI:         cfg.ExternalUI,
			Secret:             cfg.Secret,
		},
		Mode:        cfg.Mode,
		LogLevel:    cfg.LogLevel,
		IPv6:        cfg.IPv6,
		Interface:   cfg.Interface,
		RoutingMark: cfg.RoutingMark,
	}, nil
}

// parseProxies 函数从RawConfig中解析代理服务器、代理组和代理提供者的配置。
// 返回解析后的代理映射、代理提供者映射和任何可能发生的错误。
// 它会自动添加DIRECT, REJECT, GLOBAL这三个特殊的代理/组。
func parseProxies(cfg *RawConfig) (proxies map[string]C.Proxy, providersMap map[string]providerTypes.ProxyProvider, err error) {
	proxies = make(map[string]C.Proxy)
	providersMap = make(map[string]providerTypes.ProxyProvider)
	proxyList := []string{}
	proxiesConfig := cfg.Proxy
	groupsConfig := cfg.ProxyGroup
	providersConfig := cfg.ProxyProvider

	// 添加内置的DIRECT和REJECT代理
	proxies["DIRECT"] = adapter.NewProxy(outbound.NewDirect())
	proxies["REJECT"] = adapter.NewProxy(outbound.NewReject())
	proxyList = append(proxyList, "DIRECT", "REJECT")

	// 解析单个代理服务器配置
	for idx, mapping := range proxiesConfig {
		proxy, err := adapter.ParseProxy(mapping)
		if err != nil {
			return nil, nil, fmt.Errorf("proxy %d: %w", idx, err)
		}

		if _, exist := proxies[proxy.Name()]; exist {
			return nil, nil, fmt.Errorf("proxy %s is the duplicate name", proxy.Name())
		}
		proxies[proxy.Name()] = proxy
		proxyList = append(proxyList, proxy.Name())
	}

	// 预先记录代理组的名称以保持顺序
	// keep the original order of ProxyGroups in config file
	for idx, mapping := range groupsConfig {
		groupName, existName := mapping["name"].(string)
		if !existName {
			return nil, nil, fmt.Errorf("proxy group %d: missing name", idx)
		}
		proxyList = append(proxyList, groupName)
	}

	// 检查代理组是否存在循环依赖，并对其进行拓扑排序
	// check if any loop exists and sort the ProxyGroups
	if err := proxyGroupsDagSort(groupsConfig); err != nil {
		return nil, nil, err
	}

	// 解析并初始化代理提供者
	// parse and initial providers
	for name, mapping := range providersConfig {
		if name == provider.ReservedName { // provider.ReservedName ("default") 是保留名称
			return nil, nil, fmt.Errorf("can not defined a provider called `%s`", provider.ReservedName)
		}

		pd, err := provider.ParseProxyProvider(name, mapping)
		if err != nil {
			return nil, nil, fmt.Errorf("parse proxy provider %s error: %w", name, err)
		}

		providersMap[name] = pd
	}

	// 初始化非Compatible类型的代理提供者
	for _, provider := range providersMap {
		log.Infoln("Start initial provider %s", provider.Name())
		if err := provider.Initial(); err != nil {
			return nil, nil, fmt.Errorf("initial proxy provider %s error: %w", provider.Name(), err)
		}
	}

	// 解析代理组配置
	// parse proxy group
	for idx, mapping := range groupsConfig {
		// 此时 groupsConfig 已经是拓扑排序后的结果
		group, err := outboundgroup.ParseProxyGroup(mapping, proxies, providersMap)
		if err != nil {
			return nil, nil, fmt.Errorf("proxy group[%d]: %w", idx, err)
		}

		groupName := group.Name()
		if _, exist := proxies[groupName]; exist {
			return nil, nil, fmt.Errorf("proxy group %s: the duplicate name", groupName)
		}

		proxies[groupName] = adapter.NewProxy(group)
	}

	// 初始化Compatible类型的代理提供者
	// initial compatible provider
	for _, pd := range providersMap {
		if pd.VehicleType() != providerTypes.Compatible {
			continue
		}

		log.Infoln("Start initial compatible provider %s", pd.Name())
		if err := pd.Initial(); err != nil {
			return nil, nil, err
		}
	}

	// 创建一个包含所有代理和代理组的默认(compatible)提供者，用于GLOBAL组
	ps := []C.Proxy{}
	for _, v := range proxyList {
		ps = append(ps, proxies[v])
	}
	hc := provider.NewHealthCheck(ps, "", 0, true)
	pd, _ := provider.NewCompatibleProvider(provider.ReservedName, ps, hc)
	providersMap[provider.ReservedName] = pd

	// 创建内置的GLOBAL代理组，它是一个Selector，包含上面创建的默认提供者
	global := outboundgroup.NewSelector(
		&outboundgroup.GroupCommonOption{
			Name: "GLOBAL",
		},
		[]providerTypes.ProxyProvider{pd},
	)
	proxies["GLOBAL"] = adapter.NewProxy(global)
	return proxies, providersMap, nil
}

// parseRules 函数从RawConfig中解析规则配置。
// 规则定义了流量如何根据类型、内容、目标等被路由到不同的代理。
// 它需要已解析的代理映射(proxies)来验证规则中引用的代理是否存在。
func parseRules(cfg *RawConfig, proxies map[string]C.Proxy) ([]C.Rule, error) {
	rules := []C.Rule{}
	rulesConfig := cfg.Rule

	// parse rules
	for idx, line := range rulesConfig {
		// 规则格式为: TYPE,PAYLOAD,TARGET[,PARAMS...]
		// 例如: DOMAIN-SUFFIX,google.com,PROXY_A
		//         IP-CIDR,192.168.1.0/24,DIRECT
		//         FINAL,PROXY_B
		rule := trimArr(strings.Split(line, ","))
		var (
			payload string
			target  string
			params  = []string{}
		)

		switch l := len(rule); {
		case l == 2:
			target = rule[1]
		case l == 3:
			payload = rule[1]
			target = rule[2]
		case l >= 4:
			payload = rule[1]
			target = rule[2]
			params = rule[3:]
		default:
			return nil, fmt.Errorf("rules[%d] [%s] error: format invalid", idx, line)
		}

		// 验证规则中指定的目标代理是否存在
		if _, ok := proxies[target]; !ok {
			return nil, fmt.Errorf("rules[%d] [%s] error: proxy [%s] not found", idx, line, target)
		}

		rule = trimArr(rule)
		params = trimArr(params)

		// 调用R.ParseRule来实际解析规则字符串为C.Rule对象
		parsed, parseErr := R.ParseRule(rule[0], payload, target, params)
		if parseErr != nil {
			return nil, fmt.Errorf("rules[%d] [%s] error: %s", idx, line, parseErr.Error())
		}

		rules = append(rules, parsed)
	}

	return rules, nil
}

// parseHosts 函数从RawConfig中解析自定义Hosts配置。
// 它返回一个trie.DomainTrie，用于高效的域名查找。
// 默认会添加 localhost -> 127.0.0.1 的映射。
func parseHosts(cfg *RawConfig) (*trie.DomainTrie, error) {
	tree := trie.New()

	// add default hosts
	if err := tree.Insert("localhost", net.IP{127, 0, 0, 1}); err != nil {
		log.Errorln("insert localhost to host error: %s", err.Error())
	}

	if len(cfg.Hosts) != 0 {
		for domain, ipStr := range cfg.Hosts {
			ip := net.ParseIP(ipStr)
			if ip == nil {
				return nil, fmt.Errorf("%s is not a valid IP", ipStr)
			}
			tree.Insert(domain, ip)
		}
	}

	return tree, nil
}

// hostWithDefaultPort 函数确保主机地址字符串包含端口号。
// 如果输入的主机字符串没有端口，则添加指定的默认端口。
func hostWithDefaultPort(host string, defPort string) (string, error) {
	if !strings.Contains(host, ":") {
		host += ":"
	}

	hostname, port, err := net.SplitHostPort(host)
	if err != nil {
		return "", err
	}

	if port == "" {
		port = defPort
	}

	return net.JoinHostPort(hostname, port), nil
}

// parseNameServer 函数解析字符串形式的DNS服务器列表，并将其转换为 []dns.NameServer 结构体切片。
// 支持多种格式，如 "8.8.8.8", "udp://8.8.8.8:53", "tcp://1.1.1.1", "tls://1.1.1.1:853", "https://dns.google/dns-query"。
// 还支持指定网络接口，例如 "10.0.0.1#en0"。
func parseNameServer(servers []string) ([]dns.NameServer, error) {
	nameservers := []dns.NameServer{}

	for idx, server := range servers {
		// 如果服务器字符串不包含 "://"，则默认为UDP协议，格式如 "8.8.8.8" 或 "8.8.8.8:53"
		// parse without scheme .e.g 8.8.8.8:53
		if !strings.Contains(server, "://") {
			server = "udp://" + server
		}
		u, err := url.Parse(server)
		if err != nil {
			return nil, fmt.Errorf("DNS NameServer[%d] format error: %s", idx, err.Error())
		}

		// 解析特定的网络接口名称，例如 "10.0.0.1#en0" 中的 "en0"
		// parse with specific interface
		// .e.g 10.0.0.1#en0
		interfaceName := u.Fragment

		var addr, dnsNetType string
		switch u.Scheme {
		case "udp":
			addr, err = hostWithDefaultPort(u.Host, "53")
			dnsNetType = ""
		case "tcp":
			addr, err = hostWithDefaultPort(u.Host, "53")
			dnsNetType = "tcp"
		case "tls":
			addr, err = hostWithDefaultPort(u.Host, "853")
			dnsNetType = "tcp-tls"
		case "https":
			clearURL := url.URL{Scheme: "https", Host: u.Host, Path: u.Path, User: u.User}
			addr = clearURL.String()
			dnsNetType = "https"
		case "dhcp":
			addr = u.Host
			dnsNetType = "dhcp"
		default:
			return nil, fmt.Errorf("DNS NameServer[%d] unsupport scheme: %s", idx, u.Scheme)
		}

		if err != nil {
			return nil, fmt.Errorf("DNS NameServer[%d] format error: %s", idx, err.Error())
		}

		nameservers = append(
			nameservers,
			dns.NameServer{
				Net:       dnsNetType,
				Addr:      addr,
				Interface: interfaceName,
			},
		)
	}
	return nameservers, nil
}

// parseNameServerPolicy 函数解析域名到DNS服务器的策略映射。
// 输入是 map[string]string，其中key是域名，value是DNS服务器字符串。
// 返回 map[string]dns.NameServer，其中value是解析后的dns.NameServer结构。
func parseNameServerPolicy(nsPolicy map[string]string) (map[string]dns.NameServer, error) {
	policy := map[string]dns.NameServer{}

	for domain, server := range nsPolicy {
		nameservers, err := parseNameServer([]string{server})
		if err != nil {
			return nil, err
		}
		if _, valid := trie.ValidAndSplitDomain(domain); !valid {
			return nil, fmt.Errorf("DNS ResoverRule invalid domain: %s", domain)
		}
		policy[domain] = nameservers[0]
	}

	return policy, nil
}

// parseFallbackIPCIDR 函数解析字符串形式的IP CIDR列表，并将其转换为 []*net.IPNet 切片。
// 用于DNS FallbackFilter中的IPCIDR条件。
func parseFallbackIPCIDR(ips []string) ([]*net.IPNet, error) {
	ipNets := []*net.IPNet{}

	for idx, ip := range ips {
		_, ipnet, err := net.ParseCIDR(ip)
		if err != nil {
			return nil, fmt.Errorf("DNS FallbackIP[%d] format error: %s", idx, err.Error())
		}
		ipNets = append(ipNets, ipnet)
	}

	return ipNets, nil
}

// parseDNS 函数从RawConfig中解析完整的DNS配置。
// 它处理NameServer, Fallback, FallbackFilter, FakeIPRange, Hosts等设置，
// 并进行必要的验证和转换，返回一个DNS结构体。
// 它依赖于已经解析的hosts数据。
func parseDNS(rawCfg *RawConfig, hosts *trie.DomainTrie) (*DNS, error) {
	cfg := rawCfg.DNS
	if cfg.Enable && len(cfg.NameServer) == 0 {
		return nil, fmt.Errorf("if DNS configuration is turned on, NameServer cannot be empty")
	}

	dnsCfg := &DNS{
		Enable:       cfg.Enable,
		Listen:       cfg.Listen,
		IPv6:         lo.FromPtrOr(cfg.IPv6, rawCfg.IPv6),
		EnhancedMode: cfg.EnhancedMode,
		FallbackFilter: FallbackFilter{
			IPCIDR: []*net.IPNet{},
		},
	}
	var err error
	if dnsCfg.NameServer, err = parseNameServer(cfg.NameServer); err != nil {
		return nil, err
	}

	if dnsCfg.Fallback, err = parseNameServer(cfg.Fallback); err != nil {
		return nil, err
	}

	if dnsCfg.NameServerPolicy, err = parseNameServerPolicy(cfg.NameServerPolicy); err != nil {
		return nil, err
	}

	if len(cfg.DefaultNameserver) == 0 {
		return nil, errors.New("default nameserver should have at least one nameserver")
	}
	if dnsCfg.DefaultNameserver, err = parseNameServer(cfg.DefaultNameserver); err != nil {
		return nil, err
	}
	// 验证DefaultNameserver是否都是纯IP地址 (不能是域名，以避免循环依赖)
	// check default nameserver is pure ip addr
	for _, ns := range dnsCfg.DefaultNameserver {
		host, _, err := net.SplitHostPort(ns.Addr)
		if err != nil || net.ParseIP(host) == nil {
			return nil, errors.New("default nameserver (non-DoH/DoT) should be pure IP")
		}
	}

	if cfg.EnhancedMode == C.DNSFakeIP {
		_, ipnet, err := net.ParseCIDR(cfg.FakeIPRange)
		if err != nil {
			return nil, err
		}

		var host *trie.DomainTrie
		// fake ip skip host filter
		if len(cfg.FakeIPFilter) != 0 {
			host = trie.New()
			for _, domain := range cfg.FakeIPFilter {
				host.Insert(domain, true)
			}
		}

		pool, err := fakeip.New(fakeip.Options{
			IPNet:       ipnet,
			Size:        1000,
			Host:        host,
			Persistence: rawCfg.Profile.StoreFakeIP,
		})
		if err != nil {
			return nil, err
		}

		dnsCfg.FakeIPRange = pool
	}

	dnsCfg.FallbackFilter.GeoIP = cfg.FallbackFilter.GeoIP
	dnsCfg.FallbackFilter.GeoIPCode = cfg.FallbackFilter.GeoIPCode
	if fallbackip, err := parseFallbackIPCIDR(cfg.FallbackFilter.IPCIDR); err == nil {
		dnsCfg.FallbackFilter.IPCIDR = fallbackip
	}
	dnsCfg.FallbackFilter.Domain = cfg.FallbackFilter.Domain

	if cfg.UseHosts {
		dnsCfg.Hosts = hosts
	}

	if len(cfg.SearchDomains) != 0 {
		for _, domain := range cfg.SearchDomains {
			if strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
				return nil, errors.New("search domains should not start or end with '.'")
			}
			if strings.Contains(domain, ":") {
				return nil, errors.New("search domains are for ipv4 only and should not contain ports")
			}
		}
		dnsCfg.SearchDomains = cfg.SearchDomains
	}

	return dnsCfg, nil
}

// parseAuthentication 函数解析认证字符串列表，将其转换为 []auth.AuthUser 切片。
// 每条认证字符串格式为 "username:password"。
func parseAuthentication(rawRecords []string) []auth.AuthUser {
	users := []auth.AuthUser{}
	for _, line := range rawRecords {
		if user, pass, found := strings.Cut(line, ":"); found {
			users = append(users, auth.AuthUser{User: user, Pass: pass})
		}
	}
	return users
}
