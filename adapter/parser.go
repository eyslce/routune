package adapter

import (
	"fmt"

	"github.com/eyslce/clash/adapter/outbound"
	"github.com/eyslce/clash/common/structure"
	C "github.com/eyslce/clash/constant"
)

// ParseProxy 函数用于解析代理配置映射并创建相应的代理实例。
// 它接收一个包含代理配置的映射，返回一个实现了C.Proxy接口的代理实例。
// 参数:
//   - mapping: 包含代理配置的映射，必须包含"type"字段指定代理类型
//
// 返回:
//   - C.Proxy: 创建的代理实例
//   - error: 如果解析过程中出现错误则返回错误信息
func ParseProxy(mapping map[string]any) (C.Proxy, error) {
	// 创建一个新的解码器，使用"proxy"作为标签名，并启用弱类型输入
	decoder := structure.NewDecoder(structure.Option{TagName: "proxy", WeaklyTypedInput: true})

	// 从配置映射中获取代理类型
	proxyType, existType := mapping["type"].(string)
	if !existType {
		return nil, fmt.Errorf("missing type")
	}

	var (
		proxy C.ProxyAdapter
		err   error
	)

	// 根据代理类型创建相应的代理实例
	switch proxyType {
	case "ss":
		// 解析Shadowsocks代理配置
		ssOption := &outbound.ShadowSocksOption{}
		err = decoder.Decode(mapping, ssOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewShadowSocks(*ssOption)
	case "ssr":
		// 解析ShadowsocksR代理配置
		ssrOption := &outbound.ShadowSocksROption{}
		err = decoder.Decode(mapping, ssrOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewShadowSocksR(*ssrOption)
	case "socks5":
		// 解析SOCKS5代理配置
		socksOption := &outbound.Socks5Option{}
		err = decoder.Decode(mapping, socksOption)
		if err != nil {
			break
		}
		proxy = outbound.NewSocks5(*socksOption)
	case "http":
		// 解析HTTP代理配置
		httpOption := &outbound.HttpOption{}
		err = decoder.Decode(mapping, httpOption)
		if err != nil {
			break
		}
		proxy = outbound.NewHttp(*httpOption)
	case "vmess":
		// 解析VMess代理配置，设置默认的HTTP选项
		vmessOption := &outbound.VmessOption{
			HTTPOpts: outbound.HTTPOptions{
				Method: "GET",
				Path:   []string{"/"},
			},
		}
		err = decoder.Decode(mapping, vmessOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewVmess(*vmessOption)
	case "snell":
		// 解析Snell代理配置
		snellOption := &outbound.SnellOption{}
		err = decoder.Decode(mapping, snellOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewSnell(*snellOption)
	case "trojan":
		// 解析Trojan代理配置
		trojanOption := &outbound.TrojanOption{}
		err = decoder.Decode(mapping, trojanOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewTrojan(*trojanOption)
	default:
		// 如果代理类型不支持，返回错误
		return nil, fmt.Errorf("unsupport proxy type: %s", proxyType)
	}

	// 如果解析过程中出现错误，返回错误信息
	if err != nil {
		return nil, err
	}

	// 使用创建的代理适配器创建代理实例并返回
	return NewProxy(proxy), nil
}
