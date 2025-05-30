package provider

import (
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"time"

	"github.com/eyslce/routune/adapter"
	"github.com/eyslce/routune/adapter/outbound"
	"github.com/eyslce/routune/common/singledo"
	C "github.com/eyslce/routune/constant"
	types "github.com/eyslce/routune/constant/provider"

	regexp "github.com/dlclark/regexp2"
	"github.com/samber/lo"
	"gopkg.in/yaml.v3"
)

var reject = adapter.NewProxy(outbound.NewReject())

const (
	ReservedName = "default"
)

type ProxySchema struct {
	Proxies []map[string]any `yaml:"proxies"`
}

// for auto gc
type ProxySetProvider struct {
	*proxySetProvider
}

type proxySetProvider struct {
	*fetcher
	proxies     []C.Proxy
	healthCheck *HealthCheck
}

func (pp *proxySetProvider) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{
		"name":        pp.Name(),
		"type":        pp.Type().String(),
		"vehicleType": pp.VehicleType().String(),
		"proxies":     pp.Proxies(),
		"updatedAt":   pp.updatedAt,
	})
}

func (pp *proxySetProvider) Name() string {
	return pp.name
}

func (pp *proxySetProvider) HealthCheck() {
	pp.healthCheck.checkAll()
}

func (pp *proxySetProvider) Update() error {
	elm, same, err := pp.fetcher.Update()
	if err == nil && !same {
		pp.onUpdate(elm)
	}
	return err
}

func (pp *proxySetProvider) Initial() error {
	elm, err := pp.fetcher.Initial()
	if err != nil {
		return err
	}

	pp.onUpdate(elm)
	return nil
}

func (pp *proxySetProvider) Type() types.ProviderType {
	return types.Proxy
}

func (pp *proxySetProvider) Proxies() []C.Proxy {
	return pp.proxies
}

func (pp *proxySetProvider) Touch() {
	pp.healthCheck.touch()
}

func (pp *proxySetProvider) setProxies(proxies []C.Proxy) {
	pp.proxies = proxies
	pp.healthCheck.setProxy(proxies)
	if pp.healthCheck.auto() {
		go pp.healthCheck.checkAll()
	}
}

func stopProxyProvider(pd *ProxySetProvider) {
	pd.healthCheck.close()
	pd.fetcher.Destroy()
}

func NewProxySetProvider(name string, interval time.Duration, filter string, vehicle types.Vehicle, hc *HealthCheck) (*ProxySetProvider, error) {
	filterReg, err := regexp.Compile(filter, regexp.None)
	if err != nil {
		return nil, fmt.Errorf("invalid filter regex: %w", err)
	}

	if hc.auto() {
		go hc.process()
	}

	pd := &proxySetProvider{
		proxies:     []C.Proxy{},
		healthCheck: hc,
	}

	onUpdate := func(elm any) {
		ret := elm.([]C.Proxy)
		pd.setProxies(ret)
	}

	proxiesParseAndFilter := func(buf []byte) (any, error) {
		schema := &ProxySchema{}

		if err := yaml.Unmarshal(buf, schema); err != nil {
			return nil, err
		}

		if schema.Proxies == nil {
			return nil, errors.New("file must have a `proxies` field")
		}

		proxies := []C.Proxy{}
		for idx, mapping := range schema.Proxies {
			if name, ok := mapping["name"].(string); ok && len(filter) > 0 {
				matched, err := filterReg.MatchString(name)
				if err != nil {
					return nil, fmt.Errorf("regex filter failed: %w", err)
				}
				if !matched {
					continue
				}
			}
			proxy, err := adapter.ParseProxy(mapping)
			if err != nil {
				return nil, fmt.Errorf("proxy %d error: %w", idx, err)
			}
			proxies = append(proxies, proxy)
		}

		if len(proxies) == 0 {
			if len(filter) > 0 {
				return nil, errors.New("doesn't match any proxy, please check your filter")
			}
			return nil, errors.New("file doesn't have any proxy")
		}

		return proxies, nil
	}

	fetcher := newFetcher(name, interval, vehicle, proxiesParseAndFilter, onUpdate)
	pd.fetcher = fetcher

	wrapper := &ProxySetProvider{pd}
	runtime.SetFinalizer(wrapper, stopProxyProvider)
	return wrapper, nil
}

// for auto gc
type CompatibleProvider struct {
	*compatibleProvider
}

type compatibleProvider struct {
	name        string
	healthCheck *HealthCheck
	proxies     []C.Proxy
}

func (cp *compatibleProvider) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{
		"name":        cp.Name(),
		"type":        cp.Type().String(),
		"vehicleType": cp.VehicleType().String(),
		"proxies":     cp.Proxies(),
	})
}

func (cp *compatibleProvider) Name() string {
	return cp.name
}

func (cp *compatibleProvider) HealthCheck() {
	cp.healthCheck.checkAll()
}

func (cp *compatibleProvider) Update() error {
	return nil
}

func (cp *compatibleProvider) Initial() error {
	return nil
}

func (cp *compatibleProvider) VehicleType() types.VehicleType {
	return types.Compatible
}

func (cp *compatibleProvider) Type() types.ProviderType {
	return types.Proxy
}

func (cp *compatibleProvider) Proxies() []C.Proxy {
	return cp.proxies
}

func (cp *compatibleProvider) Touch() {
	cp.healthCheck.touch()
}

func stopCompatibleProvider(pd *CompatibleProvider) {
	pd.healthCheck.close()
}

func NewCompatibleProvider(name string, proxies []C.Proxy, hc *HealthCheck) (*CompatibleProvider, error) {
	if len(proxies) == 0 {
		return nil, errors.New("provider need one proxy at least")
	}

	if hc.auto() {
		go hc.process()
	}

	pd := &compatibleProvider{
		name:        name,
		proxies:     proxies,
		healthCheck: hc,
	}

	wrapper := &CompatibleProvider{pd}
	runtime.SetFinalizer(wrapper, stopCompatibleProvider)
	return wrapper, nil
}

var _ types.ProxyProvider = (*FilterableProvider)(nil)

type FilterableProvider struct {
	name      string
	providers []types.ProxyProvider
	filterReg *regexp.Regexp
	single    *singledo.Single
}

func (fp *FilterableProvider) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{
		"name":        fp.Name(),
		"type":        fp.Type().String(),
		"vehicleType": fp.VehicleType().String(),
		"proxies":     fp.Proxies(),
	})
}

func (fp *FilterableProvider) Name() string {
	return fp.name
}

func (fp *FilterableProvider) HealthCheck() {
}

func (fp *FilterableProvider) Update() error {
	return nil
}

func (fp *FilterableProvider) Initial() error {
	return nil
}

func (fp *FilterableProvider) VehicleType() types.VehicleType {
	return types.Compatible
}

func (fp *FilterableProvider) Type() types.ProviderType {
	return types.Proxy
}

func (fp *FilterableProvider) Proxies() []C.Proxy {
	elm, _, _ := fp.single.Do(func() (any, error) {
		proxies := lo.FlatMap(
			fp.providers,
			func(item types.ProxyProvider, _ int) []C.Proxy {
				return lo.Filter(
					item.Proxies(),
					func(item C.Proxy, _ int) bool {
						matched, _ := fp.filterReg.MatchString(item.Name())
						return matched
					})
			})

		if len(proxies) == 0 {
			proxies = append(proxies, reject)
		}
		return proxies, nil
	})

	return elm.([]C.Proxy)
}

func (fp *FilterableProvider) Touch() {
	for _, provider := range fp.providers {
		provider.Touch()
	}
}

func NewFilterableProvider(name string, providers []types.ProxyProvider, filterReg *regexp.Regexp) *FilterableProvider {
	return &FilterableProvider{
		name:      name,
		providers: providers,
		filterReg: filterReg,
		single:    singledo.NewSingle(time.Second * 10),
	}
}
