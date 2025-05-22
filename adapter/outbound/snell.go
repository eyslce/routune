// Package outbound 实现了 Clash 的出站代理适配器
package outbound

import (
	"context"
	"fmt"
	"net"
	"strconv"

	"github.com/eyslce/clash/common/structure"
	"github.com/eyslce/clash/component/dialer"
	C "github.com/eyslce/clash/constant"
	obfs "github.com/eyslce/clash/transport/simple-obfs"
	"github.com/eyslce/clash/transport/snell"
)

// Snell 实现了 Snell 代理适配器
// 支持多种混淆方式和版本
type Snell struct {
	*Base
	psk        []byte            // 预共享密钥
	pool       *snell.Pool       // 连接池（仅用于 v2 版本）
	obfsOption *simpleObfsOption // 混淆选项
	version    int               // Snell 版本
}

// SnellOption 包含创建 Snell 代理适配器所需的配置选项
type SnellOption struct {
	BasicOption
	Name     string         `proxy:"name"`                // 代理名称
	Server   string         `proxy:"server"`              // 代理服务器地址
	Port     int            `proxy:"port"`                // 代理服务器端口
	Psk      string         `proxy:"psk"`                 // 预共享密钥
	UDP      bool           `proxy:"udp,omitempty"`       // 是否支持 UDP
	Version  int            `proxy:"version,omitempty"`   // Snell 版本
	ObfsOpts map[string]any `proxy:"obfs-opts,omitempty"` // 混淆选项
}

// streamOption 包含创建 Snell 流连接所需的选项
type streamOption struct {
	psk        []byte            // 预共享密钥
	version    int               // Snell 版本
	addr       string            // 服务器地址
	obfsOption *simpleObfsOption // 混淆选项
}

// streamConn 创建一个 Snell 流连接
func streamConn(c net.Conn, option streamOption) *snell.Snell {
	switch option.obfsOption.Mode {
	case "tls":
		c = obfs.NewTLSObfs(c, option.obfsOption.Host)
	case "http":
		_, port, _ := net.SplitHostPort(option.addr)
		c = obfs.NewHTTPObfs(c, option.obfsOption.Host, port)
	}
	return snell.StreamConn(c, option.psk, option.version)
}

// StreamConn 实现 C.ProxyAdapter 接口
// 将普通连接转换为 Snell 代理连接
func (s *Snell) StreamConn(c net.Conn, metadata *C.Metadata) (net.Conn, error) {
	c = streamConn(c, streamOption{s.psk, s.version, s.addr, s.obfsOption})
	err := snell.WriteHeader(c, metadata.String(), uint(metadata.DstPort), s.version)
	return c, err
}

// DialContext 实现 C.ProxyAdapter 接口
// 创建一个到代理服务器的连接
func (s *Snell) DialContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (_ C.Conn, err error) {
	if s.version == snell.Version2 && len(opts) == 0 {
		c, err := s.pool.Get()
		if err != nil {
			return nil, err
		}

		if err = snell.WriteHeader(c, metadata.String(), uint(metadata.DstPort), s.version); err != nil {
			c.Close()
			return nil, err
		}
		return NewConn(c, s), err
	}

	c, err := dialer.DialContext(ctx, "tcp", s.addr, s.Base.DialOptions(opts...)...)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", s.addr, err)
	}
	tcpKeepAlive(c)

	defer func(c net.Conn) {
		safeConnClose(c, err)
	}(c)

	c, err = s.StreamConn(c, metadata)
	return NewConn(c, s), err
}

// ListenPacketContext 实现 C.ProxyAdapter 接口
// 创建一个 UDP 数据包连接
func (s *Snell) ListenPacketContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (C.PacketConn, error) {
	c, err := dialer.DialContext(ctx, "tcp", s.addr, s.Base.DialOptions(opts...)...)
	if err != nil {
		return nil, err
	}
	tcpKeepAlive(c)
	c = streamConn(c, streamOption{s.psk, s.version, s.addr, s.obfsOption})

	err = snell.WriteUDPHeader(c, s.version)
	if err != nil {
		return nil, err
	}

	pc := snell.PacketConn(c)
	return newPacketConn(pc, s), nil
}

// NewSnell 创建一个新的 Snell 代理适配器
func NewSnell(option SnellOption) (*Snell, error) {
	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))
	psk := []byte(option.Psk)

	decoder := structure.NewDecoder(structure.Option{TagName: "obfs", WeaklyTypedInput: true})
	obfsOption := &simpleObfsOption{Host: "bing.com"}
	if err := decoder.Decode(option.ObfsOpts, obfsOption); err != nil {
		return nil, fmt.Errorf("snell %s initialize obfs error: %w", addr, err)
	}

	switch obfsOption.Mode {
	case "tls", "http", "":
		break
	default:
		return nil, fmt.Errorf("snell %s obfs mode error: %s", addr, obfsOption.Mode)
	}

	// backward compatible
	if option.Version == 0 {
		option.Version = snell.DefaultSnellVersion
	}
	switch option.Version {
	case snell.Version1, snell.Version2:
		if option.UDP {
			return nil, fmt.Errorf("snell version %d not support UDP", option.Version)
		}
	case snell.Version3:
	default:
		return nil, fmt.Errorf("snell version error: %d", option.Version)
	}

	s := &Snell{
		Base: &Base{
			name:  option.Name,
			addr:  addr,
			tp:    C.Snell,
			udp:   option.UDP,
			iface: option.Interface,
			rmark: option.RoutingMark,
		},
		psk:        psk,
		obfsOption: obfsOption,
		version:    option.Version,
	}

	if option.Version == snell.Version2 {
		s.pool = snell.NewPool(func(ctx context.Context) (*snell.Snell, error) {
			c, err := dialer.DialContext(ctx, "tcp", addr, s.Base.DialOptions()...)
			if err != nil {
				return nil, err
			}

			tcpKeepAlive(c)
			return streamConn(c, streamOption{psk, option.Version, addr, obfsOption}), nil
		})
	}
	return s, nil
}
