// Package outbound 实现了 routune 的出站代理适配器
package outbound

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"

	"github.com/eyslce/routune/component/dialer"
	C "github.com/eyslce/routune/constant"
)

// Http 实现了 HTTP 代理适配器
// 支持 HTTP 和 HTTPS 代理，可配置认证信息和自定义请求头
type Http struct {
	*Base
	user      string      // 代理认证用户名
	pass      string      // 代理认证密码
	tlsConfig *tls.Config // TLS 配置
	Headers   http.Header // 自定义请求头
}

// HttpOption 包含创建 HTTP 代理适配器所需的配置选项
type HttpOption struct {
	BasicOption
	Name           string            `proxy:"name"`                       // 代理名称
	Server         string            `proxy:"server"`                     // 代理服务器地址
	Port           int               `proxy:"port"`                       // 代理服务器端口
	UserName       string            `proxy:"username,omitempty"`         // 认证用户名
	Password       string            `proxy:"password,omitempty"`         // 认证密码
	TLS            bool              `proxy:"tls,omitempty"`              // 是否启用 TLS
	SNI            string            `proxy:"sni,omitempty"`              // TLS SNI
	SkipCertVerify bool              `proxy:"skip-cert-verify,omitempty"` // 是否跳过证书验证
	Headers        map[string]string `proxy:"headers,omitempty"`          // 自定义请求头
}

// StreamConn 实现 C.ProxyAdapter 接口
// 将普通连接转换为 HTTP 代理连接
func (h *Http) StreamConn(c net.Conn, metadata *C.Metadata) (net.Conn, error) {
	if h.tlsConfig != nil {
		cc := tls.Client(c, h.tlsConfig)
		ctx, cancel := context.WithTimeout(context.Background(), C.DefaultTLSTimeout)
		defer cancel()
		err := cc.HandshakeContext(ctx)
		c = cc
		if err != nil {
			return nil, fmt.Errorf("%s connect error: %w", h.addr, err)
		}
	}

	if err := h.shakeHand(metadata, c); err != nil {
		return nil, err
	}
	return c, nil
}

// DialContext 实现 C.ProxyAdapter 接口
// 创建一个到代理服务器的连接
func (h *Http) DialContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (_ C.Conn, err error) {
	c, err := dialer.DialContext(ctx, "tcp", h.addr, h.Base.DialOptions(opts...)...)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", h.addr, err)
	}
	tcpKeepAlive(c)

	defer func(c net.Conn) {
		safeConnClose(c, err)
	}(c)

	c, err = h.StreamConn(c, metadata)
	if err != nil {
		return nil, err
	}

	return NewConn(c, h), nil
}

// shakeHand 执行 HTTP CONNECT 握手
// 发送 CONNECT 请求并处理响应
func (h *Http) shakeHand(metadata *C.Metadata, rw io.ReadWriter) error {
	addr := metadata.RemoteAddress()
	req := &http.Request{
		Method: http.MethodConnect,
		URL: &url.URL{
			Host: addr,
		},
		Host:   addr,
		Header: h.Headers.Clone(),
	}

	req.Header.Add("Proxy-Connection", "Keep-Alive")

	if h.user != "" && h.pass != "" {
		auth := h.user + ":" + h.pass
		req.Header.Add("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(auth)))
	}

	if err := req.Write(rw); err != nil {
		return err
	}

	resp, err := http.ReadResponse(bufio.NewReader(rw), req)
	if err != nil {
		return err
	}

	if resp.StatusCode == http.StatusOK {
		return nil
	}

	if resp.StatusCode == http.StatusProxyAuthRequired {
		return errors.New("HTTP need auth")
	}

	if resp.StatusCode == http.StatusMethodNotAllowed {
		return errors.New("CONNECT method not allowed by proxy")
	}

	if resp.StatusCode >= http.StatusInternalServerError {
		return errors.New(resp.Status)
	}

	return fmt.Errorf("can not connect remote err code: %d", resp.StatusCode)
}

// NewHttp 创建一个新的 HTTP 代理适配器
func NewHttp(option HttpOption) *Http {
	var tlsConfig *tls.Config
	if option.TLS {
		sni := option.Server
		if option.SNI != "" {
			sni = option.SNI
		}
		tlsConfig = &tls.Config{
			InsecureSkipVerify: option.SkipCertVerify,
			ServerName:         sni,
		}
	}

	headers := http.Header{}
	for name, value := range option.Headers {
		headers.Add(name, value)
	}

	return &Http{
		Base: &Base{
			name:  option.Name,
			addr:  net.JoinHostPort(option.Server, strconv.Itoa(option.Port)),
			tp:    C.Http,
			iface: option.Interface,
			rmark: option.RoutingMark,
		},
		user:      option.UserName,
		pass:      option.Password,
		tlsConfig: tlsConfig,
		Headers:   headers,
	}
}
