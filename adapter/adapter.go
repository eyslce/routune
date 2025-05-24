package adapter

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/eyslce/routune/common/queue"
	"github.com/eyslce/routune/component/dialer"
	C "github.com/eyslce/routune/constant"

	"go.uber.org/atomic"
)

// Proxy 是 C.ProxyAdapter 的装饰器，增加了健康检查和延迟历史记录功能。
type Proxy struct {
	C.ProxyAdapter              // 内嵌的代理适配器，用于实际的网络连接。
	history        *queue.Queue // 存储最近的延迟测试历史记录。
	alive          *atomic.Bool // 原子布尔值，表示代理当前是否可用。
}

// Alive 实现 C.Proxy 接口，返回代理的当前可用状态。
func (p *Proxy) Alive() bool {
	return p.alive.Load()
}

// Dial 实现 C.Proxy 接口，使用默认 TCP 超时建立连接。
// 它内部调用 DialContext。
func (p *Proxy) Dial(metadata *C.Metadata) (C.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), C.DefaultTCPTimeout)
	defer cancel()
	return p.DialContext(ctx, metadata)
}

// DialContext 实现 C.ProxyAdapter 接口，使用提供的上下文和元数据建立 TCP 连接。
// 它会更新代理的存活状态。
func (p *Proxy) DialContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (C.Conn, error) {
	conn, err := p.ProxyAdapter.DialContext(ctx, metadata, opts...)
	p.alive.Store(err == nil) // 如果连接成功，则认为代理存活。
	return conn, err
}

// DialUDP 实现 C.ProxyAdapter 接口，使用默认 UDP 超时建立 UDP 连接。
// 它内部调用 ListenPacketContext。
func (p *Proxy) DialUDP(metadata *C.Metadata) (C.PacketConn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), C.DefaultUDPTimeout)
	defer cancel()
	return p.ListenPacketContext(ctx, metadata)
}

// ListenPacketContext 实现 C.ProxyAdapter 接口，使用提供的上下文和元数据建立 UDP 包连接。
// 它会更新代理的存活状态。
func (p *Proxy) ListenPacketContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (C.PacketConn, error) {
	pc, err := p.ProxyAdapter.ListenPacketContext(ctx, metadata, opts...)
	p.alive.Store(err == nil) // 如果连接成功，则认为代理存活。
	return pc, err
}

// DelayHistory 实现 C.Proxy 接口，返回代理的延迟历史记录。
func (p *Proxy) DelayHistory() []C.DelayHistory {
	queue := p.history.Copy() // 复制队列以避免并发问题。
	histories := []C.DelayHistory{}
	for _, item := range queue {
		histories = append(histories, item.(C.DelayHistory))
	}
	return histories
}

// LastDelay 实现 C.Proxy 接口，返回最后一次记录的延迟。
// 如果代理不可用或没有历史记录，则返回 uint16 的最大值。
func (p *Proxy) LastDelay() (delay uint16) {
	var max uint16 = 0xffff // 定义最大延迟值，通常表示不可用或超时。
	if !p.alive.Load() {    // 如果代理当前标记为不可用，则直接返回最大延迟。
		return max
	}

	last := p.history.Last() // 获取队列中最新的历史记录。
	if last == nil {         // 如果没有历史记录，返回最大延迟。
		return max
	}
	history := last.(C.DelayHistory)
	if history.Delay == 0 { // 如果记录的延迟为0（可能表示测试失败或未完成），也返回最大延迟。
		return max
	}
	return history.Delay
}

// MarshalJSON 实现 C.ProxyAdapter 接口，自定义 Proxy 结构体的 JSON 序列化行为。
// 它在基础适配器的 JSON 输出之上添加了 history, alive, name 和 udp 字段。
func (p *Proxy) MarshalJSON() ([]byte, error) {
	inner, err := p.ProxyAdapter.MarshalJSON() // 获取内嵌适配器的 JSON 表示。
	if err != nil {
		return inner, err
	}

	mapping := map[string]any{}
	json.Unmarshal(inner, &mapping) // 将内嵌适配器的 JSON 解码到 map 中。
	// 添加 Proxy 特有的字段。
	mapping["history"] = p.DelayHistory()
	mapping["alive"] = p.Alive()
	mapping["name"] = p.Name()
	mapping["udp"] = p.SupportUDP()
	return json.Marshal(mapping) // 将包含所有字段的 map 重新编码为 JSON。
}

// URLTest 实现 C.Proxy 接口，测试代理到指定 URL 的连接延迟。
// 它会向 URL 发送 HEAD 请求，并记录延迟结果。
// delay 是第一次请求的延迟，meanDelay 是两次请求的平均延迟。
// 测试结果会更新代理的存活状态和延迟历史。
func (p *Proxy) URLTest(ctx context.Context, url string) (delay, meanDelay uint16, err error) {
	// defer 语句确保在函数返回前执行，用于更新代理状态和历史记录。
	defer func() {
		p.alive.Store(err == nil) // 根据测试结果更新代理的存活状态。
		record := C.DelayHistory{Time: time.Now()}
		if err == nil { // 如果测试成功，记录延迟。
			record.Delay = delay
			record.MeanDelay = meanDelay
		}
		p.history.Put(record)     // 将测试记录添加到历史队列。
		if p.history.Len() > 10 { // 保持历史记录队列的长度不超过10。
			p.history.Pop()
		}
	}()

	addr, err := urlToMetadata(url) // 将 URL 字符串转换为元数据结构。
	if err != nil {
		return
	}

	start := time.Now()                        // 记录测试开始时间。
	instance, err := p.DialContext(ctx, &addr) // 通过代理建立到目标地址的连接。
	if err != nil {
		return // 连接失败，直接返回错误。
	}
	defer instance.Close() // 确保连接在使用后关闭。

	req, err := http.NewRequest(http.MethodHead, url, nil) // 创建一个 HEAD 请求。
	if err != nil {
		return
	}
	req = req.WithContext(ctx) // 将上下文与请求关联。

	// 配置 HTTP 传输层，使其通过已建立的代理连接进行拨号。
	transport := &http.Transport{
		Dial: func(string, string) (net.Conn, error) {
			return instance, nil // 使用已建立的连接。
		},
		// 以下配置参考自 http.DefaultTransport，用于优化连接管理。
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	// 创建 HTTP 客户端。
	client := http.Client{
		Transport: transport,
		// 配置客户端在重定向时不自动跟随，而是返回上一个响应。
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	defer client.CloseIdleConnections() // 关闭客户端的空闲连接。

	resp, err := client.Do(req) // 发送第一个 HEAD 请求。
	if err != nil {
		return // 请求失败，返回错误。
	}
	resp.Body.Close()                                    // 关闭响应体。
	delay = uint16(time.Since(start) / time.Millisecond) // 计算第一次请求的延迟。

	// 尝试发送第二个 HEAD 请求以计算平均延迟。
	// 某些服务器可能会在第一次请求后立即关闭连接，因此这里的错误会被忽略。
	resp, err = client.Do(req)
	if err != nil {
		// 忽略错误，因为某些服务器会劫持连接并立即关闭。
		// 此时只返回第一次的延迟。
		return delay, 0, nil
	}
	resp.Body.Close()
	meanDelay = uint16(time.Since(start) / time.Millisecond / 2) // 计算两次请求的平均延迟。

	return
}

// NewProxy 创建一个新的 Proxy 实例。
// 它接收一个 C.ProxyAdapter 作为参数，并初始化延迟历史队列和存活状态。
func NewProxy(adapter C.ProxyAdapter) *Proxy {
	// 初始化 Proxy 结构体，历史队列长度为10，初始状态为存活。
	return &Proxy{adapter, queue.New(10), atomic.NewBool(true)}
}

// urlToMetadata 将 URL 字符串解析为 C.Metadata 结构。
// 它从 URL 中提取主机名和端口号。如果 URL 中没有指定端口，
// 它会根据 URL 的 scheme (http 或 https) 推断默认端口。
func urlToMetadata(rawURL string) (addr C.Metadata, err error) {
	u, err := url.Parse(rawURL) // 解析 URL 字符串。
	if err != nil {
		return
	}

	port := u.Port() // 获取 URL 中的端口号。
	if port == "" {  // 如果端口号为空，则根据 scheme 设置默认端口。
		switch u.Scheme {
		case "https":
			port = "443"
		case "http":
			port = "80"
		default:
			// 如果 scheme 不是 http 或 https，则返回错误。
			err = fmt.Errorf("%s scheme not Support", rawURL)
			return
		}
	}

	p, _ := strconv.ParseUint(port, 10, 16) // 将端口字符串转换为 uint16 类型。

	// 填充 Metadata 结构。
	addr = C.Metadata{
		Host:    u.Hostname(), // 设置主机名。
		DstIP:   nil,          // 目标 IP 地址在此处不设置。
		DstPort: C.Port(p),    // 设置目标端口。
	}
	return
}
