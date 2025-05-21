// Package statistic 提供了网络流量统计和连接管理的功能
package statistic

import (
	"net"
	"time"

	C "github.com/eyslce/clash/constant"

	"github.com/gofrs/uuid/v5"
	"go.uber.org/atomic"
)

// tracker 定义了连接跟踪器的基本接口
type tracker interface {
	ID() string   // 返回跟踪器的唯一标识符
	Close() error // 关闭跟踪器
}

// trackerInfo 包含连接跟踪的基本信息
type trackerInfo struct {
	UUID          uuid.UUID     `json:"id"`          // 连接的唯一标识符
	Metadata      *C.Metadata   `json:"metadata"`    // 连接的元数据
	UploadTotal   *atomic.Int64 `json:"upload"`      // 上传流量统计
	DownloadTotal *atomic.Int64 `json:"download"`    // 下载流量统计
	Start         time.Time     `json:"start"`       // 连接开始时间
	Chain         C.Chain       `json:"chains"`      // 代理链信息
	Rule          string        `json:"rule"`        // 匹配的规则类型
	RulePayload   string        `json:"rulePayload"` // 规则的具体内容
}

// tcpTracker 实现了TCP连接的流量跟踪
type tcpTracker struct {
	C.Conn       `json:"-"` // 底层TCP连接
	*trackerInfo            // 跟踪信息
	manager      *Manager   // 统计管理器
}

// ID 返回TCP跟踪器的唯一标识符
func (tt *tcpTracker) ID() string {
	return tt.UUID.String()
}

// Read 读取数据并更新下载流量统计
func (tt *tcpTracker) Read(b []byte) (int, error) {
	n, err := tt.Conn.Read(b)
	download := int64(n)
	tt.manager.PushDownloaded(download)
	tt.DownloadTotal.Add(download)
	return n, err
}

// Write 写入数据并更新上传流量统计
func (tt *tcpTracker) Write(b []byte) (int, error) {
	n, err := tt.Conn.Write(b)
	upload := int64(n)
	tt.manager.PushUploaded(upload)
	tt.UploadTotal.Add(upload)
	return n, err
}

// Close 关闭TCP跟踪器并从管理器中移除
func (tt *tcpTracker) Close() error {
	tt.manager.Leave(tt)
	return tt.Conn.Close()
}

// NewTCPTracker 创建一个新的TCP连接跟踪器
func NewTCPTracker(conn C.Conn, manager *Manager, metadata *C.Metadata, rule C.Rule) *tcpTracker {
	uuid, _ := uuid.NewV4()

	t := &tcpTracker{
		Conn:    conn,
		manager: manager,
		trackerInfo: &trackerInfo{
			UUID:          uuid,
			Start:         time.Now(),
			Metadata:      metadata,
			Chain:         conn.Chains(),
			Rule:          "",
			UploadTotal:   atomic.NewInt64(0),
			DownloadTotal: atomic.NewInt64(0),
		},
	}

	if rule != nil {
		t.trackerInfo.Rule = rule.RuleType().String()
		t.trackerInfo.RulePayload = rule.Payload()
	}

	manager.Join(t)
	return t
}

// udpTracker 实现了UDP连接的流量跟踪
type udpTracker struct {
	C.PacketConn `json:"-"` // 底层UDP连接
	*trackerInfo            // 跟踪信息
	manager      *Manager   // 统计管理器
}

// ID 返回UDP跟踪器的唯一标识符
func (ut *udpTracker) ID() string {
	return ut.UUID.String()
}

// ReadFrom 从UDP连接读取数据并更新下载流量统计
func (ut *udpTracker) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := ut.PacketConn.ReadFrom(b)
	download := int64(n)
	ut.manager.PushDownloaded(download)
	ut.DownloadTotal.Add(download)
	return n, addr, err
}

// WriteTo 向UDP连接写入数据并更新上传流量统计
func (ut *udpTracker) WriteTo(b []byte, addr net.Addr) (int, error) {
	n, err := ut.PacketConn.WriteTo(b, addr)
	upload := int64(n)
	ut.manager.PushUploaded(upload)
	ut.UploadTotal.Add(upload)
	return n, err
}

// Close 关闭UDP跟踪器并从管理器中移除
func (ut *udpTracker) Close() error {
	ut.manager.Leave(ut)
	return ut.PacketConn.Close()
}

// NewUDPTracker 创建一个新的UDP连接跟踪器
func NewUDPTracker(conn C.PacketConn, manager *Manager, metadata *C.Metadata, rule C.Rule) *udpTracker {
	uuid, _ := uuid.NewV4()

	ut := &udpTracker{
		PacketConn: conn,
		manager:    manager,
		trackerInfo: &trackerInfo{
			UUID:          uuid,
			Start:         time.Now(),
			Metadata:      metadata,
			Chain:         conn.Chains(),
			Rule:          "",
			UploadTotal:   atomic.NewInt64(0),
			DownloadTotal: atomic.NewInt64(0),
		},
	}

	if rule != nil {
		ut.trackerInfo.Rule = rule.RuleType().String()
		ut.trackerInfo.RulePayload = rule.Payload()
	}

	manager.Join(ut)
	return ut
}
