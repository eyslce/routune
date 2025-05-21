// Package statistic 提供了网络流量统计和连接管理的功能
package statistic

import (
	"sync"
	"time"

	"go.uber.org/atomic"
)

// DefaultManager 是默认的统计管理器实例
var DefaultManager *Manager

func init() {
	// 初始化默认统计管理器
	DefaultManager = &Manager{
		uploadTemp:    atomic.NewInt64(0),
		downloadTemp:  atomic.NewInt64(0),
		uploadBlip:    atomic.NewInt64(0),
		downloadBlip:  atomic.NewInt64(0),
		uploadTotal:   atomic.NewInt64(0),
		downloadTotal: atomic.NewInt64(0),
	}

	// 启动统计处理协程
	go DefaultManager.handle()
}

// Manager 是流量统计管理器，负责跟踪和管理所有网络连接
type Manager struct {
	connections   sync.Map      // 存储所有活动连接
	uploadTemp    *atomic.Int64 // 临时上传流量统计
	downloadTemp  *atomic.Int64 // 临时下载流量统计
	uploadBlip    *atomic.Int64 // 每秒上传流量统计
	downloadBlip  *atomic.Int64 // 每秒下载流量统计
	uploadTotal   *atomic.Int64 // 总上传流量统计
	downloadTotal *atomic.Int64 // 总下载流量统计
}

// Join 将新的连接添加到管理器中
func (m *Manager) Join(c tracker) {
	m.connections.Store(c.ID(), c)
}

// Leave 从管理器中移除指定的连接
func (m *Manager) Leave(c tracker) {
	m.connections.Delete(c.ID())
}

// PushUploaded 更新上传流量统计
func (m *Manager) PushUploaded(size int64) {
	m.uploadTemp.Add(size)
	m.uploadTotal.Add(size)
}

// PushDownloaded 更新下载流量统计
func (m *Manager) PushDownloaded(size int64) {
	m.downloadTemp.Add(size)
	m.downloadTotal.Add(size)
}

// Now 返回当前的流量统计（每秒）
func (m *Manager) Now() (up int64, down int64) {
	return m.uploadBlip.Load(), m.downloadBlip.Load()
}

// Snapshot 返回当前统计数据的快照
func (m *Manager) Snapshot() *Snapshot {
	connections := []tracker{}
	m.connections.Range(func(key, value any) bool {
		connections = append(connections, value.(tracker))
		return true
	})

	return &Snapshot{
		UploadTotal:   m.uploadTotal.Load(),
		DownloadTotal: m.downloadTotal.Load(),
		Connections:   connections,
	}
}

// ResetStatistic 重置所有统计数据
func (m *Manager) ResetStatistic() {
	m.uploadTemp.Store(0)
	m.uploadBlip.Store(0)
	m.uploadTotal.Store(0)
	m.downloadTemp.Store(0)
	m.downloadBlip.Store(0)
	m.downloadTotal.Store(0)
}

// handle 每秒更新流量统计
func (m *Manager) handle() {
	ticker := time.NewTicker(time.Second)

	for range ticker.C {
		m.uploadBlip.Store(m.uploadTemp.Load())
		m.uploadTemp.Store(0)
		m.downloadBlip.Store(m.downloadTemp.Load())
		m.downloadTemp.Store(0)
	}
}

// Snapshot 包含统计数据的快照信息
type Snapshot struct {
	DownloadTotal int64     `json:"downloadTotal"` // 总下载流量
	UploadTotal   int64     `json:"uploadTotal"`   // 总上传流量
	Connections   []tracker `json:"connections"`   // 当前活动连接列表
}
