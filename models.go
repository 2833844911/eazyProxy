package main

import (
	"sync"
	"time"
)

// 代理服务器状态
type ProxyStatus struct {
	Running         bool      `json:"running"`
	StartTime       time.Time `json:"start_time"`
	ConnectionCount int       `json:"connection_count"`
	mutex           sync.RWMutex
}

// 域名访问统计
type DomainStat struct {
	Domain    string    `json:"domain"`
	Count     int       `json:"count"`
	LastVisit time.Time `json:"last_visit"`
}

// 请求统计管理器
type StatsManager struct {
	TotalRequests int                    `json:"total_requests"`
	DomainStats   map[string]*DomainStat `json:"domain_stats"`
	mutex         sync.RWMutex
}

// 创建新的统计管理器
func NewStatsManager() *StatsManager {
	return &StatsManager{
		TotalRequests: 0,
		DomainStats:   make(map[string]*DomainStat),
		mutex:         sync.RWMutex{},
	}
}

// 记录请求
func (sm *StatsManager) RecordRequest(domain string) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	sm.TotalRequests++

	// 更新域名统计
	if _, exists := sm.DomainStats[domain]; !exists {
		sm.DomainStats[domain] = &DomainStat{
			Domain:    domain,
			Count:     0,
			LastVisit: time.Now(),
		}
	}

	sm.DomainStats[domain].Count++
	sm.DomainStats[domain].LastVisit = time.Now()
}

// 获取所有域名统计
func (sm *StatsManager) GetDomainStats() []*DomainStat {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	stats := make([]*DomainStat, 0, len(sm.DomainStats))
	for _, stat := range sm.DomainStats {
		stats = append(stats, stat)
	}

	return stats
}

// 获取总请求数
func (sm *StatsManager) GetTotalRequests() int {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()
	return sm.TotalRequests
}

// 重置统计信息
func (sm *StatsManager) Reset() {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	sm.TotalRequests = 0
	sm.DomainStats = make(map[string]*DomainStat)
}

// 扩展代理配置
type ExtendedProxyConfig struct {
	ProxyConfig
	AdminUsername string
	AdminPassword string
	WebPort       string
	Status        *ProxyStatus
	StatsManager  *StatsManager
}

// 创建新的扩展代理配置
func NewExtendedProxyConfig() *ExtendedProxyConfig {
	return &ExtendedProxyConfig{
		ProxyConfig: ProxyConfig{
			ListenAddr: "0.0.0.0:8080",
			CredStore:  NewCredentialStore(),
		},
		AdminUsername: "admin",
		AdminPassword: "admin",
		WebPort:       "8081",
		Status:        &ProxyStatus{Running: false, StartTime: time.Time{}, ConnectionCount: 0, mutex: sync.RWMutex{}},
		StatsManager:  NewStatsManager(),
	}
}
