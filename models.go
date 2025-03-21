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

// 单个代理端口配置
type ProxyPortConfig struct {
	ID              string            `json:"id"`                // 唯一标识符
	ListenAddr      string            `json:"listen_addr"`       // 监听地址，格式为 "IP:端口"
	Enabled         bool              `json:"enabled"`           // 是否启用
	Status          *ProxyStatus      `json:"status"`            // 代理状态
	AllowAnonymous  bool              `json:"allow_anonymous"`   // 是否允许匿名访问
	PortUsers       map[string]string `json:"-"`                 // 端口专用用户，key为用户名，value为密码
	NoAuthUsers     map[string]bool   `json:"-"`                 // 端口专用无需认证的用户
	usersMutex      sync.RWMutex      `json:"-"`                 // 用于保护用户映射的互斥锁
	UseForwardProxy bool              `json:"use_forward_proxy"` // 是否启用代理转发
	RemoteProxyAddr string            `json:"remote_proxy_addr"` // 远程代理地址
	RemoteProxyUser string            `json:"remote_proxy_user"` // 远程代理用户名
	RemoteProxyPass string            `json:"remote_proxy_pass"` // 远程代理密码
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
	AdminUsername   string
	AdminPassword   string
	WebPort         string
	Status          *ProxyStatus
	StatsManager    *StatsManager
	UseForwardProxy bool   // 是否启用代理转发功能
	AllowAnonymous  bool   // 是否允许匿名访问（不需要认证）
	RemoteProxyAddr string // 远程代理服务器地址
	RemoteProxyUser string // 远程代理服务器用户名
	RemoteProxyPass string // 远程代理服务器密码

	// 多端口配置
	ProxyPorts      map[string]*ProxyPortConfig // 多端口配置，key为端口ID
	proxyPortsMutex sync.RWMutex                // 用于保护ProxyPorts的互斥锁
}

// 创建新的扩展代理配置
func NewExtendedProxyConfig() *ExtendedProxyConfig {
	config := &ExtendedProxyConfig{
		ProxyConfig: ProxyConfig{
			ListenAddr: "0.0.0.0:8080",
			CredStore:  NewCredentialStore(),
		},
		AdminUsername:   "admin",
		AdminPassword:   "admin",
		WebPort:         "8081",
		Status:          &ProxyStatus{Running: false, StartTime: time.Time{}, ConnectionCount: 0, mutex: sync.RWMutex{}},
		StatsManager:    NewStatsManager(),
		UseForwardProxy: false, // 默认不启用代理转发
		AllowAnonymous:  false, // 默认不允许匿名访问
		RemoteProxyAddr: "127.0.0.1:7890",
		RemoteProxyUser: "dsdddd",
		RemoteProxyPass: "dsdddd",
		ProxyPorts:      make(map[string]*ProxyPortConfig),
		proxyPortsMutex: sync.RWMutex{},
	}

	// 添加默认端口配置
	defaultPort := &ProxyPortConfig{
		ID:              "default",
		ListenAddr:      "0.0.0.0:8080",
		Enabled:         true,
		Status:          &ProxyStatus{Running: false, StartTime: time.Time{}, ConnectionCount: 0, mutex: sync.RWMutex{}},
		AllowAnonymous:  false,
		PortUsers:       make(map[string]string),
		NoAuthUsers:     make(map[string]bool),
		usersMutex:      sync.RWMutex{},
		UseForwardProxy: false,
		RemoteProxyAddr: "",
		RemoteProxyUser: "",
		RemoteProxyPass: "",
	}
	config.ProxyPorts["default"] = defaultPort

	return config
}

// 添加代理端口配置
func (ec *ExtendedProxyConfig) AddProxyPort(port *ProxyPortConfig) {
	ec.proxyPortsMutex.Lock()
	defer ec.proxyPortsMutex.Unlock()
	ec.ProxyPorts[port.ID] = port
}

// 获取代理端口配置
func (ec *ExtendedProxyConfig) GetProxyPort(id string) *ProxyPortConfig {
	ec.proxyPortsMutex.RLock()
	defer ec.proxyPortsMutex.RUnlock()
	return ec.ProxyPorts[id]
}

// 删除代理端口配置
func (ec *ExtendedProxyConfig) DeleteProxyPort(id string) {
	ec.proxyPortsMutex.Lock()
	defer ec.proxyPortsMutex.Unlock()
	delete(ec.ProxyPorts, id)
}

// 获取所有代理端口配置
func (ec *ExtendedProxyConfig) GetAllProxyPorts() []*ProxyPortConfig {
	ec.proxyPortsMutex.RLock()
	defer ec.proxyPortsMutex.RUnlock()

	ports := make([]*ProxyPortConfig, 0, len(ec.ProxyPorts))
	for _, port := range ec.ProxyPorts {
		ports = append(ports, port)
	}
	return ports
}

// 用户凭证存储
type CredentialStore struct {
	credentials map[string]string
	noAuthUsers map[string]bool // 存储无需认证的用户
	mutex       sync.RWMutex
}

// 创建新的凭证存储
func NewCredentialStore() *CredentialStore {
	return &CredentialStore{
		credentials: make(map[string]string),
		noAuthUsers: make(map[string]bool),
		mutex:       sync.RWMutex{},
	}
}

// 添加用户凭证
func (cs *CredentialStore) AddCredential(username, password string) {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()
	cs.credentials[username] = password
}

// 添加无需认证的用户
func (cs *CredentialStore) AddNoAuthUser(username string) {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()
	cs.noAuthUsers[username] = true
}

// 检查是否为无需认证的用户
func (cs *CredentialStore) IsNoAuthUser(username string) bool {
	cs.mutex.RLock()
	defer cs.mutex.RUnlock()
	return cs.noAuthUsers[username]
}

// 验证用户凭证
func (cs *CredentialStore) Validate(username, password string) bool {
	cs.mutex.RLock()
	defer cs.mutex.RUnlock()

	// 检查是否为无需认证的用户
	if cs.noAuthUsers[username] {
		return true
	}

	// 否则验证用户名和密码
	stored, exists := cs.credentials[username]
	return exists && stored == password
}

// 添加端口用户
func (pc *ProxyPortConfig) AddUser(username, password string) {
	pc.usersMutex.Lock()
	defer pc.usersMutex.Unlock()
	pc.PortUsers[username] = password
}

// 添加端口无需认证用户
func (pc *ProxyPortConfig) AddNoAuthUser(username string) {
	pc.usersMutex.Lock()
	defer pc.usersMutex.Unlock()
	pc.NoAuthUsers[username] = true
}

// 删除端口用户
func (pc *ProxyPortConfig) DeleteUser(username string) {
	pc.usersMutex.Lock()
	defer pc.usersMutex.Unlock()
	delete(pc.PortUsers, username)
	delete(pc.NoAuthUsers, username)
}

// 验证端口用户
func (pc *ProxyPortConfig) ValidateUser(username, password string) bool {
	pc.usersMutex.RLock()
	defer pc.usersMutex.RUnlock()

	// 检查是否为无需认证的用户
	if pc.NoAuthUsers[username] {
		return true
	}

	// 否则验证用户名和密码
	storedPassword, exists := pc.PortUsers[username]
	return exists && storedPassword == password
}

// 获取所有端口用户
func (pc *ProxyPortConfig) GetAllUsers() []map[string]interface{} {
	pc.usersMutex.RLock()
	defer pc.usersMutex.RUnlock()

	users := make([]map[string]interface{}, 0)

	// 添加普通用户
	for username, _ := range pc.PortUsers {
		// 跳过同时也是无需认证的用户
		if pc.NoAuthUsers[username] {
			continue
		}

		users = append(users, map[string]interface{}{
			"username": username,
			"no_auth":  false,
		})
	}

	// 添加无需认证的用户
	for username := range pc.NoAuthUsers {
		users = append(users, map[string]interface{}{
			"username": username,
			"no_auth":  true,
		})
	}

	return users
}
