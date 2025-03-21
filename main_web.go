package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// JWT令牌密钥
var jwtSecret []byte

// 全局配置
var globalConfig *ExtendedProxyConfig

// 代理服务器实例
var proxyServer *ProxyServer

// 代理服务器控制
var proxyMutex sync.Mutex
var proxyRunning bool
var proxyStopChan chan struct{}

// 多端口代理服务器实例映射，key为端口ID
var proxyServers = make(map[string]*ProxyServer)
var proxyRunningStatus = make(map[string]bool)

// 初始化函数
func init() {
	// 生成随机JWT密钥
	jwtSecret = make([]byte, 32)
	_, err := rand.Read(jwtSecret)
	if err != nil {
		log.Fatalf("无法生成JWT密钥: %v\n", err)
	}

	// 初始化全局配置
	globalConfig = NewExtendedProxyConfig()

	// 初始化代理控制
	proxyRunning = false
	proxyStopChan = make(chan struct{})
}

// 主函数
func main() {
	// 设置Gin模式
	gin.SetMode(gin.ReleaseMode)

	// 创建Gin路由
	r := gin.Default()

	// 提供静态文件
	r.Static("/static", "./static")

	// 加载HTML模板
	r.LoadHTMLGlob("templates/*")

	// 路由组
	api := r.Group("/api")
	{
		// 登录API
		api.POST("/login", handleLogin)

		// 需要认证的API
		auth := api.Group("/")
		auth.Use(authMiddleware())
		{
			// 代理服务器控制
			auth.GET("/proxy/status", handleProxyStatus)
			auth.POST("/proxy/start", handleProxyStart)
			auth.POST("/proxy/stop", handleProxyStop)

			// 用户管理
			auth.GET("/users", handleGetUsers)
			auth.POST("/users", handleAddUser)
			auth.DELETE("/users/:username", handleDeleteUser)

			// 设置管理
			auth.GET("/settings", handleGetSettings)
			auth.POST("/settings", handleUpdateSettings)

			// 统计信息
			auth.GET("/stats", handleGetStats)
			auth.POST("/stats/reset", handleResetStats)

			// 多端口管理API
			auth.GET("/proxy/ports", handleGetProxyPorts)
			auth.POST("/proxy/ports", handleAddProxyPort)
			auth.GET("/proxy/ports/:id", handleGetProxyPort)
			auth.PUT("/proxy/ports/:id", handleUpdateProxyPort)
			auth.DELETE("/proxy/ports/:id", handleDeleteProxyPort)
			auth.POST("/proxy/ports/:id/start", handleStartProxyPort)
			auth.POST("/proxy/ports/:id/stop", handleStopProxyPort)

			// 端口用户管理API
			auth.GET("/proxy/ports/:id/users", handleGetPortUsers)
			auth.POST("/proxy/ports/:id/users", handleAddPortUser)
			auth.DELETE("/proxy/ports/:id/users/:username", handleDeletePortUser)

			// 端口代理转发设置API
			auth.GET("/proxy/ports/:id/forward", handleGetPortForward)
			auth.POST("/proxy/ports/:id/forward", handleUpdatePortForward)
		}
	}

	// 页面路由
	r.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "login.html", nil)
	})

	r.GET("/dashboard", func(c *gin.Context) {
		c.HTML(http.StatusOK, "dashboard.html", nil)
	})

	// 启动Web服务器
	log.Printf("启动Web管理界面，监听地址: 0.0.0.0:%s\n", globalConfig.WebPort)
	go r.Run(":" + globalConfig.WebPort)

	// 启动代理服务器
	startProxyServer()

	// 启动默认代理服务器
	startProxyPort("default")

	// 等待信号
	select {}
}

// 认证中间件
func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 获取Authorization头
		auth := c.GetHeader("Authorization")
		if auth == "" || !strings.HasPrefix(auth, "Bearer ") {
			c.JSON(http.StatusUnauthorized, gin.H{
				"success": false,
				"message": "未授权访问",
			})
			c.Abort()
			return
		}

		// 提取令牌
		token := auth[7:]

		// 验证令牌
		if !validateToken(token) {
			c.JSON(http.StatusUnauthorized, gin.H{
				"success": false,
				"message": "无效的令牌",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// 验证令牌
func validateToken(token string) bool {
	// 简单实现，实际应用中应该使用JWT库
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}

	// 解码payload
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}

	// 解析payload
	var payload struct {
		Username string    `json:"username"`
		Exp      time.Time `json:"exp"`
	}

	err = json.Unmarshal(payloadBytes, &payload)
	if err != nil {
		return false
	}

	// 检查过期时间
	if time.Now().After(payload.Exp) {
		return false
	}

	// 检查用户名
	return payload.Username == globalConfig.AdminUsername
}

// 生成令牌
func generateToken(username string) string {
	// 简单实现，实际应用中应该使用JWT库
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))

	// 创建payload
	payload := struct {
		Username string    `json:"username"`
		Exp      time.Time `json:"exp"`
	}{
		Username: username,
		Exp:      time.Now().Add(24 * time.Hour),
	}

	payloadBytes, _ := json.Marshal(payload)
	payloadBase64 := base64.RawURLEncoding.EncodeToString(payloadBytes)

	// 创建签名
	signature := base64.RawURLEncoding.EncodeToString([]byte("signature"))

	return header + "." + payloadBase64 + "." + signature
}

// 处理登录请求
func handleLogin(c *gin.Context) {
	// 解析请求
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "无效的请求",
		})
		return
	}

	// 验证管理员凭证
	if req.Username == globalConfig.AdminUsername && req.Password == globalConfig.AdminPassword {
		// 生成令牌
		token := generateToken(req.Username)

		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"token":   token,
		})
	} else {
		c.JSON(http.StatusUnauthorized, gin.H{
			"success": false,
			"message": "用户名或密码错误",
		})
	}
}

// 处理获取代理状态
func handleProxyStatus(c *gin.Context) {
	globalConfig.Status.mutex.RLock()
	defer globalConfig.Status.mutex.RUnlock()

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"running":          globalConfig.Status.Running,
			"start_time":       globalConfig.Status.StartTime,
			"connection_count": globalConfig.Status.ConnectionCount,
			"address":          globalConfig.ProxyConfig.ListenAddr,
		},
	})
}

// 处理启动代理服务器
func handleProxyStart(c *gin.Context) {
	proxyMutex.Lock()
	defer proxyMutex.Unlock()

	if proxyRunning {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "代理服务器已经在运行",
		})
		return
	}

	// 启动代理服务器
	go startProxyServer()

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "代理服务器已启动",
	})
}

// 处理停止代理服务器
func handleProxyStop(c *gin.Context) {
	proxyMutex.Lock()
	defer proxyMutex.Unlock()

	if !proxyRunning {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "代理服务器未运行",
		})
		return
	}

	// 停止代理服务器
	stopProxyServer()

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "代理服务器已停止",
	})
}

// 处理获取用户列表
func handleGetUsers(c *gin.Context) {
	globalConfig.CredStore.mutex.RLock()
	defer globalConfig.CredStore.mutex.RUnlock()

	users := make([]gin.H, 0, len(globalConfig.CredStore.credentials))
	for username := range globalConfig.CredStore.credentials {
		users = append(users, gin.H{
			"username": username,
			"no_auth":  globalConfig.CredStore.IsNoAuthUser(username),
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    users,
	})
}

// 处理添加用户
func handleAddUser(c *gin.Context) {
	// 解析请求
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		NoAuth   bool   `json:"no_auth"`
	}

	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "无效的请求",
		})
		return
	}

	// 验证用户名
	if req.Username == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "用户名不能为空",
		})
		return
	}

	// 如果不是无认证用户，则验证密码
	if !req.NoAuth && req.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "密码不能为空",
		})
		return
	}

	// 添加用户
	globalConfig.CredStore.AddCredential(req.Username, req.Password)

	// 如果是无认证用户，记录到无认证用户列表
	if req.NoAuth {
		globalConfig.CredStore.AddNoAuthUser(req.Username)
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "用户已添加",
	})
}

// 处理删除用户
func handleDeleteUser(c *gin.Context) {
	username := c.Param("username")

	globalConfig.CredStore.mutex.Lock()
	defer globalConfig.CredStore.mutex.Unlock()

	// 检查用户是否存在
	if _, exists := globalConfig.CredStore.credentials[username]; !exists {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"message": "用户不存在",
		})
		return
	}

	// 删除用户
	delete(globalConfig.CredStore.credentials, username)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "用户已删除",
	})
}

// 处理获取设置
func handleGetSettings(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"proxy_port":        strings.Split(globalConfig.ListenAddr, ":")[1],
			"web_port":          globalConfig.WebPort,
			"admin_username":    globalConfig.AdminUsername,
			"use_forward_proxy": globalConfig.UseForwardProxy,
			"allow_anonymous":   globalConfig.AllowAnonymous,
			"remote_proxy_addr": globalConfig.RemoteProxyAddr,
			"remote_proxy_user": globalConfig.RemoteProxyUser,
			"remote_proxy_pass": globalConfig.RemoteProxyPass,
		},
	})
}

// 处理更新设置
func handleUpdateSettings(c *gin.Context) {
	// 解析请求
	var req struct {
		ProxyPort       string `json:"proxy_port"`
		WebPort         string `json:"web_port"`
		AdminUsername   string `json:"admin_username"`
		AdminPassword   string `json:"admin_password"`
		UseForwardProxy bool   `json:"use_forward_proxy"`
		AllowAnonymous  bool   `json:"allow_anonymous"`
		RemoteProxyAddr string `json:"remote_proxy_addr"`
		RemoteProxyUser string `json:"remote_proxy_user"`
		RemoteProxyPass string `json:"remote_proxy_pass"`
	}

	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "无效的请求",
		})
		return
	}

	// 验证端口
	proxyPort, err := strconv.Atoi(req.ProxyPort)
	if err != nil || proxyPort < 1 || proxyPort > 65535 {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "无效的代理端口",
		})
		return
	}

	webPort, err := strconv.Atoi(req.WebPort)
	if err != nil || webPort < 1 || webPort > 65535 || webPort == proxyPort {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "无效的Web端口或与代理端口冲突",
		})
		return
	}

	// 验证用户名
	if req.AdminUsername == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "管理员用户名不能为空",
		})
		return
	}

	// 如果启用了代理转发，验证远程代理地址
	if req.UseForwardProxy && req.RemoteProxyAddr == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "启用代理转发时，远程代理地址不能为空",
		})
		return
	}

	// 更新设置
	proxyMutex.Lock()
	defer proxyMutex.Unlock()

	// 更新代理端口
	globalConfig.ListenAddr = fmt.Sprintf("0.0.0.0:%s", req.ProxyPort)

	// 更新Web端口
	globalConfig.WebPort = req.WebPort

	// 更新管理员用户名
	globalConfig.AdminUsername = req.AdminUsername

	// 更新管理员密码（如果提供）
	if req.AdminPassword != "" {
		globalConfig.AdminPassword = req.AdminPassword
	}

	// 更新代理转发设置
	globalConfig.UseForwardProxy = req.UseForwardProxy

	// 更新匿名访问设置
	globalConfig.AllowAnonymous = req.AllowAnonymous

	// 更新远程代理设置
	if req.RemoteProxyAddr != "" {
		globalConfig.RemoteProxyAddr = req.RemoteProxyAddr
	}
	if req.RemoteProxyUser != "" {
		globalConfig.RemoteProxyUser = req.RemoteProxyUser
	}
	if req.RemoteProxyPass != "" {
		globalConfig.RemoteProxyPass = req.RemoteProxyPass
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "设置已更新",
	})
}

// 处理获取统计信息
func handleGetStats(c *gin.Context) {
	// 获取域名统计
	domainStats := globalConfig.StatsManager.GetDomainStats()

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"total_requests": globalConfig.StatsManager.GetTotalRequests(),
			"domain_stats":   domainStats,
		},
	})
}

// 处理重置统计信息
func handleResetStats(c *gin.Context) {
	// 重置统计信息
	globalConfig.StatsManager.Reset()

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "统计信息已重置",
	})
}

// 处理获取所有代理端口
func handleGetProxyPorts(c *gin.Context) {
	ports := globalConfig.GetAllProxyPorts()

	// 转换为JSON格式
	result := make([]gin.H, 0, len(ports))
	for _, port := range ports {
		port.Status.mutex.RLock()
		result = append(result, gin.H{
			"id":               port.ID,
			"listen_addr":      port.ListenAddr,
			"enabled":          port.Enabled,
			"running":          port.Status.Running,
			"start_time":       port.Status.StartTime,
			"connection_count": port.Status.ConnectionCount,
			"allow_anonymous":  port.AllowAnonymous,
		})
		port.Status.mutex.RUnlock()
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    result,
	})
}

// 处理添加代理端口
func handleAddProxyPort(c *gin.Context) {
	var req struct {
		ListenAddr     string `json:"listen_addr"`
		AllowAnonymous bool   `json:"allow_anonymous"`
	}

	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "无效的请求",
		})
		return
	}

	// 验证监听地址
	if req.ListenAddr == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "监听地址不能为空",
		})
		return
	}

	// 生成唯一ID
	portID := fmt.Sprintf("port_%d", time.Now().UnixNano())

	// 创建新的端口配置
	port := &ProxyPortConfig{
		ID:              portID,
		ListenAddr:      req.ListenAddr,
		Enabled:         true,
		Status:          &ProxyStatus{Running: false, StartTime: time.Time{}, ConnectionCount: 0, mutex: sync.RWMutex{}},
		AllowAnonymous:  req.AllowAnonymous,
		PortUsers:       make(map[string]string), // 初始化用户映射
		NoAuthUsers:     make(map[string]bool),   // 初始化无需认证用户映射
		usersMutex:      sync.RWMutex{},
		UseForwardProxy: false,
		RemoteProxyAddr: "",
		RemoteProxyUser: "",
		RemoteProxyPass: "",
	}

	// 添加到全局配置
	globalConfig.AddProxyPort(port)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "代理端口已添加",
		"data":    port,
	})
}

// 处理获取单个代理端口
func handleGetProxyPort(c *gin.Context) {
	id := c.Param("id")

	port := globalConfig.GetProxyPort(id)
	if port == nil {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"message": "代理端口不存在",
		})
		return
	}

	port.Status.mutex.RLock()
	result := gin.H{
		"id":               port.ID,
		"listen_addr":      port.ListenAddr,
		"enabled":          port.Enabled,
		"running":          port.Status.Running,
		"start_time":       port.Status.StartTime,
		"connection_count": port.Status.ConnectionCount,
		"allow_anonymous":  port.AllowAnonymous,
	}
	port.Status.mutex.RUnlock()

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    result,
	})
}

// 处理更新代理端口
func handleUpdateProxyPort(c *gin.Context) {
	id := c.Param("id")

	port := globalConfig.GetProxyPort(id)
	if port == nil {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"message": "端口不存在",
		})
		return
	}

	var req struct {
		ListenAddr     string `json:"listen_addr"`
		Enabled        bool   `json:"enabled"`
		AllowAnonymous bool   `json:"allow_anonymous"`
	}

	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "无效的请求",
		})
		return
	}

	// 验证监听地址
	if req.ListenAddr == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "监听地址不能为空",
		})
		return
	}

	// 检查是否需要重启代理
	needRestart := port.Status.Running && (port.ListenAddr != req.ListenAddr || port.Enabled != req.Enabled)

	// 如果需要重启，先停止代理
	if needRestart {
		stopProxyPort(id)
	}

	// 更新配置
	port.ListenAddr = req.ListenAddr
	port.Enabled = req.Enabled
	port.AllowAnonymous = req.AllowAnonymous

	// 如果需要重启且启用状态为true，则重新启动代理
	if needRestart && req.Enabled {
		go startProxyPort(id)
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "代理端口已更新",
	})
}

// 处理删除代理端口
func handleDeleteProxyPort(c *gin.Context) {
	id := c.Param("id")

	// 不允许删除默认端口
	if id == "default" {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "不能删除默认端口",
		})
		return
	}

	port := globalConfig.GetProxyPort(id)
	if port == nil {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"message": "代理端口不存在",
		})
		return
	}

	// 如果端口正在运行，需要先停止
	if port.Status.Running {
		stopProxyPort(id)
	}

	// 删除配置
	globalConfig.DeleteProxyPort(id)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "代理端口已删除",
	})
}

// 处理启动单个代理端口
func handleStartProxyPort(c *gin.Context) {
	id := c.Param("id")

	port := globalConfig.GetProxyPort(id)
	if port == nil {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"message": "代理端口不存在",
		})
		return
	}

	// 检查是否已启用
	if !port.Enabled {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "该代理端口未启用",
		})
		return
	}

	// 检查是否已运行
	if port.Status.Running {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "代理服务器已经在运行",
		})
		return
	}

	// 启动代理服务器
	go startProxyPort(id)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "代理服务器已启动",
	})
}

// 处理停止单个代理端口
func handleStopProxyPort(c *gin.Context) {
	id := c.Param("id")

	port := globalConfig.GetProxyPort(id)
	if port == nil {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"message": "代理端口不存在",
		})
		return
	}

	// 检查是否正在运行
	if !port.Status.Running {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "代理服务器未运行",
		})
		return
	}

	// 停止代理服务器
	stopProxyPort(id)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "代理服务器已停止",
	})
}

// 启动单个代理端口
func startProxyPort(id string) {
	proxyMutex.Lock()
	defer proxyMutex.Unlock()

	// 检查是否已运行
	if proxyRunningStatus[id] {
		return
	}

	port := globalConfig.GetProxyPort(id)
	if port == nil || !port.Enabled {
		return
	}

	// 创建代理服务器
	proxyServers[id] = NewProxyServer(globalConfig, id)

	// 标记为运行中
	proxyRunningStatus[id] = true

	// 启动服务器
	go func() {
		log.Printf("启动HTTPS代理服务器，监听地址: %s (端口ID: %s)\n", port.ListenAddr, id)

		err := proxyServers[id].Start()
		if err != nil {
			log.Printf("启动代理服务器失败: %v (端口ID: %s)\n", err, id)

			// 更新状态
			proxyMutex.Lock()
			proxyRunningStatus[id] = false
			port.Status.mutex.Lock()
			port.Status.Running = false
			port.Status.mutex.Unlock()
			proxyMutex.Unlock()
		}
	}()
}

// 停止单个代理端口
func stopProxyPort(id string) {
	proxyMutex.Lock()
	defer proxyMutex.Unlock()

	// 检查是否正在运行
	if !proxyRunningStatus[id] {
		return
	}

	// 关闭TCP监听器
	listenerMutex.Lock()
	if listener, ok := proxyListeners[id]; ok && listener != nil {
		listener.Close()
		delete(proxyListeners, id)
	}
	listenerMutex.Unlock()

	// 更新状态
	proxyRunningStatus[id] = false

	port := globalConfig.GetProxyPort(id)
	if port != nil {
		port.Status.mutex.Lock()
		port.Status.Running = false
		port.Status.mutex.Unlock()
	}

	// 等待一小段时间确保端口释放
	time.Sleep(100 * time.Millisecond)

	log.Printf("HTTPS代理服务器已停止 (端口ID: %s)\n", id)
}

// 兼容旧版本的启动代理服务器函数
func startProxyServer() {
	startProxyPort("default")
}

// 兼容旧版本的停止代理服务器函数
func stopProxyServer() {
	stopProxyPort("default")
}

// 处理获取端口用户
func handleGetPortUsers(c *gin.Context) {
	portID := c.Param("id")

	port := globalConfig.GetProxyPort(portID)
	if port == nil {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"message": "端口不存在",
		})
		return
	}

	users := port.GetAllUsers()

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    users,
	})
}

// 处理添加端口用户
func handleAddPortUser(c *gin.Context) {
	portID := c.Param("id")

	port := globalConfig.GetProxyPort(portID)
	if port == nil {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"message": "端口不存在",
		})
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		NoAuth   bool   `json:"no_auth"`
	}

	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "无效的请求",
		})
		return
	}

	// 验证用户名
	if req.Username == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "用户名不能为空",
		})
		return
	}

	// 验证密码（如果不是无需认证的用户）
	if !req.NoAuth && req.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "密码不能为空",
		})
		return
	}

	// 添加用户
	if req.NoAuth {
		port.AddNoAuthUser(req.Username)
	} else {
		port.AddUser(req.Username, req.Password)
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "用户已添加",
	})
}

// 处理删除端口用户
func handleDeletePortUser(c *gin.Context) {
	portID := c.Param("id")
	username := c.Param("username")

	port := globalConfig.GetProxyPort(portID)
	if port == nil {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"message": "端口不存在",
		})
		return
	}

	port.DeleteUser(username)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "用户已删除",
	})
}

// 处理获取端口代理转发设置
func handleGetPortForward(c *gin.Context) {
	portID := c.Param("id")
	
	port := globalConfig.GetProxyPort(portID)
	if port == nil {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"message": "端口不存在",
		})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"use_forward_proxy": port.UseForwardProxy,
			"remote_proxy_addr": port.RemoteProxyAddr,
			"remote_proxy_user": port.RemoteProxyUser,
			// 不返回密码，保护安全
		},
	})
}

// 处理更新端口代理转发设置
func handleUpdatePortForward(c *gin.Context) {
	portID := c.Param("id")
	
	port := globalConfig.GetProxyPort(portID)
	if port == nil {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"message": "端口不存在",
		})
		return
	}
	
	var req struct {
		UseForwardProxy bool   `json:"use_forward_proxy"`
		RemoteProxyAddr string `json:"remote_proxy_addr"`
		RemoteProxyUser string `json:"remote_proxy_user"`
		RemoteProxyPass string `json:"remote_proxy_pass"`
	}
	
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "无效的请求",
		})
		return
	}
	
	// 验证远程代理地址（如果启用了代理转发）
	if req.UseForwardProxy && req.RemoteProxyAddr == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "远程代理地址不能为空",
		})
		return
	}
	
	// 更新设置
	port.UseForwardProxy = req.UseForwardProxy
	port.RemoteProxyAddr = req.RemoteProxyAddr
	port.RemoteProxyUser = req.RemoteProxyUser
	
	// 只有在提供了新密码时才更新密码
	if req.RemoteProxyPass != "" {
		port.RemoteProxyPass = req.RemoteProxyPass
	}
	
	// 保存配置到文件
	saveConfig()
	
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "代理转发设置已更新",
	})
}

// 保存配置到文件
func saveConfig() {
	// 将配置序列化为JSON
	configData, err := json.MarshalIndent(globalConfig, "", "  ")
	if err != nil {
		log.Printf("序列化配置失败: %v", err)
		return
	}
	
	// 写入配置文件
	err = os.WriteFile("config.json", configData, 0644)
	if err != nil {
		log.Printf("保存配置文件失败: %v", err)
		return
	}
	
	log.Println("配置已保存到文件")
}
