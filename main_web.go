package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
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
	}

	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "无效的请求",
		})
		return
	}

	// 验证用户名和密码
	if req.Username == "" || req.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "用户名和密码不能为空",
		})
		return
	}

	// 添加用户
	globalConfig.CredStore.AddCredential(req.Username, req.Password)

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
			"proxy_port":     strings.Split(globalConfig.ListenAddr, ":")[1],
			"web_port":       globalConfig.WebPort,
			"admin_username": globalConfig.AdminUsername,
		},
	})
}

// 处理更新设置
func handleUpdateSettings(c *gin.Context) {
	// 解析请求
	var req struct {
		ProxyPort     string `json:"proxy_port"`
		WebPort       string `json:"web_port"`
		AdminUsername string `json:"admin_username"`
		AdminPassword string `json:"admin_password"`
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

// 启动代理服务器
func startProxyServer() {
	proxyMutex.Lock()
	defer proxyMutex.Unlock()

	if proxyRunning {
		return
	}

	// 创建新的停止通道
	proxyStopChan = make(chan struct{})

	// 更新状态
	globalConfig.Status.mutex.Lock()
	globalConfig.Status.Running = true
	globalConfig.Status.StartTime = time.Now()
	globalConfig.Status.ConnectionCount = 0
	globalConfig.Status.mutex.Unlock()

	// 创建代理服务器
	proxyServer = NewProxyServer(globalConfig)

	// 启动代理服务器
	go func() {
		log.Printf("启动HTTPS代理服务器，监听地址: %s\n", globalConfig.ListenAddr)
		log.Printf("已配置用户: %d 个\n", len(globalConfig.CredStore.credentials))

		// 标记为运行中
		proxyRunning = true

		// 启动服务器
		err := proxyServer.Start()
		if err != nil {
			log.Printf("启动代理服务器失败: %v\n", err)

			// 更新状态
			proxyMutex.Lock()
			proxyRunning = false
			globalConfig.Status.mutex.Lock()
			globalConfig.Status.Running = false
			globalConfig.Status.mutex.Unlock()
			proxyMutex.Unlock()
		}
	}()
}

// 停止代理服务器
func stopProxyServer() {
	if !proxyRunning {
		return
	}

	// 关闭停止通道
	close(proxyStopChan)

	// 关闭TCP监听器
	listenerMutex.Lock()
	if proxyListener != nil {
		proxyListener.Close()
		proxyListener = nil
	}
	listenerMutex.Unlock()

	// 更新状态
	proxyRunning = false
	globalConfig.Status.mutex.Lock()
	globalConfig.Status.Running = false
	globalConfig.Status.mutex.Unlock()

	// 等待一小段时间确保端口释放
	time.Sleep(100 * time.Millisecond)

	log.Printf("HTTPS代理服务器已停止\n")
}
