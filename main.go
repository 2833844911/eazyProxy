package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// 用户凭证存储
type CredentialStore struct {
	credentials map[string]string
	mutex       sync.RWMutex
}

// 创建新的凭证存储
func NewCredentialStore() *CredentialStore {
	return &CredentialStore{
		credentials: make(map[string]string),
		mutex:       sync.RWMutex{},
	}
}

// 添加用户凭证
func (cs *CredentialStore) AddCredential(username, password string) {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()
	cs.credentials[username] = password
}

// 验证用户凭证
func (cs *CredentialStore) Validate(username, password string) bool {
	cs.mutex.RLock()
	defer cs.mutex.RUnlock()
	stored, exists := cs.credentials[username]
	return exists && stored == password
}

// 代理服务器配置
type ProxyConfig struct {
	ListenAddr string
	CredStore  *CredentialStore
}

// 代理服务器
type ProxyServer struct {
	config interface{}
}

// 创建新的代理服务器
func NewProxyServer(config interface{}) *ProxyServer {
	return &ProxyServer{
		config: config,
	}
}

// 代理服务器监听器
var proxyListener net.Listener
var listenerMutex sync.Mutex

// 启动代理服务器
func (ps *ProxyServer) Start() error {
	// 获取监听地址
	var listenAddr string
	if config, ok := ps.config.(ProxyConfig); ok {
		listenAddr = config.ListenAddr
	} else if extConfig, ok := ps.config.(*ExtendedProxyConfig); ok {
		listenAddr = extConfig.ListenAddr
	} else {
		return fmt.Errorf("无效的配置类型")
	}

	// 加锁确保线程安全
	listenerMutex.Lock()

	// 创建监听器
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		listenerMutex.Unlock()
		return fmt.Errorf("无法监听地址 %s: %v", listenAddr, err)
	}

	// 保存监听器的引用
	proxyListener = listener
	listenerMutex.Unlock()

	log.Printf("HTTPS代理服务器已启动，监听地址: %s\n", listenAddr)

	// 监听连接请求
	for {
		client, err := listener.Accept()
		if err != nil {
			// 检查是否是因为监听器被关闭导致的错误
			if strings.Contains(err.Error(), "use of closed network connection") {
				log.Printf("监听器已关闭，代理服务器停止\n")
				break
			}
			log.Printf("接受连接失败: %v\n", err)
			continue
		}

		go ps.handleConnection(client)
	}

	return nil
}

// 处理客户端连接
func (ps *ProxyServer) handleConnection(client net.Conn) {
	defer client.Close()

	// 更新连接计数
	if config, ok := ps.config.(*ExtendedProxyConfig); ok {
		config.Status.mutex.Lock()
		config.Status.ConnectionCount++
		config.Status.mutex.Unlock()
	}

	// 设置读取超时
	client.SetReadDeadline(time.Now().Add(30 * time.Second))

	// 读取HTTP请求
	reader := bufio.NewReader(client)
	req, err := http.ReadRequest(reader)
	if err != nil {
		log.Printf("读取请求失败: %v\n", err)
		return
	}

	// 验证代理认证
	if !ps.authenticate(req) {
		ps.sendAuthRequired(client)
		return
	} else {
		//client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	}

	// 记录域名访问统计
	if config, ok := ps.config.(*ExtendedProxyConfig); ok {
		domain := req.Host
		if strings.Contains(domain, ":") {
			domain = strings.Split(domain, ":")[0]
		}
		config.StatsManager.RecordRequest(domain)
	}

	// 处理CONNECT方法（HTTPS代理）
	if req.Method == http.MethodConnect {
		ps.handleHTTPS(client, req)
		return
	}

	// 处理HTTP请求
	ps.handleHTTP(client, req, reader)
}

// 验证用户认证
func (ps *ProxyServer) authenticate(req *http.Request) bool {
	// 获取Proxy-Authorization头
	authHeader := req.Header.Get("Proxy-Authorization")
	if authHeader == "" {
		return false
	}

	// 解析认证信息
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || parts[0] != "Basic" {
		return false
	}

	// 解码Base64编码的凭证
	credentials, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}

	// 分离用户名和密码
	pair := strings.SplitN(string(credentials), ":", 2)
	if len(pair) != 2 {
		return false
	}

	username, password := pair[0], pair[1]

	// 验证凭证
	var credStore *CredentialStore
	if config, ok := ps.config.(ProxyConfig); ok {
		credStore = config.CredStore
	} else if extConfig, ok := ps.config.(*ExtendedProxyConfig); ok {
		credStore = extConfig.CredStore
	} else {
		return false
	}

	return credStore.Validate(username, password)
}

// 发送认证要求响应
func (ps *ProxyServer) sendAuthRequired(client net.Conn) {
	response := "HTTP/1.1 407 Proxy Authentication Required\r\n" +
		"Proxy-Authenticate: Basic realm=\"Proxy\"\r\n" +
		"Content-Length: 0\r\n\r\n"
	client.Write([]byte(response))
}

// 处理HTTPS请求
func (ps *ProxyServer) handleHTTPS(client net.Conn, req *http.Request) {
	log.Printf("处理HTTPS请求: %s", req.Host)
	// 连接到目标服务器
	target, err := net.Dial("tcp", strings.TrimSpace(req.Host))
	if err != nil {
		log.Printf("无法连接到目标服务器 %s: %v\n", req.Host, err)
		return
	}
	defer target.Close()

	// 发送200 Connection Established响应
	response := "HTTP/1.1 200 Connection Established\r\n\r\n"
	_, err = client.Write([]byte(response))
	if err != nil {
		log.Printf("发送响应失败: %v\n", err)
		return
	}

	// 双向转发数据
	ps.tunnel(client, target)
}

// 处理HTTP请求
func (ps *ProxyServer) handleHTTP(client net.Conn, req *http.Request, reader *bufio.Reader) {
	// 确保请求有完整的URL
	if req.URL.Scheme == "" {
		req.URL.Scheme = "http"
	}
	if req.URL.Host == "" {
		req.URL.Host = req.Host
	}

	// 移除Proxy-Authorization头，避免将凭证发送到目标服务器
	req.Header.Del("Proxy-Authorization")
	req.Header.Del("Proxy-Connection")
	// req.Header.Set("Connection", "close")

	// 连接到目标服务器
	log.Printf("处理HTTP请求: %s", req.URL.Host)
	var target net.Conn
	var err error
	if strings.Contains(req.URL.Host, ":") {
		target, err = net.Dial("tcp", strings.TrimSpace(req.URL.Host))

	} else {
		target, err = net.Dial("tcp", strings.TrimSpace(req.URL.Host)+":80")

	}
	if err != nil {
		log.Printf("无法连接到目标服务器 %s: %v\n", req.URL.Host, err)
		return
	}
	defer target.Close()

	// 将请求发送到目标服务器
	err = req.Write(target)
	if err != nil {
		log.Printf("发送请求到目标服务器失败: %v\n", err)
		return
	}

	// 将目标服务器的响应发送回客户端
	_, err = io.Copy(client, target)
	if err != nil && err != io.EOF {
		log.Printf("转发响应失败: %v\n", err)
	}
}

// 在客户端和目标服务器之间建立双向隧道
func (ps *ProxyServer) tunnel(client, target net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	// 客户端 -> 目标服务器
	go func() {
		defer wg.Done()
		_, err := io.Copy(target, client)
		if err != nil {
			if strings.Contains(err.Error(), "connection reset by peer") {
				log.Printf("客户端连接已重置: %v", err)
			} else if err != io.EOF {
				log.Printf("转发客户端数据失败: %v", err)
			}
		}
		target.(*net.TCPConn).CloseWrite()
	}()

	// 目标服务器 -> 客户端
	go func() {
		defer wg.Done()
		_, err := io.Copy(client, target)
		if err != nil {
			if strings.Contains(err.Error(), "connection reset by peer") {
				log.Printf("目标服务器连接已重置: %v", err)
			} else if err != io.EOF {
				log.Printf("转发服务器数据失败: %v", err)
			}
		}
		client.(*net.TCPConn).CloseWrite()
	}()

	wg.Wait()
}

// 此文件不再包含main函数，main函数已移至main_web.go
// 这里只保留代理服务器的核心功能实现
