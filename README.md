# eazyProxy 代理服务器

一个功能强大的HTTP/HTTPS代理服务器，具有Web管理界面、用户认证和请求统计功能。

## 功能特点

- **HTTP/HTTPS代理**：支持HTTP和HTTPS协议的代理转发
- **用户认证**：基于用户名和密码的代理认证机制
- **Web管理界面**：直观的Web界面，方便管理代理服务器
- **实时监控**：查看代理服务器的运行状态和连接数
- **域名访问统计**：记录和统计访问的域名和请求次数
- **多用户管理**：支持添加、删除和管理多个代理用户
- **配置灵活**：可自定义代理监听地址、端口和管理员账户

## 系统要求

- Go 1.16 或更高版本
- 支持Windows、Linux和macOS系统

## 安装说明

### 从源码安装

1. 克隆代码仓库

```bash
git clone https://github.com/2833844911/eazyProxy.git
cd eazyProxy
```

2. 安装依赖

```bash
go mod download
```

3. 编译项目

```bash
go build -o eazyProxy
```

## 快速开始

1. 运行程序

```bash
# Windows
eazyProxy.exe

# Linux/macOS
./eazyProxy
```

2. 访问Web管理界面

打开浏览器，访问 `http://localhost:8081`

3. 使用默认管理员账户登录

- 用户名：admin
- 密码：admin

## 配置说明

### 默认配置

- 代理服务器监听地址：0.0.0.0:8080
- Web管理界面地址：0.0.0.0:8081
- 管理员用户名：admin
- 管理员密码：admin

### 通过Web界面配置

登录Web管理界面后，可以在设置页面修改以下配置：

- 代理服务器监听地址和端口
- Web管理界面端口
- 管理员密码

## 使用示例

### 配置浏览器使用代理

1. 在浏览器的网络设置中，配置HTTP代理为你的服务器地址和端口（默认为 `127.0.0.1:8080`）
2. 当提示输入代理认证时，输入你在Web管理界面中创建的用户名和密码

### 使用Python请求示例

```python
import requests

proxies = {
    'http': 'http://username:password@127.0.0.1:8080',
    'https': 'http://username:password@127.0.0.1:8080'
}

response = requests.get('https://example.com', proxies=proxies)
print(response.text)
```

### 使用curl示例

```bash
curl -x http://username:password@127.0.0.1:8080 https://example.com
```

## Web管理界面功能

### 仪表盘

- 查看代理服务器运行状态
- 监控当前连接数
- 查看代理服务器启动时间

### 用户管理

- 添加新的代理用户
- 删除现有代理用户
- 查看所有代理用户列表

### 统计信息

- 查看总请求数
- 查看各域名访问统计
- 查看最近访问的域名
- 重置统计数据

### 设置

- 修改代理服务器监听地址
- 修改Web管理界面端口
- 修改管理员密码

## 常见问题

### 代理服务器无法启动

- 检查端口是否被占用
- 确保有足够的权限绑定端口

### 无法连接到代理

- 确认代理服务器已启动
- 检查防火墙设置
- 验证用户名和密码是否正确

### 无法访问Web管理界面

- 确认Web服务已启动
- 检查端口是否正确
- 检查防火墙设置


## 贡献

欢迎提交问题和功能请求！如果你想贡献代码，请先开issue讨论你想要改变的内容。