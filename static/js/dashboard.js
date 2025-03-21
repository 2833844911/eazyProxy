document.addEventListener('DOMContentLoaded', function() {
    // 检查登录状态
    if (!localStorage.getItem('token')) {
        window.location.href = '/';
        return;
    }
    
    // 获取DOM元素
    const logoutBtn = document.getElementById('logout-btn');
    const navItems = document.querySelectorAll('.nav-menu li');
    const panels = document.querySelectorAll('.panel');
    const startProxyBtn = document.getElementById('start-proxy');
    const stopProxyBtn = document.getElementById('stop-proxy');
    const addUserForm = document.getElementById('add-user-form');
    const settingsForm = document.getElementById('settings-form');
    const resetStatsBtn = document.getElementById('reset-stats');
    
    // 初始化页面
    updateProxyStatus();
    loadUsers();
    loadSettings();
    loadStats();
    
    // 设置定时刷新
    setInterval(updateProxyStatus, 5000);
    setInterval(loadStats, 10000);
    
    // 处理导航菜单点击
    navItems.forEach(item => {
        item.addEventListener('click', function() {
            const tabId = this.getAttribute('data-tab');
            
            // 更新活动标签
            navItems.forEach(nav => nav.classList.remove('active'));
            this.classList.add('active');
            
            // 显示对应面板
            panels.forEach(panel => {
                if (panel.id === tabId + '-panel') {
                    panel.classList.add('active');
                } else {
                    panel.classList.remove('active');
                }
            });
        });
    });
    
    // 处理退出登录
    logoutBtn.addEventListener('click', function() {
        localStorage.removeItem('token');
        window.location.href = '/';
    });
    
    // 处理启动代理服务器
    startProxyBtn.addEventListener('click', function() {
        fetch('/api/proxy/start', {
            method: 'POST',
            headers: {
                'Authorization': 'Bearer ' + localStorage.getItem('token')
            }
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                updateProxyStatus();
            } else {
                alert('启动服务失败: ' + data.message);
            }
        })
        .catch(error => {
            console.error('启动服务请求失败:', error);
            alert('启动服务请求失败，请稍后重试');
        });
    });
    
    // 处理停止代理服务器
    stopProxyBtn.addEventListener('click', function() {
        fetch('/api/proxy/stop', {
            method: 'POST',
            headers: {
                'Authorization': 'Bearer ' + localStorage.getItem('token')
            }
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                updateProxyStatus();
            } else {
                alert('停止服务失败: ' + data.message);
            }
        })
        .catch(error => {
            console.error('停止服务请求失败:', error);
            alert('停止服务请求失败，请稍后重试');
        });
    });
    
    // 处理添加用户
    addUserForm.addEventListener('submit', function(e) {
        e.preventDefault();
        
        const username = document.getElementById('new-username').value;
        const password = document.getElementById('new-password').value;
        
        fetch('/api/users', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + localStorage.getItem('token')
            },
            body: JSON.stringify({
                username: username,
                password: password
            })
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                // 重置表单
                addUserForm.reset();
                // 刷新用户列表
                loadUsers();
            } else {
                alert('添加用户失败: ' + data.message);
            }
        })
        .catch(error => {
            console.error('添加用户请求失败:', error);
            alert('添加用户请求失败，请稍后重试');
        });
    });
    
    // 处理保存设置
    settingsForm.addEventListener('submit', function(e) {
        e.preventDefault();
        
        const proxyPort = document.getElementById('proxy-port').value;
        const webPort = document.getElementById('web-port').value;
        const adminUsername = document.getElementById('admin-username').value;
        const adminPassword = document.getElementById('admin-password').value;
        const useForwardProxy = document.getElementById('use-forward-proxy').checked;
        
        fetch('/api/settings', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + localStorage.getItem('token')
            },
            body: JSON.stringify({
                proxy_port: proxyPort,
                web_port: webPort,
                admin_username: adminUsername,
                admin_password: adminPassword || undefined,
                use_forward_proxy: useForwardProxy
            })
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                alert('设置已保存，部分设置可能需要重启服务器才能生效');
                // 重置密码字段
                document.getElementById('admin-password').value = '';
            } else {
                alert('保存设置失败: ' + data.message);
            }
        })
        .catch(error => {
            console.error('保存设置请求失败:', error);
            alert('保存设置请求失败，请稍后重试');
        });
    });
    
    // 处理重置统计
    resetStatsBtn.addEventListener('click', function() {
        if (confirm('确定要重置所有统计数据吗？')) {
            fetch('/api/stats/reset', {
                method: 'POST',
                headers: {
                    'Authorization': 'Bearer ' + localStorage.getItem('token')
                }
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    loadStats();
                } else {
                    alert('重置统计失败: ' + data.message);
                }
            })
            .catch(error => {
                console.error('重置统计请求失败:', error);
                alert('重置统计请求失败，请稍后重试');
            });
        }
    });
    
    // 更新代理服务器状态
    function updateProxyStatus() {
        fetch('/api/proxy/status', {
            headers: {
                'Authorization': 'Bearer ' + localStorage.getItem('token')
            }
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                const status = data.data;
                const statusElement = document.getElementById('proxy-status');
                const addressElement = document.getElementById('proxy-address');
                const startTimeElement = document.getElementById('start-time');
                const connectionCountElement = document.getElementById('connection-count');
                
                // 更新状态显示
                statusElement.textContent = status.running ? '运行中' : '已停止';
                statusElement.className = 'value status-indicator ' + (status.running ? 'running' : 'stopped');
                
                addressElement.textContent = status.address;
                
                if (status.running) {
                    startTimeElement.textContent = new Date(status.start_time).toLocaleString();
                    connectionCountElement.textContent = status.connection_count;
                    
                    // 更新按钮状态
                    startProxyBtn.disabled = true;
                    stopProxyBtn.disabled = false;
                } else {
                    startTimeElement.textContent = '-';
                    connectionCountElement.textContent = '0';
                    
                    // 更新按钮状态
                    startProxyBtn.disabled = false;
                    stopProxyBtn.disabled = true;
                }
            }
        })
        .catch(error => {
            console.error('获取代理状态失败:', error);
        });
    }
    
    // 加载用户列表
    function loadUsers() {
        fetch('/api/users', {
            headers: {
                'Authorization': 'Bearer ' + localStorage.getItem('token')
            }
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                const userList = document.getElementById('user-list');
                userList.innerHTML = '';
                
                data.data.forEach(user => {
                    const row = document.createElement('tr');
                    
                    const usernameCell = document.createElement('td');
                    usernameCell.textContent = user.username;
                    
                    const passwordCell = document.createElement('td');
                    passwordCell.textContent = '••••••••';
                    
                    const actionCell = document.createElement('td');
                    const deleteBtn = document.createElement('button');
                    deleteBtn.textContent = '删除';
                    deleteBtn.className = 'btn-delete';
                    deleteBtn.addEventListener('click', function() {
                        deleteUser(user.username);
                    });
                    actionCell.appendChild(deleteBtn);
                    
                    row.appendChild(usernameCell);
                    row.appendChild(passwordCell);
                    row.appendChild(actionCell);
                    
                    userList.appendChild(row);
                });
            }
        })
        .catch(error => {
            console.error('获取用户列表失败:', error);
        });
    }
    
    // 删除用户
    function deleteUser(username) {
        if (confirm(`确定要删除用户 "${username}" 吗？`)) {
            fetch(`/api/users/${username}`, {
                method: 'DELETE',
                headers: {
                    'Authorization': 'Bearer ' + localStorage.getItem('token')
                }
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    loadUsers();
                } else {
                    alert('删除用户失败: ' + data.message);
                }
            })
            .catch(error => {
                console.error('删除用户请求失败:', error);
                alert('删除用户请求失败，请稍后重试');
            });
        }
    }
    
    // 加载设置
    function loadSettings() {
        fetch('/api/settings', {
            headers: {
                'Authorization': 'Bearer ' + localStorage.getItem('token')
            }
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                const settings = data.data;
                
                document.getElementById('proxy-port').value = settings.proxy_port;
                document.getElementById('web-port').value = settings.web_port;
                document.getElementById('admin-username').value = settings.admin_username;
                document.getElementById('use-forward-proxy').checked = settings.use_forward_proxy || false;
            }
        })
        .catch(error => {
            console.error('获取设置失败:', error);
        });
    }
    
    // 加载统计信息
    function loadStats() {
        fetch('/api/stats', {
            headers: {
                'Authorization': 'Bearer ' + localStorage.getItem('token')
            }
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                const stats = data.data;
                
                // 更新总请求数
                document.getElementById('total-requests').textContent = stats.total_requests;
                
                // 更新域名统计
                const domainStatsElement = document.getElementById('domain-stats');
                domainStatsElement.innerHTML = '';
                
                if (stats.domain_stats.length === 0) {
                    const row = document.createElement('tr');
                    const cell = document.createElement('td');
                    cell.colSpan = 3;
                    cell.textContent = '暂无数据';
                    cell.style.textAlign = 'center';
                    row.appendChild(cell);
                    domainStatsElement.appendChild(row);
                } else {
                    stats.domain_stats.forEach(domain => {
                        const row = document.createElement('tr');
                        
                        const domainCell = document.createElement('td');
                        domainCell.textContent = domain.domain;
                        
                        const countCell = document.createElement('td');
                        countCell.textContent = domain.count;
                        
                        const lastVisitCell = document.createElement('td');
                        lastVisitCell.textContent = new Date(domain.last_visit).toLocaleString();
                        
                        row.appendChild(domainCell);
                        row.appendChild(countCell);
                        row.appendChild(lastVisitCell);
                        
                        domainStatsElement.appendChild(row);
                    });
                }
            }
        })
        .catch(error => {
            console.error('获取统计信息失败:', error);
        });
    }
});