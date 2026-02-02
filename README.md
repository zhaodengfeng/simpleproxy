# SIMPLEPROXY

一键安装多种代理协议的脚本，支持 Shadowsocks-rust、Reality、Hysteria2、V2Ray+TLS+WS 和 Snell。

**当前版本**: `260202d`

## 支持的协议

| 协议 | 域名要求 | 端口 | 特点 |
|------|---------|------|------|
| Shadowsocks-rust | ❌ 不需要 | 可选 | 轻量快速，支持 2022-blake3 加密 |
| Reality (Xray) | ⚠️ 可选 | 可选 | 无域名时用偷证书模式，有域名时用 TLS |
| Hysteria2 | ⚠️ 可选 | 可选 | 基于 QUIC，支持端口跳跃(Port Hopping) |
| V2Ray+TLS+WS | ✅ 需要 | 可选 (默认443) | 支持 WebSocket 模式，自动申请 SSL 证书 |
| Snell | ❌ 不需要 | 可选 | Surge 专属协议，支持 v5 和自定义 DNS |

## 快速开始

### 安装

```bash
wget https://raw.githubusercontent.com/zhaodengfeng/simpleproxy/main/simpleproxy.sh && bash simpleproxy.sh
```

或

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/zhaodengfeng/simpleproxy/main/simpleproxy.sh)
```

### 系统要求

- **操作系统**: Ubuntu 16.04+ / Debian 9+ / CentOS 7+
- **权限**: 需要 root 权限
- **网络**: 需要访问 GitHub 下载组件

## 功能特性

### 1. SIMPLEPROXY 品牌
脚本已统一命名为 SIMPLEPROXY，菜单顶部显示版本号（格式：YYMMDD + 字母，如 `260202c`）。

### 2. 端口自定义
每个代理协议安装时都支持自定义端口号：
- 直接输入端口号 → 使用指定端口
- 直接回车 → 随机生成端口 (20000-65000)

### 3. 加密方式选择（Shadowsocks-rust）

安装时可选择加密方式（默认：`2022-blake3-aes-128-gcm`）：

| 选项 | 加密方式 | 密码长度 |
|------|---------|---------|
| 1 | 2022-blake3-aes-128-gcm (默认) | 24字符 (base64) |
| 2 | 2022-blake3-aes-256-gcm | 44字符 (base64) |
| 3 | 2022-blake3-chacha20-poly1305 | 44字符 (base64) |
| 4 | aes-256-gcm | 16字符 |
| 5 | aes-128-gcm | 16字符 |
| 6 | chacha20-ietf-poly1305 | 16字符 |

2022-blake3 系列使用 `dd if=/dev/urandom | base64` 生成符合规范的密钥。

### 4. 域名 + SSL 证书（Reality/Hysteria2/V2Ray+TLS+WS）

**Reality**: 
- 无域名 → 使用偷证书模式 (`www.microsoft.com`)
- 有域名 → 自动申请 Let's Encrypt 证书，使用真实 TLS

**Hysteria2**:
- 无域名 → 使用自签名证书（客户端需设置 `insecure=1`）
- 有域名 → 自动申请 Let's Encrypt 证书

**V2Ray+TLS+WS**:
- 必须使用域名，自动申请并配置 SSL 证书
- 可选择是否启用 WebSocket 支持（默认启用）
- 启用 WS：Nginx 反代，随机路径
- 不启用 WS：直接 TLS 连接

### 5. SSL 证书复用
如果检测到已有有效的 Let's Encrypt 证书（剩余 >30 天），脚本会自动复用，避免重复申请。

### 6. 自定义 DNS（Snell v5）
Snell 安装时支持自定义 DNS 服务器（默认：`8.8.8.8, 1.1.1.1`）。

### 7. 端口跳跃（Hysteria2 Port Hopping）
Hysteria2 安装时可选择启用端口跳跃功能（Port Hopping），提升抗封锁能力：
- 可选启用/禁用（默认：不启用）
- 自定义起始端口和结束端口
- 自定义跳跃间隔（默认：30秒）
- 自动配置防火墙放行端口范围

默认配置（参考官方文档）：
- 起始端口：主端口 +1
- 结束端口：主端口 +100
- 跳跃间隔：30秒

### 8. 证书自动续期
使用 Let's Encrypt 的协议会自动添加 cron 任务，每天 3 点检查并续期证书。

### 8. 升级 / 卸载

脚本提供完整的生命周期管理：
- ✅ 安装代理
- ✅ 升级代理（支持单个或全部）
- ✅ 卸载代理（支持单个或全部）
- ✅ 服务管理（重启、查看状态）
- ✅ 查看客户端配置

## 使用示例

### 安装 Shadowsocks-rust（2022-blake3 加密）

```
╔══════════════════════════════════════╗
║    SIMPLEPROXY v260202c              ║
╚══════════════════════════════════════╝

 1. 安装代理
 ...

请输入数字: 1

=========== 安装代理 ===========
 1. 安装 Shadowsocks-rust (不需要域名)
 ...

请输入数字: 1

Installing Shadowsocks-rust...

请输入端口号(回车或等待15秒随机生成): 8443

请选择加密方式:
 1. 2022-blake3-aes-128-gcm (默认)
 2. 2022-blake3-aes-256-gcm
 3. 2022-blake3-chacha20-poly1305
 4. aes-256-gcm
 5. aes-128-gcm
 6. chacha20-ietf-poly1305
请输入数字(回车或等待15秒使用默认): [回车]

使用加密方式: 2022-blake3-aes-128-gcm

Shadowsocks-rust 安装完成!
=========== Shadowsocks-rust 配置信息 ===========
服务器地址: 1.2.3.4
端口: 8443
密码: AbCdEfGhIjKlMnOpQrStUv==
加密方式: 2022-blake3-aes-128-gcm

ss://...#Shadowsocks
```

### 安装 V2Ray+TLS+WS

```
请输入数字: 4

Installing V2Ray + TLS + WebSocket...

==== 域名配置 ====
请输入已解析到本机的域名: your-domain.com
请输入端口(回车或等待15秒默认为443): [回车]
使用默认端口: 443

是否启用 WebSocket 支持? (y/n, 默认y): [回车]

检测到已有证书，还剩 89 天到期，复用现有证书

V2Ray 安装完成!
=========== V2Ray + TLS + WebSocket 配置信息 ===========
协议: VMess
地址: your-domain.com
端口: 443
UUID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
AlterID: 0
传输协议: WebSocket
路径: /aBcDeFgH
TLS: 开启
SNI: your-domain.com

vmess://...#V2Ray-WS
```

### 安装 Hysteria2（带端口跳跃）

```
请输入数字: 3

Installing Hysteria2...

请输入端口号(回车或等待15秒随机生成): 45000

是否启用端口跳跃(Port Hopping)? (y/n, 默认n): y

端口跳跃配置 (参考官方文档):
请输入起始端口 (默认: 45001): [回车]
请输入结束端口 (默认: 45100): [回车]
请输入跳跃间隔秒数 (默认: 30): [回车]

端口跳跃: 45001-45100, 间隔 30 秒

正在配置防火墙端口范围...

Hysteria2 安装完成!
=========== Hysteria2 配置信息 ===========
服务器地址: 1.2.3.4:45000
密码: xxxxxxxxxxxxxxxx
TLS: 自签名证书 (需跳过验证)
端口跳跃: 45001-45100 (间隔 30秒)

hysteria2://xxx@1.2.3.4:45000?insecure=1&hop=45001-45100&hop_interval=30#Hysteria2
```

## 客户端配置路径

安装完成后，配置信息保存在：

| 协议 | 配置文件路径 |
|------|-------------|
| Shadowsocks-rust | `/etc/shadowsocks/client.json` |
| Reality | `/usr/local/etc/xray/reclient.json` |
| Hysteria2 | `/etc/hysteria/hyclient.json` |
| V2Ray+TLS+WS | `/usr/local/etc/xray/v2client.json` |
| Snell | `/etc/snell/client.json` |

## 配置文件示例

### Shadowsocks-rust (2022-blake3)

```json
{
    "server": "0.0.0.0",
    "server_port": 8443,
    "password": "AbCdEfGhIjKlMnOpQrStUv==",
    "method": "2022-blake3-aes-128-gcm"
}
```

### Reality (TLS模式)

```
vless://uuid@your-domain.com:port?security=tls&sni=your-domain.com&flow=xtls-rprx-vision#Reality
```

### Reality (偷证书模式)

```
vless://uuid@1.2.3.4:port?security=reality&sni=www.microsoft.com&pbk=xxx&sid=xxx&flow=xtls-rprx-vision#Reality
```

### Hysteria2

```
hysteria2://password@1.2.3.4:port?insecure=1#Hysteria2
```

### Hysteria2（带端口跳跃）

```
hysteria2://password@1.2.3.4:mainport?insecure=1&hop=45001-45100&hop_interval=30#Hysteria2
```

服务端配置：
```yaml
listen: :45000,:45001-45100
auth:
  type: password
  password: your-password
hopInterval: 30s
```

### V2Ray+TLS+WS

```
vmess://eyJ2IjoiMiIsInBzIjoiVjJSYXktV1MiLCJhZGQiOiJ5b3VyLWRvbWFpbi5jb20iLCJwb3J0IjoiNDQzIiwiaWQiOiJ1dWlkIiwiYWlkIjoiMCIsIm5ldCI6IndzIiwidHlwZSI6Im5vbmUiLCJob3N0IjoieW91ci1kb21haW4uY29tIiwicGF0aCI6Ii9hQmNEZUZnSCIsInRscyI6InRscyJ9#V2Ray-WS
```

### Snell v5

```
snell://psk@1.2.3.4:port?version=5#Snell
```

## 卸载

运行脚本选择「卸载代理」菜单，支持：
- 单独卸载某个代理
- 一键卸载所有代理

卸载会清除：
- 服务文件
- 配置文件
- 二进制程序

## 常见问题

### 1. 证书申请失败
检查：
- 域名是否正确解析到服务器 IP
- 80 端口是否被占用
- 防火墙是否放行 80 端口

### 2. SSL 证书复用
如果已有有效证书（>30天），脚本会自动复用并提示：
```
检测到已有证书，还剩 89 天到期，复用现有证书
```

### 3. 端口被占用
脚本会检查端口占用情况，如果冲突会提示错误。可以：
- 选择其他端口
- 先停止占用该端口的服务

### 4. 如何查看日志

```bash
# Shadowsocks
journalctl -u shadowsocks.service -f

# Reality/Xray
journalctl -u xray.service -f

# Hysteria2
journalctl -u hysteria-server.service -f

# V2Ray+WS
journalctl -u xray.service -f

# Snell
journalctl -u snell.service -f
```

### 5. Reality 和 V2Ray+WS 状态区分
脚本通过检查不同的标记文件来区分：
- Reality: `/usr/local/etc/xray/reclient.json`
- V2Ray+WS: `/usr/local/etc/xray/v2client.json`

## 更新脚本

```bash
rm -f simpleproxy.sh
wget https://raw.githubusercontent.com/zhaodengfeng/simpleproxy/main/simpleproxy.sh
chmod +x simpleproxy.sh
```

## 版本历史

| 版本 | 日期 | 更新内容 |
|------|------|---------|
| 260202d | 2025-02-02 | 新增 Hysteria2 端口跳跃(Port Hopping)支持 |
| 260202c | 2025-02-02 | 修复 Reality/V2Ray+WS 状态检测冲突，优化 Shadowsocks 启动逻辑 |
| 260202b | 2025-02-02 | 修复 Shadowsocks 2022-blake3 密钥生成 |
| 260202 | 2025-02-02 | 初始版本，支持 5 种代理协议 |

## 致谢

基于 [yeahwu/v2ray-wss](https://github.com/yeahwu/v2ray-wss) 修改，感谢原作者。

Shadowsocks 2022-blake3 密钥生成参考 [jinqians/ss-2022.sh](https://github.com/jinqians/ss-2022.sh)。

## License

MIT
