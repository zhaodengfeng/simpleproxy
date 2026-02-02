# SimpleProxy

一键安装多种代理协议的脚本，支持 Shadowsocks-rust、Reality、Hysteria2、AnyTLS 和 Snell。

## 支持的协议

| 协议 | 域名要求 | 端口 | 特点 |
|------|---------|------|------|
| Shadowsocks-rust | ❌ 不需要 | 可选 | 轻量快速，兼容性好 |
| Reality (Xray) | ⚠️ 可选 | 可选 | 无域名时用偷证书模式，有域名时用 TLS |
| Hysteria2 | ⚠️ 可选 | 可选 | 基于 QUIC，抗封锁能力强 |
| AnyTLS | ✅ 需要 | 可选 (默认443) | 新兴协议，自动申请 SSL 证书 |
| Snell | ❌ 不需要 | 可选 | Surge 专属协议 |

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

### 1. 端口自定义
每个代理协议安装时都支持自定义端口号：
- 直接输入端口号 → 使用指定端口
- 直接回车 → 随机生成端口 (20000-65000)

### 2. 域名 + SSL 证书（Reality/Hysteria2/AnyTLS）

**Reality**: 
- 无域名 → 使用偷证书模式 (`www.microsoft.com`)
- 有域名 → 自动申请 Let's Encrypt 证书，使用真实 TLS

**Hysteria2**:
- 无域名 → 使用自签名证书（客户端需设置 `insecure=1`）
- 有域名 → 自动申请 Let's Encrypt 证书

**AnyTLS**:
- 必须使用域名，自动申请并配置 SSL 证书

### 3. 证书自动续期
使用 Let's Encrypt 的协议会自动添加 cron 任务，每天 3 点检查并续期证书。

### 4. 升级 / 卸载

脚本提供完整的生命周期管理：
- ✅ 安装代理
- ✅ 升级代理（支持单个或全部）
- ✅ 卸载代理（支持单个或全部）
- ✅ 服务管理（重启、查看状态）
- ✅ 查看客户端配置

## 使用示例

### 安装 Reality（带域名）

```
==========================================
  代理安装管理脚本
==========================================

 1. 安装代理
 ...

请输入数字: 1

 1. 安装 Shadowsocks-rust (不需要域名)
 2. 安装 Reality (可选域名)
 ...

请输入数字: 2

Installing Reality (Xray)...

请输入端口号(回车或等待15秒随机生成): 8443
是否使用自己的域名? (y/n, 默认n): y

==== Reality 域名配置 ====
请输入已解析到本机的域名: your-domain.com

正在为 your-domain.com 申请SSL证书...
SSL证书安装成功!

Reality 安装完成!
=========== Reality (TLS模式) 配置信息 ===========
协议: VLESS
地址: your-domain.com
端口: 8443
UUID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
流控: xtls-rprx-vision
安全: tls
SNI: your-domain.com

vless://...#Reality-TLS
```

### 安装 Hysteria2（无域名）

```
请输入端口号(回车或等待15秒随机生成): [回车]
使用随机端口: 38472
是否使用自己的域名? (y/n, 默认n): [回车]

Hysteria2 安装完成!
=========== Hysteria2 配置信息 ===========
服务器地址: 1.2.3.4:38472
密码: xxxxxxxxxxxxxxxx
TLS: 自签名证书 (需跳过验证)

hysteria2://...?insecure=1#Hysteria2
```

## 客户端配置路径

安装完成后，配置信息保存在：

| 协议 | 配置文件路径 |
|------|-------------|
| Shadowsocks-rust | `/etc/shadowsocks/client.json` |
| Reality | `/usr/local/etc/xray/reclient.json` |
| Hysteria2 | `/etc/hysteria/hyclient.json` |
| AnyTLS | `/etc/anytls/client.json` |
| Snell | `/etc/snell/client.json` |

## 配置文件示例

### Shadowsocks-rust

```json
{
    "server": "0.0.0.0",
    "server_port": 45678,
    "password": "your-password",
    "method": "aes-256-gcm"
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

### AnyTLS

```
anytls://password@your-domain.com:443?sni=your-domain.com&fp=xxx&path=/anytls#AnyTLS
```

### Snell

```
snell://psk@1.2.3.4:port?version=4#Snell
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

### 2. 端口被占用
脚本会检查端口占用情况，如果冲突会提示错误。可以：
- 选择其他端口
- 先停止占用该端口的服务

### 3. 如何查看日志

```bash
# Shadowsocks
journalctl -u shadowsocks.service -f

# Reality/Xray
journalctl -u xray.service -f

# Hysteria2
journalctl -u hysteria-server.service -f

# AnyTLS
journalctl -u anytls.service -f

# Snell
journalctl -u snell.service -f
```

## 更新脚本

```bash
cd ~/simpleproxy
git pull
```

## 安全提示

- 建议定期更换密码/密钥
- 建议使用防火墙限制端口访问（如仅允许特定 IP）
- 建议启用 BBR 拥塞控制算法提升性能

## 致谢

基于 [yeahwu/v2ray-wss](https://github.com/yeahwu/v2ray-wss) 修改，感谢原作者。

## License

MIT
