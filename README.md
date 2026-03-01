# SimpleProxy

SimpleProxy is a lightweight Linux script for quick deployment and management of common proxy protocols. Designed with a modular architecture for better maintainability and extensibility.

## Features

- **Modular Design**: Core logic separated into reusable library modules
- **Protocol Plugins**: Each proxy protocol as an independent module
- **Interactive Menu**: Terminal-based UI for easy management
- **Health Checks**: Built-in diagnostics and status monitoring
- **SSL Automation**: Automatic certificate申请 and renewal
- **Firewall Integration**: Automatic port management for ufw/firewalld

## Supported Proxy Services

| Protocol | Features | Status |
|----------|----------|--------|
| **Shadowsocks-rust** | Multiple ciphers (2022-blake3, AES-GCM, ChaCha20) | ✅ Ready |
| **VLESS + Reality** | XTLS Vision, TLS/Steal modes | ✅ Ready |
| **Hysteria 2** | UDP-based, Port Hopping support | ✅ Ready |
| **V2Ray + WS** | WebSocket + TLS + Nginx | ✅ Ready |
| **Snell** | Surge optimized, v4 protocol | ✅ Ready |

## Requirements

- Linux server (Ubuntu/Debian/CentOS/RHEL)
- Root privileges
- Public IP address
- Git, curl, wget

## One-Command Install

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/zhaodengfeng/simpleproxy/main/install.sh)
```

After installation, use the `simpleproxy` command from anywhere.

### About Remote Installer Execution (important)

出于供应链安全考虑：**SimpleProxy 默认禁止执行任何远程脚本**（例如 acme.sh / Xray / Hysteria2 的 upstream installer）。

当你确实需要这些能力时，请在运行前显式开启：

```bash
ALLOW_REMOTE_INSTALL=1 simpleproxy
```

一条命令（安装 + 首次运行，且允许远程脚本执行）：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/zhaodengfeng/simpleproxy/main/install.sh) \
  && ALLOW_REMOTE_INSTALL=1 simpleproxy
```

> 说明：开启后仍然会从 HTTPS 下载脚本到临时文件再执行；如果你追求更强的可复现/可验证性，建议自行做版本 pin + hash 校验。

## Usage

```bash
# Start the interactive menu
sudo simpleproxy

# Or run directly
sudo /opt/simpleproxy/simpleproxy.sh
```

### AI 分流（SS 上游）

SimpleProxy 支持把命中 **AI/OpenAI 规则** 的流量单独分流到一个 **Shadowsocks 上游**（适用于你已有上游 SS，希望仅让 AI 相关域名走上游）。

- 菜单：
  - `10. 配置 AI 分流 (SS 上游)`
  - `11. 关闭 AI 分流`
- 规则来源：会拉取并合并 ACL4SSR 的 `AI.list` 与 `OpenAi.list`，生成本地规则文件。
- 配置方式：会让你输入上游 SS 的 server/port/method/password。

安全说明：AI 上游配置文件**不会再通过 `source` 执行**，而是解析固定 `KEY=VALUE`（已做端口校验），避免命令注入。

### Menu Options

```
[安装选项]
  1. Shadowsocks-rust
  2. Reality (VLESS)
  3. Hysteria2
  4. V2Ray + TLS + WebSocket
  5. Snell

[管理选项]
  6. 卸载服务
  7. 查看状态
  8. 健康检查
  9. 完全卸载
  0. 退出
```

## Project Structure

```
/opt/simpleproxy/
├── simpleproxy.sh      # Main entry point & menu
├── install.sh          # One-click installer
├── lib/
│   ├── common.sh       # Shared utilities (validation, network, firewall)
│   ├── logging.sh      # Logging system with rotation
│   └── checksum.sh     # File integrity verification
└── protocols/
    ├── shadowsocks.sh  # Shadowsocks-rust module
    ├── reality.sh      # VLESS + Reality module
    ├── hysteria2.sh    # Hysteria2 module
    ├── v2ray.sh        # V2Ray + WebSocket module
    └── snell.sh        # Snell proxy module
```

## Architecture

### Modular Design
- **lib/common.sh**: Common functions (domain validation, random generation, firewall rules, backups)
- **lib/logging.sh**: Structured logging with rotation support
- **protocols/*.sh**: Self-contained protocol modules with standardized interface:
  - `install_<protocol>()` - Installation logic
  - `uninstall_<protocol>()` - Clean removal
  - `upgrade_<protocol>()` - In-place upgrade
  - `status_<protocol>()` - Status check

### State Management
- Installation state: `/var/lib/simpleproxy/*.state`
- Exported configs: `/var/lib/simpleproxy/exports/`
- Backups: `/var/backups/simpleproxy/`
- Logs: `/var/log/simpleproxy.log`

## Manual Installation

```bash
# Clone repository
git clone --depth 1 https://github.com/zhaodengfeng/simpleproxy.git /opt/simpleproxy

# Set permissions
chmod +x /opt/simpleproxy/simpleproxy.sh
chmod +x /opt/simpleproxy/lib/*.sh
chmod +x /opt/simpleproxy/protocols/*.sh

# Create symlink
ln -s /opt/simpleproxy/simpleproxy.sh /usr/local/bin/simpleproxy

# Run
sudo simpleproxy
```

## Upgrade

```bash
# Update to latest version
cd /opt/simpleproxy && git pull

# Or reinstall
sudo simpleproxy  # Then use upgrade option for each protocol
```

## Uninstall

```bash
# Remove all services and data
sudo simpleproxy  # Select option 9 (完全卸载)

# Or manually
rm -rf /opt/simpleproxy
rm -f /usr/local/bin/simpleproxy
rm -rf /var/lib/simpleproxy
rm -rf /var/backups/simpleproxy
```

## Troubleshooting

### Check service status
```bash
sudo simpleproxy  # Option 7
```

### View logs
```bash
tail -f /var/log/simpleproxy.log
journalctl -u <service-name> -f
```

### Health check
```bash
sudo simpleproxy  # Option 8
```

### Manual protocol management
```bash
# Example: Check shadowsocks status
cd /opt/simpleproxy
bash ./protocols/shadowsocks.sh status_shadowsocks
```

> 注意：协议脚本会自行计算并锁定 lib 路径（不再接受通过环境变量覆盖 MODULE_DIR），以避免 source 路径劫持风险。

## Security Considerations

- 配置文件使用更严格的权限（例如私钥 **600**，证书 **644**）
- AI 分流上游配置不再通过 `source` 加载，改为解析固定 `KEY=VALUE`，避免命令注入
- 远程脚本执行默认禁用；需要时必须显式设置 `ALLOW_REMOTE_INSTALL=1`
- 输入校验：域名/端口/密码等基础检查
- 临时文件/下载尽量使用 `mktemp`，降低 /tmp 竞态与覆盖风险
- 自动防火墙放行（ufw/firewalld）

## Contributing

Contributions are welcome! Please ensure:
- Follow the modular structure for new protocols
- Include install/uninstall/upgrade/status functions
- Add proper error handling and logging
- Update this README

## Changelog

### v260224a (Refactored)
- ✅ Complete modular rewrite
- ✅ Extracted common functions to lib/
- ✅ Each protocol as independent module
- ✅ Enhanced logging with rotation
- ✅ Unified error handling
- ✅ Improved maintainability

## License

GPL-3.0

## Disclaimer

This tool is for educational and legitimate network management purposes only. Users are responsible for complying with local laws and regulations.
