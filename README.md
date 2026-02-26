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

### About Remote Installer Confirmation (new)

For higher safety, when some protocol installers need to execute upstream remote scripts (e.g. Xray/Hysteria), SimpleProxy will ask you to type `YES` before continuing.

If you need unattended automation, you can skip that confirmation:

```bash
ALLOW_REMOTE_SCRIPT=1 simpleproxy
```

## Usage

```bash
# Start the interactive menu
sudo simpleproxy

# Or run directly
sudo /opt/simpleproxy/simpleproxy.sh
```

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
MODULE_DIR=/opt/simpleproxy/lib bash /opt/simpleproxy/protocols/shadowsocks.sh status_shadowsocks
```

## Security Considerations

- All configuration files are created with restrictive permissions (600/644)
- SSL certificates are properly permissioned (600 for private keys)
- Input validation for domains, ports, and passwords
- No shell metacharacters allowed in keys
- Automatic firewall rules for opened ports

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
