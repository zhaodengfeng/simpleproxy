# SimpleProxy

SimpleProxy is a lightweight Linux script for quick deployment and management of common proxy protocols.

It is designed for users who want a single interactive script to install services, check status, and manage configs on a VPS.

## Features

- **Modular Architecture**: Clean separation of core functions, protocol implementations, and utilities
- **One-Command Install**: Quick installation via install.sh script
- **SHA256 Verification**: Built-in checksum validation for security
- **Interactive Terminal Menu**: Easy install/manage/uninstall via TUI
- **Log Rotation**: Automatic log management (10MB size limit, keep 5 files)
- **Comprehensive Testing**: Unit tests with bats and static analysis with shellcheck
- **Suitable for fresh Linux VPS setup**

## Supported Proxy Services

- **Shadowsocks-rust** - Fast and stable for daily use
- **VLESS + Reality** - Can run without domain binding
- **Hysteria 2** - Port hopping support for unstable networks
- **V2Ray + TLS + WebSocket** - Standard WebSocket proxy
- **Snell** - Lightweight proxy protocol

## Requirements

- Linux server (Ubuntu/Debian/CentOS/RHEL/Fedora/Arch/Alpine)
- Root privileges
- Public network access
- Git (will be auto-installed if missing)

## One-Command Install

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/zhaodengfeng/simpleproxy/main/install.sh)
```

This will:
1. Detect your Linux distribution
2. Install required dependencies (curl, git, openssl, wget)
3. Clone the repository to `/opt/simpleproxy`
4. Set up proper permissions
5. Create command symlink: `simpleproxy -> /opt/simpleproxy/simpleproxy.sh`

## Manual Installation

If you prefer manual installation:

```bash
# Clone the repository
git clone --depth 1 https://github.com/zhaodengfeng/simpleproxy.git /opt/simpleproxy

# Set permissions
chmod +x /opt/simpleproxy/simpleproxy.sh
chmod +x /opt/simpleproxy/lib/*.sh
chmod +x /opt/simpleproxy/protocols/*.sh

# Create symlink (optional)
ln -s /opt/simpleproxy/simpleproxy.sh /usr/local/bin/simpleproxy

# Create log directory
mkdir -p /var/log/simpleproxy
```

## Usage

After installation, you can use SimpleProxy via the command:

```bash
# Start the interactive menu
simpleproxy

# Or run directly
sudo /opt/simpleproxy/simpleproxy.sh
```

### Menu Options

1. **安装代理** - Install proxy services
2. **卸载代理** - Uninstall proxy services
3. **查看状态** - View service status
4. **管理配置** - Manage configurations
5. **查看日志** - View logs (with rotation support)
6. **备份/恢复** - Backup and restore configs
7. **更新脚本** - Update SimpleProxy to latest version
0. **退出** - Exit

## Project Structure

```
/opt/simpleproxy/
├── simpleproxy.sh          # Main entry point script
├── install.sh              # One-command installer
├── Makefile                # Development tasks
├── checksums.txt           # SHA256 checksums for verification
├── lib/                    # Core library modules
│   ├── common.sh           # Common utilities and functions
│   ├── logging.sh          # Logging system with rotation
│   └── checksum.sh         # SHA256 verification utilities
├── protocols/              # Protocol-specific implementations
│   ├── shadowsocks.sh      # Shadowsocks-rust installer
│   ├── reality.sh          # VLESS + Reality installer
│   ├── hysteria2.sh        # Hysteria 2 installer
│   ├── v2ray.sh            # V2Ray + TLS + WebSocket installer
│   └── snell.sh            # Snell installer
└── tests/                  # Test suite
    ├── test_common.bats    # Tests for common functions
    └── test_checksum.bats  # Tests for checksum functions

/var/log/simpleproxy/       # Log directory
```

## Uninstallation

To completely remove SimpleProxy from your system:

```bash
# Remove the installation directory
sudo rm -rf /opt/simpleproxy

# Remove the command symlink
sudo rm -f /usr/local/bin/simpleproxy

# Remove log directory (optional)
sudo rm -rf /var/log/simpleproxy

# Remove any installed proxy services (use the script before removal)
# simpleproxy -> 选择 "2. 卸载代理"
```

## Development & Testing

For developers who want to contribute or modify SimpleProxy:

### Prerequisites

```bash
# Install bats (testing framework)
npm install -g bats

# Install shellcheck (static analysis)
# Ubuntu/Debian:
sudo apt-get install shellcheck

# macOS:
brew install shellcheck

# CentOS/RHEL/Fedora:
sudo dnf install shellcheck
```

### Development Commands

```bash
# Run all tests
make test

# Run unit tests only
make test-unit

# Run shellcheck static analysis
make test-shellcheck

# Check dependencies
make check

# Install locally (create symlink)
sudo make install

# Clean up test files
make clean
```

### Testing Structure

- **Unit Tests**: Located in `tests/*.bats`
  - `test_common.bats` - Tests for common utilities
  - `test_checksum.bats` - Tests for SHA256 checksum validation

- **Static Analysis**: All shell scripts are checked with shellcheck

### Adding New Protocols

To add a new proxy protocol:

1. Create a new file in `protocols/` directory (e.g., `protocols/newproto.sh`)
2. Implement required functions following the existing protocol patterns
3. Source the file in `simpleproxy.sh`
4. Add tests in `tests/` directory
5. Update checksums: `sha256sum lib/*.sh protocols/*.sh simpleproxy.sh > checksums.txt`

## Security

- All downloads are verified with SHA256 checksums
- Scripts run with `set -euo pipefail` for strict error handling
- Input validation on all user inputs
- Secure temporary file handling
- Log files have restricted permissions

## Notes

- Please use this project responsibly and comply with local laws and regulations
- Regular backups are recommended: use the built-in backup/restore feature
- Log rotation is automatic (10MB per file, keeps 5 files)

## License

GPL-3.0
