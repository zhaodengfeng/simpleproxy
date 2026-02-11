# SimpleProxy

SimpleProxy is a lightweight Linux script for quick deployment and management of common proxy protocols.

It is designed for users who want a single interactive script to install services, check status, and manage configs on a VPS.

## Features

- Install and manage multiple proxy services in one script
- Interactive terminal menu for install/manage/uninstall
- Basic service status checks and config helpers
- Suitable for fresh Linux VPS setup

## Supported Proxy Services

- Shadowsocks-rust
- VLESS + Reality
- Hysteria 2
- V2Ray + TLS + WebSocket
- Snell

## Requirements

- Linux server (Ubuntu/Debian recommended)
- Root privileges
- Public network access

## One-Command Install

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/zhaodengfeng/simpleproxy/main/simpleproxy.sh)
```

## Local Run

```bash
chmod +x simpleproxy.sh
sudo ./simpleproxy.sh
```

Then follow the interactive menu in terminal.

## Project Structure

- `simpleproxy.sh` — main installer and management script

## Notes

- Please use this project responsibly and comply with local laws and regulations.

## License

GPL-3.0
