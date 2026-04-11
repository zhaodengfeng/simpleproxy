# SimpleProxy

A modular Bash script for installing and managing multiple proxy protocols on Linux servers via an interactive menu.

## Supported Protocols

| Protocol | Implementation | Default Port | Transport |
|----------|---------------|-------------|-----------|
| Shadowsocks-rust | ss-server (latest release from GitHub) | User-defined | TCP/UDP |
| VLESS + Reality | Xray-core | 443 | TCP |
| Hysteria2 | sing-box | User-defined | UDP (QUIC) |
| V2Ray + TLS + WebSocket | Xray-core + Nginx | 443 | TCP |
| Snell | snell-server (version fetched from Surge KB) | User-defined | TCP |
| ShadowTLS v3 | sing-box | User-defined | TCP |
| AnyTLS | sing-box | User-defined | TCP |
| Trojan | sing-box | User-defined | TCP |
| TUIC V5 | sing-box | User-defined | UDP (QUIC) |

## Features

- **Modular architecture** — shared libraries in `lib/`, protocol-specific modules in `protocols/`
- **Interactive menu** — install, uninstall, upgrade, and monitor all protocols from a single interface
- **Health checks** — service status, listening ports, certificate expiration tracking
- **SSL automation** — ACME certificate issuance and renewal
- **AI shunt** — route AI/OpenAI domain traffic to an upstream Shadowsocks server using ACL4SSR rules (`AI.list` + `OpenAi.list`)
- **sing-box backend** — shared sing-box binary for ShadowTLS v3, AnyTLS, Trojan, TUIC V5, and Hysteria2 protocols
- **Self-signed certificate** — auto-generated EC P-256 certificate shared across TLS-based sing-box protocols
- **Self-test mode** — validate file integrity and Bash syntax without making system changes
- **Auto-rollback** — configuration changes are backed up and rolled back on validation failure
- **Snell DNS** — optional custom DNS configuration during Snell installation (supports IP addresses and DoH/DoT URLs)
- **Upgrade support** — in-place upgrade for each protocol, fetching the latest version from upstream

## Requirements

- Linux (Ubuntu / Debian / CentOS / RHEL)
- Root privileges
- Public IP address
- `git`, `curl`, `wget`

## Installation

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/zhaodengfeng/simpleproxy/main/install.sh)
```

After installation:

```bash
sudo simpleproxy
# or
sudo sp
```

## Menu

```
[Install]
  1. Shadowsocks-rust
  2. Reality (VLESS)
  3. Hysteria2     (sing-box)
  4. V2Ray + TLS + WebSocket
  5. Snell
  6. ShadowTLS v3  (sing-box)
  7. AnyTLS        (sing-box)
  8. Trojan        (sing-box)
  9. TUIC V5       (sing-box)

[Manage]
 10. Uninstall service
 11. Upgrade service
 12. View status
 13. Health check
 14. Full uninstall
 15. Configure AI shunt (SS upstream)
 16. Disable AI shunt
  0. Exit
```

## Project Layout

```
/opt/simpleproxy/
├── simpleproxy.sh          # Main script (menu, dispatch, health checks)
├── install.sh              # One-line installer
├── lib/
│   ├── common.sh           # Shared utilities (OS detection, firewall, SSL, IP)
│   ├── logging.sh          # Logging helpers
│   └── singbox.sh          # sing-box binary/cert/service management
└── protocols/
    ├── shadowsocks.sh      # Shadowsocks-rust install/uninstall/upgrade/status
    ├── reality.sh          # VLESS + Reality (Xray)
    ├── hysteria2.sh        # Hysteria2 (sing-box)
    ├── v2ray.sh            # V2Ray + TLS + WebSocket (Xray + Nginx)
    ├── snell.sh            # Snell (version from Surge KB page)
    ├── shadowtls.sh        # ShadowTLS v3 (sing-box)
    ├── anytls.sh           # AnyTLS (sing-box)
    ├── trojan.sh           # Trojan (sing-box)
    └── tuic.sh             # TUIC V5 (sing-box)
```

## Upgrade

```bash
cd /opt/simpleproxy && git pull
sudo simpleproxy    # then choose "Upgrade service"
```

## Uninstall

```bash
sudo simpleproxy    # then choose "Full uninstall"
```

## AI Shunt

SimpleProxy can route traffic matching AI/OpenAI domain rules to an upstream Shadowsocks server.

- **Rule source**: ACL4SSR `AI.list` + `OpenAi.list` (auto-downloaded)
- **Configuration**: prompted for upstream SS parameters (server / port / method / password)
- **Safety**: upstream config is parsed as fixed `KEY=VALUE` pairs — never `source`d
- **Rollback**: Xray configs are backed up before modification; auto-rollback on `xray -test` failure

## Troubleshooting

| Command | Purpose |
|---------|---------|
| `sudo simpleproxy --self-test` | Validate file integrity and Bash syntax |
| `sudo simpleproxy` → "View status" | Show all service statuses and ports |
| `tail -f /var/log/simpleproxy.log` | Application log |
| `journalctl -u <service-name> -f` | systemd journal for a specific service |

## Security Notes

- Private keys are set to permission **600**; certificates to **644**
- AI upstream config is parsed, not sourced — no arbitrary code execution
- Configuration changes back up and roll back automatically on validation failure
- Temporary downloads use `mktemp` to reduce `/tmp` race conditions
- Protocol scripts resolve their own `lib/` path internally to prevent `source` path-hijack

## License

GPL-3.0

## Disclaimer

For legitimate network management only. You are responsible for compliance with local laws.
