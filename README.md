# SimpleProxy

SimpleProxy is a modular Linux script to install and manage common proxy protocols with an interactive menu.

## Features

- Modular architecture (`lib/` + `protocols/`)
- Interactive menu + health checks
- SSL automation + basic firewall integration
- AI shunt: route AI/OpenAI domains to an upstream Shadowsocks server

## Supported protocols

- Shadowsocks-rust
- VLESS + Reality (Xray)
- Hysteria2
- V2Ray + TLS + WebSocket (Xray + Nginx)
- Snell

## Requirements

- Linux (Ubuntu/Debian/CentOS/RHEL)
- Root privileges
- Public IP
- `git`, `curl`, `wget`

## Install

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/zhaodengfeng/simpleproxy/main/install.sh)
```

After installation, run:

```bash
sudo simpleproxy
# or
sudo sp
```


## AI shunt (SS upstream)

SimpleProxy can route traffic matching **AI/OpenAI domain rules** to an **upstream Shadowsocks** server.

- Rule source: ACL4SSR `AI.list` + `OpenAi.list`
- You will be prompted for upstream SS: `server/port/method/password`
- Safety: upstream config is parsed as fixed `KEY=VALUE` (no `source` execution)

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
 10. 配置 AI 分流 (SS 上游)
 11. 关闭 AI 分流
  0. 退出
```

## Layout

```
/opt/simpleproxy/
├── simpleproxy.sh
├── install.sh
├── lib/
└── protocols/
```

## Upgrade

```bash
cd /opt/simpleproxy && git pull
sudo simpleproxy
```

## Uninstall

```bash
sudo simpleproxy  # choose: 完全卸载
```

## Troubleshooting

- Self-test: `sudo simpleproxy --self-test`
- Status: `sudo simpleproxy` → menu “查看状态”
- Logs: `tail -f /var/log/simpleproxy.log`
- systemd logs: `journalctl -u <service-name> -f`
- If you hit `MODULE_DIR: readonly variable`, update to the latest `main` or reinstall from the current `install.sh`

## Manual protocol invocation

```bash
cd /opt/simpleproxy
bash ./protocols/shadowsocks.sh status_shadowsocks
```

Note: protocol scripts compute and lock their `lib/` path internally (no `MODULE_DIR` override) to reduce `source` path-hijack risk.

## Security notes

- Private keys are set to **600** (certs typically **644**)
- AI upstream config is not sourced; it is parsed
- AI shunt changes now back up Xray configs and roll back automatically on validation failure
- Temporary downloads prefer `mktemp` to reduce `/tmp` race/overwrite risk

## License

GPL-3.0

## Disclaimer

For legitimate network management only. You are responsible for compliance with local laws.
