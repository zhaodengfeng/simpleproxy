#!/bin/bash
# shadowtls.sh - ShadowTLS v3 协议管理 (基于 sing-box)
# ShadowTLS v3 使用双 inbound 联动: shadowtls 外层 + shadowsocks 内层
# 包含安装、卸载、升级、状态检查功能

# 加载依赖
MODULE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)"
source "${MODULE_DIR}/common.sh"
source "${MODULE_DIR}/logging.sh"
source "${MODULE_DIR}/singbox.sh"

# 配置路径
readonly STLS_CONFIG_DIR="/etc/sing-box/shadowtls"
readonly STLS_CONFIG_FILE="${STLS_CONFIG_DIR}/config.json"
readonly STLS_CLIENT_FILE="${STLS_CONFIG_DIR}/client.json"
readonly STLS_CLIENT_TXT="${STLS_CONFIG_DIR}/client.txt"
readonly STLS_SERVICE="singbox-shadowtls"
readonly STLS_TLS_SERVER="addons.mozilla.org"

# ============================================
# 安装 ShadowTLS v3
# ============================================
install_shadowtls() {
    log_info "开始安装 ShadowTLS v3"
    echo -e "${BLUE}正在安装 ShadowTLS v3 (sing-box)...${NC}"

    # 1. 端口输入
    echo ""
    read -t 15 -p "请输入端口号(回车或等待15秒随机生成): " port_input || true
    local port
    if [[ -n "$port_input" ]]; then
        port=$port_input
    else
        port=$(gen_port 20000 65000)
        echo -e "${GREEN}使用随机端口: ${port}${NC}"
    fi

    if ! validate_port "$port"; then
        port=$(gen_port 20000 65000)
        echo -e "${YELLOW}端口无效，使用随机端口: ${port}${NC}"
    fi

    if has_listening_port "$port"; then
        echo -e "${RED}错误: 端口 ${port} 已被占用${NC}"
        return 1
    fi

    # 2. 生成密码和密钥
    local uuid
    uuid=$(gen_uuid)
    local ss_password
    ss_password=$(dd if=/dev/urandom bs=16 count=1 2>/dev/null | base64 -w 0)
    local ss_method="2022-blake3-aes-128-gcm"

    # 3. 安装 sing-box
    install_singbox_binary || return 1

    # 4. 生成服务端配置
    mkdir -p "$STLS_CONFIG_DIR"
    cat > "$STLS_CONFIG_FILE" <<EOF
{
    "inbounds": [
        {
            "type": "shadowtls",
            "tag": "shadowtls-in",
            "listen": "::",
            "listen_port": ${port},
            "detour": "shadowtls-ss-in",
            "version": 3,
            "users": [
                {
                    "password": "${uuid}"
                }
            ],
            "handshake": {
                "server": "${STLS_TLS_SERVER}",
                "server_port": 443
            },
            "strict_mode": true
        },
        {
            "type": "shadowsocks",
            "tag": "shadowtls-ss-in",
            "listen": "127.0.0.1",
            "network": "tcp",
            "method": "${ss_method}",
            "password": "${ss_password}",
            "multiplex": {
                "enabled": true,
                "padding": true
            }
        }
    ],
    "outbounds": [
        {
            "type": "direct"
        }
    ]
}
EOF

    # 5. 创建服务并启动
    create_singbox_service "$STLS_SERVICE" "$STLS_CONFIG_FILE"
    if ! start_singbox_service "$STLS_SERVICE"; then
        return 1
    fi

    # 6. 防火墙
    check_firewall_port "$port" tcp

    # 7. 标记安装
    mark_installed shadowtls

    # 8. 生成客户端配置 (ShadowTLS v3 需要 sing-box 客户端)
    local server_ip
    server_ip=$(get_public_ip)

    cat > "$STLS_CLIENT_FILE" <<EOF
{
    "inbounds": [
        {
            "type": "mixed",
            "listen": "127.0.0.1",
            "listen_port": 1080,
            "tag": "mixed-in"
        }
    ],
    "outbounds": [
        {
            "type": "shadowsocks",
            "method": "${ss_method}",
            "password": "${ss_password}",
            "detour": "shadowtls-out",
            "multiplex": {
                "enabled": true,
                "protocol": "h2mux",
                "max_connections": 8,
                "min_streams": 16,
                "padding": true
            }
        },
        {
            "type": "shadowtls",
            "tag": "shadowtls-out",
            "server": "${server_ip}",
            "server_port": ${port},
            "version": 3,
            "password": "${uuid}",
            "tls": {
                "enabled": true,
                "server_name": "${STLS_TLS_SERVER}",
                "utls": {
                    "enabled": true,
                    "fingerprint": "firefox"
                }
            }
        }
    ]
}
EOF
    chmod 600 "$STLS_CLIENT_FILE"

    # 9. 生成人类可读的信息文件
    cat > "$STLS_CLIENT_TXT" <<EOF
=========== ShadowTLS v3 配置信息 ===========
服务器地址: ${server_ip}
端口: ${port}
ShadowTLS 密码(UUID): ${uuid}
SS 密码: ${ss_password}
SS 加密方式: ${ss_method}
TLS 伪装域名: ${STLS_TLS_SERVER}

⚠️  ShadowTLS v3 客户端需要 sing-box 内核
客户端配置文件: ${STLS_CLIENT_FILE}
EOF
    chmod 600 "$STLS_CLIENT_TXT"

    export_json "shadowtls" "{\"protocol\":\"shadowtls\",\"server\":\"${server_ip}\",\"port\":${port},\"version\":3}"
    log_info "ShadowTLS v3 安装完成 port=${port}"

    echo ""
    echo -e "${GREEN}ShadowTLS v3 安装完成!${NC}"
    cat "$STLS_CLIENT_TXT"
}

# ============================================
# 卸载 ShadowTLS v3
# ============================================
uninstall_shadowtls() {
    log_info "开始卸载 ShadowTLS v3"
    echo -e "${BLUE}正在卸载 ShadowTLS v3...${NC}"

    systemctl stop "$STLS_SERVICE" 2>/dev/null || true
    systemctl disable "$STLS_SERVICE" 2>/dev/null || true
    rm -f "/etc/systemd/system/${STLS_SERVICE}.service"
    rm -rf "$STLS_CONFIG_DIR"
    systemctl daemon-reload

    mark_uninstalled shadowtls
    rm -f "${EXPORT_DIR}/shadowtls.json"
    uninstall_singbox_binary

    echo -e "${GREEN}ShadowTLS v3 已卸载${NC}"
}

# ============================================
# 升级 ShadowTLS v3
# ============================================
upgrade_shadowtls() {
    echo -e "${BLUE}正在升级 ShadowTLS v3...${NC}"

    local bak
    bak=$(backup_upgrade_context "shadowtls")
    cp -f "$STLS_CONFIG_FILE" "$bak/config.json" 2>/dev/null || true

    systemctl stop "$STLS_SERVICE" 2>/dev/null || true
    upgrade_singbox_binary || return 1

    systemctl start "$STLS_SERVICE"
    if ! systemctl is-active --quiet "$STLS_SERVICE"; then
        rollback_file_if_needed "$bak/config.json" "$STLS_CONFIG_FILE"
        log_error "升级后服务启动失败"
        return 1
    fi

    echo -e "${GREEN}ShadowTLS v3 升级完成!${NC}"
}

# ============================================
# 状态检查
# ============================================
status_shadowtls() {
    echo -e "${BLUE}=== ShadowTLS v3 状态 ===${NC}"

    if is_marked_installed shadowtls; then
        echo -e "${GREEN}✓ 已安装${NC}"
    else
        echo -e "${YELLOW}○ 未安装${NC}"
        return 1
    fi

    if systemctl is-active --quiet "$STLS_SERVICE" 2>/dev/null; then
        echo -e "${GREEN}✓ 服务运行中${NC}"
    else
        echo -e "${RED}✗ 服务未运行${NC}"
    fi

    if [[ -f "$STLS_CONFIG_FILE" ]]; then
        echo -e "${BLUE}配置信息:${NC}"
        grep -E '"listen_port"|"version"|"method"' "$STLS_CONFIG_FILE" 2>/dev/null || true
    fi

    if [[ -f "$STLS_CONFIG_FILE" ]]; then
        local port
        port=$(grep '"listen_port"' "$STLS_CONFIG_FILE" | head -1 | grep -oE '[0-9]+')
        if [[ -n "$port" ]] && ss -tuln 2>/dev/null | grep -q ":${port} "; then
            echo -e "${GREEN}✓ 端口 ${port} 正在监听${NC}"
        elif [[ -n "$port" ]]; then
            echo -e "${YELLOW}○ 端口 ${port} 未监听${NC}"
        fi
    fi
}

# 执行传入的命令
"$@"
