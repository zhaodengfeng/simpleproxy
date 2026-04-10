#!/bin/bash
# anytls.sh - AnyTLS 协议管理 (基于 sing-box)
# AnyTLS 是 sing-box 原生协议，配置简洁
# 包含安装、卸载、升级、状态检查功能

# 加载依赖
MODULE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)"
source "${MODULE_DIR}/common.sh"
source "${MODULE_DIR}/logging.sh"
source "${MODULE_DIR}/singbox.sh"

# 配置路径
readonly ATLS_CONFIG_DIR="/etc/sing-box/anytls"
readonly ATLS_CONFIG_FILE="${ATLS_CONFIG_DIR}/config.json"
readonly ATLS_CLIENT_FILE="${ATLS_CONFIG_DIR}/client.txt"
readonly ATLS_SERVICE="singbox-anytls"

# ============================================
# 安装 AnyTLS
# ============================================
install_anytls() {
    log_info "开始安装 AnyTLS"
    echo -e "${BLUE}正在安装 AnyTLS (sing-box)...${NC}"

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

    # 2. 生成密码
    local password
    password=$(gen_uuid)
    local tls_server="$SINGBOX_DEFAULT_TLS_SERVER"

    # 3. 安装 sing-box + 生成自签证书
    install_singbox_binary || return 1
    generate_self_signed_cert "$tls_server"

    # 4. 生成服务端配置
    mkdir -p "$ATLS_CONFIG_DIR"
    cat > "$ATLS_CONFIG_FILE" <<EOF
{
    "inbounds": [
        {
            "type": "anytls",
            "tag": "anytls-in",
            "listen": "::",
            "listen_port": ${port},
            "users": [
                {
                    "password": "${password}"
                }
            ],
            "padding_scheme": [],
            "tls": {
                "enabled": true,
                "certificate_path": "${SINGBOX_CERT_DIR}/cert.pem",
                "key_path": "${SINGBOX_CERT_DIR}/private.key"
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
    create_singbox_service "$ATLS_SERVICE" "$ATLS_CONFIG_FILE"
    if ! start_singbox_service "$ATLS_SERVICE"; then
        return 1
    fi

    # 6. 防火墙
    check_firewall_port "$port" tcp

    # 7. 标记安装
    mark_installed anytls

    # 8. 生成分享链接
    local server_ip
    server_ip=$(get_public_ip)
    local fingerprint
    fingerprint=$(get_cert_fingerprint_sha256)
    local share_link="anytls://${password}@${server_ip}:${port}?security=tls&sni=${tls_server}&fp=firefox&insecure=1&allowInsecure=1#AnyTLS"

    cat > "$ATLS_CLIENT_FILE" <<EOF
=========== AnyTLS 配置信息 ===========
服务器地址: ${server_ip}
端口: ${port}
密码: ${password}
TLS 域名: ${tls_server}
证书指纹: ${fingerprint}

分享链接 (Clash Meta / mihomo):
${share_link}

Clash Meta 配置片段:
- name: "AnyTLS"
  type: anytls
  server: ${server_ip}
  port: ${port}
  password: ${password}
  client-fingerprint: firefox
  udp: true
  sni: ${tls_server}
  skip-cert-verify: false
  fingerprint: ${fingerprint}
EOF
    chmod 600 "$ATLS_CLIENT_FILE"

    export_json "anytls" "{\"protocol\":\"anytls\",\"server\":\"${server_ip}\",\"port\":${port}}"
    log_info "AnyTLS 安装完成 port=${port}"

    echo ""
    echo -e "${GREEN}AnyTLS 安装完成!${NC}"
    cat "$ATLS_CLIENT_FILE"
}

# ============================================
# 卸载 AnyTLS
# ============================================
uninstall_anytls() {
    log_info "开始卸载 AnyTLS"
    echo -e "${BLUE}正在卸载 AnyTLS...${NC}"

    systemctl stop "$ATLS_SERVICE" 2>/dev/null || true
    systemctl disable "$ATLS_SERVICE" 2>/dev/null || true
    rm -f "/etc/systemd/system/${ATLS_SERVICE}.service"
    rm -rf "$ATLS_CONFIG_DIR"
    systemctl daemon-reload

    mark_uninstalled anytls
    rm -f "${EXPORT_DIR}/anytls.json"
    uninstall_singbox_binary

    echo -e "${GREEN}AnyTLS 已卸载${NC}"
}

# ============================================
# 升级 AnyTLS
# ============================================
upgrade_anytls() {
    echo -e "${BLUE}正在升级 AnyTLS...${NC}"

    local bak
    bak=$(backup_upgrade_context "anytls")
    cp -f "$ATLS_CONFIG_FILE" "$bak/config.json" 2>/dev/null || true

    systemctl stop "$ATLS_SERVICE" 2>/dev/null || true
    upgrade_singbox_binary || return 1

    systemctl start "$ATLS_SERVICE"
    if ! systemctl is-active --quiet "$ATLS_SERVICE"; then
        rollback_file_if_needed "$bak/config.json" "$ATLS_CONFIG_FILE"
        log_error "升级后服务启动失败"
        return 1
    fi

    echo -e "${GREEN}AnyTLS 升级完成!${NC}"
}

# ============================================
# 状态检查
# ============================================
status_anytls() {
    echo -e "${BLUE}=== AnyTLS 状态 ===${NC}"

    if is_marked_installed anytls; then
        echo -e "${GREEN}✓ 已安装${NC}"
    else
        echo -e "${YELLOW}○ 未安装${NC}"
        return 1
    fi

    if systemctl is-active --quiet "$ATLS_SERVICE" 2>/dev/null; then
        echo -e "${GREEN}✓ 服务运行中${NC}"
    else
        echo -e "${RED}✗ 服务未运行${NC}"
    fi

    if [[ -f "$ATLS_CONFIG_FILE" ]]; then
        echo -e "${BLUE}配置信息:${NC}"
        grep -E '"listen_port"|"type"' "$ATLS_CONFIG_FILE" | head -3 || true
    fi

    if [[ -f "$ATLS_CONFIG_FILE" ]]; then
        local port
        port=$(grep '"listen_port"' "$ATLS_CONFIG_FILE" | head -1 | grep -oE '[0-9]+')
        if [[ -n "$port" ]] && ss -tuln 2>/dev/null | grep -q ":${port} "; then
            echo -e "${GREEN}✓ 端口 ${port} 正在监听${NC}"
        elif [[ -n "$port" ]]; then
            echo -e "${YELLOW}○ 端口 ${port} 未监听${NC}"
        fi
    fi
}

# 执行传入的命令
"$@"
