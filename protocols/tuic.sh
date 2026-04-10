#!/bin/bash
# tuic.sh - TUIC V5 协议管理 (基于 sing-box)
# TUIC V5 基于 QUIC (UDP)，支持双重认证 (UUID + password)
# 包含安装、卸载、升级、状态检查功能

# 加载依赖
MODULE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)"
source "${MODULE_DIR}/common.sh"
source "${MODULE_DIR}/logging.sh"
source "${MODULE_DIR}/singbox.sh"

# 配置路径
readonly TUIC_CONFIG_DIR="/etc/sing-box/tuic"
readonly TUIC_CONFIG_FILE="${TUIC_CONFIG_DIR}/config.json"
readonly TUIC_CLIENT_FILE="${TUIC_CONFIG_DIR}/client.txt"
readonly TUIC_SERVICE="singbox-tuic"

# ============================================
# 安装 TUIC V5
# ============================================
install_tuic() {
    log_info "开始安装 TUIC V5"
    echo -e "${BLUE}正在安装 TUIC V5 (sing-box)...${NC}"

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

    # 2. 拥塞控制算法选择
    echo ""
    echo -e "${YELLOW}请选择拥塞控制算法:${NC}"
    echo " 1. bbr (默认，推荐)"
    echo " 2. cubic"
    echo " 3. new_reno"
    read -t 15 -p "请输入数字(回车或等待15秒使用默认): " cc_choice || true

    local congestion_control="bbr"
    case "${cc_choice:-1}" in
        1|"") congestion_control="bbr" ;;
        2)    congestion_control="cubic" ;;
        3)    congestion_control="new_reno" ;;
        *)    congestion_control="bbr" ;;
    esac
    echo -e "${GREEN}使用拥塞控制: ${congestion_control}${NC}"

    # 3. 生成双重认证凭据
    local uuid
    uuid=$(gen_uuid)
    local password
    password=$(gen_uuid)
    local tls_server="$SINGBOX_DEFAULT_TLS_SERVER"

    # 4. 安装 sing-box + 自签证书
    install_singbox_binary || return 1
    generate_self_signed_cert "$tls_server"

    # 5. 生成服务端配置
    mkdir -p "$TUIC_CONFIG_DIR"
    cat > "$TUIC_CONFIG_FILE" <<EOF
{
    "inbounds": [
        {
            "type": "tuic",
            "tag": "tuic-in",
            "listen": "::",
            "listen_port": ${port},
            "users": [
                {
                    "uuid": "${uuid}",
                    "password": "${password}"
                }
            ],
            "congestion_control": "${congestion_control}",
            "zero_rtt_handshake": false,
            "tls": {
                "enabled": true,
                "alpn": [
                    "h3"
                ],
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

    # 6. 创建服务并启动
    create_singbox_service "$TUIC_SERVICE" "$TUIC_CONFIG_FILE"
    if ! start_singbox_service "$TUIC_SERVICE"; then
        return 1
    fi

    # 7. 防火墙 (TUIC 使用 UDP!)
    check_firewall_port "$port" udp

    # 8. 标记安装
    mark_installed tuic

    # 9. 生成分享链接
    local server_ip
    server_ip=$(get_public_ip)
    local fingerprint
    fingerprint=$(get_cert_fingerprint_sha256)
    local share_link="tuic://${uuid}:${password}@${server_ip}:${port}?sni=${tls_server}&alpn=h3&congestion_control=${congestion_control}&udp_relay_mode=native&insecure=1&allowInsecure=1#TUIC-V5"

    cat > "$TUIC_CLIENT_FILE" <<EOF
=========== TUIC V5 配置信息 ===========
服务器地址: ${server_ip}
端口: ${port} (UDP)
UUID: ${uuid}
密码: ${password}
拥塞控制: ${congestion_control}
TLS 域名: ${tls_server}
证书指纹: ${fingerprint}

分享链接 (通用):
${share_link}

Clash Meta 配置片段:
- name: "TUIC-V5"
  type: tuic
  server: ${server_ip}
  port: ${port}
  uuid: ${uuid}
  password: ${password}
  alpn: [h3]
  reduce-rtt: true
  request-timeout: 8000
  udp-relay-mode: native
  congestion-controller: ${congestion_control}
  sni: ${tls_server}
  skip-cert-verify: false
  fingerprint: ${fingerprint}
EOF
    chmod 600 "$TUIC_CLIENT_FILE"

    export_json "tuic" "{\"protocol\":\"tuic\",\"server\":\"${server_ip}\",\"port\":${port},\"congestion\":\"${congestion_control}\"}"
    log_info "TUIC V5 安装完成 port=${port} (UDP)"

    echo ""
    echo -e "${GREEN}TUIC V5 安装完成!${NC}"
    cat "$TUIC_CLIENT_FILE"
}

# ============================================
# 卸载 TUIC V5
# ============================================
uninstall_tuic() {
    log_info "开始卸载 TUIC V5"
    echo -e "${BLUE}正在卸载 TUIC V5...${NC}"

    systemctl stop "$TUIC_SERVICE" 2>/dev/null || true
    systemctl disable "$TUIC_SERVICE" 2>/dev/null || true
    rm -f "/etc/systemd/system/${TUIC_SERVICE}.service"
    rm -rf "$TUIC_CONFIG_DIR"
    systemctl daemon-reload

    mark_uninstalled tuic
    rm -f "${EXPORT_DIR}/tuic.json"
    uninstall_singbox_binary

    echo -e "${GREEN}TUIC V5 已卸载${NC}"
}

# ============================================
# 升级 TUIC V5
# ============================================
upgrade_tuic() {
    echo -e "${BLUE}正在升级 TUIC V5...${NC}"

    local bak
    bak=$(backup_upgrade_context "tuic")
    cp -f "$TUIC_CONFIG_FILE" "$bak/config.json" 2>/dev/null || true

    systemctl stop "$TUIC_SERVICE" 2>/dev/null || true
    upgrade_singbox_binary || return 1

    systemctl start "$TUIC_SERVICE"
    if ! systemctl is-active --quiet "$TUIC_SERVICE"; then
        rollback_file_if_needed "$bak/config.json" "$TUIC_CONFIG_FILE"
        log_error "升级后服务启动失败"
        return 1
    fi

    echo -e "${GREEN}TUIC V5 升级完成!${NC}"
}

# ============================================
# 状态检查
# ============================================
status_tuic() {
    echo -e "${BLUE}=== TUIC V5 状态 ===${NC}"

    if is_marked_installed tuic; then
        echo -e "${GREEN}✓ 已安装${NC}"
    else
        echo -e "${YELLOW}○ 未安装${NC}"
        return 1
    fi

    if systemctl is-active --quiet "$TUIC_SERVICE" 2>/dev/null; then
        echo -e "${GREEN}✓ 服务运行中${NC}"
    else
        echo -e "${RED}✗ 服务未运行${NC}"
    fi

    if [[ -f "$TUIC_CONFIG_FILE" ]]; then
        echo -e "${BLUE}配置信息:${NC}"
        grep -E '"listen_port"|"congestion_control"' "$TUIC_CONFIG_FILE" || true
    fi

    if [[ -f "$TUIC_CONFIG_FILE" ]]; then
        local port
        port=$(grep '"listen_port"' "$TUIC_CONFIG_FILE" | head -1 | grep -oE '[0-9]+')
        if [[ -n "$port" ]] && ss -tuln 2>/dev/null | grep -q ":${port} "; then
            echo -e "${GREEN}✓ 端口 ${port} 正在监听 (UDP)${NC}"
        elif [[ -n "$port" ]]; then
            echo -e "${YELLOW}○ 端口 ${port} 未监听${NC}"
        fi
    fi
}

# 执行传入的命令
"$@"
