#!/bin/bash
# hysteria2.sh - Hysteria2 协议管理 (基于 sing-box)
# 支持端口跳跃和自定义域名

MODULE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)"
source "${MODULE_DIR}/common.sh"
source "${MODULE_DIR}/logging.sh"
source "${MODULE_DIR}/singbox.sh"

# 配置路径
readonly HY2_CONFIG_DIR="/etc/sing-box/hysteria2"
readonly HY2_CONFIG_FILE="${HY2_CONFIG_DIR}/config.json"
readonly HY2_CLIENT_FILE="${HY2_CONFIG_DIR}/client.txt"
readonly HY2_SERVICE="singbox-hysteria2"

# ============================================
# 安装 Hysteria2
# ============================================
install_hysteria2() {
    log_info "开始安装 Hysteria2 (sing-box)"
    echo -e "${BLUE}正在安装 Hysteria2 (sing-box)...${NC}"

    # 请求端口
    echo ""
    read -t 15 -p "请输入端口号(回车或等待15秒随机生成): " hyport_input || true
    local hyport
    if [[ -n "$hyport_input" ]]; then
        hyport=$hyport_input
    else
        hyport=$(gen_port 20000 65000)
        echo -e "${GREEN}使用随机端口: ${hyport}${NC}"
    fi

    # 验证端口
    if ! validate_port "$hyport"; then
        hyport=$(gen_port 20000 65000)
        echo -e "${YELLOW}端口无效，使用随机端口: ${hyport}${NC}"
    fi

    # 检查端口占用
    if has_listening_port "$hyport"; then
        echo -e "${RED}错误: 端口 ${hyport} 已被占用${NC}"
        return 1
    fi

    # 安装 sing-box
    install_singbox_binary || return 1

    mkdir -p "$HY2_CONFIG_DIR"

    # 端口跳跃配置
    echo ""
    read -p "是否启用端口跳跃(Port Hopping)? (y/n, 默认n): " use_hop
    local hop_start=""
    local hop_end=""
    local hop_interval=""

    if [[ "$use_hop" =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}端口跳跃配置:${NC}"

        read -t 15 -p "请输入起始端口 (默认: $((hyport+1))): " hop_start_input || true
        hop_start=${hop_start_input:-$((hyport+1))}

        read -t 15 -p "请输入结束端口 (默认: $((hyport+100))): " hop_end_input || true
        hop_end=${hop_end_input:-$((hyport+100))}

        read -t 15 -p "请输入跳跃间隔秒数 (默认: 30): " hop_interval_input || true
        hop_interval=${hop_interval_input:-30}

        echo -e "${GREEN}端口跳跃: ${hop_start}-${hop_end}, 间隔 ${hop_interval} 秒${NC}"

        # 开放防火墙端口范围
        open_firewall_port_range "$hop_start" "$hop_end" udp
    fi

    # 域名配置
    read -p "是否使用自己的域名? (y/n, 默认n): " use_domain

    local hypass
    hypass=$(gen_random 32)
    local server_ip
    server_ip=$(get_public_ip)
    local hyserver="${server_ip}"
    local hydomain=""
    local hyinsecure="1"
    local tls_cert=""
    local tls_key=""
    local tls_sni="www.microsoft.com"

    if [[ "$use_domain" =~ ^[Yy]$ ]]; then
        read -p "请输入已解析到本机的域名: " hydomain
        if [[ -n "$hydomain" ]]; then
            hyserver="${hydomain}"

            # 申请 SSL 证书
            if apply_ssl "$hydomain" 2>/dev/null; then
                hyinsecure="0"
                tls_cert="/etc/letsencrypt/live/${hydomain}/fullchain.pem"
                tls_key="/etc/letsencrypt/live/${hydomain}/privkey.pem"
                tls_sni="${hydomain}"
            else
                echo -e "${YELLOW}证书申请失败，将使用自签名证书${NC}"
                generate_self_signed_cert "www.microsoft.com"
                tls_cert="${SINGBOX_CERT_DIR}/cert.pem"
                tls_key="${SINGBOX_CERT_DIR}/private.key"
            fi
        fi
    else
        generate_self_signed_cert "www.microsoft.com"
        tls_cert="${SINGBOX_CERT_DIR}/cert.pem"
        tls_key="${SINGBOX_CERT_DIR}/private.key"
    fi

    # 配置 iptables 端口跳跃转发 (与后端无关)
    if [[ -n "$hop_start" && -n "$hop_end" ]]; then
        echo -e "${GREEN}配置 iptables 端口跳跃转发: ${hop_start}-${hop_end}/udp -> :${hyport}${NC}"
        iptables -t nat -A PREROUTING -p udp --dport "${hop_start}:${hop_end}" -j REDIRECT --to-ports "${hyport}"
        ip6tables -t nat -A PREROUTING -p udp --dport "${hop_start}:${hop_end}" -j REDIRECT --to-ports "${hyport}" 2>/dev/null || true
        # 持久化
        if command -v netfilter-persistent &>/dev/null; then
            netfilter-persistent save
        elif command -v iptables-save &>/dev/null; then
            iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
            ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true
        fi
    fi

    # 生成 sing-box JSON 配置
    cat > "$HY2_CONFIG_FILE" <<EOF
{
    "inbounds": [
        {
            "type": "hysteria2",
            "tag": "hysteria2-in",
            "listen": "::",
            "listen_port": ${hyport},
            "users": [
                {
                    "password": "${hypass}"
                }
            ],
            "masquerade": {
                "type": "proxy",
                "url": "https://www.microsoft.com",
                "rewrite_host": true
            },
            "tls": {
                "enabled": true,
                "server_name": "${tls_sni}",
                "certificate": "${tls_cert}",
                "key": "${tls_key}"
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

    # 创建服务并启动
    create_singbox_service "$HY2_SERVICE" "$HY2_CONFIG_FILE"
    if ! start_singbox_service "$HY2_SERVICE"; then
        return 1
    fi

    # 生成客户端配置
    local hop_info=""
    local hy_query=""

    [[ -n "$hop_start" && -n "$hop_end" ]] && hop_info="端口跳跃: ${hop_start}-${hop_end} (间隔 ${hop_interval}秒)"
    [[ "$hyinsecure" == "1" ]] && hy_query="insecure=1"

    if [[ -n "$hop_start" && -n "$hop_end" ]]; then
        [[ -n "$hy_query" ]] && hy_query="${hy_query}&"
        hy_query="${hy_query}hop=${hop_start}-${hop_end}&hop_interval=${hop_interval}"
    fi

    local hy_link="hysteria2://${hypass}@${hyserver}:${hyport}"
    [[ -n "$hy_query" ]] && hy_link="${hy_link}?${hy_query}"

    cat > "$HY2_CLIENT_FILE" <<EOF
=========== Hysteria2 配置信息 ===========
服务器地址: ${hyserver}:${hyport}
密码: ${hypass}
$( [[ -n "$hydomain" && "$hyinsecure" == "0" ]] && echo "TLS: 已启用 (Let's Encrypt)" || echo "TLS: 自签名证书 (需跳过验证)" )
${hop_info}

${hy_link}#Hysteria2
EOF
    chmod 600 "$HY2_CLIENT_FILE"

    mark_installed hysteria2
    export_json "hysteria2" "{\"protocol\":\"hysteria2\",\"server\":\"${hyserver}\",\"port\":${hyport},\"client\":\"${HY2_CLIENT_FILE}\"}"
    check_firewall_port "${hyport}" udp
    [[ -n "$hop_start" ]] && check_firewall_port "${hop_start}" udp
    [[ -n "$hop_end" ]] && check_firewall_port "${hop_end}" udp

    log_info "Hysteria2 安装完成 port=${hyport} domain=${hydomain:-none}"

    echo ""
    echo -e "${GREEN}Hysteria2 安装完成!${NC}"
    cat "$HY2_CLIENT_FILE"
}

# ============================================
# 升级 Hysteria2
# ============================================
upgrade_hysteria2() {
    echo -e "${BLUE}正在升级 Hysteria2 (sing-box)...${NC}"

    local bak
    bak=$(backup_upgrade_context "hysteria2")
    cp -f "$HY2_CONFIG_FILE" "$bak/config.json" 2>/dev/null || true

    systemctl stop "$HY2_SERVICE" 2>/dev/null || true
    upgrade_singbox_binary || return 1

    if ! start_singbox_service "$HY2_SERVICE"; then
        rollback_file_if_needed "$bak/config.json" "$HY2_CONFIG_FILE"
        return 1
    fi

    echo -e "${GREEN}Hysteria2 升级完成!${NC}"
}

# ============================================
# 卸载 Hysteria2
# ============================================
uninstall_hysteria2() {
    log_info "开始卸载 Hysteria2"
    echo -e "${BLUE}正在卸载 Hysteria2...${NC}"

    systemctl stop "$HY2_SERVICE" 2>/dev/null || true
    systemctl disable "$HY2_SERVICE" 2>/dev/null || true

    # 清理端口跳跃 iptables 规则
    if [[ -f "$HY2_CONFIG_FILE" ]]; then
        local hyport
        hyport=$(grep '"listen_port"' "$HY2_CONFIG_FILE" 2>/dev/null | grep -oE '[0-9]+' | head -1)
        if [[ -n "$hyport" ]]; then
            # 删除所有指向该端口的 PREROUTING REDIRECT 规则
            while iptables -t nat -D PREROUTING -p udp -j REDIRECT --to-ports "$hyport" 2>/dev/null; do :; done
            while ip6tables -t nat -D PREROUTING -p udp -j REDIRECT --to-ports "$hyport" 2>/dev/null; do :; done
            # 持久化
            if command -v netfilter-persistent &>/dev/null; then
                netfilter-persistent save 2>/dev/null || true
            elif command -v iptables-save &>/dev/null; then
                iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
                ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true
            fi
        fi
    fi

    # 清理旧版官方 hysteria 残留（若存在）
    systemctl stop hysteria-server.service 2>/dev/null || true
    systemctl disable hysteria-server.service 2>/dev/null || true
    rm -f /usr/local/bin/hysteria
    rm -rf /etc/hysteria
    rm -f /etc/systemd/system/hysteria-server.service

    rm -rf "$HY2_CONFIG_DIR"
    rm -f "/etc/systemd/system/${HY2_SERVICE}.service"

    mark_uninstalled hysteria2
    rm -f "$EXPORT_DIR/hysteria2.json"
    systemctl daemon-reload
    uninstall_singbox_binary

    echo -e "${GREEN}Hysteria2 已卸载${NC}"
}

# ============================================
# 状态检查
# ============================================
status_hysteria2() {
    echo -e "${BLUE}=== Hysteria2 状态 ===${NC}"

    if is_marked_installed hysteria2; then
        echo -e "${GREEN}✓ 已安装${NC}"
    else
        echo -e "${YELLOW}○ 未安装${NC}"
        return 1
    fi

    if systemctl is-active --quiet "$HY2_SERVICE" 2>/dev/null; then
        echo -e "${GREEN}✓ 服务运行中${NC}"
    else
        echo -e "${RED}✗ 服务未运行${NC}"
    fi

    if [[ -f "$HY2_CONFIG_FILE" ]]; then
        echo -e "${BLUE}配置信息:${NC}"
        grep -E '"listen_port"|"type"' "$HY2_CONFIG_FILE" | head -3 || true
    fi

    if [[ -f "$HY2_CONFIG_FILE" ]]; then
        local port
        port=$(grep '"listen_port"' "$HY2_CONFIG_FILE" | head -1 | grep -oE '[0-9]+')
        if [[ -n "$port" ]] && ss -tuln 2>/dev/null | grep -q ":${port} "; then
            echo -e "${GREEN}✓ 端口 ${port} 正在监听${NC}"
        elif [[ -n "$port" ]]; then
            echo -e "${YELLOW}○ 端口 ${port} 未监听${NC}"
        fi
    fi
}

# 执行传入的命令
"$@"
