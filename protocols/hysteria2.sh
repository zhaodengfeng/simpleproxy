#!/bin/bash
# hysteria2.sh - Hysteria2 协议管理
# 支持端口跳跃和自定义域名

readonly MODULE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)"
source "${MODULE_DIR}/common.sh"
source "${MODULE_DIR}/logging.sh"

# 配置路径
readonly HY2_CONFIG_DIR="/etc/hysteria"
readonly HY2_CONFIG_FILE="${HY2_CONFIG_DIR}/config.yaml"
readonly HY2_CLIENT_FILE="${HY2_CONFIG_DIR}/hyclient.json"
readonly HY2_SERVICE="hysteria-server.service"

# ============================================
# 安装 Hysteria2
# ============================================
install_hysteria2() {
    log_info "开始安装 Hysteria2"
    echo -e "${BLUE}正在安装 Hysteria2...${NC}"
    
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
    
    # 安装 Hysteria
    if ! command -v hysteria >/dev/null 2>&1; then
        echo -e "${BLUE}未检测到 hysteria，正在安装...${NC}"
        run_remote_script "https://get.hy2.sh/" || return 1
    fi
    
    local hysteria_bin
    hysteria_bin=$(command -v hysteria)
    if [[ ! -x "$hysteria_bin" ]]; then
        echo -e "${RED}错误: hysteria 安装失败或不可执行${NC}"
        return 1
    fi
    echo -e "${GREEN}hysteria 版本: $(hysteria version 2>/dev/null | head -1)${NC}"
    
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
    
    if [[ "$use_domain" =~ ^[Yy]$ ]]; then
        read -p "请输入已解析到本机的域名: " hydomain
        if [[ -n "$hydomain" ]]; then
            hyserver="${hydomain}"
            
            # 申请 SSL 证书
            if apply_ssl "$hydomain" 2>/dev/null; then
                hyinsecure="0"
            else
                echo -e "${YELLOW}证书申请失败，将使用自签名证书${NC}"
            fi
        fi
    fi
    
    # 生成配置
    local listen_line="listen: :${hyport}"
    [[ -n "$hop_start" && -n "$hop_end" ]] && listen_line="listen: :${hyport},:${hop_start}-${hop_end}"
    
    local hop_config=""
    [[ -n "$hop_interval" ]] && hop_config="hopInterval: ${hop_interval}s"
    
    if [[ "$hyinsecure" == "0" && -n "$hydomain" ]]; then
        # 使用 Let's Encrypt 证书
        cat > "$HY2_CONFIG_FILE" <<EOF
${listen_line}
auth:
  type: password
  password: ${hypass}

masquerade:
  type: proxy
  proxy:
    url: https://www.microsoft.com
    rewriteHost: true

tls:
  cert: /etc/letsencrypt/live/${hydomain}/fullchain.pem
  key: /etc/letsencrypt/live/${hydomain}/privkey.pem
${hop_config}
EOF
    else
        # 使用自签名证书
        cat > "$HY2_CONFIG_FILE" <<EOF
${listen_line}
auth:
  type: password
  password: ${hypass}

masquerade:
  type: proxy
  proxy:
    url: https://www.microsoft.com
    rewriteHost: true

tls:
  cert: ${HY2_CONFIG_DIR}/server.crt
  key: ${HY2_CONFIG_DIR}/server.key
${hop_config}
EOF
        
        # 生成自签名证书 (有效期365天)
        openssl req -x509 -nodes -newkey ec:<(openssl ecparam -name prime256v1) \
            -keyout "${HY2_CONFIG_DIR}/server.key" -out "${HY2_CONFIG_DIR}/server.crt" \
            -subj "/CN=www.microsoft.com" -days 365
        
        chmod 644 "${HY2_CONFIG_DIR}/server.crt"
        chmod 600 "${HY2_CONFIG_DIR}/server.key"
    fi
    
    # 创建 systemd 服务
    cat > "/etc/systemd/system/${HY2_SERVICE}" <<EOF
[Unit]
Description=Hysteria Server
After=network.target

[Service]
Type=simple
ExecStart=${hysteria_bin} server -c ${HY2_CONFIG_FILE}
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable "$HY2_SERVICE"
    sleep 1
    systemctl start "$HY2_SERVICE"
    
    # 检查服务状态
    sleep 3
    if systemctl is-active --quiet "$HY2_SERVICE"; then
        echo -e "${GREEN}✓ Hysteria2 服务已成功启动${NC}"
    else
        echo -e "${RED}✗ Hysteria2 服务启动失败，正在重试...${NC}"
        systemctl daemon-reload
        sleep 1
        systemctl restart "$HY2_SERVICE"
        sleep 3
        if systemctl is-active --quiet "$HY2_SERVICE"; then
            echo -e "${GREEN}✓ Hysteria2 服务已成功启动${NC}"
        else
            echo -e "${RED}✗ Hysteria2 服务启动失败，请手动检查: journalctl -u ${HY2_SERVICE}${NC}"
        fi
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
    echo -e "${BLUE}正在升级 Hysteria2...${NC}"
    
    local bak
    bak=$(backup_upgrade_context "hysteria2")
    cp -f "$HY2_CONFIG_FILE" "$bak/config.yaml" 2>/dev/null || true
    cp -f "$(command -v hysteria)" "$bak/hysteria" 2>/dev/null || true
    
    systemctl stop "$HY2_SERVICE"
    
    run_remote_script "https://get.hy2.sh/" || {
        rollback_file_if_needed "$bak/config.yaml" "$HY2_CONFIG_FILE"
        rollback_file_if_needed "$bak/hysteria" "$(command -v hysteria)"
        return 1
    }
    
    systemctl start "$HY2_SERVICE"
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
    rm -f /usr/local/bin/hysteria
    rm -rf "$HY2_CONFIG_DIR"
    rm -f "/etc/systemd/system/${HY2_SERVICE}"
    
    mark_uninstalled hysteria2
    rm -f "$EXPORT_DIR/hysteria2.json"
    systemctl daemon-reload
    
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
        grep -E '^listen:|^  password:' "$HY2_CONFIG_FILE" | head -2 || true
    fi
}

# 执行传入的命令
"$@"
