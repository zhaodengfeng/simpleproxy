#!/bin/bash
# v2ray.sh - V2Ray + TLS + WebSocket 协议管理

MODULE_DIR="${MODULE_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)}"
source "${MODULE_DIR}/common.sh"
source "${MODULE_DIR}/logging.sh"

# 配置路径
readonly V2RAY_CONFIG="/usr/local/etc/xray/v2ray.json"
readonly V2RAY_CLIENT="/usr/local/etc/xray/v2client.json"
readonly V2RAY_SERVICE="xray-v2ray.service"

# ============================================
# 安装 V2Ray + TLS + WebSocket
# ============================================
install_v2ray() {
    log_info "开始安装 V2Ray + TLS + WebSocket"
    echo -e "${BLUE}正在安装 V2Ray + TLS + WebSocket...${NC}"
    
    # 域名输入 (从主脚本获取)
    echo -e "${YELLOW}提示: V2Ray 需要域名和 SSL 证书${NC}"
    read -p "请输入已解析到本机的域名: " DOMAIN
    
    if [[ -z "$DOMAIN" ]]; then
        echo -e "${RED}错误: 域名不能为空${NC}"
        return 1
    fi
    
    if ! validate_domain "$DOMAIN"; then
        echo -e "${RED}错误: 域名格式无效${NC}"
        return 1
    fi
    
    read -t 15 -p "请输入端口(回车或等待15秒默认为443): " GET_PORT
    GET_PORT=${GET_PORT:-443}
    
    if ! validate_port "$GET_PORT"; then
        echo -e "${RED}错误: 端口无效，使用默认端口 443${NC}"
        GET_PORT=443
    fi
    
    # 检查端口占用
    if netstat -ntlp 2>/dev/null | grep -q ":80 " || netstat -ntlp 2>/dev/null | grep -q ":$GET_PORT "; then
        echo -e "${YELLOW}警告: 80 或 ${GET_PORT} 端口被占用${NC}"
        read -p "是否继续? (y/n): " confirm
        [[ ! "$confirm" =~ ^[Yy]$ ]] && return 1
    fi
    
    # WebSocket 支持
    read -p "是否启用 WebSocket 支持? (y/n, 默认y): " use_ws
    use_ws=${use_ws:-y}
    
    local vport
    vport=$(gen_port 20000 65000)
    local vuuid
    vuuid=$(gen_uuid)
    local server_ip
    server_ip=$(get_public_ip)
    local vpath="/$(gen_random 8)"
    local use_nginx=true
    
    [[ "$use_ws" =~ ^[Nn]$ ]] && use_nginx=false && vport=$GET_PORT
    
    install_common_deps
    
    # 安装 Nginx
    if [[ "$use_nginx" == true ]]; then
        local os_type
        os_type=$(detect_os)
        if [[ "$os_type" == "debian" ]]; then
            apt-get install -y nginx
        else
            yum install -y nginx
        fi
        systemctl stop nginx 2>/dev/null || true
    fi
    
    # 申请 SSL 证书
    if ! source "${MODULE_DIR}/../simpleproxy.sh" >/dev/null 2>&1 || ! apply_ssl "$DOMAIN"; then
        echo -e "${RED}SSL 证书申请失败${NC}"
        return 1
    fi
    
    # 安装 Xray
    if ! command -v xray &> /dev/null; then
        echo -e "${BLUE}正在安装 Xray...${NC}"
        run_remote_script "https://github.com/XTLS/Xray-install/raw/main/install-release.sh" @ install || return 1
    fi
    
    mkdir -p /usr/local/etc/xray
    confirm_xray_overwrite "$V2RAY_CONFIG" || return 1
    
    if [[ "$use_nginx" == true ]]; then
        # WebSocket 模式
        cat > "$V2RAY_CONFIG" <<EOF
{
  "inbounds": [
    {
      "port": ${vport},
      "listen": "127.0.0.1",
      "protocol": "vmess",
      "settings": {
        "clients": [
          {
            "id": "${vuuid}",
            "alterId": 0
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "${vpath}"
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    }
  ]
}
EOF
        
        # Nginx 配置
        mkdir -p /etc/nginx/conf.d
        backup_file /etc/nginx/conf.d/simpleproxy.conf
        cat > /etc/nginx/conf.d/simpleproxy.conf <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN};
    location / {
        return 301 https://\$server_name\$request_uri;
    }
}

server {
    listen ${GET_PORT} ssl http2;
    listen [::]:${GET_PORT} ssl http2;
    server_name ${DOMAIN};
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:HIGH:!aNULL:!MD5:!RC4:!DHE;
    ssl_prefer_server_ciphers on;
    ssl_certificate /etc/letsencrypt/live/${DOMAIN}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${DOMAIN}/privkey.pem;

    location / {
        default_type text/plain;
        return 200 "Hello World!";
    }

    location ${vpath} {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:${vport};
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
        proxy_read_timeout 86400;
    }
}
EOF
        
        if ! nginx -t; then
            echo -e "${RED}Nginx 配置校验失败${NC}"
            return 1
        fi
        
        systemctl daemon-reload
        systemctl enable nginx.service
        sleep 1
        systemctl restart nginx.service
    else
        # 直连 TLS 模式
        cat > "$V2RAY_CONFIG" <<EOF
{
  "inbounds": [
    {
      "port": ${vport},
      "protocol": "vmess",
      "settings": {
        "clients": [
          {
            "id": "${vuuid}",
            "alterId": 0
          }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "/usr/local/etc/xray/certs/${DOMAIN}.crt",
              "keyFile": "/usr/local/etc/xray/certs/${DOMAIN}.key"
            }
          ]
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    }
  ]
}
EOF
    fi
    
    # 配置服务
    systemctl daemon-reload
    ensure_xray_service_unit "xray-v2ray" "$V2RAY_CONFIG"
    systemctl enable "$V2RAY_SERVICE"
    
    sync
    sleep 1
    
    # 验证配置
    echo -e "${BLUE}正在验证 Xray 配置...${NC}"
    local test_output
    test_output=$(xray -test -config "$V2RAY_CONFIG" 2>&1)
    if echo "$test_output" | grep -q "Configuration OK"; then
        echo -e "${GREEN}✓ 配置验证通过${NC}"
    else
        echo -e "${RED}✗ 配置验证失败${NC}"
        echo "$test_output" | head -5
        return 1
    fi
    
    # 启动服务
    echo -e "${BLUE}正在启动 Xray 服务...${NC}"
    systemctl start "$V2RAY_SERVICE"
    sleep 5
    
    if systemctl is-active --quiet "$V2RAY_SERVICE"; then
        echo -e "${GREEN}✓ V2Ray 服务已成功启动${NC}"
    else
        echo -e "${RED}✗ V2Ray 服务启动失败${NC}"
        echo -e "${YELLOW}查看日志: journalctl -u ${V2RAY_SERVICE} -n 20${NC}"
        return 1
    fi
    
    # 生成客户端配置
    local ws_info=""
    local vmess_config=""
    
    if [[ "$use_nginx" == true ]]; then
        ws_info="WebSocket 路径: ${vpath}"
        vmess_config='{
  "v": "2",
  "ps": "V2Ray-'"${DOMAIN}"'",
  "add": "'"${DOMAIN}"'",
  "port": "'"${GET_PORT}"'",
  "id": "'"${vuuid}"'",
  "aid": "0",
  "scy": "auto",
  "net": "ws",
  "type": "none",
  "host": "'"${DOMAIN}"'",
  "path": "'"${vpath}"'",
  "tls": "tls"
}'
    else
        vmess_config='{
  "v": "2",
  "ps": "V2Ray-'"${DOMAIN}"'",
  "add": "'"${DOMAIN}"'",
  "port": "'"${GET_PORT}"'",
  "id": "'"${vuuid}"'",
  "aid": "0",
  "scy": "auto",
  "net": "tcp",
  "type": "none",
  "host": "",
  "path": "",
  "tls": "tls"
}'
    fi
    
    local vmess_link="vmess://$(echo -n "$vmess_config" | base64 -w 0)"
    
    cat > "$V2RAY_CLIENT" <<EOF
=========== V2Ray 配置信息 ===========
协议: VMess
地址: ${DOMAIN}
端口: ${GET_PORT}
UUID: ${vuuid}
额外ID: 0
传输: $([[ "$use_nginx" == true ]] && echo "WebSocket" || echo "TCP")
TLS: 启用
${ws_info}

${vmess_link}
EOF
    chmod 600 "$V2RAY_CLIENT"
    
    mark_installed v2ray
    export_json "v2ray" "{\"protocol\":\"vmess\",\"server\":\"${DOMAIN}\",\"port\":${GET_PORT},\"client\":\"${V2RAY_CLIENT}\"}"
    check_firewall_port "${GET_PORT}" tcp
    
    log_info "V2Ray 安装完成 domain=${DOMAIN} port=${GET_PORT}"
    
    echo ""
    echo -e "${GREEN}V2Ray 安装完成!${NC}"
    cat "$V2RAY_CLIENT"
}

# ============================================
# 升级 V2Ray
# ============================================
upgrade_v2ray() {
    echo -e "${BLUE}正在升级 V2Ray...${NC}"
    
    local bak
    bak=$(backup_upgrade_context "v2ray")
    cp -f "$V2RAY_CONFIG" "$bak/v2ray.json" 2>/dev/null || true
    
    run_remote_script "https://github.com/XTLS/Xray-install/raw/main/install-release.sh" @ install || {
        rollback_file_if_needed "$bak/v2ray.json" "$V2RAY_CONFIG"
        return 1
    }
    
    systemctl restart "$V2RAY_SERVICE"
    echo -e "${GREEN}V2Ray 升级完成!${NC}"
}

# ============================================
# 卸载 V2Ray
# ============================================
uninstall_v2ray() {
    log_info "开始卸载 V2Ray"
    echo -e "${BLUE}正在卸载 V2Ray...${NC}"
    
    systemctl stop "$V2RAY_SERVICE" 2>/dev/null || true
    systemctl disable "$V2RAY_SERVICE" 2>/dev/null || true
    rm -f "/etc/systemd/system/${V2RAY_SERVICE}"
    rm -f "$V2RAY_CONFIG"
    rm -f "$V2RAY_CLIENT"
    
    mark_uninstalled v2ray
    rm -f "$EXPORT_DIR/v2ray.json"
    systemctl daemon-reload
    
    echo -e "${GREEN}V2Ray 已卸载${NC}"
}

# ============================================
# 状态检查
# ============================================
status_v2ray() {
    echo -e "${BLUE}=== V2Ray 状态 ===${NC}"
    
    if is_marked_installed v2ray; then
        echo -e "${GREEN}✓ 已安装${NC}"
    else
        echo -e "${YELLOW}○ 未安装${NC}"
        return 1
    fi
    
    if systemctl is-active --quiet "$V2RAY_SERVICE" 2>/dev/null; then
        echo -e "${GREEN}✓ 服务运行中${NC}"
    else
        echo -e "${RED}✗ 服务未运行${NC}"
    fi
    
    if [[ -f "$V2RAY_CONFIG" ]]; then
        echo -e "${BLUE}配置信息:${NC}"
        grep -E '"port"|"protocol"|"network"' "$V2RAY_CONFIG" | head -3 || true
    fi
}

# 执行传入的命令
"$@"
