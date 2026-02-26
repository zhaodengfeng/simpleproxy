#!/bin/bash
# reality.sh - Reality (Xray) 协议管理
# 支持 Reality 模式和 TLS 模式

MODULE_DIR="${MODULE_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)}"
source "${MODULE_DIR}/common.sh"
source "${MODULE_DIR}/logging.sh"

# 配置路径
readonly REALITY_CONFIG="/usr/local/etc/xray/reality.json"
readonly REALITY_CLIENT="/usr/local/etc/xray/reclient.json"
readonly REALITY_SERVICE="xray-reality.service"

# ============================================
# 安装 Reality
# ============================================
install_reality() {
    log_info "开始安装 Reality"
    echo -e "${BLUE}正在安装 Reality...${NC}"
    
    # 请求端口
    echo ""
    read -t 15 -p "请输入端口号(回车或等待15秒随机生成): " rport_input || true
    local rport
    if [[ -n "$rport_input" ]]; then
        rport=$rport_input
    else
        rport=$(gen_port 20000 65000)
        echo -e "${GREEN}使用随机端口: ${rport}${NC}"
    fi
    
    # 验证端口
    if ! validate_port "$rport"; then
        rport=$(gen_port 20000 65000)
        echo -e "${YELLOW}端口无效，使用随机端口: ${rport}${NC}"
    fi
    
    # 检查端口占用
    if netstat -ntlp 2>/dev/null | grep -q ":$rport "; then
        echo -e "${RED}错误: 端口 ${rport} 已被占用${NC}"
        return 1
    fi
    
    local ruuid
    ruuid=$(gen_uuid)
    local rshortid
    rshortid=$(gen_random 8)
    local server_ip
    server_ip=$(get_public_ip)
    local rsni="www.microsoft.com"
    local rdomain=""
    local client_sni="${rsni}"
    local xray_installed=false
    
    # 询问是否使用自定义域名 (TLS 模式)
    read -p "是否使用自己的域名(开启TLS模式)? (y/n, 默认n): " use_domain
    if [[ "$use_domain" =~ ^[Yy]$ ]]; then
        read -p "请输入已解析到本机的域名: " rdomain
        if [[ -n "$rdomain" ]]; then
            echo -e "${BLUE}为域名 ${rdomain} 申请证书...${NC}"
            if ! apply_ssl "$rdomain"; then
                echo -e "${YELLOW}证书申请失败，将使用Reality模式${NC}"
                rdomain=""
            fi
        fi
    fi
    
    # 安装 Xray (如果未安装)
    if ! command -v xray &> /dev/null; then
        echo -e "${BLUE}正在安装 Xray...${NC}"
        run_remote_script "https://github.com/XTLS/Xray-install/raw/main/install-release.sh" @ install || return 1
        xray_installed=true
    fi
    
    export PATH="/usr/local/bin:$PATH"
    
    # 等待 Xray 可用
    local retry_count=0
    while ! command -v xray &> /dev/null && [[ $retry_count -lt 5 ]]; do
        sleep 1
        retry_count=$((retry_count + 1))
    done
    
    if ! command -v xray &> /dev/null; then
        echo -e "${RED}错误: Xray 安装失败或命令不可用${NC}"
        return 1
    fi
    
    echo -e "${GREEN}Xray 已安装，版本: $(xray version | head -1)${NC}"
    
    # 生成 X25519 密钥对
    echo -e "${BLUE}生成 X25519 密钥对...${NC}"
    local key_output
    key_output=$(xray x25519 2>/dev/null)
    
    if [[ -z "$key_output" ]]; then
        echo -e "${RED}错误: Xray x25519 命令无输出${NC}"
        return 1
    fi
    
    local rprivatekey
    rprivatekey=$(echo "$key_output" | grep "PrivateKey:" | awk '{print $2}' | tr -d '[:space:]')
    local rpublickey
    rpublickey=$(echo "$key_output" | grep -E "PublicKey:|Password:" | head -1 | awk '{print $2}' | tr -d '[:space:]')
    
    echo -e "${BLUE}私钥长度: ${#rprivatekey}, 公钥长度: ${#rpublickey}${NC}"
    
    if [[ -z "$rprivatekey" ]] || [[ ${#rprivatekey} -lt 40 ]]; then
        echo -e "${RED}错误: 无法生成 X25519 私钥 (长度: ${#rprivatekey})${NC}"
        return 1
    fi
    
    if [[ -z "$rpublickey" ]] || [[ ${#rpublickey} -lt 40 ]]; then
        echo -e "${RED}错误: 无法解析 X25519 公钥 (长度: ${#rpublickey})${NC}"
        return 1
    fi
    
    mkdir -p /usr/local/etc/xray
    confirm_xray_overwrite "$REALITY_CONFIG" || return 1
    
    if [[ -n "$rdomain" ]]; then
        # TLS 模式
        client_sni="$rdomain"
        cat > "$REALITY_CONFIG" <<EOF
{
  "inbounds": [
    {
      "port": ${rport},
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "${ruuid}",
            "flow": "xtls-rprx-vision"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "/usr/local/etc/xray/certs/${rdomain}.crt",
              "keyFile": "/usr/local/etc/xray/certs/${rdomain}.key"
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
        # 设置自动续期
        if command -v setup_cert_renewal >/dev/null 2>&1; then
            setup_cert_renewal "$rdomain"
        fi
        
        cat > "$REALITY_CLIENT" <<EOF
=========== Reality (TLS模式) 配置信息 ===========
协议: VLESS
地址: ${rdomain}
端口: ${rport}
UUID: ${ruuid}
流控: xtls-rprx-vision
安全: tls
SNI: ${client_sni}

vless://${ruuid}@${rdomain}:${rport}?security=tls&sni=${client_sni}&flow=xtls-rprx-vision&encryption=none#Reality-TLS
EOF
    else
        # Reality 模式 (窃取证书)
        cat > "$REALITY_CONFIG" <<EOF
{
  "inbounds": [
    {
      "port": ${rport},
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "${ruuid}",
            "flow": "xtls-rprx-vision"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "${rsni}:443",
          "xver": 0,
          "serverNames": ["${rsni}"],
          "privateKey": "${rprivatekey}",
          "shortIds": ["${rshortid}"]
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
        cat > "$REALITY_CLIENT" <<EOF
=========== Reality 配置信息 ===========
协议: VLESS
地址: ${server_ip}
端口: ${rport}
UUID: ${ruuid}
流控: xtls-rprx-vision
安全: reality
公钥: ${rpublickey}
Short ID: ${rshortid}
Server Name: ${rsni}

vless://${ruuid}@${server_ip}:${rport}?security=reality&sni=${rsni}&pbk=${rpublickey}&sid=${rshortid}&flow=xtls-rprx-vision&encryption=none#Reality
EOF
    fi
    
    chmod 600 "$REALITY_CLIENT"
    
    # 配置服务
    systemctl daemon-reload
    ensure_xray_service_unit "xray-reality" "$REALITY_CONFIG"
    systemctl enable "$REALITY_SERVICE"
    
    sync
    sleep 1
    
    # 验证配置
    echo -e "${BLUE}正在验证 Xray 配置...${NC}"
    local test_output
    test_output=$(xray -test -config "$REALITY_CONFIG" 2>&1)
    if echo "$test_output" | grep -q "Configuration OK"; then
        echo -e "${GREEN}✓ 配置验证通过${NC}"
    else
        echo -e "${RED}✗ 配置验证失败${NC}"
        echo -e "${YELLOW}错误信息:${NC}"
        echo "$test_output" | head -5
        return 1
    fi
    
    # 启动服务
    echo -e "${BLUE}正在启动 Xray 服务...${NC}"
    systemctl start "$REALITY_SERVICE"
    sleep 5
    
    # 检查服务状态
    retry_count=0
    local max_retries=3
    while [[ $retry_count -lt $max_retries ]]; do
        if systemctl is-active --quiet "$REALITY_SERVICE"; then
            echo -e "${GREEN}✓ Reality 服务已成功启动${NC}"
            break
        fi
        retry_count=$((retry_count + 1))
        [[ $retry_count -lt $max_retries ]] && echo -e "${YELLOW}等待服务启动... (${retry_count}/${max_retries})${NC}" && sleep 3
    done
    
    if [[ $retry_count -eq $max_retries ]]; then
        echo -e "${RED}✗ Reality 服务启动失败${NC}"
        show_diagnostic_info
        return 1
    fi
    
    mark_installed reality
    export_json "reality" "{\"protocol\":\"vless\",\"service\":\"${REALITY_SERVICE}\",\"config\":\"${REALITY_CONFIG}\",\"client\":\"${REALITY_CLIENT}\"}"
    check_firewall_port "${rport}" tcp
    log_info "Reality 安装完成 port=${rport} domain=${rdomain:-none}"
    
    echo ""
    echo -e "${GREEN}Reality 安装完成!${NC}"
    cat "$REALITY_CLIENT"
}

# ============================================
# 升级 Reality
# ============================================
upgrade_reality() {
    echo -e "${BLUE}正在升级 Reality(Xray)...${NC}"
    
    local bak
    bak=$(backup_upgrade_context "reality")
    cp -f "$REALITY_CONFIG" "$bak/reality.json" 2>/dev/null || true
    
    run_remote_script "https://github.com/XTLS/Xray-install/raw/main/install-release.sh" @ install || {
        rollback_file_if_needed "$bak/reality.json" "$REALITY_CONFIG"
        return 1
    }
    
    systemctl restart "$REALITY_SERVICE" || {
        rollback_file_if_needed "$bak/reality.json" "$REALITY_CONFIG"
        systemctl restart "$REALITY_SERVICE" 2>/dev/null || true
        return 1
    }
    
    echo -e "${GREEN}Reality(Xray) 升级完成!${NC}"
}

# ============================================
# 卸载 Reality
# ============================================
uninstall_reality() {
    log_info "开始卸载 Reality"
    echo -e "${BLUE}正在卸载 Reality (Xray)...${NC}"
    
    systemctl stop "$REALITY_SERVICE" 2>/dev/null || true
    systemctl disable "$REALITY_SERVICE" 2>/dev/null || true
    rm -f "/etc/systemd/system/${REALITY_SERVICE}"
    rm -f "$REALITY_CONFIG"
    rm -f "$REALITY_CLIENT"
    
    mark_uninstalled reality
    rm -f "$EXPORT_DIR/reality.json"
    systemctl daemon-reload
    
    echo -e "${GREEN}Reality 已卸载${NC}"
}

# ============================================
# 状态检查
# ============================================
status_reality() {
    echo -e "${BLUE}=== Reality 状态 ===${NC}"
    
    if is_marked_installed reality; then
        echo -e "${GREEN}✓ 已安装${NC}"
    else
        echo -e "${YELLOW}○ 未安装${NC}"
        return 1
    fi
    
    if systemctl is-active --quiet "$REALITY_SERVICE" 2>/dev/null; then
        echo -e "${GREEN}✓ 服务运行中${NC}"
    else
        echo -e "${RED}✗ 服务未运行${NC}"
    fi
    
    if [[ -f "$REALITY_CONFIG" ]]; then
        echo -e "${BLUE}配置信息:${NC}"
        grep -E '"port"|"protocol"' "$REALITY_CONFIG" | head -3 || true
    fi
}

# ============================================
# 诊断信息
# ============================================
show_diagnostic_info() {
    echo ""
    echo -e "${YELLOW}=== 诊断信息 ===${NC}"
    
    echo -e "${YELLOW}1. 检查 Xray 二进制文件:${NC}"
    which xray && xray version 2>&1 | head -2 || echo -e "${RED}Xray 未找到${NC}"
    echo ""
    
    echo -e "${YELLOW}2. 检查配置有效性:${NC}"
    xray -test -config "$REALITY_CONFIG" 2>&1 || true
    echo ""
    
    echo -e "${YELLOW}3. 查看服务状态:${NC}"
    systemctl status "$REALITY_SERVICE" --no-pager 2>&1 | head -10 || true
    echo ""
    
    echo -e "${YELLOW}4. 查看详细日志:${NC}"
    journalctl -u "$REALITY_SERVICE" -n 20 --no-pager 2>&1 || true
}

# 执行传入的命令
"$@"
