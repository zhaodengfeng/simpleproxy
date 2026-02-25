#!/bin/bash
# SIMPLEPROXY - A Multi-Protocol Proxy Installer
# Supports: Shadowsocks-rust, Reality, Hysteria2, V2Ray+TLS+WS, Snell
# Version: 260224a
#
# 重构版本: 模块化设计，protocols/ 目录包含各协议实现

set -euo pipefail

# 获取脚本目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULE_DIR="${SCRIPT_DIR}/lib"

# 加载通用模块
source "${MODULE_DIR}/common.sh"
source "${MODULE_DIR}/logging.sh"

# 协议加载路径
PROTOCOLS_DIR="${SCRIPT_DIR}/protocols"

# ============================================
# SSL 证书函数 (需要 domain 输入，保留在主程序)
# ============================================

input_domain() {
    echo ""
    echo -e "${YELLOW}==== 域名配置 ====${NC}"
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
        echo -e "${YELLOW}端口无效，使用默认端口 443${NC}"
        GET_PORT=443
    fi
    
    # 检查端口占用
    local isPort
    isPort=$(netstat -ntlp 2>/dev/null | grep -E ':80 |:'"$GET_PORT"' ') || true
    if [[ -n "$isPort" ]]; then
        echo -e "${YELLOW}警告: 80或${GET_PORT}端口被占用${NC}"
        echo "$isPort"
        read -p "是否继续? (y/n): " confirm
        [[ ! "$confirm" =~ ^[Yy]$ ]] && return 1
    fi
    
    return 0
}

install_acme() {
    if [[ ! -f "$HOME/.acme.sh/acme.sh" ]]; then
        echo -e "${BLUE}Installing acme.sh...${NC}"
        curl -fsSL --proto '=https' --tlsv1.2 https://get.acme.sh | sh -s email=admin@localhost.com
        "$HOME/.acme.sh/acme.sh" --set-default-ca --server letsencrypt
    fi
    export PATH="$HOME/.acme.sh:$PATH"
}

apply_ssl() {
    local domain=$1
    local nginx_was_active=0
    local apache2_was_active=0
    local httpd_was_active=0
    
    install_acme
    
    echo -e "${BLUE}正在为 ${domain} 申请SSL证书...${NC}"
    
    # 检查现有证书
    if [[ -f "/etc/letsencrypt/live/${domain}/fullchain.pem" ]] && [[ -f "/etc/letsencrypt/live/${domain}/privkey.pem" ]]; then
        echo -e "${YELLOW}检测到已有证书，检查有效性...${NC}"
        local cert_end_date
        cert_end_date=$(openssl x509 -in "/etc/letsencrypt/live/${domain}/fullchain.pem" -noout -enddate 2>/dev/null | cut -d= -f2)
        if [[ -n "$cert_end_date" ]]; then
            local cert_epoch
            cert_epoch=$(date -d "$cert_end_date" +%s 2>/dev/null)
            local current_epoch
            current_epoch=$(date +%s)
            local days_left=$(( (cert_epoch - current_epoch) / 86400 ))
            
            if [[ $days_left -gt 30 ]]; then
                echo -e "${GREEN}✓ 已有证书有效，还剩 ${days_left} 天${NC}"
                mkdir -p /usr/local/etc/xray/certs
                cp "/etc/letsencrypt/live/${domain}/fullchain.pem" "/usr/local/etc/xray/certs/${domain}.crt"
                cp "/etc/letsencrypt/live/${domain}/privkey.pem" "/usr/local/etc/xray/certs/${domain}.key"
                chmod 644 "/usr/local/etc/xray/certs/${domain}.crt"
                chmod 600 "/usr/local/etc/xray/certs/${domain}.key"
                return 0
            else
                echo -e "${YELLOW}证书将在 ${days_left} 天后过期，重新申请${NC}"
            fi
        fi
    fi
    
    mkdir -p "/etc/letsencrypt/live/$domain"
    
    # 停止占用 80 端口的服务
    systemctl is-active --quiet nginx && nginx_was_active=1 || true
    systemctl is-active --quiet apache2 && apache2_was_active=1 || true
    systemctl is-active --quiet httpd && httpd_was_active=1 || true
    
    echo -e "${BLUE}停止可能占用80端口的服务...${NC}"
    systemctl stop nginx 2>/dev/null || true
    systemctl stop apache2 2>/dev/null || true
    systemctl stop httpd 2>/dev/null || true
    sleep 2
    
    # 申请证书
    "$HOME/.acme.sh/acme.sh" --set-default-ca --server letsencrypt
    "$HOME/.acme.sh/acme.sh" --issue -d "$domain" --standalone --keylength ec-256 --force
    local issue_result=$?
    
    if [[ $issue_result -ne 0 ]]; then
        echo -e "${RED}证书申请失败${NC}"
        [[ $nginx_was_active -eq 1 ]] && systemctl start nginx 2>/dev/null || true
        [[ $apache2_was_active -eq 1 ]] && systemctl start apache2 2>/dev/null || true
        [[ $httpd_was_active -eq 1 ]] && systemctl start httpd 2>/dev/null || true
        return 1
    fi
    
    # 安装证书
    "$HOME/.acme.sh/acme.sh" --installcert -d "$domain" --ecc \
        --fullchain-file "/etc/letsencrypt/live/$domain/fullchain.pem" \
        --key-file "/etc/letsencrypt/live/$domain/privkey.pem" \
        --reloadcmd "systemctl restart nginx 2>/dev/null || true"
    
    # 设置权限
    chmod 700 /etc/letsencrypt/live
    chmod 700 /etc/letsencrypt/archive 2>/dev/null || true
    chmod 644 "/etc/letsencrypt/live/$domain/fullchain.pem"
    chmod 600 "/etc/letsencrypt/live/$domain/privkey.pem"
    
    mkdir -p /usr/local/etc/xray/certs
    cp "/etc/letsencrypt/live/$domain/fullchain.pem" "/usr/local/etc/xray/certs/${domain}.crt"
    cp "/etc/letsencrypt/live/$domain/privkey.pem" "/usr/local/etc/xray/certs/${domain}.key"
    chmod 644 "/usr/local/etc/xray/certs/${domain}.crt"
    chmod 600 "/usr/local/etc/xray/certs/${domain}.key"
    
    [[ $nginx_was_active -eq 1 ]] && systemctl start nginx 2>/dev/null || true
    [[ $apache2_was_active -eq 1 ]] && systemctl start apache2 2>/dev/null || true
    [[ $httpd_was_active -eq 1 ]] && systemctl start httpd 2>/dev/null || true
    
    echo -e "${GREEN}SSL证书安装成功!${NC}"
    return 0
}

setup_cert_renewal() {
    local domain=$1
    
    cat > /etc/letsencrypt/renewal-hooks/deploy/xray-certs.sh <<'EOF'
#!/bin/bash
for dom in $(find /etc/letsencrypt/live -mindepth 1 -maxdepth 1 -type d | xargs -n1 basename); do
    if [[ -f "/etc/letsencrypt/live/$dom/fullchain.pem" ]]; then
        cp "/etc/letsencrypt/live/$dom/fullchain.pem" "/usr/local/etc/xray/certs/${dom}.crt"
        cp "/etc/letsencrypt/live/$dom/privkey.pem" "/usr/local/etc/xray/certs/${dom}.key"
        chmod 644 "/usr/local/etc/xray/certs/${dom}.crt"
        chmod 600 "/usr/local/etc/xray/certs/${dom}.key"
    fi
done
systemctl restart xray-reality.service 2>/dev/null || true
systemctl restart xray-v2ray.service 2>/dev/null || true
EOF
    chmod +x /etc/letsencrypt/renewal-hooks/deploy/xray-certs.sh 2>/dev/null || true
    
    # 添加 cron 任务
    (crontab -l 2>/dev/null | grep -v "acme.sh --cron"; echo "0 3 * * * $HOME/.acme.sh/acme.sh --cron --home \"$HOME/.acme.sh\" > /dev/null 2>&1") | crontab -
    
    echo -e "${GREEN}证书自动续期已设置${NC}"
}

# ============================================
# 协议调用函数
# ============================================

call_protocol() {
    local protocol="$1"
    local action="$2"
    local script="${PROTOCOLS_DIR}/${protocol}.sh"
    
    if [[ ! -f "$script" ]]; then
        echo -e "${RED}错误: 协议脚本不存在: ${script}${NC}"
        return 1
    fi
    
    MODULE_DIR="$MODULE_DIR" bash "$script" "${action}_${protocol}"
}

# ============================================
# 健康检查
# ============================================

health_check() {
    echo ""
    echo -e "${YELLOW}=========== 一键健康检查 ===========${NC}"
    log_info "运行健康检查"
    
    local services=("shadowsocks.service" "xray-reality.service" "xray-v2ray.service" "hysteria-server.service" "snell.service")
    for s in "${services[@]}"; do
        if systemctl is-active --quiet "$s" 2>/dev/null; then
            echo -e "${GREEN}✓ $s: 运行中${NC}"
        else
            echo -e "${YELLOW}○ $s: 未运行${NC}"
        fi
    done
    
    echo ""
    echo -e "${BLUE}监听端口(关键服务):${NC}"
    ss -tulpen 2>/dev/null | grep -E 'ssserver|xray|hysteria|snell' || echo "未检测到相关监听"
    
    echo ""
    if [[ -d /etc/letsencrypt/live ]]; then
        echo -e "${BLUE}证书到期检查:${NC}"
        for crt in /etc/letsencrypt/live/*/fullchain.pem; do
            [[ -f "$crt" ]] || continue
            local d
            d=$(basename "$(dirname "$crt")")
            local end epoch now days
            end=$(openssl x509 -in "$crt" -noout -enddate 2>/dev/null | cut -d= -f2)
            epoch=$(date -d "$end" +%s 2>/dev/null)
            now=$(date +%s)
            days=$(( (epoch-now)/86400 ))
            echo "- $d: 剩余 ${days} 天"
        done
    fi
    
    echo ""
    echo -e "${BLUE}防火墙工具:${NC}"
    command -v ufw >/dev/null 2>&1 && echo "- ufw 已安装"
    command -v firewall-cmd >/dev/null 2>&1 && echo "- firewalld 已安装"
}

# ============================================
# 主菜单
# ============================================

show_menu() {
    clear
    echo -e "${GREEN}═══════════════════════════════════════════${NC}"
    echo -e "${GREEN}        SimpleProxy 管理脚本 v${SCRIPT_VERSION}${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════${NC}"
    echo ""
    echo "  ${BLUE}[安装选项]${NC}"
    echo "    1. Shadowsocks-rust"
    echo "    2. Reality (VLESS)"
    echo "    3. Hysteria2"
    echo "    4. V2Ray + TLS + WebSocket"
    echo "    5. Snell"
    echo ""
    echo "  ${BLUE}[管理选项]${NC}"
    echo "    6. 卸载服务"
    echo "    7. 查看状态"
    echo "    8. 健康检查"
    echo "    9. 完全卸载"
    echo ""
    echo "    0. 退出"
    echo ""
    echo -e "${GREEN}═══════════════════════════════════════════${NC}"
}

handle_install() {
    local choice=$1
    case $choice in
        1) call_protocol shadowsocks install ;;
        2) call_protocol reality install ;;
        3) call_protocol hysteria2 install ;;
        4) call_protocol v2ray install ;;
        5) call_protocol snell install ;;
        *) echo -e "${RED}无效选项${NC}" ;;
    esac
}

handle_uninstall() {
    echo ""
    echo -e "${YELLOW}选择要卸载的服务:${NC}"
    echo "  1. Shadowsocks-rust"
    echo "  2. Reality"
    echo "  3. Hysteria2"
    echo "  4. V2Ray"
    echo "  5. Snell"
    echo "  6. 全部卸载"
    echo "  0. 取消"
    read -p "请选择: " uninstall_choice
    
    case $uninstall_choice in
        1) call_protocol shadowsocks uninstall ;;
        2) call_protocol reality uninstall ;;
        3) call_protocol hysteria2 uninstall ;;
        4) call_protocol v2ray uninstall ;;
        5) call_protocol snell uninstall ;;
        6)
            call_protocol shadowsocks uninstall 2>/dev/null || true
            call_protocol reality uninstall 2>/dev/null || true
            call_protocol hysteria2 uninstall 2>/dev/null || true
            call_protocol v2ray uninstall 2>/dev/null || true
            call_protocol snell uninstall 2>/dev/null || true
            ;;
        0) return ;;
        *) echo -e "${RED}无效选项${NC}" ;;
    esac
}

handle_status() {
    echo ""
    call_protocol shadowsocks status 2>/dev/null || true
    echo ""
    call_protocol reality status 2>/dev/null || true
    echo ""
    call_protocol hysteria2 status 2>/dev/null || true
    echo ""
    call_protocol v2ray status 2>/dev/null || true
    echo ""
    call_protocol snell status 2>/dev/null || true
}

# ============================================
# 主程序
# ============================================

main() {
    check_root
    init_directories
    
    while true; do
        show_menu
        read -p "请输入选项: " choice
        
        case $choice in
            1|2|3|4|5)
                handle_install "$choice"
                echo ""
                read -p "按回车键继续..."
                ;;
            6)
                handle_uninstall
                echo ""
                read -p "按回车键继续..."
                ;;
            7)
                handle_status
                echo ""
                read -p "按回车键继续..."
                ;;
            8)
                health_check
                echo ""
                read -p "按回车键继续..."
                ;;
            9)
                echo -e "${RED}警告: 这将卸载所有服务和数据!${NC}"
                read -p "确定要继续? (yes/no): " confirm
                if [[ "$confirm" == "yes" ]]; then
                    handle_uninstall
                    rm -rf "$STATE_DIR" "$EXPORT_DIR" "$BACKUP_ROOT"
                    echo -e "${GREEN}已完全卸载${NC}"
                fi
                echo ""
                read -p "按回车键继续..."
                ;;
            0)
                echo -e "${GREEN}再见!${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}无效选项${NC}"
                sleep 1
                ;;
        esac
    done
}

# 运行主程序
main
