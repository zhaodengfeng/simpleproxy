#!/bin/bash
# SIMPLEPROXY - A Multi-Protocol Proxy Installer
# Supports: Shadowsocks-rust, Reality, Hysteria2, V2Ray+TLS+WS, Snell
# Version: 260224a
#
# 重构版本: 模块化设计，protocols/ 目录包含各协议实现

set -euo pipefail

# 全局锁：防止并发运行导致状态/配置冲突
acquire_global_lock() {
    local lock_file="/var/lock/simpleproxy.lock"
    mkdir -p /var/lock
    exec 9>"$lock_file"
    if ! flock -n 9; then
        echo -e "\033[1;33m另一个 simpleproxy 实例正在运行，请稍后再试。\033[0m"
        exit 1
    fi
}
acquire_global_lock

# 获取脚本目录 (处理符号链接情况)
if [[ -L "${BASH_SOURCE[0]}" ]]; then
    # 如果是符号链接，获取真实路径
    SCRIPT_PATH="$(readlink -f "${BASH_SOURCE[0]}")"
else
    SCRIPT_PATH="${BASH_SOURCE[0]}"
fi
SCRIPT_DIR="$(cd "$(dirname "$SCRIPT_PATH")" && pwd)"
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

# 注意: install_acme, apply_ssl, setup_cert_renewal 函数已移至 lib/common.sh

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
