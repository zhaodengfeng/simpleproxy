#!/bin/bash
# SIMPLEPROXY - A Multi-Protocol Proxy Installer (Modular Version)

set -euo pipefail

# Get the real script path (resolve symlinks)
get_script_dir() {
    local source="${BASH_SOURCE[0]}"
    while [[ -L "$source" ]]; do
        local dir="$(cd "$(dirname "$source")" && pwd)"
        source="$(readlink "$source" 2>/dev/null || realpath "$source" 2>/dev/null)"
        [[ "$source" != /* ]] && source="$dir/$source"
    done
    cd "$(dirname "$source")" && pwd
}

SCRIPT_DIR="$(get_script_dir)"
MODULE_DIR="${SCRIPT_DIR}/lib"
PROTO_DIR="${SCRIPT_DIR}/protocols"

if [[ ! -d "${MODULE_DIR}" ]]; then
    echo "Error: Cannot find lib/ directory at ${MODULE_DIR}" >&2
    echo "Please run install.sh first." >&2
    exit 1
fi

source "${MODULE_DIR}/common.sh"
source "${MODULE_DIR}/logging.sh"
source "${MODULE_DIR}/checksum.sh"

for proto in shadowsocks reality hysteria2 v2ray snell; do
    [[ -f "${PROTO_DIR}/${proto}.sh" ]] && source "${PROTO_DIR}/${proto}.sh"
done

# 安装代理菜单
show_install_menu(){
    clear
    echo -e "${CYAN}════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}║${NC}           ${GREEN}安装代理服务${NC}                      ${CYAN}║${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════${NC}"
    echo ""
    echo "1. Shadowsocks-rust"
    echo "2. VLESS + Reality"
    echo "3. Hysteria 2"
    echo "4. V2Ray + TLS + WebSocket"
    echo "5. Snell"
    echo "0. 返回主菜单"
    echo ""
    echo -n "请选择 [0-5]: "
}

# 安装代理主函数
install_proxy(){
    while true; do
        show_install_menu
        read -r choice
        case $choice in
            1) echo "正在安装 Shadowsocks-rust..."; sleep 1; echo "安装完成（示例）"; read -p "按回车继续..." ;;
            2) echo "正在安装 VLESS + Reality..."; sleep 1; echo "安装完成（示例）"; read -p "按回车继续..." ;;
            3) echo "正在安装 Hysteria 2..."; sleep 1; echo "安装完成（示例）"; read -p "按回车继续..." ;;
            4) echo "正在安装 V2Ray + WS..."; sleep 1; echo "安装完成（示例）"; read -p "按回车继续..." ;;
            5) echo "正在安装 Snell..."; sleep 1; echo "安装完成（示例）"; read -p "按回车继续..." ;;
            0) return ;;
            *) echo "无效选择" ;;
        esac
    done
}

# 卸载代理
uninstall_proxy(){
    echo -e "${YELLOW}卸载功能正在开发中...${NC}"
    read -p "按回车继续..."
}

# 查看状态
show_status(){
    echo -e "${CYAN}服务状态检查${NC}"
    echo "================"
    systemctl list-units --type=service --state=running 2>/dev/null | grep -E "(shadowsocks|xray|sing-box|hysteria|v2ray|snell)" || echo "暂无运行中的代理服务"
    read -p "按回车继续..."
}

# 主菜单
show_main_menu(){
    clear
    echo -e "${CYAN}════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}║${NC}        ${GREEN}SimpleProxy 代理管理器${NC}              ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}        ${YELLOW}版本: ${SCRIPT_VERSION:-260224a}${NC}                       ${CYAN}║${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════${NC}"
    echo ""
    echo "1. 安装代理"
    echo "2. 卸载代理"
    echo "3. 查看状态"
    echo "4. 管理配置"
    echo "5. 查看日志"
    echo "6. 备份/恢复"
    echo "7. 更新脚本"
    echo "0. 退出"
    echo ""
    echo -n "请选择 [0-7]: "
}

main(){
    check_root 2>/dev/null || { echo "需要 root 权限"; exit 1; }
    init_directories 2>/dev/null || true
    init_logging 2>/dev/null || true
    
    while true; do
        show_main_menu
        read -r choice
        case $choice in
            1) install_proxy ;;
            2) uninstall_proxy ;;
            3) show_status ;;
            4) echo "配置管理 - 开发中"; read -p "按回车继续..." ;;
            5) view_logs 50 2>/dev/null || echo "日志功能暂不可用"; read -p "按回车继续..." ;;
            6) echo "备份恢复 - 开发中"; read -p "按回车继续..." ;;
            7) echo "更新脚本 - 开发中"; read -p "按回车继续..." ;;
            0) echo "再见!"; exit 0 ;;
            *) echo "无效选择"; sleep 1 ;;
        esac
    done
}

main "$@"
