#!/bin/bash
# SIMPLEPROXY - A Multi-Protocol Proxy Installer (Modular Version)
# Supports: Shadowsocks-rust, Reality, Hysteria2, V2Ray+TLS+WS, Snell

set -euo pipefail

# Get the real script path (resolve symlinks)
get_script_dir() {
    local source="${BASH_SOURCE[0]}"
    # Resolve symlinks to get the real script path
    while [[ -L "$source" ]]; do
        local dir="$(cd "$(dirname "$source")" && pwd)"
        source="$(readlink "$source" 2>/dev/null || realpath "$source" 2>/dev/null)"
        # If readlink returned a relative path, prepend the dir
        [[ "$source" != /* ]] && source="$dir/$source"
    done
    cd "$(dirname "$source")" && pwd
}

# Get script directory
SCRIPT_DIR="$(get_script_dir)"
MODULE_DIR="${SCRIPT_DIR}/lib"
PROTO_DIR="${SCRIPT_DIR}/protocols"

# Check if running from correct location (modules exist)
if [[ ! -d "${MODULE_DIR}" ]]; then
    echo "Error: Cannot find lib/ directory at ${MODULE_DIR}" >&2
    echo "Please run install.sh first to install SimpleProxy properly." >&2
    echo "Or run the script directly from /opt/simpleproxy/" >&2
    exit 1
fi

# Source modules
source "${MODULE_DIR}/common.sh"
source "${MODULE_DIR}/logging.sh"
source "${MODULE_DIR}/checksum.sh"

# Source protocol modules
for proto in shadowsocks reality hysteria2 v2ray snell; do
    [[ -f "${PROTO_DIR}/${proto}.sh" ]] && source "${PROTO_DIR}/${proto}.sh"
done

# 显示主菜单
show_main_menu(){
    clear
    echo -e "${CYAN}════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}║${NC}        ${GREEN}SimpleProxy 代理管理器${NC}              ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}        ${YELLOW}版本: ${SCRIPT_VERSION}${NC}                       ${CYAN}║${NC}"
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

# 主循环
main(){
    check_root
    init_directories
    init_logging
    
    while true; do
        show_main_menu
        read -r choice
        case $choice in
            1) echo "安装功能 - 待实现" ;;
            2) echo "卸载功能 - 待实现" ;;
            3) echo "状态功能 - 待实现" ;;
            4) echo "配置功能 - 待实现" ;;
            5) view_logs 50 ;;
            6) echo "备份功能 - 待实现" ;;
            7) echo "更新功能 - 待实现" ;;
            0) echo "再见!"; exit 0 ;;
            *) echo "无效选择" ;;
        esac
        echo ""
        read -p "按回车继续..."
    done
}

# Run main
main "$@"
