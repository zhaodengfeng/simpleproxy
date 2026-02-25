#!/bin/bash
# common.sh - 通用工具函数库
# 包含颜色定义、验证函数、随机生成、路径常量等

# 严格模式
set -euo pipefail

# Script version (format: YYMMDD.N)
SCRIPT_VERSION="260224a"

# Color codes
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m' # No Color

# Global paths
readonly STATE_DIR="/var/lib/simpleproxy"
readonly EXPORT_DIR="/var/lib/simpleproxy/exports"
readonly BACKUP_ROOT="/var/backups/simpleproxy"
readonly LOG_FILE="/var/log/simpleproxy.log"

# Module directory (for loading other modules)
readonly MODULE_DIR="${MODULE_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
readonly PROJECT_DIR="$(dirname "$MODULE_DIR")"

# Domain and port (set during initialization)
DOMAIN=""
GET_PORT=""

# ============================================
# 基础检查函数
# ============================================

# 检查是否以 root 运行
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}错误: 必须使用 root 权限运行此脚本!${NC}" >&2
        exit 1
    fi
}

# 检查命令是否存在
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# 检查是否为 systemd 系统
is_systemd() {
    [[ -d /run/systemd/system ]] || [[ -d /var/run/systemd/system ]]
}

# ============================================
# OS 检测函数
# ============================================

# 获取 OS ID (debian, ubuntu, centos, etc.)
get_os_id() {
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        echo "$ID"
    else
        echo "unknown"
    fi
}

# 获取 OS 版本
get_os_version() {
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        echo "$VERSION_ID"
    else
        echo "unknown"
    fi
}

# 检测系统类型 (debian/rhel)
detect_os() {
    if [[ -f /usr/bin/apt-get ]]; then
        echo "debian"
    elif [[ -f /usr/bin/yum ]]; then
        echo "rhel"
    else
        echo "unknown"
    fi
}

# ============================================
# 输入验证函数 (Security)
# ============================================

# 验证域名格式 (RFC 1123 兼容)
validate_domain() {
    local domain="$1"
    [[ -z "$domain" ]] && return 1
    [[ ${#domain} -gt 253 ]] && return 1
    echo "$domain" | grep -qE '^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
}

# 验证端口号
validate_port() {
    local port="$1"
    [[ "$port" =~ ^[0-9]+$ ]] || return 1
    [[ "$port" -ge 1 && "$port" -le 65535 ]] || return 1
}

# 验证密码/密钥 (不允许 shell 元字符)
validate_key() {
    local key="$1"
    local max_len="${2:-256}"
    [[ -z "$key" ]] && return 1
    [[ ${#key} -gt $max_len ]] && return 1
    ! echo "$key" | grep -qE '[;|&$`\\<>(){}\[\]!]'
}

# ============================================
# 随机生成函数
# ============================================

# 生成随机字符串 (使用 openssl 或 /dev/urandom)
gen_random() {
    local length="${1:-16}"
    local result=""
    
    # 验证长度
    if ! [[ "$length" =~ ^[0-9]+$ ]] || [[ "$length" -lt 1 ]] || [[ "$length" -gt 1024 ]]; then
        length=16
    fi
    
    # 优先使用 openssl
    if command -v openssl &>/dev/null; then
        result=$(openssl rand -base64 64 2>/dev/null | tr -dc 'a-zA-Z0-9' | head -c "$length")
    fi
    
    # 回退到 /dev/urandom
    if [[ -z "$result" ]]; then
        result=$(head -c 256 /dev/urandom 2>/dev/null | tr -dc 'a-zA-Z0-9' | head -c "$length")
    fi
    
    # 最终回退
    if [[ -z "$result" ]]; then
        echo "ERROR: 无法生成安全随机值" >&2
        return 1
    fi
    
    echo -n "$result"
}

# 生成 UUID v4
gen_uuid() {
    local uuid
    uuid=$(cat /proc/sys/kernel/random/uuid 2>/dev/null | head -1 | tr -d '[:space:]')
    
    # 验证 UUID 格式
    if [[ -z "$uuid" ]] || [[ ${#uuid} -ne 36 ]] || \
       ! echo "$uuid" | grep -qE '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'; then
        # 手动生成 UUID v4
        uuid=$(tr -dc 'a-f0-9' < /dev/urandom | head -c 8)
        uuid="${uuid}-$(tr -dc 'a-f0-9' < /dev/urandom | head -c 4)"
        uuid="${uuid}-4$(tr -dc 'a-f0-9' < /dev/urandom | head -c 3)"
        uuid="${uuid}-$(tr -dc '89ab' < /dev/urandom | head -c 1)$(tr -dc 'a-f0-9' < /dev/urandom | head -c 3)"
        uuid="${uuid}-$(tr -dc 'a-f0-9' < /dev/urandom | head -c 12)"
    fi
    echo -n "$uuid"
}

# 生成随机端口 (检查端口是否可用)
gen_port() {
    local min="${1:-10000}"
    local max="${2:-65535}"
    local port
    while true; do
        port=$(shuf -i "$min-$max" -n 1)
        if ! ss -tuln 2>/dev/null | grep -q ":$port "; then
            echo "$port"
            return 0
        fi
    done
}

# ============================================
# 网络工具函数
# ============================================

# 获取公网 IP (多源回退)
get_public_ip() {
    local ip=""
    ip=$(curl -s --connect-timeout 5 https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null | awk -F= '/^ip=/{print $2}' | tr -d '\r\n')
    [[ -z "$ip" ]] && ip=$(curl -s --connect-timeout 5 https://ifconfig.co/ip 2>/dev/null | tr -d '\r\n')
    [[ -z "$ip" ]] && ip=$(curl -s --connect-timeout 5 https://api.ipify.org 2>/dev/null | tr -d '\r\n')
    [[ -z "$ip" ]] && ip=$(curl -s --connect-timeout 5 https://ifconfig.me 2>/dev/null | tr -d '\r\n')
    [[ -z "$ip" ]] && ip=$(curl -s --connect-timeout 5 https://icanhazip.com 2>/dev/null | tr -d '\r\n')
    
    # 基本 IP 验证
    if echo "$ip" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}$|^([0-9a-fA-F:]+:+)+[0-9a-fA-F]+$'; then
        echo "$ip"
    else
        echo ""
    fi
}

# 别名兼容 (getIP -> get_public_ip)
getIP() {
    get_public_ip
}

# ============================================
# 输出函数
# ============================================

# 打印彩色消息
print_color() {
    local color="$1"
    local message="$2"
    case "$color" in
        red)    echo -e "${RED}${message}${NC}" ;;
        green)  echo -e "${GREEN}${message}${NC}" ;;
        yellow) echo -e "${YELLOW}${message}${NC}" ;;
        blue)   echo -e "${BLUE}${message}${NC}" ;;
        cyan)   echo -e "${CYAN}${message}${NC}" ;;
        *)      echo -e "$message" ;;
    esac
}

# 错误并退出
die() {
    local message="$1"
    local exit_code="${2:-1}"
    print_color "red" "错误: $message"
    exit "$exit_code"
}

# 警告
warn() {
    print_color "yellow" "警告: $1"
}

# 成功
success() {
    print_color "green" "$1"
}

# 信息
info() {
    print_color "blue" "$1"
}

# ============================================
# 文件和备份函数
# ============================================

# 备份文件
backup_file() {
    local target_file="$1"
    if [[ -f "$target_file" ]]; then
        local backup_path="${target_file}.bak.$(date +%Y%m%d%H%M%S)"
        cp -f "$target_file" "$backup_path"
        echo -e "${YELLOW}已备份: ${backup_path}${NC}"
    fi
}

# 回滚文件
rollback_file_if_needed() {
    local backup_file="$1"
    local target_file="$2"
    [[ -f "$backup_file" ]] && cp -f "$backup_file" "$target_file"
}

# 初始化目录
init_directories() {
    for dir in "$STATE_DIR" "$EXPORT_DIR" "$BACKUP_ROOT"; do
        [[ -d "$dir" ]] || mkdir -p "$dir"
    done
}

# 备份升级上下文
backup_upgrade_context() {
    local name="$1"
    local ts
    ts=$(date +%Y%m%d%H%M%S)
    local dir="$BACKUP_ROOT/${name}-${ts}"
    mkdir -p "$dir"
    echo "$dir"
}

# ============================================
# 状态管理函数
# ============================================

# 标记已安装
mark_installed() {
    init_directories
    echo "installed_at=$(date -Iseconds)" > "$STATE_DIR/$1.state"
}

# 标记已卸载
mark_uninstalled() {
    rm -f "$STATE_DIR/$1.state"
}

# 检查是否已安装
is_marked_installed() {
    [[ -f "$STATE_DIR/$1.state" ]]
}

# 导出 JSON 配置
export_json() {
    local name="$1"
    local content="$2"
    init_directories
    printf '%s\n' "$content" > "$EXPORT_DIR/${name}.json"
}

# ============================================
# 系统服务函数
# ============================================

# 确保 Xray 服务单元存在
ensure_xray_service_unit() {
    local svc="$1"
    local cfg="$2"
    cat > "/etc/systemd/system/${svc}.service" <<EOF
[Unit]
Description=Xray Service (${svc})
After=network.target nss-lookup.target

[Service]
Type=simple
ExecStart=/usr/local/bin/xray run -config ${cfg}
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
}

# 确认 Xray 配置覆盖
confirm_xray_overwrite() {
    local target_config="${1:-/usr/local/etc/xray/config.json}"
    if [[ -f "$target_config" ]]; then
        echo -e "${YELLOW}检测到已有 Xray 配置: ${target_config}。继续安装会覆盖该配置。${NC}"
        read -p "是否继续并覆盖? (y/N): " overwrite_confirm
        if [[ ! "$overwrite_confirm" =~ ^[Yy]$ ]]; then
            echo -e "${YELLOW}已取消安装，未覆盖现有 Xray 配置。${NC}"
            return 1
        fi
        backup_file "$target_config"
    fi
    return 0
}

# ============================================
# 防火墙函数
# ============================================

check_firewall_port() {
    local port="$1"
    local proto="${2:-tcp}"
    
    if command_exists ufw; then
        if ufw status 2>/dev/null | grep -Eq "${port}/${proto}.*ALLOW"; then
            echo -e "${GREEN}✓ 防火墙放行: ${port}/${proto} (ufw)${NC}"
        else
            echo -e "${YELLOW}○ 防火墙可能未放行: ${port}/${proto} (ufw)${NC}"
        fi
    elif command_exists firewall-cmd; then
        if firewall-cmd --list-ports 2>/dev/null | grep -Eq "(^| )${port}/${proto}( |$)"; then
            echo -e "${GREEN}✓ 防火墙放行: ${port}/${proto} (firewalld)${NC}"
        else
            echo -e "${YELLOW}○ 防火墙可能未放行: ${port}/${proto} (firewalld)${NC}"
        fi
    else
        echo -e "${YELLOW}○ 未检测到 ufw/firewalld，请手动确认端口: ${port}/${proto}${NC}"
    fi
}

# 开放端口
open_firewall_port() {
    local port="$1"
    local proto="${2:-tcp}"
    
    if command_exists ufw; then
        ufw allow "${port}/${proto}" 2>/dev/null || true
    elif command_exists firewall-cmd; then
        firewall-cmd --add-port="${port}/${proto}" --permanent 2>/dev/null || true
        firewall-cmd --reload 2>/dev/null || true
    fi
}

# 开放端口范围
open_firewall_port_range() {
    local start_port="$1"
    local end_port="$2"
    local proto="${3:-tcp}"
    
    if command_exists ufw; then
        ufw allow "${start_port}:${end_port}/${proto}" 2>/dev/null || true
    elif command_exists firewall-cmd; then
        firewall-cmd --add-port="${start_port}-${end_port}/${proto}" --permanent 2>/dev/null || true
        firewall-cmd --reload 2>/dev/null || true
    fi
}

# ============================================
# 远程脚本执行 (Security)
# ============================================

run_remote_script() {
    local script_url="$1"
    shift
    
    local tmp_script
    tmp_script=$(mktemp /tmp/simpleproxy-remote.XXXXXX.sh) || return 1
    
    if ! curl -fL --proto '=https' --tlsv1.2 --retry 3 --retry-delay 1 "$script_url" -o "$tmp_script"; then
        echo -e "${RED}下载远程脚本失败: ${script_url}${NC}"
        rm -f "$tmp_script"
        return 1
    fi
    
    # 基本完整性检查
    if [[ ! -s "$tmp_script" ]] || ! head -n 1 "$tmp_script" | grep -qE '^#!/'; then
        echo -e "${RED}远程脚本校验失败(空文件或缺少 shebang): ${script_url}${NC}"
        rm -f "$tmp_script"
        return 1
    fi
    
    if ! bash "$tmp_script" "$@"; then
        echo -e "${RED}远程脚本执行失败: ${script_url}${NC}"
        rm -f "$tmp_script"
        return 1
    fi
    
    rm -f "$tmp_script"
    return 0
}

# ============================================
# 依赖安装
# ============================================

install_common_deps() {
    local os_type
    os_type=$(detect_os)
    
    if [[ "$os_type" == "debian" ]]; then
        apt-get update -y && apt-get install -y curl wget socat cron net-tools openssl
    elif [[ "$os_type" == "rhel" ]]; then
        yum update -y
        yum install -y epel-release
        yum install -y curl wget socat cronie net-tools openssl
    fi
}

# ============================================
# 时区设置
# ============================================

set_timezone() {
    timedatectl set-timezone Asia/Shanghai 2>/dev/null || true
}

# 自动初始化
check_root
set_timezone
