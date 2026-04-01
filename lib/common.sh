#!/bin/bash
# common.sh - 通用工具函数库
# 包含颜色定义、验证函数、随机生成、路径常量等

# 严格模式
set -euo pipefail

# Script version (format: YYMMDD.N)
SCRIPT_VERSION="260320"

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
        grep -E '^ID=' /etc/os-release | cut -d= -f2 | tr -d '"'
    else
        echo "unknown"
    fi
}

# 获取 OS 版本
get_os_version() {
    if [[ -f /etc/os-release ]]; then
        grep -E '^VERSION_ID=' /etc/os-release | cut -d= -f2 | tr -d '"'
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
# 规则: 仅允许字母/数字/连字符，各标签以字母数字开头结尾，最长253字符
validate_domain() {
    local domain="$1"
    [[ -z "$domain" ]] && return 1
    [[ ${#domain} -gt 253 ]] && return 1
    [[ "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$ ]]
}

# 验证端口号
validate_port() {
    local port="$1"
    [[ "$port" =~ ^[0-9]+$ ]] || return 1
    [[ "$port" -ge 1 && "$port" -le 65535 ]] || return 1
}

# 验证密码/密钥 (只允许 Base64 字符和 =_-)
validate_key() {
    local key="$1"
    local max_len="${2:-256}"
    [[ -z "$key" ]] && return 1
    [[ ${#key} -gt $max_len ]] && return 1
    [[ "$key" =~ ^[a-zA-Z0-9+/=_-]+$ ]]
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

# 端口占用检查（优先 ss，其次 netstat）
has_listening_port() {
    local port="$1"

    if command -v ss >/dev/null 2>&1; then
        ss -tuln 2>/dev/null | grep -qE "[[:space:]]:${port}[[:space:]]"
        return $?
    fi

    if command -v netstat >/dev/null 2>&1; then
        netstat -ntlp 2>/dev/null | grep -qE "[.:]${port}[[:space:]]"
        return $?
    fi

    return 1
}

# 生成随机端口 (检查端口是否可用)
gen_port() {
    local min="${1:-10000}"
    local max="${2:-65535}"
    local port
    local attempts=0
    local max_attempts=1000
    while [[ $attempts -lt $max_attempts ]]; do
        port=$(shuf -i "$min-$max" -n 1)
        if ! has_listening_port "$port"; then
            echo "$port"
            return 0
        fi
        attempts=$((attempts + 1))
    done
    echo -e "${RED}错误: 在 ${min}-${max} 范围内未找到可用端口${NC}" >&2
    return 1
}

# ============================================
# 交互式端口输入 (公共)
# ============================================

# 交互式获取端口，支持默认值和随机生成
# 用法: prompt_port [default|random] [min] [max]
#   default: 指定默认端口号，或 "random" 表示随机生成
prompt_port() {
    local default="${1:-random}"
    local min="${2:-20000}"
    local max="${3:-65000}"
    local port_input port

    read -t 15 -p "请输入端口号(回车或等待15秒${default:+默认${default}}): " port_input || true

    if [[ -n "$port_input" ]]; then
        port=$port_input
    elif [[ "$default" == "random" ]]; then
        port=$(gen_port "$min" "$max") || return 1
        echo -e "${GREEN}使用随机端口: ${port}${NC}"
    else
        port=$default
        echo -e "${GREEN}使用默认端口: ${port}${NC}"
    fi

    if ! validate_port "$port"; then
        port=$(gen_port "$min" "$max") || return 1
        echo -e "${YELLOW}端口无效，使用随机端口: ${port}${NC}"
    fi

    if has_listening_port "$port"; then
        echo -e "${RED}错误: 端口 ${port} 已被占用${NC}"
        return 1
    fi

    echo "$port"
}

# ============================================
# 服务启动等待 (公共)
# ============================================

# 等待 systemd 服务启动，带重试
# 用法: wait_service_start <service_name> [max_retries] [sleep_seconds]
wait_service_start() {
    local service="$1"
    local max_retries="${2:-3}"
    local sleep_sec="${3:-3}"
    local retry_count=0

    while [[ $retry_count -lt $max_retries ]]; do
        if systemctl is-active --quiet "$service"; then
            echo -e "${GREEN}✓ ${service} 已成功启动${NC}"
            return 0
        fi
        retry_count=$((retry_count + 1))
        if [[ $retry_count -lt $max_retries ]]; then
            echo -e "${YELLOW}等待服务启动... (${retry_count}/${max_retries})${NC}"
            sleep "$sleep_sec"
        fi
    done

    echo -e "${RED}✗ ${service} 启动失败${NC}"
    return 1
}

# ============================================
# 网络工具函数
# ============================================

# 获取公网 IPv4 地址 (强制 IPv4，多源回退)
get_public_ip() {
    local ip=""
    ip=$(curl -4 -s --connect-timeout 5 https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null | awk -F= '/^ip=/{print $2}' | tr -d '\r\n')
    [[ -z "$ip" ]] && ip=$(curl -4 -s --connect-timeout 5 https://api.ipify.org 2>/dev/null | tr -d '\r\n')
    [[ -z "$ip" ]] && ip=$(curl -4 -s --connect-timeout 5 https://ifconfig.co/ip 2>/dev/null | tr -d '\r\n')
    [[ -z "$ip" ]] && ip=$(curl -4 -s --connect-timeout 5 https://ifconfig.me 2>/dev/null | tr -d '\r\n')
    [[ -z "$ip" ]] && ip=$(curl -4 -s --connect-timeout 5 https://icanhazip.com 2>/dev/null | tr -d '\r\n')

    # 基本 IPv4 格式验证
    if echo "$ip" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}$'; then
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
    [[ "$1" =~ ^[a-zA-Z0-9_-]+$ ]] || return 1
    init_directories
    echo "installed_at=$(date -Iseconds)" > "$STATE_DIR/$1.state"
}

# 标记已卸载
mark_uninstalled() {
    [[ "$1" =~ ^[a-zA-Z0-9_-]+$ ]] || return 1
    rm -f "$STATE_DIR/$1.state"
}

# 检查是否已安装
is_marked_installed() {
    [[ "$1" =~ ^[a-zA-Z0-9_-]+$ ]] || return 1
    [[ -f "$STATE_DIR/$1.state" ]]
}

# 导出 JSON 配置
export_json() {
    local name="$1"
    local content="$2"
    [[ "$name" =~ ^[a-zA-Z0-9_-]+$ ]] || return 1
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
    shift || true

    local tmp_script
    tmp_script="$(mktemp /tmp/simpleproxy-remote.XXXXXX.sh)" || return 1

    if ! curl -fL --proto '=https' --tlsv1.2 --retry 3 --retry-delay 1 "$script_url" -o "$tmp_script"; then
        echo -e "${RED}下载远程脚本失败: ${script_url}${NC}"
        rm -f "$tmp_script"
        return 1
    fi

    if [[ ! -s "$tmp_script" ]] || ! head -n 1 "$tmp_script" | grep -qE '^#!/'; then
        echo -e "${RED}远程脚本校验失败(空文件或缺少 shebang): ${script_url}${NC}"
        rm -f "$tmp_script"
        return 1
    fi

    local rc=0
    if bash "$tmp_script" "$@"; then
        :
    else
        rc=$?
        echo -e "${RED}远程脚本执行失败: ${script_url}${NC}"
        rm -f "$tmp_script"
        return "$rc"
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
        apt-get update -y && apt-get install -y \
            curl wget openssl unzip python3 socat cron net-tools iproute2
    elif [[ "$os_type" == "rhel" ]]; then
        yum update -y
        yum install -y epel-release
        yum install -y \
            curl wget openssl unzip python3 socat cronie net-tools iproute
    fi
}

# ============================================
# 时区设置
# ============================================

set_timezone() {
    local current_tz
    current_tz=$(timedatectl show -p Timezone --value 2>/dev/null || true)
    if [[ -n "$current_tz" && "$current_tz" != "Etc/UTC" && "$current_tz" != "UTC" ]]; then
        return 0
    fi
    read -t 10 -p "当前时区为 ${current_tz:-未知}，是否设置为 Asia/Shanghai? (Y/n): " tz_confirm || true
    if [[ ! "$tz_confirm" =~ ^[Nn]$ ]]; then
        timedatectl set-timezone Asia/Shanghai 2>/dev/null || true
    fi
}

# ============================================
# SSL 证书函数
# ============================================

install_acme() {
    if [[ ! -f "$HOME/.acme.sh/acme.sh" ]]; then
        echo -e "${BLUE}Installing acme.sh...${NC}"
        local acme_email=""
        read -t 30 -p "请输入用于 Let's Encrypt 证书通知的邮箱(回车跳过): " acme_email || true
        acme_email="${acme_email:-noreply@example.com}"
        run_remote_script "https://get.acme.sh/" -s email="$acme_email" || {
            echo -e "${RED}acme.sh 安装失败${NC}"
            return 1
        }
        "$HOME/.acme.sh/acme.sh" --set-default-ca --server letsencrypt
    fi
    export PATH="$HOME/.acme.sh:$PATH"
}

apply_ssl() {
    local domain=$1

    if ! validate_domain "$domain"; then
        echo -e "${RED}错误: 域名格式无效: ${domain}${NC}"
        return 1
    fi

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

    # 确保续期 hook 目录存在（某些系统默认没有该目录）
    mkdir -p /etc/letsencrypt/renewal-hooks/deploy
    mkdir -p /usr/local/etc/xray/certs

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
    
    # 添加 cron 任务（若系统未安装 crontab，则仅提示不阻断安装）
    if command -v crontab >/dev/null 2>&1; then
        (crontab -l 2>/dev/null | grep -v "acme.sh --cron"; echo "0 3 * * * $HOME/.acme.sh/acme.sh --cron --home \"$HOME/.acme.sh\" > /dev/null 2>&1") | crontab - || true
        echo -e "${GREEN}证书自动续期已设置${NC}"
    else
        echo -e "${YELLOW}提示: 未检测到 crontab，已跳过自动续期定时任务设置${NC}"
    fi
}

