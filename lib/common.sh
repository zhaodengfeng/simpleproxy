#!/bin/bash
# common.sh - 通用工具函数
# 包含颜色定义、随机数生成、基础常量等

# Script version (format: YYYYMMDD.N)
SCRIPT_VERSION="260224a"

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Global paths
STATE_DIR="/var/lib/simpleproxy"
EXPORT_DIR="/var/lib/simpleproxy/exports"
BACKUP_ROOT="/var/backups/simpleproxy"
LOG_FILE="/var/log/simpleproxy.log"

# Module directory (for loading other modules)
MODULE_DIR="${MODULE_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
PROJECT_DIR="$(dirname "$MODULE_DIR")"

# Domain and port (set during initialization)
DOMAIN=""
GET_PORT=""

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}Error: This script must be run as root!${NC}" >&2
        exit 1
    fi
}

# Set timezone to Asia/Shanghai
set_timezone() {
    timedatectl set-timezone Asia/Shanghai 2>/dev/null || true
}

# Generate random alphanumeric string
# Usage: gen_random [length]
gen_random() {
    local length=${1:-16}
    tr -dc 'a-zA-Z0-9' < /dev/urandom | fold -w "$length" | head -n 1
}

# Generate UUID v4
gen_uuid() {
    local uuid
    uuid=$(cat /proc/sys/kernel/random/uuid 2>/dev/null | head -1 | tr -d '[:space:]')

    # Validate UUID format
    if [[ -z "$uuid" ]] || [[ ${#uuid} -ne 36 ]] || \
       ! echo "$uuid" | grep -qE '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'; then
        # Fallback: manually generate UUID v4
        uuid=$(tr -dc 'a-f0-9' < /dev/urandom | head -c 8)
        uuid="${uuid}-$(tr -dc 'a-f0-9' < /dev/urandom | head -c 4)"
        uuid="${uuid}-4$(tr -dc 'a-f0-9' < /dev/urandom | head -c 3)"
        uuid="${uuid}-$(tr -dc '89ab' < /dev/urandom | head -c 1)$(tr -dc 'a-f0-9' < /dev/urandom | head -c 3)"
        uuid="${uuid}-$(tr -dc 'a-f0-9' < /dev/urandom | head -c 12)"
    fi
    echo -n "$uuid"
}

# Generate random port
# Usage: gen_port [min] [max]
gen_port() {
    local min=${1:-10000}
    local max=${2:-65535}
    local port
    while true; do
        port=$(shuf -i "$min-$max" -n 1)
        if ! ss -tuln | grep -q ":$port "; then
            echo "$port"
            return 0
        fi
    done
}

# Get public IP address
get_public_ip() {
    local ip=""
    # Try multiple services
    ip=$(curl -s --connect-timeout 5 https://api.ipify.org 2>/dev/null) || \
    ip=$(curl -s --connect-timeout 5 https://ifconfig.me 2>/dev/null) || \
    ip=$(curl -s --connect-timeout 5 https://icanhazip.com 2>/dev/null)
    echo "$ip"
}

# Print colored message
# Usage: print_color <color> <message>
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

# Print error message and exit
# Usage: die <message> [exit_code]
die() {
    local message="$1"
    local exit_code=${2:-1}
    print_color "red" "Error: $message"
    exit "$exit_code"
}

# Print warning message
# Usage: warn <message>
warn() {
    print_color "yellow" "Warning: $1"
}

# Print success message
# Usage: success <message>
success() {
    print_color "green" "$1"
}

# Print info message
# Usage: info <message>
info() {
    print_color "blue" "$1"
}

# Check if command exists
# Usage: command_exists <command>
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check if system is systemd-based
is_systemd() {
    [[ -d /run/systemd/system ]] || [[ -d /var/run/systemd/system ]]
}

# Get OS ID (debian, ubuntu, centos, etc.)
get_os_id() {
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        echo "$ID"
    else
        echo "unknown"
    fi
}

# Get OS version
get_os_version() {
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        echo "$VERSION_ID"
    else
        echo "unknown"
    fi
}

# Initialize directories
init_directories() {
    for dir in "$STATE_DIR" "$EXPORT_DIR" "$BACKUP_ROOT"; do
        if [[ ! -d "$dir" ]]; then
            mkdir -p "$dir"
        fi
    done
}
