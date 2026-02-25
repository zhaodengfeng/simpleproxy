#!/bin/bash
# SimpleProxy 一键安装脚本
# 用于从 GitHub 克隆并安装 SimpleProxy

set -euo pipefail

# 颜色定义
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m' # No Color

# 配置
readonly REPO_URL="https://github.com/zhaodengfeng/simpleproxy.git"
readonly INSTALL_DIR="/opt/simpleproxy"
readonly BIN_LINK="/usr/local/bin/simpleproxy"
readonly LOG_DIR="/var/log/simpleproxy"

# 打印信息
info() {
    echo -e "${CYAN}[INFO]${NC} $1"
}

# 打印成功
success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

# 打印警告
warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# 打印错误并退出
error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

# 检查是否为 root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "此脚本需要 root 权限运行，请使用 sudo 或以 root 用户执行"
    fi
}

# 检测操作系统
detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$ID
        VERSION=$VERSION_ID
    elif [[ -f /etc/redhat-release ]]; then
        OS="centos"
    elif [[ -f /etc/debian_version ]]; then
        OS="debian"
    else
        OS="unknown"
    fi
}

# 安装依赖
install_dependencies() {
    info "正在安装依赖..."

    local deps=("curl" "git" "openssl" "wget")

    case $OS in
        ubuntu|debian)
            apt-get update -qq
            apt-get install -y -qq "${deps[@]}" bash-completion
            ;;
        centos|rhel|fedora|rocky|almalinux)
            if command -v dnf &>/dev/null; then
                dnf install -y -q "${deps[@]}" bash-completion
            else
                yum install -y -q "${deps[@]}" bash-completion
            fi
            ;;
        arch|manjaro)
            pacman -Sy --noconfirm --quiet "${deps[@]}" bash-completion
            ;;
        alpine)
            apk add --no-cache "${deps[@]}" bash-completion
            ;;
        *)
            warn "未知操作系统，请手动安装: ${deps[*]}"
            ;;
    esac

    success "依赖安装完成"
}

# 检查并安装 git
check_git() {
    if ! command -v git &>/dev/null; then
        info "Git 未安装，正在安装..."
        install_dependencies
    fi
}

# 克隆仓库
clone_repo() {
    info "正在克隆 SimpleProxy 仓库..."

    # 如果目录已存在，先备份
    if [[ -d "$INSTALL_DIR" ]]; then
        warn "安装目录已存在: $INSTALL_DIR"
        local backup_dir="${INSTALL_DIR}.backup.$(date +%Y%m%d_%H%M%S)"
        info "备份到: $backup_dir"
        mv "$INSTALL_DIR" "$backup_dir"
    fi

    # 创建安装目录
    mkdir -p "$(dirname "$INSTALL_DIR")"

    # 克隆仓库
    if ! git clone --depth 1 "$REPO_URL" "$INSTALL_DIR"; then
        error "克隆仓库失败，请检查网络连接"
    fi

    success "仓库克隆完成"
}

# 设置权限
set_permissions() {
    info "正在设置权限..."

    # 设置脚本权限
    chmod +x "$INSTALL_DIR/simpleproxy.sh"
    chmod +x "$INSTALL_DIR/lib"/*.sh
    chmod +x "$INSTALL_DIR/protocols"/*.sh

    # 创建日志目录
    mkdir -p "$LOG_DIR"

    success "权限设置完成"
}

# 创建符号链接
create_symlink() {
    info "正在创建命令符号链接..."

    # 删除旧的符号链接（如果存在）
    if [[ -L "$BIN_LINK" ]]; then
        rm -f "$BIN_LINK"
    fi

    # 创建新的符号链接
    ln -s "$INSTALL_DIR/simpleproxy.sh" "$BIN_LINK"

    success "符号链接创建完成: $BIN_LINK -> $INSTALL_DIR/simpleproxy.sh"
}

# 验证安装
verify_installation() {
    info "正在验证安装..."

    if [[ -f "$INSTALL_DIR/simpleproxy.sh" ]]; then
        success "SimpleProxy 安装成功"
    else
        error "安装验证失败，simpleproxy.sh 不存在"
    fi

    if [[ -L "$BIN_LINK" ]]; then
        success "命令链接验证成功"
    else
        error "命令链接创建失败"
    fi
}

# 显示完成信息
show_completion() {
    echo ""
    echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}         SimpleProxy 安装完成！${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
    echo ""
    echo "安装路径: $INSTALL_DIR"
    echo "日志目录: $LOG_DIR"
    echo ""
    echo "使用方法:"
    echo "  simpleproxy           # 启动管理界面"
    echo "  simpleproxy --help    # 显示帮助信息"
    echo ""
    echo "或直接运行:"
    echo "  sudo $INSTALL_DIR/simpleproxy.sh"
    echo ""
    echo -e "${YELLOW}首次运行提示:${NC}"
    echo "  1. 运行 'simpleproxy' 启动交互式管理菜单"
    echo "  2. 选择 '1. 安装代理' 开始安装代理服务"
    echo "  3. 所有代理配置保存在 $INSTALL_DIR/config/ 目录"
    echo ""
    echo -e "${CYAN}感谢使用 SimpleProxy！${NC}"
    echo ""
}

# 主函数
main() {
    echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}       SimpleProxy 一键安装脚本${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
    echo ""

    # 检查 root
    check_root

    # 检测系统
    detect_os
    info "检测到操作系统: $OS"

    # 安装依赖和克隆
    check_git
    install_dependencies
    clone_repo
    set_permissions
    create_symlink
    verify_installation

    # 显示完成信息
    show_completion
}

# 运行主函数
main "$@"
