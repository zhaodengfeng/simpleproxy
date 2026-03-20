#!/bin/bash
# shadowsocks.sh - Shadowsocks-rust 协议管理
# 包含安装、卸载、升级、状态检查功能

# 加载依赖
MODULE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)"
source "${MODULE_DIR}/common.sh"
source "${MODULE_DIR}/logging.sh"

# 配置路径
readonly SS_CONFIG_DIR="/etc/shadowsocks"
readonly SS_CONFIG_FILE="${SS_CONFIG_DIR}/config.json"
readonly SS_CLIENT_FILE="${SS_CONFIG_DIR}/client.json"
readonly SS_SERVICE="shadowsocks.service"

# ============================================
# 安装 Shadowsocks-rust
# ============================================
install_shadowsocks() {
    log_info "开始安装 Shadowsocks-rust"
    echo -e "${BLUE}正在安装 Shadowsocks-rust...${NC}"
    
    # 请求端口输入
    echo ""
    read -t 15 -p "请输入端口号(回车或等待15秒随机生成): " ssport_input || true
    local ssport
    if [[ -n "$ssport_input" ]]; then
        ssport=$ssport_input
    else
        ssport=$(gen_port 20000 65000)
        echo -e "${GREEN}使用随机端口: ${ssport}${NC}"
    fi
    
    # 验证端口
    if ! validate_port "$ssport"; then
        ssport=$(gen_port 20000 65000)
        echo -e "${YELLOW}端口无效，使用随机端口: ${ssport}${NC}"
    fi
    
    # 检查端口占用
    if has_listening_port "$ssport"; then
        echo -e "${RED}错误: 端口 ${ssport} 已被占用${NC}"
        return 1
    fi
    
    # 加密方式选择
    echo ""
    echo -e "${YELLOW}请选择加密方式:${NC}"
    echo " 1. 2022-blake3-aes-128-gcm (默认)"
    echo " 2. 2022-blake3-aes-256-gcm"
    echo " 3. 2022-blake3-chacha20-poly1305"
    echo " 4. aes-256-gcm"
    echo " 5. aes-128-gcm"
    echo " 6. chacha20-ietf-poly1305"
    read -t 15 -p "请输入数字(回车或等待15秒使用默认): " ss_method_choice || true
    
    local smethod="2022-blake3-aes-128-gcm"
    local sspass=""
    
    case "$ss_method_choice" in
        1|"") 
            smethod="2022-blake3-aes-128-gcm"
            sspass=$(dd if=/dev/urandom bs=16 count=1 2>/dev/null | base64 -w 0)
            ;;
        2) 
            smethod="2022-blake3-aes-256-gcm"
            sspass=$(dd if=/dev/urandom bs=32 count=1 2>/dev/null | base64 -w 0)
            ;;
        3) 
            smethod="2022-blake3-chacha20-poly1305"
            sspass=$(dd if=/dev/urandom bs=32 count=1 2>/dev/null | base64 -w 0)
            ;;
        4) 
            smethod="aes-256-gcm"
            sspass=$(gen_random 16)
            ;;
        5) 
            smethod="aes-128-gcm"
            sspass=$(gen_random 16)
            ;;
        6) 
            smethod="chacha20-ietf-poly1305"
            sspass=$(gen_random 16)
            ;;
        *) 
            echo -e "${YELLOW}无效选项，使用默认 2022-blake3-aes-128-gcm${NC}"
            smethod="2022-blake3-aes-128-gcm"
            sspass=$(dd if=/dev/urandom bs=16 count=1 2>/dev/null | base64 -w 0)
            ;;
    esac
    
    echo -e "${GREEN}使用加密方式: ${smethod}${NC}"
    
    # 获取最新版本
    echo -e "${BLUE}获取 Shadowsocks-rust 最新版本...${NC}"
    local ssrust_version
    ssrust_version=$(curl -sIL "https://github.com/shadowsocks/shadowsocks-rust/releases/latest" | grep -i location | sed -E 's/.*tag\/(v[0-9.]+).*/\1/')
    [[ -z "$ssrust_version" ]] && ssrust_version="v1.24.0"
    echo -e "${GREEN}版本: ${ssrust_version}${NC}"
    
    # 检测架构
    local arch
    arch=$(uname -m)
    local download_arch="x86_64-unknown-linux-gnu"
    case $arch in
        x86_64) download_arch="x86_64-unknown-linux-gnu" ;;
        aarch64|arm64) download_arch="aarch64-unknown-linux-gnu" ;;
        armv7l) download_arch="armv7-unknown-linux-gnueabihf" ;;
    esac
    
    local download_url="https://github.com/shadowsocks/shadowsocks-rust/releases/download/${ssrust_version}/shadowsocks-${ssrust_version}.${download_arch}.tar.xz"
    
    # 创建安全临时目录
    local tmp_dir
    tmp_dir=$(mktemp -d /tmp/simpleproxy-ss.XXXXXX) || return 1
    chmod 700 "$tmp_dir"
    
    # 下载安装
    local download_file="${tmp_dir}/ss-rust.tar.xz"
    if ! wget -q --show-progress "$download_url" -O "$download_file"; then
        echo -e "${RED}下载 Shadowsocks-rust 失败${NC}"
        rm -rf "$tmp_dir"
        return 1
    fi
    
    if ! tar -xf "$download_file" -C "$tmp_dir"; then
        echo -e "${RED}解压 Shadowsocks-rust 失败${NC}"
        rm -rf "$tmp_dir"
        return 1
    fi
    
    mv "${tmp_dir}/ssserver" /usr/local/bin/
    mv "${tmp_dir}/ssmanager" /usr/local/bin/ 2>/dev/null || true
    mv "${tmp_dir}/ssurl" /usr/local/bin/ 2>/dev/null || true
    mv "${tmp_dir}/ssservice" /usr/local/bin/ 2>/dev/null || true
    chmod +x /usr/local/bin/ssserver /usr/local/bin/ssmanager /usr/local/bin/ssurl /usr/local/bin/ssservice 2>/dev/null || true
    
    if [[ ! -x /usr/local/bin/ssserver ]]; then
        echo -e "${RED}ssserver 安装失败或不可执行${NC}"
        rm -rf "$tmp_dir"
        return 1
    fi
    
    # 清理临时目录
    rm -rf "$tmp_dir"
    
    # 创建配置
    mkdir -p "$SS_CONFIG_DIR"
    cat > "$SS_CONFIG_FILE" <<EOF
{
    "server":"0.0.0.0",
    "server_port":${ssport},
    "password":"${sspass}",
    "timeout":300,
    "method":"${smethod}",
    "fast_open":true
}
EOF
    
    # 创建 systemd 服务
    cat > "/etc/systemd/system/${SS_SERVICE}" <<EOF
[Unit]
Description=Shadowsocks-rust Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/ssserver -c ${SS_CONFIG_FILE}
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable "$SS_SERVICE"
    sleep 1
    
    # 启动服务 (带重试)
    echo -e "${BLUE}正在启动 Shadowsocks 服务...${NC}"
    local retry_count=0
    local max_retries=3
    
    while [[ $retry_count -lt $max_retries ]]; do
        systemctl restart "$SS_SERVICE" 2>/dev/null || systemctl start "$SS_SERVICE" 2>/dev/null
        sleep 2
        
        if systemctl is-active --quiet "$SS_SERVICE"; then
            echo -e "${GREEN}✓ Shadowsocks-rust 服务已成功启动${NC}"
            break
        fi
        
        retry_count=$((retry_count + 1))
        [[ $retry_count -lt $max_retries ]] && echo -e "${YELLOW}第 ${retry_count} 次启动尝试失败，重试中...${NC}" && sleep 2
    done
    
    if [[ $retry_count -eq $max_retries ]]; then
        echo -e "${RED}✗ Shadowsocks-rust 服务启动失败${NC}"
        show_diagnostic_info "$SS_SERVICE"
        return 1
    fi
    
    # 保存客户端配置
    local server_ip
    server_ip=$(get_public_ip)
    cat > "$SS_CLIENT_FILE" <<EOF
=========== Shadowsocks-rust 配置信息 ===========
服务器地址: ${server_ip}
端口: ${ssport}
密码: ${sspass}
加密方式: ${smethod}

ss://$(echo -n "${smethod}:${sspass}" | base64 -w 0)@${server_ip}:${ssport}#Shadowsocks
EOF
    chmod 600 "$SS_CLIENT_FILE"
    
    # 标记安装状态
    mark_installed shadowsocks
    export_json "shadowsocks" "{\"protocol\":\"shadowsocks\",\"server\":\"${server_ip}\",\"port\":${ssport},\"method\":\"${smethod}\"}"
    check_firewall_port "${ssport}" tcp
    log_info "Shadowsocks-rust 安装完成 port=${ssport}"
    
    echo ""
    echo -e "${GREEN}Shadowsocks-rust 安装完成!${NC}"
    cat "$SS_CLIENT_FILE"
}

# ============================================
# 升级 Shadowsocks-rust
# ============================================
upgrade_shadowsocks() {
    echo -e "${BLUE}正在升级 Shadowsocks-rust...${NC}"
    
    local bak
    bak=$(backup_upgrade_context "shadowsocks")
    cp -f "$SS_CONFIG_FILE" "$bak/config.json" 2>/dev/null || true
    cp -f /usr/local/bin/ssserver "$bak/ssserver" 2>/dev/null || true
    systemctl stop "$SS_SERVICE"
    
    local ssrust_version
    ssrust_version=$(curl -sIL "https://github.com/shadowsocks/shadowsocks-rust/releases/latest" | grep -i location | sed -E 's/.*tag\/(v[0-9.]+).*/\1/')
    [[ -z "$ssrust_version" ]] && ssrust_version="v1.24.0"
    
    local arch
    arch=$(uname -m)
    local download_arch="x86_64-unknown-linux-gnu"
    case $arch in
        aarch64|arm64) download_arch="aarch64-unknown-linux-gnu" ;;
    esac
    
    # 创建安全临时目录
    local tmp_dir
    tmp_dir=$(mktemp -d /tmp/simpleproxy-ss.XXXXXX) || return 1
    chmod 700 "$tmp_dir"
    
    local download_file="${tmp_dir}/ss-rust.tar.xz"
    if ! wget -q "https://github.com/shadowsocks/shadowsocks-rust/releases/download/${ssrust_version}/shadowsocks-${ssrust_version}.${download_arch}.tar.xz" -O "$download_file"; then
        echo -e "${RED}下载 Shadowsocks-rust 失败${NC}"
        rollback_file_if_needed "$bak/ssserver" /usr/local/bin/ssserver
        rollback_file_if_needed "$bak/config.json" "$SS_CONFIG_FILE"
        rm -rf "$tmp_dir"
        return 1
    fi
    
    if ! tar -xf "$download_file" -C "$tmp_dir"; then
        echo -e "${RED}解压失败${NC}"
        rollback_file_if_needed "$bak/ssserver" /usr/local/bin/ssserver
        rollback_file_if_needed "$bak/config.json" "$SS_CONFIG_FILE"
        rm -rf "$tmp_dir"
        return 1
    fi
    
    mv "${tmp_dir}/ssserver" /usr/local/bin/
    chmod +x /usr/local/bin/ssserver
    rm -rf "$tmp_dir"
    
    systemctl start "$SS_SERVICE"
    echo -e "${GREEN}Shadowsocks-rust 升级完成!${NC}"
}

# ============================================
# 卸载 Shadowsocks-rust
# ============================================
uninstall_shadowsocks() {
    log_info "开始卸载 Shadowsocks-rust"
    echo -e "${BLUE}正在卸载 Shadowsocks-rust...${NC}"
    
    systemctl stop "$SS_SERVICE" 2>/dev/null || true
    systemctl disable "$SS_SERVICE" 2>/dev/null || true
    rm -f /usr/local/bin/ssserver /usr/local/bin/ssservice /usr/local/bin/ssurl /usr/local/bin/ssmanager
    rm -rf "$SS_CONFIG_DIR"
    rm -f "/etc/systemd/system/${SS_SERVICE}"
    
    mark_uninstalled shadowsocks
    rm -f "$EXPORT_DIR/shadowsocks.json"
    systemctl daemon-reload
    
    echo -e "${GREEN}Shadowsocks-rust 已卸载${NC}"
}

# ============================================
# 状态检查
# ============================================
status_shadowsocks() {
    echo -e "${BLUE}=== Shadowsocks-rust 状态 ===${NC}"
    
    # 检查安装状态
    if is_marked_installed shadowsocks; then
        echo -e "${GREEN}✓ 已安装${NC}"
    else
        echo -e "${YELLOW}○ 未安装${NC}"
        return 1
    fi
    
    # 检查服务状态
    if systemctl is-active --quiet "$SS_SERVICE" 2>/dev/null; then
        echo -e "${GREEN}✓ 服务运行中${NC}"
    else
        echo -e "${RED}✗ 服务未运行${NC}"
    fi
    
    # 显示配置信息
    if [[ -f "$SS_CONFIG_FILE" ]]; then
        echo -e "${BLUE}配置信息:${NC}"
        grep -E '"server_port"|"method"' "$SS_CONFIG_FILE" || true
    fi
    
    # 检查端口监听
    if [[ -f "$SS_CONFIG_FILE" ]]; then
        local port
        port=$(grep '"server_port"' "$SS_CONFIG_FILE" | grep -oE '[0-9]+' | head -1)
        if ss -tuln 2>/dev/null | grep -q ":$port "; then
            echo -e "${GREEN}✓ 端口 ${port} 正在监听${NC}"
        else
            echo -e "${YELLOW}○ 端口 ${port} 未监听${NC}"
        fi
    fi
}

# ============================================
# 诊断信息
# ============================================
show_diagnostic_info() {
    local service="$1"
    echo ""
    echo -e "${YELLOW}=== 诊断信息 ===${NC}"
    echo -e "${YELLOW}1. 检查二进制文件:${NC}"
    ls -la /usr/local/bin/ssserver 2>&1 || true
    echo ""
    echo -e "${YELLOW}2. 检查配置文件:${NC}"
    cat "$SS_CONFIG_FILE" 2>&1 || true
    echo ""
    echo -e "${YELLOW}3. 查看服务状态:${NC}"
    systemctl status "$service" --no-pager 2>&1 | head -10 || true
    echo ""
    echo -e "${YELLOW}4. 查看详细日志:${NC}"
    journalctl -u "$service" -n 20 --no-pager 2>&1 || true
}

# 执行传入的命令
"$@"
