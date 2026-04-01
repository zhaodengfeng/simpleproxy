#!/bin/bash
# snell.sh - Snell 协议管理

MODULE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)"
source "${MODULE_DIR}/common.sh"
source "${MODULE_DIR}/logging.sh"

# 配置路径
readonly SNELL_CONFIG_DIR="/etc/snell"
readonly SNELL_CONFIG_FILE="${SNELL_CONFIG_DIR}/config.conf"
readonly SNELL_CLIENT_FILE="${SNELL_CONFIG_DIR}/client.txt"
readonly SNELL_SERVICE="snell.service"

# ============================================
# 安装 Snell
# ============================================
install_snell() {
    log_info "开始安装 Snell"
    echo -e "${BLUE}正在安装 Snell...${NC}"
    
    # 请求端口
    echo ""
    read -t 15 -p "请输入端口号(回车或等待15秒随机生成): " snell_port_input || true
    local snell_port
    if [[ -n "$snell_port_input" ]]; then
        snell_port=$snell_port_input
    else
        snell_port=$(gen_port 20000 65000)
        echo -e "${GREEN}使用随机端口: ${snell_port}${NC}"
    fi
    
    # 验证端口
    if ! validate_port "$snell_port"; then
        snell_port=$(gen_port 20000 65000)
        echo -e "${YELLOW}端口无效，使用随机端口: ${snell_port}${NC}"
    fi
    
    # 检查端口占用
    if has_listening_port "$snell_port"; then
        echo -e "${RED}错误: 端口 ${snell_port} 已被占用${NC}"
        return 1
    fi
    
    # 生成 PSK
    local snell_psk
    snell_psk=$(gen_random 32)

    # DNS 配置
    echo ""
    read -t 15 -p "请输入 DNS 服务器(多个用逗号分隔，回车跳过使用系统默认，例: 1.1.1.1, 8.8.8.8): " snell_dns_input || true
    if [[ -n "$snell_dns_input" ]] && [[ "$snell_dns_input" =~ [$'\n'$'\r'$'\t'] ]]; then
        echo -e "${RED}DNS 输入包含非法控制字符${NC}"
        return 1
    fi

    # 检测架构并下载
    local arch
    arch=$(uname -m)
    local snell_arch="amd64"
    case $arch in
        x86_64) snell_arch="amd64" ;;
        aarch64) snell_arch="aarch64" ;;
        armv7l) snell_arch="armv7l" ;;
        i386|i686) snell_arch="i386" ;;
        *) 
            echo -e "${RED}不支持的架构: ${arch}${NC}"
            return 1
            ;;
    esac
    
    echo -e "${BLUE}下载 Snell (架构: ${snell_arch})...${NC}"
    
    # 获取最新版本 (从 Surge KB release notes 页面解析)
    local snell_version
    snell_version=$(curl -s "https://kb.nssurge.com/surge-knowledge-base/release-notes/snell" \
        | grep -oE 'snell-server-v[0-9]+\.[0-9]+\.[0-9]+' \
        | sed 's/snell-server-v//' \
        | sort -t. -k1,1n -k2,2n -k3,3n \
        | tail -1)
    [[ -z "$snell_version" ]] && snell_version="4.1.1"
    
    local download_url="https://dl.nssurge.com/snell/snell-server-v${snell_version}-linux-${snell_arch}.zip"
    
    # 创建安全临时目录
    local tmp_dir
    tmp_dir=$(mktemp -d /tmp/simpleproxy-snell.XXXXXX) || return 1
    chmod 700 "$tmp_dir"
    
    local download_file="${tmp_dir}/snell-server.zip"
    if ! wget -q --show-progress "$download_url" -O "$download_file"; then
        echo -e "${RED}下载 Snell 失败${NC}"
        rm -rf "$tmp_dir"
        return 1
    fi
    
    if ! unzip -o "$download_file" -d "$tmp_dir"; then
        echo -e "${RED}解压 Snell 失败${NC}"
        rm -rf "$tmp_dir"
        return 1
    fi
    
    mv "${tmp_dir}/snell-server" /usr/local/bin/
    chmod +x /usr/local/bin/snell-server
    
    if [[ ! -x /usr/local/bin/snell-server ]]; then
        echo -e "${RED}snell-server 安装失败或不可执行${NC}"
        rm -rf "$tmp_dir"
        return 1
    fi
    
    # 清理临时目录
    rm -rf "$tmp_dir"
    
    # 创建配置目录
    mkdir -p "$SNELL_CONFIG_DIR"
    
    # 创建配置文件
    {
        echo "[snell-server]"
        echo "listen = 0.0.0.0:${snell_port}"
        echo "psk = ${snell_psk}"
        echo "ipv6 = false"
        [[ -n "$snell_dns_input" ]] && echo "dns = ${snell_dns_input}"
    } > "$SNELL_CONFIG_FILE"
    
    chmod 600 "$SNELL_CONFIG_FILE"
    
    # 创建 systemd 服务
    cat > "/etc/systemd/system/${SNELL_SERVICE}" <<EOF
[Unit]
Description=Snell Proxy Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/snell-server -c ${SNELL_CONFIG_FILE}
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable "$SNELL_SERVICE"
    sleep 1
    systemctl start "$SNELL_SERVICE"
    
    # 检查服务状态
    sleep 3
    if systemctl is-active --quiet "$SNELL_SERVICE"; then
        echo -e "${GREEN}✓ Snell 服务已成功启动${NC}"
    else
        echo -e "${RED}✗ Snell 服务启动失败${NC}"
        echo -e "${YELLOW}查看日志: journalctl -u ${SNELL_SERVICE} -n 20${NC}"
        return 1
    fi
    
    # 获取服务器 IP
    local server_ip
    server_ip=$(get_public_ip)
    
    # 生成客户端配置
    cat > "$SNELL_CLIENT_FILE" <<EOF
=========== Snell 配置信息 ===========
服务器地址: ${server_ip}
端口: ${snell_port}
PSK: ${snell_psk}
协议版本: v5

Surge 配置示例:
[Proxy]
Snell = snell, ${server_ip}, ${snell_port}, psk=${snell_psk}, version=5
EOF
    chmod 600 "$SNELL_CLIENT_FILE"
    
    # 标记安装状态
    mark_installed snell
    export_json "snell" "{\"protocol\":\"snell\",\"server\":\"${server_ip}\",\"port\":${snell_port},\"client\":\"${SNELL_CLIENT_FILE}\"}"
    check_firewall_port "${snell_port}" tcp
    log_info "Snell 安装完成 port=${snell_port}"
    
    echo ""
    echo -e "${GREEN}Snell 安装完成!${NC}"
    cat "$SNELL_CLIENT_FILE"
}

# ============================================
# 升级 Snell
# ============================================
upgrade_snell() {
    echo -e "${BLUE}正在升级 Snell...${NC}"
    
    local bak
    bak=$(backup_upgrade_context "snell")
    cp -f "$SNELL_CONFIG_FILE" "$bak/config.conf" 2>/dev/null || true
    cp -f /usr/local/bin/snell-server "$bak/snell-server" 2>/dev/null || true
    
    systemctl stop "$SNELL_SERVICE"
    
    local arch
    arch=$(uname -m)
    local snell_arch="amd64"
    case $arch in
        aarch64) snell_arch="aarch64" ;;
        armv7l) snell_arch="armv7l" ;;
        i386|i686) snell_arch="i386" ;;
    esac
    
    local snell_version
    snell_version=$(curl -s "https://kb.nssurge.com/surge-knowledge-base/release-notes/snell" \
        | grep -oE 'snell-server-v[0-9]+\.[0-9]+\.[0-9]+' \
        | sed 's/snell-server-v//' \
        | sort -t. -k1,1n -k2,2n -k3,3n \
        | tail -1)
    [[ -z "$snell_version" ]] && snell_version="4.1.1"
    
    local download_url="https://dl.nssurge.com/snell/snell-server-v${snell_version}-linux-${snell_arch}.zip"

    local tmp_dir
    tmp_dir=$(mktemp -d /tmp/simpleproxy-snell-upg.XXXXXX) || return 1
    chmod 700 "$tmp_dir"

    local zip_file="$tmp_dir/snell-server.zip"

    if ! wget -q "$download_url" -O "$zip_file"; then
        echo -e "${RED}下载 Snell 失败${NC}"
        rollback_file_if_needed "$bak/snell-server" /usr/local/bin/snell-server
        rollback_file_if_needed "$bak/config.conf" "$SNELL_CONFIG_FILE"
        rm -rf "$tmp_dir"
        return 1
    fi

    if ! unzip -o "$zip_file" -d "$tmp_dir"; then
        echo -e "${RED}解压失败${NC}"
        rollback_file_if_needed "$bak/snell-server" /usr/local/bin/snell-server
        rm -rf "$tmp_dir"
        return 1
    fi

    mv "$tmp_dir/snell-server" /usr/local/bin/
    chmod +x /usr/local/bin/snell-server
    rm -rf "$tmp_dir"
    
    systemctl start "$SNELL_SERVICE"
    echo -e "${GREEN}Snell 升级完成!${NC}"
}

# ============================================
# 卸载 Snell
# ============================================
uninstall_snell() {
    log_info "开始卸载 Snell"
    echo -e "${BLUE}正在卸载 Snell...${NC}"
    
    systemctl stop "$SNELL_SERVICE" 2>/dev/null || true
    systemctl disable "$SNELL_SERVICE" 2>/dev/null || true
    rm -f /usr/local/bin/snell-server
    rm -rf "$SNELL_CONFIG_DIR"
    rm -f "/etc/systemd/system/${SNELL_SERVICE}"
    
    mark_uninstalled snell
    rm -f "$EXPORT_DIR/snell.json"
    systemctl daemon-reload
    
    echo -e "${GREEN}Snell 已卸载${NC}"
}

# ============================================
# 状态检查
# ============================================
status_snell() {
    echo -e "${BLUE}=== Snell 状态 ===${NC}"
    
    if is_marked_installed snell; then
        echo -e "${GREEN}✓ 已安装${NC}"
    else
        echo -e "${YELLOW}○ 未安装${NC}"
        return 1
    fi
    
    if systemctl is-active --quiet "$SNELL_SERVICE" 2>/dev/null; then
        echo -e "${GREEN}✓ 服务运行中${NC}"
    else
        echo -e "${RED}✗ 服务未运行${NC}"
    fi
    
    if [[ -f "$SNELL_CONFIG_FILE" ]]; then
        echo -e "${BLUE}配置信息:${NC}"
        grep -E '^listen|^psk' "$SNELL_CONFIG_FILE" | head -2 || true
    fi
}

# 执行传入的命令
"$@"
