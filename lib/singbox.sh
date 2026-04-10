#!/bin/bash
# singbox.sh - sing-box 后端管理
# 统一管理 sing-box 二进制、自签证书、systemd 服务
# 供 ShadowTLS v3 / AnyTLS / Trojan / TUIC V5 等协议共用

# 防止重复加载
[[ -n "${_SINGBOX_SH_LOADED:-}" ]] && return 0
_SINGBOX_SH_LOADED=1

# 依赖 common.sh 和 logging.sh (由调用方预先 source)
# 仅在未加载时加载 (独立调试场景)
if ! declare -F log_info &>/dev/null; then
    MODULE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    source "${MODULE_DIR}/common.sh"
    source "${MODULE_DIR}/logging.sh"
fi

# sing-box 路径常量 (使用 declare 避免 readonly 重复声明问题)
SINGBOX_BIN="/usr/local/bin/sing-box"
SINGBOX_WORK_DIR="/etc/sing-box"
SINGBOX_CERT_DIR="${SINGBOX_WORK_DIR}/cert"
SINGBOX_DEFAULT_TLS_SERVER="addons.mozilla.org"

# ============================================
# sing-box 二进制管理
# ============================================

# 下载安装 sing-box 最新稳定版
install_singbox_binary() {
    if [[ -x "$SINGBOX_BIN" ]]; then
        local current_ver
        current_ver=$("$SINGBOX_BIN" version 2>/dev/null | head -1 || true)
        log_info "sing-box 已存在: ${current_ver}"
        return 0
    fi

    log_info "开始安装 sing-box..."
    echo -e "${BLUE}正在下载 sing-box...${NC}"

    local arch
    case "$(uname -m)" in
        x86_64)       arch="amd64" ;;
        aarch64|arm64) arch="arm64" ;;
        armv7l)       arch="armv7" ;;
        *)
            log_error "不支持的架构: $(uname -m)"
            echo -e "${RED}不支持的架构: $(uname -m)${NC}"
            return 1
            ;;
    esac

    # 获取最新版本号
    local version
    version=$(curl -fsSL --connect-timeout 10 "https://api.github.com/repos/SagerNet/sing-box/releases/latest" 2>/dev/null \
        | grep '"tag_name"' | head -1 | sed 's/.*"v\([^"]*\)".*/\1/')
    if [[ -z "$version" ]]; then
        log_error "无法获取 sing-box 最新版本号"
        return 1
    fi
    echo -e "${GREEN}版本: v${version}${NC}"

    local url="https://github.com/SagerNet/sing-box/releases/download/v${version}/sing-box-${version}-linux-${arch}.tar.gz"

    local tmp_dir
    tmp_dir=$(mktemp -d /tmp/simpleproxy-singbox.XXXXXX) || return 1
    chmod 700 "$tmp_dir"

    if ! wget -q --show-progress "$url" -O "${tmp_dir}/singbox.tar.gz" 2>&1; then
        echo -e "${RED}下载 sing-box 失败${NC}"
        rm -rf "$tmp_dir"
        return 1
    fi

    if ! tar -xzf "${tmp_dir}/singbox.tar.gz" -C "$tmp_dir" 2>&1; then
        echo -e "${RED}解压 sing-box 失败${NC}"
        rm -rf "$tmp_dir"
        return 1
    fi

    # 查找解压后的 sing-box 二进制
    local bin_path
    bin_path=$(find "$tmp_dir" -name "sing-box" -type f | head -1)
    if [[ -z "$bin_path" ]]; then
        echo -e "${RED}未找到 sing-box 二进制文件${NC}"
        rm -rf "$tmp_dir"
        return 1
    fi

    install -m 755 "$bin_path" "$SINGBOX_BIN"
    rm -rf "$tmp_dir"

    mkdir -p "$SINGBOX_WORK_DIR"

    log_success "sing-box v${version} 安装完成"
    echo -e "${GREEN}✓ sing-box v${version} 安装完成${NC}"
    return 0
}

# 升级 sing-box 二进制
upgrade_singbox_binary() {
    log_info "升级 sing-box..."
    local old_version
    old_version=$("$SINGBOX_BIN" version 2>/dev/null | head -1 || echo "unknown")

    local bak_bin="${SINGBOX_BIN}.bak"
    cp -f "$SINGBOX_BIN" "$bak_bin" 2>/dev/null || true

    rm -f "$SINGBOX_BIN"
    if ! install_singbox_binary; then
        # 回滚
        [[ -f "$bak_bin" ]] && mv -f "$bak_bin" "$SINGBOX_BIN"
        log_error "sing-box 升级失败，已回滚"
        return 1
    fi

    rm -f "$bak_bin"
    local new_version
    new_version=$("$SINGBOX_BIN" version 2>/dev/null | head -1 || echo "unknown")
    log_info "sing-box 升级: ${old_version} → ${new_version}"
    echo -e "${GREEN}sing-box 升级: ${old_version} → ${new_version}${NC}"
}

# 卸载 sing-box (仅在无协议使用时)
uninstall_singbox_binary() {
    for proto in shadowtls anytls trojan tuic; do
        is_marked_installed "$proto" && return 0
    done
    rm -f "$SINGBOX_BIN" "${SINGBOX_BIN}.bak"
    # 如果没有任何 sing-box 配置目录存在则清理证书
    local has_config=0
    for d in shadowtls anytls trojan tuic; do
        [[ -d "${SINGBOX_WORK_DIR}/${d}" ]] && has_config=1 && break
    done
    if [[ $has_config -eq 0 ]]; then
        rm -rf "$SINGBOX_CERT_DIR"
    fi
    log_info "sing-box 二进制已移除"
}

# ============================================
# 自签证书管理
# ============================================

# 生成自签证书 (供多个协议共用)
generate_self_signed_cert() {
    local tls_server="${1:-$SINGBOX_DEFAULT_TLS_SERVER}"
    mkdir -p "$SINGBOX_CERT_DIR"

    if [[ -f "${SINGBOX_CERT_DIR}/cert.pem" && -f "${SINGBOX_CERT_DIR}/private.key" ]]; then
        log_info "自签证书已存在，跳过生成"
        return 0
    fi

    log_info "生成自签证书 (CN=${tls_server})..."
    openssl ecparam -genkey -name prime256v1 -out "${SINGBOX_CERT_DIR}/private.key" 2>/dev/null
    openssl req -new -x509 -days 36500 \
        -key "${SINGBOX_CERT_DIR}/private.key" \
        -out "${SINGBOX_CERT_DIR}/cert.pem" \
        -subj "/CN=${tls_server}" 2>/dev/null

    chmod 600 "${SINGBOX_CERT_DIR}/private.key"
    chmod 644 "${SINGBOX_CERT_DIR}/cert.pem"
    log_success "自签证书已生成 (CN=${tls_server})"
    echo -e "${GREEN}✓ 自签证书已生成${NC}"
}

# 获取证书 SHA256 指纹 (冒号分隔格式)
get_cert_fingerprint_sha256() {
    openssl x509 -fingerprint -sha256 -noout -in "${SINGBOX_CERT_DIR}/cert.pem" 2>/dev/null \
        | sed 's/.*=//' | tr -d ' '
}

# 获取证书 Base64 SHA256 指纹 (sing-box 客户端格式)
get_cert_fingerprint_base64() {
    openssl x509 -outform der -in "${SINGBOX_CERT_DIR}/cert.pem" 2>/dev/null \
        | openssl dgst -sha256 -binary | base64
}

# ============================================
# systemd 服务管理
# ============================================

# 创建 sing-box systemd 服务 (每个协议一个独立实例)
create_singbox_service() {
    local name="$1"
    local config_path="$2"

    cat > "/etc/systemd/system/${name}.service" <<EOF
[Unit]
Description=sing-box ${name} service
Documentation=https://sing-box.sagernet.org
After=network.target nss-lookup.target

[Service]
Type=simple
User=root
NoNewPrivileges=yes
ExecStart=${SINGBOX_BIN} run -c ${config_path}
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=5
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    log_info "systemd 服务已创建: ${name}.service"
}

# 启动 sing-box 服务 (带重试)
start_singbox_service() {
    local service="$1"
    local max_retries=3
    local retry_count=0

    echo -e "${BLUE}正在启动 ${service} 服务...${NC}"
    systemctl enable "$service" 2>/dev/null || true

    while [[ $retry_count -lt $max_retries ]]; do
        systemctl restart "$service" 2>/dev/null || systemctl start "$service" 2>/dev/null
        sleep 2

        if systemctl is-active --quiet "$service"; then
            echo -e "${GREEN}✓ ${service} 服务已启动${NC}"
            return 0
        fi

        retry_count=$((retry_count + 1))
        [[ $retry_count -lt $max_retries ]] && echo -e "${YELLOW}第 ${retry_count} 次启动失败，重试中...${NC}" && sleep 2
    done

    echo -e "${RED}✗ ${service} 服务启动失败${NC}"
    echo -e "${YELLOW}诊断信息:${NC}"
    systemctl status "$service" --no-pager 2>&1 | head -10 || true
    journalctl -u "$service" -n 20 --no-pager 2>&1 || true
    return 1
}
