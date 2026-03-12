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
    
    read -t 15 -p "请输入端口(回车或等待15秒默认为443): " GET_PORT || true
    GET_PORT=${GET_PORT:-443}
    
    if ! validate_port "$GET_PORT"; then
        echo -e "${YELLOW}端口无效，使用默认端口 443${NC}"
        GET_PORT=443
    fi
    
    # 检查端口占用
    local isPort
    isPort=""
    has_listening_port 80 && isPort="$(ss -tuln 2>/dev/null | grep -E '[[:space:]]:80[[:space:]]' || true)"
    has_listening_port "$GET_PORT" && isPort="${isPort}
$(ss -tuln 2>/dev/null | grep -E '[[:space:]]:'"$GET_PORT"'[[:space:]]' || true)"
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
    
    bash "$script" "${action}_${protocol}"
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
    echo -e "  ${BLUE}[安装选项]${NC}"
    echo "    1. Shadowsocks-rust"
    echo "    2. Reality (VLESS)"
    echo "    3. Hysteria2"
    echo "    4. V2Ray + TLS + WebSocket"
    echo "    5. Snell"
    echo ""
    echo -e "  ${BLUE}[管理选项]${NC}"
    echo "    6. 卸载服务"
    echo "    7. 查看状态"
    echo "    8. 健康检查"
    echo "    9. 完全卸载"
    echo "   10. 配置 AI 分流 (SS 上游)"
    echo "   11. 关闭 AI 分流"
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
# AI 分流（仅 SS 上游）
# ============================================

AI_RULE_DIR="/usr/local/etc/xray/rules"
AI_DOMAIN_FILE="${AI_RULE_DIR}/ai_domains.txt"
AI_UPSTREAM_FILE="${STATE_DIR}/ai-upstream-ss.env"

update_ai_rules() {
    mkdir -p "$AI_RULE_DIR"
    local tmp1 tmp2
    tmp1=$(mktemp /tmp/simpleproxy-ai1.XXXXXX) || return 1
    tmp2=$(mktemp /tmp/simpleproxy-ai2.XXXXXX) || { rm -f "$tmp1"; return 1; }

    if ! curl -fsSL "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/AI.list" -o "$tmp1"; then
        echo -e "${RED}下载 AI.list 失败${NC}"
        rm -f "$tmp1" "$tmp2"
        return 1
    fi

    if ! curl -fsSL "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/OpenAi.list" -o "$tmp2"; then
        echo -e "${RED}下载 OpenAi.list 失败${NC}"
        rm -f "$tmp1" "$tmp2"
        return 1
    fi

    cat "$tmp1" "$tmp2" | awk -F, '
        /^[[:space:]]*#/ {next}
        NF < 2 {next}
        {
          gsub(/[[:space:]]+/, "", $0)
          type=toupper($1)
          val=$2
          if (val=="") next
          if (type=="DOMAIN-SUFFIX") print "domain:" val
          else if (type=="DOMAIN") print "full:" val
          else if (type=="DOMAIN-KEYWORD") print "keyword:" val
        }
    ' | sort -u > "$AI_DOMAIN_FILE"

    rm -f "$tmp1" "$tmp2"

    if [[ ! -s "$AI_DOMAIN_FILE" ]]; then
        echo -e "${RED}AI 规则为空，已中止${NC}"
        return 1
    fi

    echo -e "${GREEN}AI 规则已更新: ${AI_DOMAIN_FILE} ($(wc -l < "$AI_DOMAIN_FILE") 条)${NC}"
    return 0
}

configure_ai_upstream_ss() {
    echo ""
    echo -e "${YELLOW}=== AI 分流上游（仅支持 SS） ===${NC}"
    read -p "上游 SS 服务器地址/IP: " AI_SS_SERVER
    read -p "上游 SS 端口: " AI_SS_PORT
    read -p "上游 SS 密码: " AI_SS_PASSWORD
    echo "请选择 SS 加密方式:"
    echo "  1. aes-128-gcm"
    echo "  2. aes-256-gcm"
    echo "  3. chacha20-ietf-poly1305"
    echo "  4. 2022-blake3-aes-128-gcm"
    echo "  5. 2022-blake3-aes-256-gcm"
    read -p "输入数字(默认 2): " ai_method_choice

    local AI_SS_METHOD="aes-256-gcm"
    case "${ai_method_choice:-2}" in
        1) AI_SS_METHOD="aes-128-gcm" ;;
        2) AI_SS_METHOD="aes-256-gcm" ;;
        3) AI_SS_METHOD="chacha20-ietf-poly1305" ;;
        4) AI_SS_METHOD="2022-blake3-aes-128-gcm" ;;
        5) AI_SS_METHOD="2022-blake3-aes-256-gcm" ;;
        *) AI_SS_METHOD="aes-256-gcm" ;;
    esac

    if [[ -z "$AI_SS_SERVER" || -z "$AI_SS_PORT" || -z "$AI_SS_PASSWORD" ]]; then
        echo -e "${RED}上游信息不完整${NC}"
        return 1
    fi
    if ! validate_port "$AI_SS_PORT"; then
        echo -e "${RED}端口无效${NC}"
        return 1
    fi

    mkdir -p "$STATE_DIR"

    # 防止换行/控制字符注入到配置文件（后续会被读取）
    if [[ "$AI_SS_SERVER$AI_SS_PORT$AI_SS_METHOD$AI_SS_PASSWORD" == *$'\n'* || \
          "$AI_SS_SERVER$AI_SS_PORT$AI_SS_METHOD$AI_SS_PASSWORD" == *$'\r'* ]]; then
        echo -e "${RED}上游参数包含非法换行字符${NC}"
        return 1
    fi

    {
        printf 'AI_SS_SERVER=%s\n' "$AI_SS_SERVER"
        printf 'AI_SS_PORT=%s\n' "$AI_SS_PORT"
        printf 'AI_SS_METHOD=%s\n' "$AI_SS_METHOD"
        printf 'AI_SS_PASSWORD=%s\n' "$AI_SS_PASSWORD"
    } > "$AI_UPSTREAM_FILE"
    chmod 600 "$AI_UPSTREAM_FILE"
    echo -e "${GREEN}AI 上游 SS 配置已保存${NC}"
    return 0
}

load_ai_upstream_ss() {
    local line
    AI_SS_SERVER=""
    AI_SS_PORT=""
    AI_SS_METHOD=""
    AI_SS_PASSWORD=""

    while IFS= read -r line || [[ -n "$line" ]]; do
        case "$line" in
            AI_SS_SERVER=*) AI_SS_SERVER="${line#AI_SS_SERVER=}" ;;
            AI_SS_PORT=*) AI_SS_PORT="${line#AI_SS_PORT=}" ;;
            AI_SS_METHOD=*) AI_SS_METHOD="${line#AI_SS_METHOD=}" ;;
            AI_SS_PASSWORD=*) AI_SS_PASSWORD="${line#AI_SS_PASSWORD=}" ;;
            ""|\#*) : ;;
            *) : ;;
        esac
    done < "$AI_UPSTREAM_FILE"

    if [[ -z "$AI_SS_SERVER" || -z "$AI_SS_PORT" || -z "$AI_SS_METHOD" || -z "$AI_SS_PASSWORD" ]]; then
        echo -e "${RED}上游配置不完整: ${AI_UPSTREAM_FILE}${NC}"
        return 1
    fi
    if ! validate_port "$AI_SS_PORT"; then
        echo -e "${RED}上游端口无效: ${AI_SS_PORT}${NC}"
        return 1
    fi
    return 0
}

apply_ai_shunt_to_config() {
    local cfg="$1"
    [[ -f "$cfg" ]] || return 1
    [[ -f "$AI_UPSTREAM_FILE" ]] || { echo -e "${RED}未找到上游配置: ${AI_UPSTREAM_FILE}${NC}"; return 1; }
    [[ -f "$AI_DOMAIN_FILE" ]] || { echo -e "${RED}未找到 AI 规则文件: ${AI_DOMAIN_FILE}${NC}"; return 1; }

    load_ai_upstream_ss || return 1

    python3 - "$cfg" "$AI_DOMAIN_FILE" "$AI_SS_SERVER" "$AI_SS_PORT" "$AI_SS_METHOD" "$AI_SS_PASSWORD" <<'PY'
import json,sys
cfg,rulef,server,port,method,password=sys.argv[1:7]
port=int(port)
with open(cfg,'r',encoding='utf-8') as f:
    data=json.load(f)
with open(rulef,'r',encoding='utf-8') as f:
    domains=[line.strip() for line in f if line.strip()]

outbounds=data.setdefault('outbounds',[])
outbounds=[o for o in outbounds if o.get('tag')!='ai-ss-out']
outbounds.append({
  'protocol':'shadowsocks',
  'tag':'ai-ss-out',
  'settings':{'servers':[{'address':server,'port':port,'method':method,'password':password}]}
})
data['outbounds']=outbounds

routing=data.setdefault('routing',{})
rules=routing.setdefault('rules',[])
rules=[r for r in rules if r.get('outboundTag')!='ai-ss-out']
if domains:
    rules.append({'type':'field','domain':domains,'outboundTag':'ai-ss-out'})
routing['rules']=rules
routing.setdefault('domainStrategy','AsIs')

with open(cfg,'w',encoding='utf-8') as f:
    json.dump(data,f,ensure_ascii=False,indent=2)
PY
}

apply_ai_shunt() {
    update_ai_rules || return 1
    configure_ai_upstream_ss || return 1

    local changed=0
    local bak
    bak=$(backup_upgrade_context "ai-shunt")

    if [[ -f /usr/local/etc/xray/reality.json ]]; then
        cp -f /usr/local/etc/xray/reality.json "$bak/reality.json" 2>/dev/null || true
        apply_ai_shunt_to_config /usr/local/etc/xray/reality.json && changed=1
        if xray -test -config /usr/local/etc/xray/reality.json >/dev/null 2>&1; then
            systemctl restart xray-reality.service 2>/dev/null || true
        else
            rollback_file_if_needed "$bak/reality.json" /usr/local/etc/xray/reality.json
            echo -e "${RED}Reality 配置校验失败，已回滚${NC}"
            return 1
        fi
    fi

    if [[ -f /usr/local/etc/xray/v2ray.json ]]; then
        cp -f /usr/local/etc/xray/v2ray.json "$bak/v2ray.json" 2>/dev/null || true
        apply_ai_shunt_to_config /usr/local/etc/xray/v2ray.json && changed=1
        if xray -test -config /usr/local/etc/xray/v2ray.json >/dev/null 2>&1; then
            systemctl restart xray-v2ray.service 2>/dev/null || true
        else
            rollback_file_if_needed "$bak/v2ray.json" /usr/local/etc/xray/v2ray.json
            echo -e "${RED}V2Ray 配置校验失败，已回滚${NC}"
            return 1
        fi
    fi

    if [[ $changed -eq 0 ]]; then
        echo -e "${YELLOW}未检测到 Reality/V2Ray 配置文件，未应用分流${NC}"
        return 1
    fi

    echo -e "${GREEN}AI 分流已生效（命中 AI/OpenAI 规则走 SS 上游）${NC}"
    return 0
}

disable_ai_shunt_in_config() {
    local cfg="$1"
    [[ -f "$cfg" ]] || return 1

    python3 - "$cfg" <<'PY'
import json,sys
cfg=sys.argv[1]
with open(cfg,'r',encoding='utf-8') as f:
    data=json.load(f)

outbounds=data.get('outbounds',[])
outbounds=[o for o in outbounds if o.get('tag')!='ai-ss-out']
data['outbounds']=outbounds

routing=data.get('routing',{})
rules=routing.get('rules',[])
rules=[r for r in rules if r.get('outboundTag')!='ai-ss-out']
routing['rules']=rules
data['routing']=routing

with open(cfg,'w',encoding='utf-8') as f:
    json.dump(data,f,ensure_ascii=False,indent=2)
PY
}

disable_ai_shunt() {
    local changed=0
    local bak
    bak=$(backup_upgrade_context "ai-shunt-disable")

    if [[ -f /usr/local/etc/xray/reality.json ]]; then
        cp -f /usr/local/etc/xray/reality.json "$bak/reality.json" 2>/dev/null || true
        disable_ai_shunt_in_config /usr/local/etc/xray/reality.json && changed=1
        if xray -test -config /usr/local/etc/xray/reality.json >/dev/null 2>&1; then
            systemctl restart xray-reality.service 2>/dev/null || true
        else
            rollback_file_if_needed "$bak/reality.json" /usr/local/etc/xray/reality.json
            echo -e "${RED}Reality 配置校验失败，已回滚${NC}"
            return 1
        fi
    fi

    if [[ -f /usr/local/etc/xray/v2ray.json ]]; then
        cp -f /usr/local/etc/xray/v2ray.json "$bak/v2ray.json" 2>/dev/null || true
        disable_ai_shunt_in_config /usr/local/etc/xray/v2ray.json && changed=1
        if xray -test -config /usr/local/etc/xray/v2ray.json >/dev/null 2>&1; then
            systemctl restart xray-v2ray.service 2>/dev/null || true
        else
            rollback_file_if_needed "$bak/v2ray.json" /usr/local/etc/xray/v2ray.json
            echo -e "${RED}V2Ray 配置校验失败，已回滚${NC}"
            return 1
        fi
    fi

    rm -f "$AI_UPSTREAM_FILE"

    if [[ $changed -eq 0 ]]; then
        echo -e "${YELLOW}未检测到 Reality/V2Ray 配置文件，无需关闭${NC}"
        return 1
    fi

    echo -e "${GREEN}AI 分流已关闭${NC}"
    return 0
}

# ============================================
# 自检模式 (无网络/无副作用)
# ============================================

self_test() {
    local failed=0
    local root_dir="$SCRIPT_DIR"

    echo -e "${BLUE}[Self-Test] 开始自检...${NC}"

    # 1) 基础文件检查
    local required=(
        "$root_dir/simpleproxy.sh"
        "$root_dir/lib/common.sh"
        "$root_dir/lib/logging.sh"
        "$root_dir/protocols/shadowsocks.sh"
        "$root_dir/protocols/reality.sh"
        "$root_dir/protocols/hysteria2.sh"
        "$root_dir/protocols/v2ray.sh"
        "$root_dir/protocols/snell.sh"
    )

    for f in "${required[@]}"; do
        if [[ -f "$f" ]]; then
            echo "[OK] 文件存在: $f"
        else
            echo "[FAIL] 文件缺失: $f"
            failed=$((failed + 1))
        fi
    done

    # 2) 语法检查
    for f in "$root_dir/simpleproxy.sh" "$root_dir"/lib/*.sh "$root_dir"/protocols/*.sh; do
        if bash -n "$f"; then
            echo "[OK] 语法通过: $(basename "$f")"
        else
            echo "[FAIL] 语法错误: $(basename "$f")"
            failed=$((failed + 1))
        fi
    done

    # 3) 动作分发检查（只做状态查询，避免副作用）
    local protocols=(shadowsocks reality hysteria2 v2ray snell)
    for p in "${protocols[@]}"; do
        local script="$root_dir/protocols/${p}.sh"
        local action="status_${p}"
        if env MODULE_DIR="$root_dir/lib" bash "$script" "$action" >/dev/null 2>&1; then
            echo "[OK] 分发正常: ${p} -> ${action}"
        else
            # status 在未安装时可能返回非0（例如未安装），不视为阻断
            echo "[WARN] 状态返回非0(可能未安装): ${p}"
        fi
    done

    echo ""
    if [[ $failed -eq 0 ]]; then
        echo -e "${GREEN}[Self-Test] 通过：未发现阻断性问题。${NC}"
        return 0
    else
        echo -e "${RED}[Self-Test] 失败：发现 ${failed} 个问题。${NC}"
        return 1
    fi
}

# ============================================
# 版本提示
# ============================================

check_version_hint() {
    # 仅在 git 仓库中做轻量检查，失败不影响主流程
    if ! command -v git >/dev/null 2>&1; then
        return 0
    fi

    if [[ ! -d "${SCRIPT_DIR}/.git" ]]; then
        return 0
    fi

    local local_rev remote_rev
    local_rev=$(git -C "$SCRIPT_DIR" rev-parse --short HEAD 2>/dev/null || true)

    # 轻量拉取远端信息（失败则静默跳过）
    git -C "$SCRIPT_DIR" fetch origin main --quiet 2>/dev/null || return 0
    remote_rev=$(git -C "$SCRIPT_DIR" rev-parse --short origin/main 2>/dev/null || true)

    if [[ -n "$local_rev" && -n "$remote_rev" && "$local_rev" != "$remote_rev" ]]; then
        echo -e "${YELLOW}检测到新版本可用: 本地 ${local_rev} -> 远端 ${remote_rev}${NC}"
        echo -e "${YELLOW}建议先执行: cd ${SCRIPT_DIR} && git pull${NC}"
        echo ""
    fi
}

# ============================================
# 主程序
# ============================================

main() {
    check_root
    acquire_global_lock
    set_timezone
    init_directories
    check_version_hint || true
    
    while true; do
        show_menu
        read -p "请输入选项: " choice
        
        case $choice in
            1|2|3|4|5)
                if ! handle_install "$choice"; then
                    echo -e "${RED}安装流程未完成，请查看上方提示。${NC}"
                fi
                echo ""
                read -p "按回车键继续..."
                ;;
            6)
                handle_uninstall || true
                echo ""
                read -p "按回车键继续..."
                ;;
            7)
                handle_status || true
                echo ""
                read -p "按回车键继续..."
                ;;
            8)
                health_check || true
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
            10)
                apply_ai_shunt || true
                echo ""
                read -p "按回车键继续..."
                ;;
            11)
                disable_ai_shunt || true
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

# 参数入口
case "${1:-}" in
    --self-test)
        self_test
        exit $?
        ;;
    -h|--help)
        echo "SimpleProxy"
        echo "用法:"
        echo "  sudo simpleproxy                         # 启动交互菜单"
        echo "  sudo simpleproxy --self-test             # 运行无副作用自检"
        echo ""
        echo "注意: Reality / V2Ray / Hysteria2 / acme.sh 等上游安装器默认被阻止执行。"
        echo "如需允许，请显式使用: ALLOW_REMOTE_INSTALL=1 sudo simpleproxy"
        exit 0
        ;;
esac

# 运行主程序
main
