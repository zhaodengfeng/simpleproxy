#!/bin/bash
# SIMPLEPROXY - A Multi-Protocol Proxy Installer
# Supports: Shadowsocks-rust, Reality, Hysteria2, V2Ray+TLS+WS, Snell
# Version: 260202d

if [[ $EUID -ne 0 ]]; then
    clear
    echo "Error: This script must be run as root!" 1>&2
    exit 1
fi

# Script version (format: YYYYMMDD.N)
SCRIPT_VERSION="260202d"

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Set timezone
timedatectl set-timezone Asia/Shanghai 2>/dev/null || true

# Generate random values
gen_random() {
    cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w ${1:-16} | head -n 1
}

gen_uuid() {
    local uuid=$(cat /proc/sys/kernel/random/uuid 2>/dev/null | head -1 | tr -d '[:space:]')
    # Validate UUID format (should be 36 chars with 4 dashes)
    if [ -z "$uuid" ] || [ ${#uuid} -ne 36 ] || ! echo "$uuid" | grep -qE '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'; then
        # Fallback: manually generate UUID v4
        uuid=$(tr -dc 'a-f0-9' < /dev/urandom | head -c 8)
        uuid="${uuid}-$(tr -dc 'a-f0-9' < /dev/urandom | head -c 4)"
        uuid="${uuid}-4$(tr -dc 'a-f0-9' < /dev/urandom | head -c 3)"
        uuid="${uuid}-$(tr -dc '89ab' < /dev/urandom | head -c 1)$(tr -dc 'a-f0-9' < /dev/urandom | head -c 3)"
        uuid="${uuid}-$(tr -dc 'a-f0-9' < /dev/urandom | head -c 12)"
    fi
    echo -n "$uuid"
}

# Global variables
DOMAIN=""
GET_PORT=""

# Get server IP
getIP() {
    local serverIP=
    serverIP=$(curl -s -4 http://www.cloudflare.com/cdn-cgi/trace 2>/dev/null | grep "ip" | awk -F "[=]" '{print $2}')
    if [[ -z "${serverIP}" ]]; then
        serverIP=$(curl -s -6 http://www.cloudflare.com/cdn-cgi/trace 2>/dev/null | grep "ip" | awk -F "[=]" '{print $2}')
    fi
    echo "${serverIP}"
}

# Check system type
detect_os() {
    if [ -f "/usr/bin/apt-get" ]; then
        echo "debian"
    elif [ -f "/usr/bin/yum" ]; then
        echo "rhel"
    else
        echo "unknown"
    fi
}

# Install common dependencies
install_common_deps() {
    local os_type=$(detect_os)
    if [ "$os_type" == "debian" ]; then
        apt-get update -y && apt-get install -y curl wget socat cron net-tools openssl
    elif [ "$os_type" == "rhel" ]; then
        yum update -y
        yum install -y epel-release
        yum install -y curl wget socat cronie net-tools openssl
    fi
}

# Install acme.sh for SSL certificates
install_acme() {
    if [ ! -f "$HOME/.acme.sh/acme.sh" ]; then
        echo -e "${BLUE}Installing acme.sh...${NC}"
        curl https://get.acme.sh | sh -s email=admin@localhost.com
        # Set Let's Encrypt as default CA (not ZeroSSL)
        ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt
    fi
    export PATH="$HOME/.acme.sh:$PATH"
}

# Input domain and port
input_domain() {
    echo ""
    echo -e "${YELLOW}==== 域名配置 ====${NC}"
    read -p "请输入已解析到本机的域名: " DOMAIN
    
    if [ -z "$DOMAIN" ]; then
        echo -e "${RED}错误: 域名不能为空${NC}"
        return 1
    fi
    
    read -t 15 -p "请输入端口(回车或等待15秒默认为443): " GET_PORT
    if [ -z "$GET_PORT" ]; then
        GET_PORT=443
    fi
    
    # Check if port is valid
    if ! [[ "$GET_PORT" =~ ^[0-9]+$ ]] || [ "$GET_PORT" -lt 1 ] || [ "$GET_PORT" -gt 65535 ]; then
        echo -e "${RED}错误: 端口无效，使用默认端口443${NC}"
        GET_PORT=443
    fi
    
    # Check if ports 80 and target port are available
    isPort=$(netstat -ntlp 2>/dev/null | grep -E ':80 |:'"$GET_PORT"' ')
    if [ -n "$isPort" ]; then
        echo -e "${YELLOW}警告: 80或${GET_PORT}端口被占用${NC}"
        echo "$isPort"
        read -p "是否继续? (y/n): " confirm
        if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
    
    return 0
}

# Apply for SSL certificate
apply_ssl() {
    local domain=$1
    
    install_acme
    
    echo -e "${BLUE}正在为 ${domain} 申请SSL证书...${NC}"
    
    # Check if certificate already exists and is valid
    if [ -f "/etc/letsencrypt/live/${domain}/fullchain.pem" ] && [ -f "/etc/letsencrypt/live/${domain}/privkey.pem" ]; then
        echo -e "${YELLOW}检测到已有证书，检查有效性...${NC}"
        local cert_end_date=$(openssl x509 -in /etc/letsencrypt/live/${domain}/fullchain.pem -noout -enddate 2>/dev/null | cut -d= -f2)
        if [ -n "$cert_end_date" ]; then
            local cert_epoch=$(date -d "$cert_end_date" +%s 2>/dev/null)
            local current_epoch=$(date +%s)
            local days_left=$(( (cert_epoch - current_epoch) / 86400 ))
            
            if [ "$days_left" -gt 30 ]; then
                echo -e "${GREEN}✓ 已有证书有效，还剩 ${days_left} 天到期，复用现有证书${NC}"
                
                # Ensure Xray certs are up to date
                mkdir -p /usr/local/etc/xray/certs
                cp /etc/letsencrypt/live/${domain}/fullchain.pem /usr/local/etc/xray/certs/${domain}.crt
                cp /etc/letsencrypt/live/${domain}/privkey.pem /usr/local/etc/xray/certs/${domain}.key
                chmod 644 /usr/local/etc/xray/certs/${domain}.crt
                chmod 644 /usr/local/etc/xray/certs/${domain}.key
                
                return 0
            else
                echo -e "${YELLOW}证书将在 ${days_left} 天后过期，重新申请${NC}"
            fi
        fi
    fi
    
    # Create directory
    mkdir -p /etc/letsencrypt/live/$domain
    
    # Stop services that may use port 80
    echo -e "${BLUE}停止可能占用80端口的服务...${NC}"
    systemctl stop nginx 2>/dev/null || true
    systemctl stop apache2 2>/dev/null || true
    systemctl stop httpd 2>/dev/null || true
    sleep 2
    
    # Issue certificate using Let's Encrypt (not ZeroSSL)
    ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt
    ~/.acme.sh/acme.sh --issue -d $domain --standalone --keylength ec-256 --force
    local issue_result=$?
    
    if [ $issue_result -ne 0 ]; then
        echo -e "${RED}证书申请失败，请检查:${NC}"
        echo "1. 域名是否正确解析到本机IP"
        echo "2. 80端口是否被其他程序占用"
        echo "3. 防火墙是否放行80端口"
        return 1
    fi
    
    # Install certificate
    ~/.acme.sh/acme.sh --installcert -d $domain --ecc \
        --fullchain-file /etc/letsencrypt/live/$domain/fullchain.pem \
        --key-file /etc/letsencrypt/live/$domain/privkey.pem \
        --reloadcmd "systemctl restart nginx 2>/dev/null || true"
    
    # Fix certificate permissions for Xray and other services
    echo -e "${BLUE}设置证书权限...${NC}"
    chmod 755 /etc/letsencrypt/live
    chmod 755 /etc/letsencrypt/archive 2>/dev/null || true
    chmod 644 /etc/letsencrypt/live/$domain/fullchain.pem
    chmod 644 /etc/letsencrypt/live/$domain/privkey.pem
    
    # Create a copy in Xray directory with proper permissions (more secure)
    mkdir -p /usr/local/etc/xray/certs
    cp /etc/letsencrypt/live/$domain/fullchain.pem /usr/local/etc/xray/certs/${domain}.crt
    cp /etc/letsencrypt/live/$domain/privkey.pem /usr/local/etc/xray/certs/${domain}.key
    chmod 644 /usr/local/etc/xray/certs/${domain}.crt
    chmod 644 /usr/local/etc/xray/certs/${domain}.key
    
    echo -e "${GREEN}SSL证书安装成功!${NC}"
    return 0
}

# Setup auto certificate renewal
setup_cert_renewal() {
    local domain=$1
    
    # Create renewal hook script to update Xray certificates
    cat > /etc/letsencrypt/renewal-hooks/deploy/xray-certs.sh <<EOF
#!/bin/bash
# Auto-update Xray certificates after renewal
for domain in \$(find /etc/letsencrypt/live -mindepth 1 -maxdepth 1 -type d | xargs -n1 basename); do
    if [ -f "/etc/letsencrypt/live/\$domain/fullchain.pem" ]; then
        cp /etc/letsencrypt/live/\$domain/fullchain.pem /usr/local/etc/xray/certs/\${domain}.crt
        cp /etc/letsencrypt/live/\$domain/privkey.pem /usr/local/etc/xray/certs/\${domain}.key
        chmod 644 /usr/local/etc/xray/certs/\${domain}.crt
        chmod 644 /usr/local/etc/xray/certs/\${domain}.key
    fi
done
systemctl restart xray.service 2>/dev/null || true
EOF
    chmod +x /etc/letsencrypt/renewal-hooks/deploy/xray-certs.sh 2>/dev/null || true
    
    # Also add to acme.sh reloadcmd for immediate updates
    ~/.acme.sh/acme.sh --installcert -d $domain --ecc \
        --reloadcmd "cp /etc/letsencrypt/live/$domain/fullchain.pem /usr/local/etc/xray/certs/${domain}.crt && cp /etc/letsencrypt/live/$domain/privkey.pem /usr/local/etc/xray/certs/${domain}.key && chmod 644 /usr/local/etc/xray/certs/${domain}.* && systemctl restart xray.service 2>/dev/null || true"
    
    # Add cron job for certificate renewal
    (crontab -l 2>/dev/null | grep -v "acme.sh --cron"; echo "0 3 * * * $HOME/.acme.sh/acme.sh --cron --home \"$HOME/.acme.sh\" > /dev/null 2>&1") | crontab -
    
    echo -e "${GREEN}证书自动续期已设置${NC}"
}

# ==================== Shadowsocks-rust ====================
install_ssrust() {
    echo -e "${BLUE}Installing Shadowsocks-rust...${NC}"
    
    # Ask for custom port
    echo ""
    read -t 15 -p "请输入端口号(回车或等待15秒随机生成): " ssport_input
    if [ -n "$ssport_input" ]; then
        local ssport=$ssport_input
    else
        local ssport=$(shuf -i 20000-65000 -n 1)
        echo -e "${GREEN}使用随机端口: ${ssport}${NC}"
    fi
    
    # Check port validity
    if ! [[ "$ssport" =~ ^[0-9]+$ ]] || [ "$ssport" -lt 1 ] || [ "$ssport" -gt 65535 ]; then
        local ssport=$(shuf -i 20000-65000 -n 1)
        echo -e "${YELLOW}端口无效，使用随机端口: ${ssport}${NC}"
    fi
    
    # Check if port is in use
    if netstat -ntlp 2>/dev/null | grep -q ":$ssport "; then
        echo -e "${RED}错误: 端口 ${ssport} 已被占用${NC}"
        return 1
    fi
    
    # Encryption method selection
    echo ""
    echo -e "${YELLOW}请选择加密方式:${NC}"
    echo " 1. 2022-blake3-aes-128-gcm (默认)"
    echo " 2. 2022-blake3-aes-256-gcm"
    echo " 3. 2022-blake3-chacha20-poly1305"
    echo " 4. aes-256-gcm"
    echo " 5. aes-128-gcm"
    echo " 6. chacha20-ietf-poly1305"
    read -t 15 -p "请输入数字(回车或等待15秒使用默认): " ss_method_choice
    
    local smethod="2022-blake3-aes-128-gcm"
    local sspass=""
    case "$ss_method_choice" in
        1|"") 
            smethod="2022-blake3-aes-128-gcm"
            # 16 bytes = 24 base64 chars
            sspass=$(dd if=/dev/urandom bs=16 count=1 2>/dev/null | base64 -w 0)
            ;;
        2) 
            smethod="2022-blake3-aes-256-gcm"
            # 32 bytes = 44 base64 chars
            sspass=$(dd if=/dev/urandom bs=32 count=1 2>/dev/null | base64 -w 0)
            ;;
        3) 
            smethod="2022-blake3-chacha20-poly1305"
            # 32 bytes = 44 base64 chars
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
    
    # Get latest version from GitHub releases redirect (no API)
    echo -e "${BLUE}获取 Shadowsocks-rust 最新版本...${NC}"
    local ssrust_version=$(curl -sIL "https://github.com/shadowsocks/shadowsocks-rust/releases/latest" | grep -i location | sed -E 's/.*tag\/(v[0-9.]+).*/\1/')
    if [ -z "$ssrust_version" ]; then
        ssrust_version="v1.24.0"
        echo -e "${YELLOW}获取版本失败，使用默认版本 ${ssrust_version}${NC}"
    else
        echo -e "${GREEN}最新版本: ${ssrust_version}${NC}"
    fi
    
    local arch=$(uname -m)
    local download_arch="x86_64-unknown-linux-gnu"
    case $arch in
        x86_64)
            download_arch="x86_64-unknown-linux-gnu"
            ;;
        aarch64|arm64)
            download_arch="aarch64-unknown-linux-gnu"
            ;;
        armv7l)
            download_arch="armv7-unknown-linux-gnueabihf"
            ;;
    esac
    
    local download_url="https://github.com/shadowsocks/shadowsocks-rust/releases/download/${ssrust_version}/shadowsocks-${ssrust_version}.${download_arch}.tar.xz"
    
    cd /tmp
    wget -q --show-progress "$download_url" -O ss-rust.tar.xz
    tar -xf ss-rust.tar.xz
    mv ssserver /usr/local/bin/
    mv ssmanager /usr/local/bin/ 2>/dev/null || true
    mv ssurl /usr/local/bin/ 2>/dev/null || true
    mv ssservice /usr/local/bin/ 2>/dev/null || true
    chmod +x /usr/local/bin/ssserver
    rm -f ss-rust.tar.xz sslocal ssmanager ssurl ssservice 2>/dev/null || true
    
    mkdir -p /etc/shadowsocks
    
    cat > /etc/shadowsocks/config.json <<EOF
{
    "server":"0.0.0.0",
    "server_port":${ssport},
    "password":"${sspass}",
    "timeout":300,
    "method":"${smethod}",
    "fast_open":true
}
EOF
    
    # Create systemd service
    cat > /etc/systemd/system/shadowsocks.service <<EOF
[Unit]
Description=Shadowsocks-rust Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/ssserver -c /etc/shadowsocks/config.json
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF
    
    # Ensure service is properly configured
    systemctl daemon-reload
    systemctl enable shadowsocks.service
    sleep 1
    
    # Start service with retry logic
    echo -e "${BLUE}正在启动 Shadowsocks 服务...${NC}"
    local retry_count=0
    local max_retries=3
    
    while [ $retry_count -lt $max_retries ]; do
        systemctl restart shadowsocks.service 2>/dev/null || systemctl start shadowsocks.service 2>/dev/null
        sleep 2
        
        if systemctl is-active --quiet shadowsocks.service; then
            echo -e "${GREEN}✓ Shadowsocks-rust 服务已成功启动${NC}"
            break
        fi
        
        retry_count=$((retry_count + 1))
        if [ $retry_count -lt $max_retries ]; then
            echo -e "${YELLOW}第 ${retry_count} 次启动尝试失败，重试中...${NC}"
            sleep 2
        fi
    done
    
    if [ $retry_count -eq $max_retries ]; then
        echo -e "${RED}✗ Shadowsocks-rust 服务启动失败${NC}"
        echo ""
        echo -e "${YELLOW}=== 诊断信息 ===${NC}"
        echo -e "${YELLOW}1. 检查二进制文件:${NC}"
        ls -la /usr/local/bin/ssserver 2>&1
        echo ""
        echo -e "${YELLOW}2. 检查配置文件:${NC}"
        cat /etc/shadowsocks/config.json
        echo ""
        echo -e "${YELLOW}3. 查看服务状态:${NC}"
        systemctl status shadowsocks.service --no-pager 2>&1 | head -10
        echo ""
        echo -e "${YELLOW}4. 查看详细日志:${NC}"
        journalctl -u shadowsocks.service -n 20 --no-pager 2>&1
    fi
    
    # Save client config
    cat > /etc/shadowsocks/client.json <<EOF
=========== Shadowsocks-rust 配置信息 ===========
服务器地址: $(getIP)
端口: ${ssport}
密码: ${sspass}
加密方式: ${smethod}

ss://$(echo -n "${smethod}:${sspass}" | base64 -w 0)@$(getIP):${ssport}#Shadowsocks
EOF
    
    echo ""
    echo -e "${GREEN}Shadowsocks-rust 安装完成!${NC}"
    cat /etc/shadowsocks/client.json
}

upgrade_ssrust() {
    echo -e "${BLUE}Upgrading Shadowsocks-rust...${NC}"
    systemctl stop shadowsocks.service
    
    local ssrust_version=$(curl -sIL "https://github.com/shadowsocks/shadowsocks-rust/releases/latest" | grep -i location | sed -E 's/.*tag\/(v[0-9.]+).*/\1/')
    if [ -z "$ssrust_version" ]; then
        ssrust_version="v1.24.0"
    fi
    
    local arch=$(uname -m)
    local download_arch="x86_64-unknown-linux-gnu"
    case $arch in
        aarch64|arm64)
            download_arch="aarch64-unknown-linux-gnu"
            ;;
    esac
    
    cd /tmp
    wget -q "https://github.com/shadowsocks/shadowsocks-rust/releases/download/${ssrust_version}/shadowsocks-${ssrust_version}.${download_arch}.tar.xz" -O ss-rust.tar.xz
    tar -xf ss-rust.tar.xz
    mv ssserver /usr/local/bin/
    chmod +x /usr/local/bin/ssserver
    rm -f ss-rust.tar.xz
    
    systemctl start shadowsocks.service
    echo -e "${GREEN}Shadowsocks-rust 升级完成!${NC}"
}

uninstall_ssrust() {
    echo -e "${BLUE}Uninstalling Shadowsocks-rust...${NC}"
    systemctl stop shadowsocks.service 2>/dev/null || true
    systemctl disable shadowsocks.service 2>/dev/null || true
    rm -f /usr/local/bin/ssserver /usr/local/bin/ssservice /usr/local/bin/ssurl /usr/local/bin/ssmanager
    rm -rf /etc/shadowsocks
    rm -f /etc/systemd/system/shadowsocks.service
    systemctl daemon-reload
    echo -e "${GREEN}Shadowsocks-rust 已卸载${NC}"
}

# ==================== Reality (Xray) ====================
install_reality() {
    echo -e "${BLUE}Installing Reality...${NC}"
    
    # Ask for custom port
    echo ""
    read -t 15 -p "请输入端口号(回车或等待15秒随机生成): " rport_input
    if [ -n "$rport_input" ]; then
        local rport=$rport_input
    else
        local rport=$(shuf -i 20000-65000 -n 1)
        echo -e "${GREEN}使用随机端口: ${rport}${NC}"
    fi
    
    # Check port validity
    if ! [[ "$rport" =~ ^[0-9]+$ ]] || [ "$rport" -lt 1 ] || [ "$rport" -gt 65535 ]; then
        local rport=$(shuf -i 20000-65000 -n 1)
        echo -e "${YELLOW}端口无效，使用随机端口: ${rport}${NC}"
    fi
    
    # Check if port is in use
    if netstat -ntlp 2>/dev/null | grep -q ":$rport "; then
        echo -e "${RED}错误: 端口 ${rport} 已被占用${NC}"
        return 1
    fi
    
    local ruuid=$(gen_uuid)
    local rshortid=$(gen_random 8)
    local server_ip=$(getIP)
    local rsni="www.microsoft.com"
    local rdomain=""
    local xray_installed=false
    
    # Ask if user wants to use custom domain for TLS mode
    read -p "是否使用自己的域名(开启TLS模式)? (y/n, 默认n): " use_domain
    if [[ "$use_domain" =~ ^[Yy]$ ]]; then
        read -p "请输入已解析到本机的域名: " rdomain
        if [ -n "$rdomain" ]; then
            echo -e "${BLUE}为域名 ${rdomain} 申请证书...${NC}"
            apply_ssl "$rdomain" || {
                echo -e "${YELLOW}证书申请失败，将使用Reality模式${NC}"
                rdomain=""
            }
        fi
    fi
    
    # Install Xray if not installed
    if ! command -v xray &> /dev/null; then
        echo -e "${BLUE}正在安装 Xray...${NC}"
        bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
        xray_installed=true
    fi
    
    # Ensure xray is in PATH
    export PATH="/usr/local/bin:$PATH"
    
    # Wait for xray to be available
    local retry_count=0
    while ! command -v xray &> /dev/null && [ $retry_count -lt 5 ]; do
        sleep 1
        retry_count=$((retry_count + 1))
    done
    
    if ! command -v xray &> /dev/null; then
        echo -e "${RED}错误: Xray 安装失败或命令不可用${NC}"
        return 1
    fi
    
    echo -e "${GREEN}Xray 已安装，版本: $(xray version | head -1)${NC}"
    
    # Generate keys - Xray outputs: PrivateKey, Password (PublicKey), Hash32
    # For Reality: PrivateKey is for server, Password (PublicKey) is for client
    echo -e "${BLUE}生成 X25519 密钥对...${NC}"
    local key_output=$(xray x25519 2>/dev/null)
    
    if [ -z "$key_output" ]; then
        echo -e "${RED}错误: Xray x25519 命令无输出${NC}"
        return 1
    fi
    
    local rprivatekey=$(echo "$key_output" | grep "PrivateKey:" | awk '{print $2}' | tr -d '[:space:]')
    local rpublickey=$(echo "$key_output" | grep "Password:" | awk '{print $2}' | tr -d '[:space:]')
    
    echo -e "${BLUE}私钥长度: ${#rprivatekey}, 公钥长度: ${#rpublickey}${NC}"
    
    if [ -z "$rprivatekey" ] || [ ${#rprivatekey} -lt 40 ]; then
        echo -e "${RED}错误: 无法生成 X25519 私钥 (长度: ${#rprivatekey})${NC}"
        echo -e "${YELLOW}Xray 输出: ${key_output}${NC}"
        return 1
    fi
    
    mkdir -p /usr/local/etc/xray
    
    if [ -n "$rdomain" ]; then
        # Use TLS with real certificate
        cat > /usr/local/etc/xray/config.json <<EOF
{
  "inbounds": [
    {
      "port": ${rport},
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "${ruuid}",
            "flow": "xtls-rprx-vision"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "/usr/local/etc/xray/certs/${rdomain}.crt",
              "keyFile": "/usr/local/etc/xray/certs/${rdomain}.key"
            }
          ]
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    }
  ]
}
EOF
        
        # Setup auto-renewal
        setup_cert_renewal "$rdomain"
        
        # Save client config
        cat > /usr/local/etc/xray/reclient.json <<EOF
=========== Reality (TLS模式) 配置信息 ===========
协议: VLESS
地址: ${rdomain}
端口: ${rport}
UUID: ${ruuid}
流控: xtls-rprx-vision
安全: tls
SNI: ${rsni}

vless://${ruuid}@${rdomain}:${rport}?security=tls&sni=${rsni}&flow=xtls-rprx-vision&encryption=none#Reality-TLS
EOF
    else
        # Use Reality with steal certificate mode
        cat > /usr/local/etc/xray/config.json <<EOF
{
  "inbounds": [
    {
      "port": ${rport},
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "${ruuid}",
            "flow": "xtls-rprx-vision"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "${rsni}:443",
          "xver": 0,
          "serverNames": [
            "${rsni}"
          ],
          "privateKey": "${rprivatekey}",
          "shortIds": [
            "${rshortid}"
          ]
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    }
  ]
}
EOF
        
        # Save client config
        cat > /usr/local/etc/xray/reclient.json <<EOF
=========== Reality 配置信息 ===========
协议: VLESS
地址: ${server_ip}
端口: ${rport}
UUID: ${ruuid}
流控: xtls-rprx-vision
安全: reality
公钥: ${rpublickey}
Short ID: ${rshortid}
Server Name: ${rsni}

vless://${ruuid}@${server_ip}:${rport}?security=reality&sni=${rsni}&pbk=${rpublickey}&sid=${rshortid}&flow=xtls-rprx-vision&encryption=none#Reality
EOF
    fi
    
    # Ensure service is properly configured
    systemctl daemon-reload
    systemctl enable xray.service
    
    # Sync to ensure config is written to disk
    sync
    sleep 1
    
    # Validate config before starting
    echo -e "${BLUE}正在验证 Xray 配置...${NC}"
    local test_output=$(xray -test -config /usr/local/etc/xray/config.json 2>&1)
    if echo "$test_output" | grep -q "Configuration OK"; then
        echo -e "${GREEN}✓ 配置验证通过${NC}"
    else
        echo -e "${RED}✗ 配置验证失败${NC}"
        echo -e "${YELLOW}错误信息:${NC}"
        echo "$test_output" | head -5
        echo ""
        echo -e "${YELLOW}配置文件内容:${NC}"
        cat /usr/local/etc/xray/config.json
        return 1
    fi
    
    # Start service
    echo -e "${BLUE}正在启动 Xray 服务...${NC}"
    systemctl start xray.service
    sleep 5
    
    # Check if service is running (retry up to 3 times)
    local retry_count=0
    local max_retries=3
    while [ $retry_count -lt $max_retries ]; do
        if systemctl is-active --quiet xray.service; then
            echo -e "${GREEN}✓ Reality/Xray 服务已成功启动${NC}"
            break
        fi
        retry_count=$((retry_count + 1))
        if [ $retry_count -lt $max_retries ]; then
            echo -e "${YELLOW}等待服务启动... (${retry_count}/${max_retries})${NC}"
            sleep 3
        fi
    done
    
    if [ $retry_count -eq $max_retries ]; then
        echo -e "${RED}✗ Reality/Xray 服务启动失败${NC}"
        echo ""
        echo -e "${YELLOW}=== 诊断信息 ===${NC}"
        
        echo -e "${YELLOW}1. 检查 Xray 二进制文件:${NC}"
        which xray && xray version 2>&1 | head -2 || echo -e "${RED}Xray 未找到${NC}"
        echo ""
        
        echo -e "${YELLOW}2. 检查配置有效性:${NC}"
        xray -test -config /usr/local/etc/xray/config.json 2>&1
        echo ""
        
        echo -e "${YELLOW}3. 查看服务状态:${NC}"
        systemctl status xray.service --no-pager 2>&1 | head -10
        echo ""
        
        echo -e "${YELLOW}4. 查看详细日志:${NC}"
        journalctl -u xray.service -n 20 --no-pager 2>&1
        echo ""
        
        echo -e "${YELLOW}5. 检查端口占用:${NC}"
        netstat -tlnp 2>/dev/null | grep -E ":${rport} " || ss -tlnp 2>/dev/null | grep -E ":${rport} " || echo "端口 ${rport} 未被占用"
        echo ""
        
        echo -e "${RED}安装失败，请检查以上诊断信息${NC}"
        return 1
    fi
    
    # Final verification
    echo ""
    echo -e "${BLUE}正在验证服务状态...${NC}"
    sleep 2
    if systemctl is-active --quiet xray.service; then
        echo -e "${GREEN}✓ 服务验证成功，正在运行${NC}"
    else
        echo -e "${RED}✗ 服务验证失败，请检查日志: journalctl -u xray.service -n 20${NC}"
        return 1
    fi
    
    echo ""
    echo -e "${GREEN}Reality 安装完成!${NC}"
    cat /usr/local/etc/xray/reclient.json
}

upgrade_reality() {
    echo -e "${BLUE}Upgrading Xray...${NC}"
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
    systemctl restart xray.service
    echo -e "${GREEN}Xray 升级完成!${NC}"
}

uninstall_reality() {
    echo -e "${BLUE}Uninstalling Reality (Xray)...${NC}"
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ remove
    rm -rf /usr/local/etc/xray
    echo -e "${GREEN}Reality 已卸载${NC}"
}

# ==================== Hysteria2 ====================
install_hy2() {
    echo -e "${BLUE}Installing Hysteria2...${NC}"
    
    # Ask for custom port
    echo ""
    read -t 15 -p "请输入端口号(回车或等待15秒随机生成): " hyport_input
    if [ -n "$hyport_input" ]; then
        local hyport=$hyport_input
    else
        local hyport=$(shuf -i 20000-65000 -n 1)
        echo -e "${GREEN}使用随机端口: ${hyport}${NC}"
    fi
    
    # Check port validity
    if ! [[ "$hyport" =~ ^[0-9]+$ ]] || [ "$hyport" -lt 1 ] || [ "$hyport" -gt 65535 ]; then
        local hyport=$(shuf -i 20000-65000 -n 1)
        echo -e "${YELLOW}端口无效，使用随机端口: ${hyport}${NC}"
    fi
    
    # Check if port is in use
    if netstat -ntlp 2>/dev/null | grep -q ":$hyport "; then
        echo -e "${RED}错误: 端口 ${hyport} 已被占用${NC}"
        return 1
    fi
    
    # Ask for port hopping
    echo ""
    read -p "是否启用端口跳跃(Port Hopping)? (y/n, 默认n): " use_hop
    local hop_start=""
    local hop_end=""
    local hop_interval=""
    
    if [[ "$use_hop" =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}端口跳跃配置 (参考官方文档):${NC}"
        
        # Ask for hop start port
        read -t 15 -p "请输入起始端口 (默认: $((hyport+1))): " hop_start_input
        if [ -n "$hop_start_input" ]; then
            hop_start=$hop_start_input
        else
            hop_start=$((hyport+1))
        fi
        
        # Ask for hop end port
        read -t 15 -p "请输入结束端口 (默认: $((hyport+100))): " hop_end_input
        if [ -n "$hop_end_input" ]; then
            hop_end=$hop_end_input
        else
            hop_end=$((hyport+100))
        fi
        
        # Ask for hop interval
        read -t 15 -p "请输入跳跃间隔秒数 (默认: 30): " hop_interval_input
        if [ -n "$hop_interval_input" ]; then
            hop_interval=$hop_interval_input
        else
            hop_interval="30"
        fi
        
        echo -e "${GREEN}端口跳跃: ${hop_start}-${hop_end}, 间隔 ${hop_interval} 秒${NC}"
        
        # Open firewall ports for hopping range
        echo -e "${BLUE}正在配置防火墙端口范围...${NC}"
        local os_type=$(detect_os)
        if command -v ufw &>/dev/null; then
            ufw allow ${hop_start}:${hop_end}/tcp 2>/dev/null || true
            ufw allow ${hop_start}:${hop_end}/udp 2>/dev/null || true
        elif command -v firewall-cmd &>/dev/null; then
            firewall-cmd --add-port=${hop_start}-${hop_end}/tcp --permanent 2>/dev/null || true
            firewall-cmd --add-port=${hop_start}-${hop_end}/udp --permanent 2>/dev/null || true
            firewall-cmd --reload 2>/dev/null || true
        fi
    fi
    
    # Ask if user wants to use custom domain
    read -p "是否使用自己的域名? (y/n, 默认n): " use_domain
    
    local hypass=$(gen_random 32)
    local server_ip=$(getIP)
    local hyserver="${server_ip}"
    local hydomain=""
    local hyinsecure="1"
    
    if [[ "$use_domain" =~ ^[Yy]$ ]]; then
        read -p "请输入已解析到本机的域名: " hydomain
        if [ -n "$hydomain" ]; then
            hyserver="${hydomain}"
            
            # Apply for SSL certificate
            apply_ssl "$hydomain" && {
                hyinsecure="0"
                
                # Setup auto-renewal
                setup_cert_renewal "$hydomain"
                
                # Generate config with optional port hopping
            local listen_line="listen: :${hyport}"
            if [ -n "$hop_start" ] && [ -n "$hop_end" ]; then
                listen_line="listen: :${hyport},:${hop_start}-${hop_end}"
            fi
            
            cat > /etc/hysteria/config.yaml <<EOF
${listen_line}
auth:
  type: password
  password: ${hypass}

masquerade:
  type: proxy
  proxy:
    url: https://www.microsoft.com
    rewriteHost: true

tls:
  cert: /etc/letsencrypt/live/${hydomain}/fullchain.pem
  key: /etc/letsencrypt/live/${hydomain}/privkey.pem
$(if [ -n "$hop_interval" ]; then echo "
# 端口跳跃配置
hopInterval: ${hop_interval}s
"; fi)
EOF
            } || {
                echo -e "${YELLOW}证书申请失败，将使用自签名证书${NC}"
                hyinsecure="1"
            }
        fi
    fi
    
    # If not using domain cert, use self-signed
    if [ -z "$hydomain" ] || [ "$hyinsecure" == "1" ]; then
        # Generate config with optional port hopping
        local listen_line="listen: :${hyport}"
        if [ -n "$hop_start" ] && [ -n "$hop_end" ]; then
            listen_line="listen: :${hyport},:${hop_start}-${hop_end}"
        fi
        
        cat > /etc/hysteria/config.yaml <<EOF
${listen_line}
auth:
  type: password
  password: ${hypass}

masquerade:
  type: proxy
  proxy:
    url: https://www.microsoft.com
    rewriteHost: true

tls:
  cert: /etc/hysteria/server.crt
  key: /etc/hysteria/server.key
$(if [ -n "$hop_interval" ]; then echo "
# 端口跳跃配置
hopInterval: ${hop_interval}s
"; fi)
EOF
        
        # Generate self-signed certificate
        openssl req -x509 -nodes -newkey ec:<(openssl ecparam -name prime256v1) \
            -keyout /etc/hysteria/server.key -out /etc/hysteria/server.crt \
            -subj "/CN=www.microsoft.com" -days 36500
        
        chmod 644 /etc/hysteria/server.crt
        chmod 600 /etc/hysteria/server.key
    fi
    
    # Create systemd service
    cat > /etc/systemd/system/hysteria-server.service <<EOF
[Unit]
Description=Hysteria Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/hysteria server -c /etc/hysteria/config.yaml
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable hysteria-server.service
    sleep 1
    systemctl start hysteria-server.service
    
    # Check if service is running
    sleep 3
    if systemctl is-active --quiet hysteria-server.service; then
        echo -e "${GREEN}✓ Hysteria2 服务已成功启动${NC}"
    else
        echo -e "${RED}✗ Hysteria2 服务启动失败，正在重试...${NC}"
        systemctl daemon-reload
        sleep 1
        systemctl restart hysteria-server.service
        sleep 3
        if systemctl is-active --quiet hysteria-server.service; then
            echo -e "${GREEN}✓ Hysteria2 服务已成功启动${NC}"
        else
            echo -e "${RED}✗ Hysteria2 服务启动失败，请手动检查: journalctl -u hysteria-server.service${NC}"
        fi
    fi
    
    # Save client config
    local hop_info=""
    local hop_url_param=""
    if [ -n "$hop_start" ] && [ -n "$hop_end" ]; then
        hop_info="端口跳跃: ${hop_start}-${hop_end} (间隔 ${hop_interval}秒)"
        hop_url_param="&hop_interval=${hop_interval}"
    fi
    
    cat > /etc/hysteria/hyclient.json <<EOF
=========== Hysteria2 配置信息 ===========
服务器地址: ${hyserver}:${hyport}
密码: ${hypass}
$( [ -n "$hydomain" ] && [ "$hyinsecure" == "0" ] && echo "TLS: 已启用 (Let's Encrypt)" || echo "TLS: 自签名证书 (需跳过验证)" )
${hop_info}

hysteria2://${hypass}@${hyserver}:${hyport}$( [ "$hyinsecure" == "1" ] && echo "?insecure=1" || echo "" )$( [ -n "$hop_start" ] && echo "&hop=${hop_start}-${hop_end}&hop_interval=${hop_interval}" || echo "" )#Hysteria2
EOF
    
    echo ""
    echo -e "${GREEN}Hysteria2 安装完成!${NC}"
    cat /etc/hysteria/hyclient.json
}

upgrade_hy2() {
    echo -e "${BLUE}Upgrading Hysteria2...${NC}"
    systemctl stop hysteria-server.service
    bash <(curl -fsSL https://get.hy2.sh/)
    systemctl start hysteria-server.service
    echo -e "${GREEN}Hysteria2 升级完成!${NC}"
}

uninstall_hy2() {
    echo -e "${BLUE}Uninstalling Hysteria2...${NC}"
    systemctl stop hysteria-server.service 2>/dev/null || true
    systemctl disable hysteria-server.service 2>/dev/null || true
    rm -f /usr/local/bin/hysteria
    rm -rf /etc/hysteria
    rm -f /etc/systemd/system/hysteria-server.service
    systemctl daemon-reload
    echo -e "${GREEN}Hysteria2 已卸载${NC}"
}

# ==================== V2Ray + TLS + WebSocket ====================
install_v2ray_ws() {
    echo -e "${BLUE}Installing V2Ray + TLS + WebSocket...${NC}"
    
    # Input domain
    input_domain || return 1
    
    # Ask if user wants WebSocket support
    read -p "是否启用 WebSocket 支持? (y/n, 默认y): " use_ws
    use_ws=${use_ws:-y}
    
    local vport=$(shuf -i 20000-65000 -n 1)
    local vuuid=$(gen_uuid)
    local server_ip=$(getIP)
    local vpath="/$(gen_random 8)"
    
    # Use port 443 if no WebSocket, otherwise random port behind nginx
    if [[ "$use_ws" =~ ^[Nn]$ ]]; then
        vport=$GET_PORT
        local use_nginx=false
    else
        local use_nginx=true
    fi
    
    install_common_deps
    
    # Install Nginx if using WebSocket
    if [ "$use_nginx" = true ]; then
        local os_type=$(detect_os)
        if [ "$os_type" == "debian" ]; then
            apt-get install -y nginx
        else
            yum install -y nginx
        fi
        systemctl stop nginx 2>/dev/null || true
    fi
    
    # Apply SSL certificate
    apply_ssl "$DOMAIN" || return 1
    
    # Install Xray (includes V2Ray core)
    if ! command -v xray &> /dev/null; then
        echo -e "${BLUE}正在安装 Xray...${NC}"
        bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
    fi
    
    mkdir -p /usr/local/etc/xray
    
    if [ "$use_nginx" = true ]; then
        # WebSocket mode with Nginx
        cat > /usr/local/etc/xray/config.json <<EOF
{
  "inbounds": [
    {
      "port": ${vport},
      "listen": "127.0.0.1",
      "protocol": "vmess",
      "settings": {
        "clients": [
          {
            "id": "${vuuid}",
            "alterId": 0
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "${vpath}"
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    }
  ]
}
EOF
        
        # Configure Nginx
        cat > /etc/nginx/nginx.conf <<EOF
pid /var/run/nginx.pid;
worker_processes auto;
worker_rlimit_nofile 51200;
events {
    worker_connections 1024;
    multi_accept on;
    use epoll;
}
http {
    server_tokens off;
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 120s;
    keepalive_requests 10000;
    types_hash_max_size 2048;
    include /etc/nginx/mime.types;
    access_log off;
    error_log /dev/null;

    server {
        listen 80;
        listen [::]:80;
        server_name ${DOMAIN};
        location / {
            return 301 https://\$server_name\$request_uri;
        }
    }
    
    server {
        listen ${GET_PORT} ssl http2;
        listen [::]:${GET_PORT} ssl http2;
        server_name ${DOMAIN};
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:HIGH:!aNULL:!MD5:!RC4:!DHE;
        ssl_prefer_server_ciphers on;
        ssl_certificate /etc/letsencrypt/live/${DOMAIN}/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/${DOMAIN}/privkey.pem;
        
        location / {
            default_type text/plain;
            return 200 "Hello World!";
        }
        
        location ${vpath} {
            proxy_redirect off;
            proxy_pass http://127.0.0.1:${vport};
            proxy_http_version 1.1;
            proxy_set_header Upgrade \$http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host \$http_host;
            proxy_read_timeout 86400;
        }
    }
}
EOF
        
        systemctl daemon-reload
        systemctl enable nginx.service
        sleep 1
        systemctl start nginx.service
    else
        # Direct TLS mode without WebSocket
        cat > /usr/local/etc/xray/config.json <<EOF
{
  "inbounds": [
    {
      "port": ${vport},
      "protocol": "vmess",
      "settings": {
        "clients": [
          {
            "id": "${vuuid}",
            "alterId": 0
          }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "/usr/local/etc/xray/certs/${DOMAIN}.crt",
              "keyFile": "/usr/local/etc/xray/certs/${DOMAIN}.key"
            }
          ]
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    }
  ]
}
EOF
    fi
    
    # Ensure service is properly configured
    systemctl daemon-reload
    systemctl enable xray.service
    
    # Sync to ensure config is written to disk
    sync
    sleep 1
    
    # Validate config before starting
    echo -e "${BLUE}正在验证 Xray 配置...${NC}"
    local test_output=$(xray -test -config /usr/local/etc/xray/config.json 2>&1)
    if echo "$test_output" | grep -q "Configuration OK"; then
        echo -e "${GREEN}✓ 配置验证通过${NC}"
    else
        echo -e "${RED}✗ 配置验证失败${NC}"
        echo -e "${YELLOW}错误信息:${NC}"
        echo "$test_output" | head -5
        return 1
    fi
    
    # Start service
    echo -e "${BLUE}正在启动 Xray 服务...${NC}"
    systemctl start xray.service
    sleep 5
    
    # Check if service is running
    if systemctl is-active --quiet xray.service; then
        echo -e "${GREEN}✓ V2Ray 服务已成功启动${NC}"
    else
        echo -e "${RED}✗ V2Ray 服务启动失败${NC}"
        echo -e "${YELLOW}查看日志: journalctl -u xray.service -n 20${NC}"
        return 1
    fi
    
    # Save client config
    mkdir -p /usr/local/etc/xray
    if [ "$use_nginx" = true ]; then
        cat > /usr/local/etc/xray/v2client.json <<EOF
=========== V2Ray + TLS + WebSocket 配置信息 ===========
协议: VMess
地址: ${DOMAIN}
端口: ${GET_PORT}
UUID: ${vuuid}
AlterID: 0
传输协议: WebSocket
路径: ${vpath}
TLS: 开启
SNI: ${DOMAIN}

vmess://$(echo -n '{"v":"2","ps":"V2Ray-WS","add":"${DOMAIN}","port":"${GET_PORT}","id":"${vuuid}","aid":"0","net":"ws","type":"none","host":"${DOMAIN}","path":"${vpath}","tls":"tls"}' | base64 -w 0)
EOF
    else
        cat > /usr/local/etc/xray/v2client.json <<EOF
=========== V2Ray + TLS 配置信息 ===========
协议: VMess
地址: ${DOMAIN}
端口: ${vport}
UUID: ${vuuid}
AlterID: 0
传输协议: TCP
TLS: 开启
SNI: ${DOMAIN}

vmess://$(echo -n '{"v":"2","ps":"V2Ray-TLS","add":"${DOMAIN}","port":"${vport}","id":"${vuuid}","aid":"0","net":"tcp","type":"none","tls":"tls"}' | base64 -w 0)
EOF
    fi
    
    # Setup auto-renewal
    setup_cert_renewal "$DOMAIN"
    
    echo ""
    echo -e "${GREEN}V2Ray 安装完成!${NC}"
    cat /usr/local/etc/xray/v2client.json
}

upgrade_v2ray_ws() {
    echo -e "${BLUE}Upgrading Xray...${NC}"
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
    systemctl restart xray.service
    echo -e "${GREEN}Xray 升级完成!${NC}"
}

uninstall_v2ray_ws() {
    echo -e "${BLUE}Uninstalling V2Ray...${NC}"
    systemctl stop xray.service nginx.service 2>/dev/null || true
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ remove
    rm -rf /usr/local/etc/xray
    rm -f /etc/systemd/system/xray.service
    systemctl daemon-reload
    echo -e "${GREEN}V2Ray 已卸载${NC}"
}

# ==================== Snell ====================
install_snell() {
    echo -e "${BLUE}Installing Snell...${NC}"
    
    # Ask for custom port
    echo ""
    read -t 15 -p "请输入端口号(回车或等待15秒随机生成): " snport_input
    if [ -n "$snport_input" ]; then
        local snport=$snport_input
    else
        local snport=$(shuf -i 20000-65000 -n 1)
        echo -e "${GREEN}使用随机端口: ${snport}${NC}"
    fi
    
    # Check port validity
    if ! [[ "$snport" =~ ^[0-9]+$ ]] || [ "$snport" -lt 1 ] || [ "$snport" -gt 65535 ]; then
        local snport=$(shuf -i 20000-65000 -n 1)
        echo -e "${YELLOW}端口无效，使用随机端口: ${snport}${NC}"
    fi
    
    # Check if port is in use
    if netstat -ntlp 2>/dev/null | grep -q ":$snport "; then
        echo -e "${RED}错误: 端口 ${snport} 已被占用${NC}"
        return 1
    fi
    
    # Ask for custom DNS servers
    echo ""
    read -t 15 -p "请输入 DNS 服务器(回车或等待15秒使用默认 8.8.8.8,1.1.1.1): " sndns_input
    if [ -n "$sndns_input" ]; then
        local sndns="$sndns_input"
        echo -e "${GREEN}使用自定义 DNS: ${sndns}${NC}"
    else
        local sndns="8.8.8.8, 1.1.1.1"
        echo -e "${GREEN}使用默认 DNS: ${sndns}${NC}"
    fi
    
    local snpsk=$(gen_random 32)
    local server_ip=$(getIP)
    
    # Detect architecture
    local arch=$(uname -m)
    local download_arch="amd64"
    case $arch in
        x86_64)
            download_arch="amd64"
            ;;
        aarch64|arm64)
            download_arch="aarch64"
            ;;
        armv7l)
            download_arch="armv7l"
            ;;
        i386|i686)
            download_arch="i386"
            ;;
    esac
    
    # Get latest Snell version from official release notes
    echo -e "${BLUE}获取 Snell 最新版本...${NC}"
    local snell_version=$(curl -s "https://kb.nssurge.com/surge-knowledge-base/zh/release-notes/snell" 2>/dev/null | grep -oE "snell-server-v[0-9]+\.[0-9]+\.[0-9]+" | head -1 | sed 's/snell-server-v//')
    if [ -z "$snell_version" ]; then
        snell_version="v5.0.1"
        echo -e "${YELLOW}获取版本失败，使用默认版本 ${snell_version}${NC}"
    else
        snell_version="v${snell_version}"
        echo -e "${GREEN}最新版本: ${snell_version}${NC}"
    fi
    
    cd /tmp
    echo -e "${BLUE}下载 Snell ${snell_version}...${NC}"
    # Official Snell download source
    local download_url="https://dl.nssurge.com/snell/snell-server-${snell_version}-linux-${download_arch}.zip"
    
    if ! wget -q --show-progress "$download_url" -O snell.zip 2>/dev/null; then
        echo -e "${YELLOW}官方源失败，尝试备用链接...${NC}"
        # Fallback to GitHub backup
        download_url="https://raw.githubusercontent.com/xOS/Others/master/snell/${snell_version}/snell-server-${snell_version}-linux-${download_arch}.zip"
        if ! wget -q --show-progress "$download_url" -O snell.zip 2>/dev/null; then
            echo -e "${RED}下载失败，请检查网络或手动下载安装包${NC}"
            return 1
        fi
    fi
    
    # Verify download
    if [ ! -f "snell.zip" ] || [ $(stat -c%s snell.zip 2>/dev/null || echo 0) -lt 1000 ]; then
        echo -e "${RED}下载文件无效或太小，可能是 GitHub 限制${NC}"
        rm -f snell.zip
        return 1
    fi
    
    if ! unzip -o snell.zip 2>/dev/null; then
        echo -e "${RED}解压失败，文件可能已损坏${NC}"
        rm -f snell.zip
        return 1
    fi
    
    mv snell-server /usr/local/bin/
    chmod +x /usr/local/bin/snell-server
    rm -f snell.zip
    
    mkdir -p /etc/snell
    
    # Snell v5 configuration with DNS support
    cat > /etc/snell/snell-server.conf <<EOF
[snell-server]
listen = 0.0.0.0:${snport}
psk = ${snpsk}
ipv6 = false
dns = ${sndns}
EOF
    
    # Create systemd service
    cat > /etc/systemd/system/snell.service <<EOF
[Unit]
Description=Snell Proxy Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/snell-server -c /etc/snell/snell-server.conf
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable snell.service
    sleep 1
    systemctl start snell.service
    
    # Check if service is running
    sleep 3
    if systemctl is-active --quiet snell.service; then
        echo -e "${GREEN}✓ Snell 服务已成功启动${NC}"
    else
        echo -e "${RED}✗ Snell 服务启动失败，正在重试...${NC}"
        systemctl daemon-reload
        sleep 1
        systemctl restart snell.service
        sleep 3
        if systemctl is-active --quiet snell.service; then
            echo -e "${GREEN}✓ Snell 服务已成功启动${NC}"
        else
            echo -e "${RED}✗ Snell 服务启动失败，请手动检查: journalctl -u snell.service${NC}"
        fi
    fi
    
    # Save client config
    cat > /etc/snell/client.json <<EOF
=========== Snell 配置信息 ===========
服务器地址: ${server_ip}
端口: ${snport}
PSK: ${snpsk}
版本: 5
DNS: ${sndns}

snell://${snpsk}@${server_ip}:${snport}?version=5#Snell
EOF
    
    echo ""
    echo -e "${GREEN}Snell 安装完成!${NC}"
    cat /etc/snell/client.json
}

upgrade_snell() {
    echo -e "${BLUE}Upgrading Snell...${NC}"
    systemctl stop snell.service
    
    local arch=$(uname -m)
    local download_arch="amd64"
    case $arch in
        aarch64|arm64)
            download_arch="aarch64"
            ;;
        armv7l)
            download_arch="armv7l"
            ;;
    esac
    
    # Get latest version for upgrade (official source)
    local snell_version=$(curl -s "https://kb.nssurge.com/surge-knowledge-base/zh/release-notes/snell" 2>/dev/null | grep -oE "snell-server-v[0-9]+\.[0-9]+\.[0-9]+" | head -1 | sed 's/snell-server-v//')
    
    # Default to v5 if version detection fails
    if [ -z "$snell_version" ]; then
        snell_version="5.0.1"
        echo -e "${YELLOW}获取版本失败，使用默认版本 v${snell_version}${NC}"
    fi
    if [ -z "$snell_version" ]; then
        snell_version="5.0.1"
    fi
    
    cd /tmp
    # Official Snell download source
    local download_url="https://dl.nssurge.com/snell/snell-server-v${snell_version}-linux-${download_arch}.zip"
    
    if ! wget -q --show-progress "$download_url" -O snell.zip 2>/dev/null; then
        echo -e "${YELLOW}官方源失败，尝试备用链接...${NC}"
        # Fallback
        download_url="https://raw.githubusercontent.com/xOS/Others/master/snell/v${snell_version}/snell-server-v${snell_version}-linux-${download_arch}.zip"
        wget -q --show-progress "$download_url" -O snell.zip
    fi
    
    unzip -o snell.zip
    mv snell-server /usr/local/bin/
    chmod +x /usr/local/bin/snell-server
    rm -f snell.zip
    
    systemctl start snell.service
    echo -e "${GREEN}Snell 升级完成!${NC}"
}

uninstall_snell() {
    echo -e "${BLUE}Uninstalling Snell...${NC}"
    systemctl stop snell.service 2>/dev/null || true
    systemctl disable snell.service 2>/dev/null || true
    rm -f /usr/local/bin/snell-server
    rm -rf /etc/snell
    rm -f /etc/systemd/system/snell.service
    systemctl daemon-reload
    echo -e "${GREEN}Snell 已卸载${NC}"
}

# Check installed proxies
check_installed() {
    echo ""
    echo -e "${YELLOW}=========== 已安装代理状态 ===========${NC}"
    
    # Shadowsocks-rust
    if systemctl is-active --quiet shadowsocks.service 2>/dev/null; then
        echo -e "${GREEN}✓ Shadowsocks-rust: 运行中${NC}"
    elif [ -f /etc/shadowsocks/config.json ]; then
        echo -e "${YELLOW}○ Shadowsocks-rust: 已安装但未运行${NC}"
    else
        echo -e "${RED}✗ Shadowsocks-rust: 未安装${NC}"
    fi
    
    # Reality - check for reclient.json specifically
    if systemctl is-active --quiet xray.service 2>/dev/null && [ -f /usr/local/etc/xray/reclient.json ]; then
        echo -e "${GREEN}✓ Reality (Xray): 运行中${NC}"
    elif [ -f /usr/local/etc/xray/reclient.json ]; then
        echo -e "${YELLOW}○ Reality (Xray): 已安装但未运行${NC}"
    else
        echo -e "${RED}✗ Reality (Xray): 未安装${NC}"
    fi
    
    # Hysteria2
    if systemctl is-active --quiet hysteria-server.service 2>/dev/null; then
        echo -e "${GREEN}✓ Hysteria2: 运行中${NC}"
    elif [ -f /etc/hysteria/config.yaml ]; then
        echo -e "${YELLOW}○ Hysteria2: 已安装但未运行${NC}"
    else
        echo -e "${RED}✗ Hysteria2: 未安装${NC}"
    fi
    
    # V2Ray+WS - check for v2client.json specifically
    if systemctl is-active --quiet xray.service 2>/dev/null && [ -f /usr/local/etc/xray/v2client.json ]; then
        echo -e "${GREEN}✓ V2Ray+TLS+WS: 运行中${NC}"
 elif [ -f /usr/local/etc/xray/v2client.json ]; then
        echo -e "${YELLOW}○ V2Ray+TLS+WS: 已安装但未运行${NC}"
    else
        echo -e "${RED}✗ V2Ray+TLS+WS: 未安装${NC}"
    fi
    
    # Snell
    if systemctl is-active --quiet snell.service 2>/dev/null; then
        echo -e "${GREEN}✓ Snell: 运行中${NC}"
    elif [ -f /etc/snell/snell-server.conf ]; then
        echo -e "${YELLOW}○ Snell: 已安装但未运行${NC}"
    else
        echo -e "${RED}✗ Snell: 未安装${NC}"
    fi
    
    echo ""
}

# Show client configs
show_configs() {
    echo ""
    echo -e "${YELLOW}=========== 客户端配置信息 ===========${NC}"
    
    local has_config=false
    
    if [ -f /etc/shadowsocks/client.json ]; then
        echo ""
        echo -e "${BLUE}--- Shadowsocks-rust ---${NC}"
        cat /etc/shadowsocks/client.json
        has_config=true
    fi
    
    if [ -f /usr/local/etc/xray/reclient.json ]; then
        echo ""
        echo -e "${BLUE}--- Reality ---${NC}"
        cat /usr/local/etc/xray/reclient.json
        has_config=true
    fi
    
    if [ -f /etc/hysteria/hyclient.json ]; then
        echo ""
        echo -e "${BLUE}--- Hysteria2 ---${NC}"
        cat /etc/hysteria/hyclient.json
        has_config=true
    fi
    
    if [ -f /usr/local/etc/xray/v2client.json ]; then
        echo ""
        echo -e "${BLUE}--- V2Ray+TLS+WS ---${NC}"
        cat /usr/local/etc/xray/v2client.json
        has_config=true
    fi
    
    if [ -f /etc/snell/client.json ]; then
        echo ""
        echo -e "${BLUE}--- Snell ---${NC}"
        cat /etc/snell/client.json
        has_config=true
    fi
    
    if [ "$has_config" = false ]; then
        echo ""
        echo -e "${YELLOW}未找到任何代理配置${NC}"
    fi
    
    echo ""
    read -p "按回车键继续..."
}

# ==================== Menu Functions ====================

install_menu() {
    clear
    check_installed
    
    echo -e "${YELLOW}=========== 安装代理 ===========${NC}"
    echo " 1. 安装 Shadowsocks-rust (不需要域名)"
    echo " 2. 安装 Reality (可选域名)"
    echo " 3. 安装 Hysteria2 (可选域名)"
    echo " 4. 安装 V2Ray+TLS+WS (需要域名，可选WS)"
    echo " 5. 安装 Snell (不需要域名)"
    echo " 0. 返回主菜单"
    echo ""
    read -p "请输入数字: " num
    
    case "$num" in
        1) install_ssrust ;;
        2) install_reality ;;
        3) install_hy2 ;;
        4) install_v2ray_ws ;;
        5) install_snell ;;
        0) return ;;
        *) echo -e "${RED}请输入正确数字${NC}"; sleep 2 ;;
    esac
    
    echo ""
    read -p "按回车键继续..."
}

upgrade_menu() {
    clear
    check_installed
    
    echo -e "${YELLOW}=========== 升级代理 ===========${NC}"
    echo " 1. 升级 Shadowsocks-rust"
    echo " 2. 升级 Reality (Xray)"
    echo " 3. 升级 Hysteria2"
    echo " 4. 升级 V2Ray+TLS+WS"
    echo " 5. 升级 Snell"
    echo " 6. 升级所有代理"
    echo " 0. 返回主菜单"
    echo ""
    read -p "请输入数字: " num
    
    case "$num" in
        1) upgrade_ssrust ;;
        2) upgrade_reality ;;
        3) upgrade_hy2 ;;
        4) upgrade_v2ray_ws ;;
        5) upgrade_snell ;;
        6) 
            upgrade_ssrust
            upgrade_reality
            upgrade_hy2
            upgrade_v2ray_ws
            upgrade_snell
            ;;
        0) return ;;
        *) echo -e "${RED}请输入正确数字${NC}"; sleep 2 ;;
    esac
    
    echo ""
    read -p "按回车键继续..."
}

uninstall_menu() {
    clear
    check_installed
    
    echo -e "${YELLOW}=========== 卸载代理 ===========${NC}"
    echo " 1. 卸载 Shadowsocks-rust"
    echo " 2. 卸载 Reality (Xray)"
    echo " 3. 卸载 Hysteria2"
    echo " 4. 卸载 V2Ray+TLS+WS"
    echo " 5. 卸载 Snell"
    echo " 6. 卸载所有代理"
    echo " 0. 返回主菜单"
    echo ""
    read -p "请输入数字: " num
    
    case "$num" in
        1) uninstall_ssrust ;;
        2) uninstall_reality ;;
        3) uninstall_hy2 ;;
        4) uninstall_v2ray_ws ;;
        5) uninstall_snell ;;
        6)
            uninstall_ssrust
            uninstall_reality
            uninstall_hy2
            uninstall_v2ray_ws
            uninstall_snell
            ;;
        0) return ;;
        *) echo -e "${RED}请输入正确数字${NC}"; sleep 2 ;;
    esac
    
    echo ""
    read -p "按回车键继续..."
}

# Main menu
show_menu() {
    clear
    check_installed
    
    # Calculate padding for centering
    local title="SIMPLEPROXY v${SCRIPT_VERSION}"
    local width=38
    local padding=$(( (width - ${#title}) / 2 ))
    local left_pad=$(printf '%*s' "$padding" '')
    local right_pad=$(printf '%*s' $((width - padding - ${#title})) '')
    
    echo -e "${YELLOW}╔══════════════════════════════════════╗${NC}"
    echo -e "${YELLOW}║${left_pad}${title}${right_pad}║${NC}"
    echo -e "${YELLOW}╚══════════════════════════════════════╝${NC}"
    echo ""
    echo " 1. 安装代理"
    echo " 2. 升级代理"
    echo " 3. 卸载代理"
    echo " 4. 查看配置"
    echo " 0. 退出"
    echo ""
    read -p "请输入数字: " num
    
    case "$num" in
        1) install_menu ;;
        2) upgrade_menu ;;
        3) uninstall_menu ;;
        4) show_configs ;;
        0) exit 0 ;;
        *) echo -e "${RED}请输入正确数字${NC}"; sleep 2 ;;
    esac
}

# Main loop
while true; do
    show_menu
    # Note: Submenus already handle "press any key to continue"
done
