#!/bin/bash
# Proxy Install Script - Modified from yeahwu/v2ray-wss
# Supports: Shadowsocks-rust, Reality, Hysteria2, AnyTLS, Snell
# forum: https://1024.day

if [[ $EUID -ne 0 ]]; then
    clear
    echo "Error: This script must be run as root!" 1>&2
    exit 1
fi

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
    cat /proc/sys/kernel/random/uuid 2>/dev/null || tr -dc 'a-f0-9' < /dev/urandom | head -c 8; echo -n '-'; tr -dc 'a-f0-9' < /dev/urandom | head -c 4; echo -n '-4'; tr -dc 'a-f0-9' < /dev/urandom | head -c 3; echo -n '-'; tr -dc '89ab' < /dev/urandom | head -c 1; tr -dc 'a-f0-9' < /dev/urandom | head -c 3; echo -n '-'; tr -dc 'a-f0-9' < /dev/urandom | head -c 12
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
    
    # Create directory
    mkdir -p /etc/letsencrypt/live/$domain
    
    # Issue certificate using standalone mode
    ~/.acme.sh/acme.sh --issue -d $domain --standalone --keylength ec-256 --force
    
    if [ $? -ne 0 ]; then
        echo -e "${RED}证书申请失败，请检查:${NC}"
        echo "1. 域名是否正确解析到本机IP"
        echo "2. 80端口是否被占用"
        return 1
    fi
    
    # Install certificate
    ~/.acme.sh/acme.sh --installcert -d $domain --ecc \
        --fullchain-file /etc/letsencrypt/live/$domain/fullchain.pem \
        --key-file /etc/letsencrypt/live/$domain/privkey.pem \
        --reloadcmd "systemctl restart nginx 2>/dev/null || true"
    
    echo -e "${GREEN}SSL证书安装成功!${NC}"
    return 0
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
    
    local sspass=$(gen_random 16)
    local smethod="aes-256-gcm"
    
    # Get latest version from GitHub releases redirect (no API)
    echo -e "${BLUE}获取 Shadowsocks-rust 最新版本...${NC}"
    local ssrust_version=$(curl -sI "https://github.com/shadowsocks/shadowsocks-rust/releases/latest" | grep -i location | sed -E 's/.*tag\/(v[0-9.]+).*/\1/')
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
    
    # Create config
    mkdir -p /etc/shadowsocks
    cat > /etc/shadowsocks/config.json <<EOF
{
    "server": "0.0.0.0",
    "server_port": ${ssport},
    "password": "${sspass}",
    "method": "${smethod}",
    "fast_open": true,
    "nameserver": "8.8.8.8",
    "mode": "tcp_and_udp"
}
EOF
    
    # Create systemd service
    cat > /etc/systemd/system/shadowsocks.service <<EOF
[Unit]
Description=Shadowsocks Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/ssserver -c /etc/shadowsocks/config.json
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable shadowsocks.service
    sleep 1
    systemctl start shadowsocks.service
    
    # Check if service is running
    sleep 3
    if systemctl is-active --quiet shadowsocks.service; then
        echo -e "${GREEN}✓ Shadowsocks-rust 服务已成功启动${NC}"
    else
        echo -e "${RED}✗ Shadowsocks-rust 服务启动失败，正在重试...${NC}"
        systemctl daemon-reload
        sleep 1
        systemctl restart shadowsocks.service
        sleep 3
        if systemctl is-active --quiet shadowsocks.service; then
            echo -e "${GREEN}✓ Shadowsocks-rust 服务已成功启动${NC}"
        else
            echo -e "${RED}✗ Shadowsocks-rust 服务启动失败，请手动检查: journalctl -u shadowsocks.service${NC}"
        fi
    fi
    
    # Save client config
    local server_ip=$(getIP)
    cat > /etc/shadowsocks/client.json <<EOF
=========== Shadowsocks-rust 配置信息 ===========
服务器地址: ${server_ip}
端口: ${ssport}
密码: ${sspass}
加密方式: ${smethod}

 shadowsocks://$(echo -n "${smethod}:${sspass}@${server_ip}:${ssport}" | base64 -w 0)
EOF
    
    echo ""
    echo -e "${GREEN}Shadowsocks-rust 安装完成!${NC}"
    cat /etc/shadowsocks/client.json
}

upgrade_ssrust() {
    echo -e "${BLUE}Upgrading Shadowsocks-rust...${NC}"
    systemctl stop shadowsocks.service
    install_ssrust
    echo -e "${GREEN}Shadowsocks-rust 升级完成!${NC}"
}

uninstall_ssrust() {
    echo -e "${BLUE}Uninstalling Shadowsocks-rust...${NC}"
    systemctl stop shadowsocks.service 2>/dev/null || true
    systemctl disable shadowsocks.service 2>/dev/null || true
    rm -f /usr/local/bin/ssserver /usr/local/bin/sslocal /usr/local/bin/ssmanager /usr/local/bin/ssurl /usr/local/bin/ssservice
    rm -rf /etc/shadowsocks
    rm -f /etc/systemd/system/shadowsocks.service
    systemctl daemon-reload
    echo -e "${GREEN}Shadowsocks-rust 已卸载${NC}"
}

# ==================== Reality ====================
install_reality() {
    echo -e "${BLUE}Installing Reality (Xray)...${NC}"
    
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
    
    # Ask if user wants to use custom domain
    read -p "是否使用自己的域名? (y/n, 默认n): " use_domain
    
    local server_ip=$(getIP)
    local rsni="www.microsoft.com"
    local rdomain=""
    local xray_installed=false
    
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
    local key_output=$(xray x25519 2>/dev/null)
    local rprivatekey=$(echo "$key_output" | grep "PrivateKey:" | awk '{print $2}' | tr -d '[:space:]')
    local rpublickey=$(echo "$key_output" | grep "Password:" | awk '{print $2}' | tr -d '[:space:]')
    
    if [ -z "$rprivatekey" ] || [ ${#rprivatekey} -lt 40 ]; then
        echo -e "${RED}错误: 无法生成 X25519 私钥${NC}"
        return 1
    fi
    
    if [ -z "$rpublickey" ] || [ ${#rpublickey} -lt 40 ]; then
        echo -e "${RED}错误: 无法生成 X25519 公钥${NC}"
        return 1
    fi
    
    local rshortid=$(openssl rand -hex 4 | tr -d '[:space:]')
    local ruuid=$(gen_uuid | tr -d '[:space:]')
    
    # If using custom domain
    if [[ "$use_domain" =~ ^[Yy]$ ]]; then
        install_common_deps
        
        echo ""
        echo -e "${YELLOW}==== Reality 域名配置 ====${NC}"
        read -p "请输入已解析到本机的域名: " rdomain
        
        if [ -n "$rdomain" ]; then
            rsni="$rdomain"
            
            # Apply for SSL certificate
            apply_ssl "$rdomain" || {
                echo -e "${YELLOW}证书申请失败，将使用默认偷证书模式${NC}"
                rsni="www.microsoft.com"
                rdomain=""
            }
        fi
    fi
    
    mkdir -p /usr/local/etc/xray
    
    # Stop xray service before modifying config
    systemctl stop xray.service 2>/dev/null || true
    
    # Build realitySettings based on whether we have a domain
    if [ -n "$rdomain" ] && [ -f "/etc/letsencrypt/live/$rdomain/fullchain.pem" ]; then
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
              "certificateFile": "/etc/letsencrypt/live/${rdomain}/fullchain.pem",
              "keyFile": "/etc/letsencrypt/live/${rdomain}/privkey.pem"
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
    
    # Validate config before starting
    echo -e "${BLUE}正在验证 Xray 配置...${NC}"
    if xray -test -config /usr/local/etc/xray/config.json 2>&1 | grep -q "Configuration OK"; then
        echo -e "${GREEN}✓ 配置验证通过${NC}"
    else
        echo -e "${YELLOW}配置可能有警告，继续尝试启动...${NC}"
    fi
    
    # Start service
    echo -e "${BLUE}正在启动 Xray 服务...${NC}"
    systemctl start xray.service
    sleep 3
    
    # Check if service is running
    if systemctl is-active --quiet xray.service; then
        echo -e "${GREEN}✓ Reality/Xray 服务已成功启动${NC}"
    else
        echo -e "${RED}✗ 第一次启动失败，正在重试...${NC}"
        systemctl daemon-reload
        sleep 1
        systemctl restart xray.service
        sleep 3
        if systemctl is-active --quiet xray.service; then
            echo -e "${GREEN}✓ Reality/Xray 服务已成功启动${NC}"
        else
            echo -e "${RED}✗ Reality/Xray 服务启动失败${NC}"
            echo ""
            echo -e "${YELLOW}=== 诊断信息 ===${NC}"
            echo -e "${YELLOW}1. 检查配置有效性:${NC}"
            xray -test -config /usr/local/etc/xray/config.json 2>&1 | head -5
            echo ""
            echo -e "${YELLOW}2. 查看日志:${NC}"
            journalctl -u xray.service -n 10 --no-pager
            echo ""
            echo -e "${YELLOW}3. 配置文件内容:${NC}"
            cat /usr/local/etc/xray/config.json
        fi
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
    
    # Ask if user wants to use custom domain
    read -p "是否使用自己的域名? (y/n, 默认n): " use_domain
    
    local hypass=$(gen_random 16)
    local server_ip=$(getIP)
    local hydomain=""
    local hyinsecure="1"
    local hyserver="${server_ip}"
    
    # Install Hysteria2
    bash <(curl -fsSL https://get.hy2.sh/)
    
    mkdir -p /etc/hysteria
    
    # If using custom domain
    if [[ "$use_domain" =~ ^[Yy]$ ]]; then
        install_common_deps
        
        echo ""
        echo -e "${YELLOW}==== Hysteria2 域名配置 ====${NC}"
        read -p "请输入已解析到本机的域名: " hydomain
        
        if [ -n "$hydomain" ]; then
            hyserver="${hydomain}"
            
            # Apply for SSL certificate
            apply_ssl "$hydomain" && {
                hyinsecure="0"
                
                # Setup auto-renewal
                setup_cert_renewal "$hydomain"
                
                cat > /etc/hysteria/config.yaml <<EOF
listen: :${hyport}

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
EOF
            } || {
                echo -e "${YELLOW}证书申请失败，将使用自签名证书${NC}"
                hyinsecure="1"
            }
        fi
    fi
    
    # If not using domain cert, use self-signed
    if [ -z "$hydomain" ] || [ "$hyinsecure" == "1" ]; then
        cat > /etc/hysteria/config.yaml <<EOF
listen: :${hyport}

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
    cat > /etc/hysteria/hyclient.json <<EOF
=========== Hysteria2 配置信息 ===========
服务器地址: ${hyserver}:${hyport}
密码: ${hypass}
$( [ -n "$hydomain" ] && [ "$hyinsecure" == "0" ] && echo "TLS: 已启用 (Let's Encrypt)" || echo "TLS: 自签名证书 (需跳过验证)" )

hysteria2://${hypass}@${hyserver}:${hyport}$( [ "$hyinsecure" == "1" ] && echo "?insecure=1" || echo "" )#Hysteria2
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

# ==================== AnyTLS ====================
install_anytls() {
    echo -e "${BLUE}Installing AnyTLS...${NC}"
    
    # Input domain
    input_domain || return 1
    
    local atport=8443
    local atpass=$(gen_random 32)
    local server_ip=$(getIP)
    
    install_common_deps
    
    # Install Nginx for reverse proxy
    local os_type=$(detect_os)
    if [ "$os_type" == "debian" ]; then
        apt-get install -y nginx
    else
        yum install -y nginx
    fi
    
    # Stop nginx for certificate application
    systemctl stop nginx 2>/dev/null || true
    
    # Apply SSL certificate
    apply_ssl "$DOMAIN" || return 1
    
    # Get latest version from GitHub releases redirect (no API)
    echo -e "${BLUE}获取 AnyTLS 最新版本...${NC}"
    local anytls_version=$(curl -sI "https://github.com/anytls/sink/releases/latest" | grep -i location | sed -E 's/.*tag\/(v[0-9.]+).*/\1/')
    if [ -z "$anytls_version" ]; then
        anytls_version="v0.11.0"
        echo -e "${YELLOW}获取版本失败，使用默认版本 ${anytls_version}${NC}"
    else
        echo -e "${GREEN}最新版本: ${anytls_version}${NC}"
    fi
    local arch=$(uname -m)
    local download_arch="x86_64-unknown-linux-musl"
    case $arch in
        aarch64|arm64)
            download_arch="aarch64-unknown-linux-musl"
            ;;
    esac
    
    local download_url="https://github.com/anytls/sink/releases/download/${anytls_version}/sink-${anytls_version}-${download_arch}.tar.gz"
    
    cd /tmp
    echo -e "${BLUE}下载 AnyTLS ${anytls_version}...${NC}"
    if ! wget -q --show-progress "$download_url" -O anytls.tar.gz; then
        echo -e "${RED}下载失败，请检查网络或手动下载${NC}"
        return 1
    fi
    
    # Verify download
    if [ ! -f "anytls.tar.gz" ] || [ $(stat -c%s anytls.tar.gz 2>/dev/null || echo 0) -lt 1000 ]; then
        echo -e "${RED}下载文件无效，可能是 GitHub 限制${NC}"
        rm -f anytls.tar.gz
        return 1
    fi
    
    tar -xzf anytls.tar.gz
    mv sink /usr/local/bin/anytls
    chmod +x /usr/local/bin/anytls
    rm -f anytls.tar.gz
    
    mkdir -p /etc/anytls
    
    # Generate certificate fingerprint
    local cert_fp=$(openssl x509 -in /etc/letsencrypt/live/$DOMAIN/fullchain.pem -noout -fingerprint -sha256 | cut -d= -f2 | tr -d ':')
    
    cat > /etc/anytls/config.json <<EOF
{
    "listen": "127.0.0.1:${atport}",
    "password": "${atpass}",
    "cert": "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem",
    "key": "/etc/letsencrypt/live/${DOMAIN}/privkey.pem",
    "congestion_control": "bbr"
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
        
        location /anytls {
            proxy_redirect off;
            proxy_pass http://127.0.0.1:${atport};
            proxy_http_version 1.1;
            proxy_set_header Upgrade \$http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host \$http_host;
        }
    }
}
EOF
    
    # Create systemd service for AnyTLS
    cat > /etc/systemd/system/anytls.service <<EOF
[Unit]
Description=AnyTLS Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/anytls -c /etc/anytls/config.json
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable anytls.service nginx.service
    sleep 1
    systemctl start anytls.service nginx.service
    
    # Check if services are running
    sleep 3
    local anytls_ok=false
    local nginx_ok=false
    
    if systemctl is-active --quiet anytls.service; then
        echo -e "${GREEN}✓ AnyTLS 服务已成功启动${NC}"
        anytls_ok=true
    else
        echo -e "${RED}✗ AnyTLS 服务启动失败，正在重试...${NC}"
        systemctl daemon-reload
        sleep 1
        systemctl restart anytls.service
        sleep 3
        if systemctl is-active --quiet anytls.service; then
            echo -e "${GREEN}✓ AnyTLS 服务已成功启动${NC}"
            anytls_ok=true
        else
            echo -e "${RED}✗ AnyTLS 服务启动失败，请手动检查: journalctl -u anytls.service${NC}"
        fi
    fi
    
    if systemctl is-active --quiet nginx.service; then
        echo -e "${GREEN}✓ Nginx 服务已成功启动${NC}"
        nginx_ok=true
    else
        echo -e "${RED}✗ Nginx 服务启动失败，正在重试...${NC}"
        systemctl daemon-reload
        sleep 1
        systemctl restart nginx.service
        sleep 3
        if systemctl is-active --quiet nginx.service; then
            echo -e "${GREEN}✓ Nginx 服务已成功启动${NC}"
            nginx_ok=true
        else
            echo -e "${RED}✗ Nginx 服务启动失败，请手动检查: nginx -t${NC}"
        fi
    fi
    
    # Setup auto-renewal
    setup_cert_renewal "$DOMAIN"
    
    # Save client config
    cat > /etc/anytls/client.json <<EOF
=========== AnyTLS 配置信息 ===========
服务器地址: ${DOMAIN}
端口: ${GET_PORT}
密码: ${atpass}
路径: /anytls
SNI: ${DOMAIN}
指纹: ${cert_fp}

anytls://${atpass}@${DOMAIN}:${GET_PORT}?sni=${DOMAIN}&fp=${cert_fp}&path=/anytls#AnyTLS
EOF
    
    echo ""
    echo -e "${GREEN}AnyTLS 安装完成!${NC}"
    cat /etc/anytls/client.json
}

upgrade_anytls() {
    echo -e "${BLUE}Upgrading AnyTLS...${NC}"
    systemctl stop anytls.service
    
    # Fixed version, no API call
    local anytls_version="v0.11.0"
    local arch=$(uname -m)
    local download_arch="x86_64-unknown-linux-musl"
    case $arch in
        aarch64|arm64)
            download_arch="aarch64-unknown-linux-musl"
            ;;
    esac
    
    cd /tmp
    wget -q "https://github.com/anytls/sink/releases/download/${anytls_version}/sink-${anytls_version}-${download_arch}.tar.gz" -O anytls.tar.gz
    tar -xzf anytls.tar.gz
    mv sink /usr/local/bin/anytls
    chmod +x /usr/local/bin/anytls
    rm -f anytls.tar.gz
    
    systemctl start anytls.service
    echo -e "${GREEN}AnyTLS 升级完成!${NC}"
}

uninstall_anytls() {
    echo -e "${BLUE}Uninstalling AnyTLS...${NC}"
    systemctl stop anytls.service nginx.service 2>/dev/null || true
    systemctl disable anytls.service 2>/dev/null || true
    rm -f /usr/local/bin/anytls
    rm -rf /etc/anytls
    rm -f /etc/systemd/system/anytls.service
    systemctl daemon-reload
    echo -e "${GREEN}AnyTLS 已卸载${NC}"
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
    
    cat > /etc/snell/snell-server.conf <<EOF
[snell-server]
listen = 0.0.0.0:${snport}
psk = ${snpsk}
ipv6 = false
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
版本: 4

snell://${snpsk}@${server_ip}:${snport}?version=4#Snell
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
    
    # Fixed version, no API call (avoid GitHub rate limit)
    local snell_version="v4.1.1"
    
    # Get latest version for upgrade (official source)
    local snell_version=$(curl -s "https://kb.nssurge.com/surge-knowledge-base/zh/release-notes/snell" 2>/dev/null | grep -oE "snell-server-v[0-9]+\.[0-9]+\.[0-9]+" | head -1 | sed 's/snell-server-v//')
    if [ -z "$snell_version" ]; then
        snell_version="5.0.1"
    fi
    snell_version="v${snell_version}"
    
    cd /tmp
    # Official Snell download source
    local download_url="https://dl.nssurge.com/snell/snell-server-${snell_version}-linux-${download_arch}.zip"
    
    if ! wget -q "$download_url" -O snell.zip 2>/dev/null; then
        # Fallback to GitHub backup
        download_url="https://raw.githubusercontent.com/xOS/Others/master/snell/${snell_version}/snell-server-${snell_version}-linux-${download_arch}.zip"
        wget -q "$download_url" -O snell.zip
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

# Setup certificate auto-renewal
setup_cert_renewal() {
    local domain=$1
    
    # Add cron job for certificate renewal
    (crontab -l 2>/dev/null | grep -v "acme.sh --cron"; echo "0 3 * * * $HOME/.acme.sh/acme.sh --cron --home \"$HOME/.acme.sh\" > /dev/null 2>&1") | crontab -
    
    echo -e "${GREEN}证书自动续期已设置${NC}"
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
    
    # Reality
    if systemctl is-active --quiet xray.service 2>/dev/null; then
        echo -e "${GREEN}✓ Reality (Xray): 运行中${NC}"
    elif [ -f /usr/local/etc/xray/config.json ]; then
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
    
    # AnyTLS
    if systemctl is-active --quiet anytls.service 2>/dev/null; then
        echo -e "${GREEN}✓ AnyTLS: 运行中${NC}"
    elif [ -f /etc/anytls/config.json ]; then
        echo -e "${YELLOW}○ AnyTLS: 已安装但未运行${NC}"
    else
        echo -e "${RED}✗ AnyTLS: 未安装${NC}"
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
    
    if [ -f /etc/shadowsocks/client.json ]; then
        echo ""
        echo -e "${BLUE}--- Shadowsocks-rust ---${NC}"
        cat /etc/shadowsocks/client.json
    fi
    
    if [ -f /usr/local/etc/xray/reclient.json ]; then
        echo ""
        echo -e "${BLUE}--- Reality ---${NC}"
        cat /usr/local/etc/xray/reclient.json
    fi
    
    if [ -f /etc/hysteria/hyclient.json ]; then
        echo ""
        echo -e "${BLUE}--- Hysteria2 ---${NC}"
        cat /etc/hysteria/hyclient.json
    fi
    
    if [ -f /etc/anytls/client.json ]; then
        echo ""
        echo -e "${BLUE}--- AnyTLS ---${NC}"
        cat /etc/anytls/client.json
    fi
    
    if [ -f /etc/snell/client.json ]; then
        echo ""
        echo -e "${BLUE}--- Snell ---${NC}"
        cat /etc/snell/client.json
    fi
    
    echo ""
}

# ==================== Menu Functions ====================

install_menu() {
    clear
    check_installed
    
    echo -e "${YELLOW}=========== 安装代理 ===========${NC}"
    echo " 1. 安装 Shadowsocks-rust (不需要域名)"
    echo " 2. 安装 Reality (可选域名)"
    echo " 3. 安装 Hysteria2 (可选域名)"
    echo " 4. 安装 AnyTLS (需要域名，自动申请证书)"
    echo " 5. 安装 Snell (不需要域名)"
    echo " 0. 返回主菜单"
    echo ""
    read -p "请输入数字: " num
    
    case "$num" in
        1) install_ssrust ;;
        2) install_reality ;;
        3) install_hy2 ;;
        4) install_anytls ;;
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
    echo " 4. 升级 AnyTLS"
    echo " 5. 升级 Snell"
    echo " 6. 升级所有代理"
    echo " 0. 返回主菜单"
    echo ""
    read -p "请输入数字: " num
    
    case "$num" in
        1) upgrade_ssrust ;;
        2) upgrade_reality ;;
        3) upgrade_hy2 ;;
        4) upgrade_anytls ;;
        5) upgrade_snell ;;
        6) 
            upgrade_ssrust
            upgrade_reality
            upgrade_hy2
            upgrade_anytls
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
    echo " 4. 卸载 AnyTLS"
    echo " 5. 卸载 Snell"
    echo " 6. 卸载所有代理"
    echo " 0. 返回主菜单"
    echo ""
    read -p "请输入数字: " num
    
    case "$num" in
        1) 
            read -p "确认卸载 Shadowsocks-rust? (y/n): " confirm
            [[ "$confirm" =~ ^[Yy]$ ]] && uninstall_ssrust
            ;;
        2) 
            read -p "确认卸载 Reality? (y/n): " confirm
            [[ "$confirm" =~ ^[Yy]$ ]] && uninstall_reality
            ;;
        3) 
            read -p "确认卸载 Hysteria2? (y/n): " confirm
            [[ "$confirm" =~ ^[Yy]$ ]] && uninstall_hy2
            ;;
        4) 
            read -p "确认卸载 AnyTLS? (y/n): " confirm
            [[ "$confirm" =~ ^[Yy]$ ]] && uninstall_anytls
            ;;
        5) 
            read -p "确认卸载 Snell? (y/n): " confirm
            [[ "$confirm" =~ ^[Yy]$ ]] && uninstall_snell
            ;;
        6) 
            read -p "确认卸载所有代理? (y/n): " confirm
            if [[ "$confirm" =~ ^[Yy]$ ]]; then
                uninstall_ssrust
                uninstall_reality
                uninstall_hy2
                uninstall_anytls
                uninstall_snell
            fi
            ;;
        0) return ;;
        *) echo -e "${RED}请输入正确数字${NC}"; sleep 2 ;;
    esac
    
    echo ""
    read -p "按回车键继续..."
}

service_menu() {
    clear
    check_installed
    
    echo -e "${YELLOW}=========== 服务管理 ===========${NC}"
    echo " 1. 重启 Shadowsocks-rust"
    echo " 2. 重启 Reality"
    echo " 3. 重启 Hysteria2"
    echo " 4. 重启 AnyTLS"
    echo " 5. 重启 Snell"
    echo " 6. 查看所有服务状态"
    echo " 0. 返回主菜单"
    echo ""
    read -p "请输入数字: " num
    
    case "$num" in
        1) systemctl restart shadowsocks.service && echo -e "${GREEN}Shadowsocks-rust 已重启${NC}" ;;
        2) systemctl restart xray.service && echo -e "${GREEN}Reality 已重启${NC}" ;;
        3) systemctl restart hysteria-server.service && echo -e "${GREEN}Hysteria2 已重启${NC}" ;;
        4) 
            systemctl restart anytls.service nginx.service && echo -e "${GREEN}AnyTLS 已重启${NC}"
            ;;
        5) systemctl restart snell.service && echo -e "${GREEN}Snell 已重启${NC}" ;;
        6) 
            echo ""
            systemctl status shadowsocks.service --no-pager 2>/dev/null || echo "Shadowsocks-rust: 未安装"
            echo "---"
            systemctl status xray.service --no-pager 2>/dev/null || echo "Reality: 未安装"
            echo "---"
            systemctl status hysteria-server.service --no-pager 2>/dev/null || echo "Hysteria2: 未安装"
            echo "---"
            systemctl status anytls.service --no-pager 2>/dev/null || echo "AnyTLS: 未安装"
            echo "---"
            systemctl status snell.service --no-pager 2>/dev/null || echo "Snell: 未安装"
            ;;
        0) return ;;
        *) echo -e "${RED}请输入正确数字${NC}"; sleep 2 ;;
    esac
    
    echo ""
    read -p "按回车键继续..."
}

# Main menu
start_menu() {
    while true; do
        clear
        echo " ================================================== "
        echo "  代理安装管理脚本                                  "
        echo "  支持: Shadowsocks-rust / Reality / Hysteria2     "
        echo "        AnyTLS / Snell                             "
        echo "  域名支持: Reality/Hysteria2/AnyTLS 可选域名+证书 "
        echo "           Shadowsocks/Snell 不需要域名            "
        echo " ================================================== "
        echo ""
        
        check_installed
        
        echo -e "${YELLOW}=========== 主菜单 ===========${NC}"
        echo " 1. 安装代理"
        echo " 2. 升级代理"
        echo " 3. 卸载代理"
        echo " 4. 服务管理 (重启/查看状态)"
        echo " 5. 查看客户端配置"
        echo " 0. 退出脚本"
        echo ""
        read -p "请输入数字: " num
        
        case "$num" in
            1) install_menu ;;
            2) upgrade_menu ;;
            3) uninstall_menu ;;
            4) service_menu ;;
            5) 
                show_configs
                read -p "按回车键继续..."
                ;;
            0) 
                echo -e "${GREEN}再见!${NC}"
                exit 0
                ;;
            *) 
                echo -e "${RED}请输入正确数字${NC}"
                sleep 2
                ;;
        esac
    done
}

# Start the script
start_menu
