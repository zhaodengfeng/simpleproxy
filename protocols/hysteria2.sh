#!/bin/bash
# hysteria2.sh - hysteria2 协议管理

source "${MODULE_DIR}/common.sh"
source "${MODULE_DIR}/logging.sh"

install_hysteria2(){
    log_info "安装 hysteria2..."
    # 具体安装逻辑
    echo "hysteria2 安装完成"
}

uninstall_hysteria2(){
    log_info "卸载 hysteria2..."
    echo "hysteria2 卸载完成"
}

status_hysteria2(){
    echo "hysteria2 状态检查"
}
