#!/bin/bash
# SIMPLEPROXY - A Multi-Protocol Proxy Installer (Modular Version)
# Supports: Shadowsocks-rust, Reality, Hysteria2, V2Ray+TLS+WS, Snell

set -euo pipefail

# Get the real script path (resolve symlinks)
get_script_dir() {
    local source="${BASH_SOURCE[0]}"
    # Resolve symlinks to get the real script path
    while [[ -L "$source" ]]; do
        local dir="$(cd "$(dirname "$source")" && pwd)"
        source="$(readlink "$source" 2>/dev/null || realpath "$source" 2>/dev/null)"
        # If readlink returned a relative path, prepend the dir
        [[ "$source" != /* ]] && source="$dir/$source"
    done
    cd "$(dirname "$source")" && pwd
}

# Get script directory
SCRIPT_DIR="$(get_script_dir)"
MODULE_DIR="${SCRIPT_DIR}/lib"
PROTO_DIR="${SCRIPT_DIR}/protocols"

# Check if running from correct location (modules exist)
if [[ ! -d "${MODULE_DIR}" ]]; then
    echo "Error: Cannot find lib/ directory at ${MODULE_DIR}" >&2
    echo "Please run install.sh first to install SimpleProxy properly." >&2
    echo "Or run the script directly from /opt/simpleproxy/" >&2
    exit 1
fi

# Source modules
source "${MODULE_DIR}/common.sh"
source "${MODULE_DIR}/logging.sh"
source "${MODULE_DIR}/checksum.sh"

# Source protocol modules
for proto in shadowsocks reality hysteria2 v2ray snell; do
    [[ -f "${PROTO_DIR}/${proto}.sh" ]] && source "${PROTO_DIR}/${proto}.sh"
done
# Check if running from correct location (modules exist)
if [[ ! -d "${MODULE_DIR}" ]]; then
    echo "Error: Cannot find lib/ directory at ${MODULE_DIR}" >&2
    echo "Please run install.sh first to install SimpleProxy properly." >&2
    echo "Or run the script directly from /opt/simpleproxy/" >&2
    exit 1
fi

# Source modules
source "${MODULE_DIR}/common.sh"
source "${MODULE_DIR}/logging.sh"
source "${MODULE_DIR}/checksum.sh"

# Source protocol modules
for proto in shadowsocks reality hysteria2 v2ray snell; do
    [[ -f "${PROTO_DIR}/${proto}.sh" ]] && source "${PROTO_DIR}/${proto}.sh"
done
