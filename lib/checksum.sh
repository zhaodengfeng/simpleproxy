#!/bin/bash
# checksum.sh - SHA256 校验模块

CHECKSUM_FILE="${PROJECT_DIR}/checksums.txt"

# 计算文件 SHA256
calc_sha256(){
    local file="$1"
    [[ -f "$file" ]] && sha256sum "$file" 2>/dev/null | awk '{print $1}' || echo ""
}

# 验证下载的文件
verify_download(){
    local file="$1" expected="$2"
    local actual=$(calc_sha256 "$file")
    [[ "$actual" == "$expected" ]]
}

# 安全下载并校验
download_with_verify(){
    local url="$1" output="$2" expected_hash="$3"
    
    if ! curl -fsSL --proto '=https' --tlsv1.2 "$url" -o "$output"; then
        echo "下载失败: $url" >&2
        return 1
    fi
    
    if [[ -n "$expected_hash" ]] && ! verify_download "$output" "$expected_hash"; then
        echo "校验失败: $output" >&2
        rm -f "$output"
        return 1
    fi
    
    return 0
}
