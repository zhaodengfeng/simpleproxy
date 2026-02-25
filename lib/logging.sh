#!/bin/bash
# logging.sh - 日志模块
# 提供统一的日志记录功能

# 日志级别: DEBUG < INFO < WARN < ERROR

# 日志文件 (从 common.sh 导入)
LOG_FILE="${LOG_FILE:-/var/log/simpleproxy.log}"

# 最大日志大小 (10MB)
readonly LOG_MAX_SIZE=$((10*1024*1024))
readonly LOG_KEEP_COUNT=5

# 初始化日志系统
init_logging() {
    local log_dir
    log_dir=$(dirname "$LOG_FILE")
    [[ ! -d "$log_dir" ]] && mkdir -p "$log_dir"
    [[ ! -f "$LOG_FILE" ]] && touch "$LOG_FILE" && chmod 644 "$LOG_FILE"
}

# 日志轮转
rotate_log_if_needed() {
    [[ -f "$LOG_FILE" ]] || return 0
    
    local size
    size=$(stat -c%s "$LOG_FILE" 2>/dev/null || echo 0)
    [[ "$size" -lt "$LOG_MAX_SIZE" ]] && return 0
    
    local i
    for ((i=LOG_KEEP_COUNT; i>=1; i--)); do
        if [[ -f "${LOG_FILE}.${i}" ]]; then
            if [[ "$i" -eq "$LOG_KEEP_COUNT" ]]; then
                rm -f "${LOG_FILE}.${i}"
            else
                mv "${LOG_FILE}.${i}" "${LOG_FILE}.$((i+1))"
            fi
        fi
    done
    mv "$LOG_FILE" "${LOG_FILE}.1"
    touch "$LOG_FILE"
    chmod 644 "$LOG_FILE"
}

# 写入日志
log_write() {
    local level="$1"
    local message="$2"
    local show_console="${3:-false}"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    init_logging
    rotate_log_if_needed
    
    printf '[%s] [%s] %s\n' "$timestamp" "$level" "$message" >> "$LOG_FILE"
    [[ "$show_console" == "true" ]] && echo "[$level] $message"
}

# 调试日志
log_debug() { log_write "DEBUG" "$1" "${2:-false}"; }

# 信息日志
log_info() { log_write "INFO" "$1" "${2:-false}"; }

# 警告日志
log_warn() { log_write "WARN" "$1" "${2:-false}"; }

# 错误日志
log_error() { log_write "ERROR" "$1" "${2:-false}"; }

# 成功日志
log_success() { log_write "SUCCESS" "$1" "${2:-false}"; }

# 旧版兼容 (simpleproxy.sh 中使用)
log_msg() {
    local level="$1"
    shift
    log_write "$level" "$*" false
}
