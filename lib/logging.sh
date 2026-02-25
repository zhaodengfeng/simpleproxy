#!/bin/bash
# logging.sh - 日志模块

init_logging(){
    local log_dir
    log_dir=$(dirname "$LOG_FILE")
    [[ ! -d "$log_dir" ]] && mkdir -p "$log_dir"
    [[ ! -f "$LOG_FILE" ]] && touch "$LOG_FILE" && chmod 644 "$LOG_FILE"
}

log_write(){
    local level="$1" message="$2" show_console=${3:-false}
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
    [[ "$show_console" == "true" ]] && echo "[$level] $message"
}

log_error(){ log_write "ERROR" "$1" "${2:-false}"; }
log_warn(){ log_write "WARN" "$1" "${2:-false}"; }
log_info(){ log_write "INFO" "$1" "${2:-false}"; }
log_success(){ log_write "SUCCESS" "$1" "${2:-false}"; }
