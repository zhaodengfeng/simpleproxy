#!/usr/bin/env bats
# 校验模块测试

setup(){
    export MODULE_DIR="${BATS_TEST_DIRNAME}/../lib"
    source "${MODULE_DIR}/checksum.sh"
}

@test "calc_sha256 returns empty for non-existent file" {
    result=$(calc_sha256 "/nonexistent/file")
    [ -z "$result" ]
}

@test "verify_download returns true for matching hash" {
    tmpfile=$(mktemp)
    echo "test content" > "$tmpfile"
    hash=$(sha256sum "$tmpfile" | awk '{print $1}')
    verify_download "$tmpfile" "$hash"
    [ "$?" -eq 0 ]
    rm -f "$tmpfile"
}
