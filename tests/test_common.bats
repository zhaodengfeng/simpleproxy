#!/usr/bin/env bats
# 通用函数测试

setup(){
    export MODULE_DIR="${BATS_TEST_DIRNAME}/../lib"
    source "${MODULE_DIR}/common.sh"
}

@test "gen_random generates correct length" {
    result=$(gen_random 16)
    [ "${#result}" -eq 16 ]
}

@test "gen_uuid generates valid UUID format" {
    result=$(gen_uuid)
    [[ "$result" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]]
}

@test "gen_port returns number within range" {
    result=$(gen_port 10000 20000)
    [ "$result" -ge 10000 ]
    [ "$result" -le 20000 ]
}

@test "command_exists returns true for existing command" {
    command_exists bash
    [ "$?" -eq 0 ]
}

@test "command_exists returns false for non-existing command" {
    ! command_exists nonexistent_command_xyz
}
