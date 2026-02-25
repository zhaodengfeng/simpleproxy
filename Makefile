.PHONY: test lint check clean install

SHELL := /bin/bash

# 运行所有测试
test: test-unit test-shellcheck

# 单元测试
test-unit:
	@echo "运行 bats 测试..."
	@which bats >/dev/null 2>&1 || (echo "请安装 bats: npm install -g bats" && exit 1)
	bats tests/*.bats

# Shellcheck 静态检查
test-shellcheck:
	@echo "运行 shellcheck..."
	@which shellcheck >/dev/null 2>&1 || (echo "请安装 shellcheck" && exit 1)
	shellcheck -x lib/*.sh protocols/*.sh simpleproxy.sh

# 检查依赖
check:
	@echo "检查依赖..."
	@bash -c 'command -v curl >/dev/null && echo "✓ curl" || echo "✗ curl"'
	@bash -c 'command -v openssl >/dev/null && echo "✓ openssl" || echo "✗ openssl"'
	@bash -c 'command -v systemctl >/dev/null 2>&1 && echo "✓ systemd" || echo "⚠ systemd (非 systemd 系统)"'

# 安装
install:
	@echo "安装 SimpleProxy..."
	@chmod +x simpleproxy.sh
	@echo "创建符号链接: /usr/local/bin/simpleproxy"
	@ln -sf "$(pwd)/simpleproxy.sh" /usr/local/bin/simpleproxy 2>/dev/null || \
		echo "提示: 需要 root 权限创建符号链接"

# 清理
clean:
	rm -f /tmp/simpleproxy_test_*
