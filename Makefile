# wxkeep Makefile — 开发与单文件分发
#
#   make            同 make build
#   make build      debug 构建 + 测试
#   make release    单文件分发产物 ./wxkeep（universal + stripped + ad-hoc 签名）
#   make clean

.PHONY: build release clean test verify-isa hooks
.ONESHELL:

# 交叉编译双架构需要完整 Xcode（xcbuild）；CLT-only 环境回退单架构。
# （111 轮注：release.yml 已随源码-only 发版策略删除——universal 资产
# 由本地 `make release` 自取，CI 只跑 build+test。）
XCBUILD = /Library/Developer/SharedFrameworks/XCBuild.framework/Versions/A/Support/xcbuild
BUILD_FLAGS = $(if $(wildcard $(XCBUILD)),--arch arm64 --arch x86_64,)

build:
	swift build
	swift test

# 真 dylib 全链路测试：显式传 REAL_DYLIB 才启用（本地机器各自指定；CI/
# 无备份机器自动跳过该组测试）。111 轮移除个人机器路径默认值—— unsuspecting
# 环境静默空跑与「测试通过」假象同源。
test:
	@if [ -n "$(REAL_DYLIB)" ]; then \
	  WXKEEP_REAL_DYLIB="$(REAL_DYLIB)" swift test; \
	else \
	  swift test; \
	fi

# L9 指令级结构证明（125 轮）：负控灵敏度 + 全语料双变体。
# 依赖 var/venv(capstone) 与 var/wxarm 切片库（本地 SOP；CI 无语料故不接线）。
verify-isa:
	@if [ -x var/venv/bin/python ]; then \
	  var/venv/bin/python tools/verify_instruction_diff.py --negative-controls && \
	  var/venv/bin/python tools/verify_instruction_diff.py --variant silent && \
	  var/venv/bin/python tools/verify_instruction_diff.py --variant keeptip; \
	else echo "缺 var/venv（capstone）——工具链准备见 docs/MAINTAINING.md"; exit 1; fi

# 变异器护栏（125 轮）：安装 pre-commit 钩子（sentinel/锚点 canonical 门）。
hooks:
	chmod +x tools/hooks/pre-commit
	git config core.hooksPath tools/hooks
	@git config core.hooksPath

# 单文件分发：universal 双架构 → 剥符号 → ad-hoc 重签（无签名的二进制在
# 别人机器上会被 Gatekeeper 直接拒）。swift release 交叉编译两种架构。
release:
	swift build -c release $(BUILD_FLAGS)
	BIN=$$(swift build -c release $(BUILD_FLAGS) --show-bin-path 2>/dev/null)/wxkeep; \
	[ -x "$$BIN" ] || BIN=.build/release/wxkeep
	strip -x $$BIN
	codesign -f -s - $$BIN
	cp $$BIN ./wxkeep
	@ls -lh ./wxkeep | awk '{print "单文件产物: " $$5 "  ->  ./wxkeep"}'
	@file ./wxkeep | cut -c1-80
	@if [ ! -x "$(XCBUILD)" ]; then echo "注意: 本机仅 CLT，产物为单架构；universal 需 Xcode（源码-only 发版后 CI 不再产资产，见 MAINTAINING 发版策略）"; fi
	./wxkeep --version

clean:
	swift package clean
	rm -f ./wxkeep
