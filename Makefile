# wxkeep Makefile — 开发与单文件分发
#
#   make            同 make build
#   make build      debug 构建 + 测试
#   make release    单文件分发产物 ./wxkeep（universal + stripped + ad-hoc 签名）
#   make clean

.PHONY: build release clean test
.ONESHELL:

# 交叉编译双架构需要完整 Xcode（xcbuild）；CLT-only 环境回退单架构，
# universal 由 CI（runner 带完整 Xcode）产出并挂到 Release。
XCBUILD = /Library/Developer/SharedFrameworks/XCBuild.framework/Versions/A/Support/xcbuild
BUILD_FLAGS = $(if $(wildcard $(XCBUILD)),--arch arm64 --arch x86_64,)

build:
	swift build
	swift test

# 真 dylib 全链路测试：备份路径存在才启用（本地机器各自指定；CI/无备份
# 机器自动跳过该组测试）。可用 make test REAL_DYLIB=/path/to/dylib 覆盖。
test:
	@if [ -n "$(REAL_DYLIB)" ]; then \
	  WXKEEP_REAL_DYLIB="$(REAL_DYLIB)" swift test; \
	else \
	  WXKEEP_REAL_DYLIB="$(wildcard $(HOME)/wechattweak-intel/wechat.dylib.orig.backup)" swift test; \
	fi

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
	@if [ ! -x "$(XCBUILD)" ]; then echo "注意: 本机仅 CLT，产物为单架构；universal 版由 CI Release 构建"; fi
	./wxkeep --version

clean:
	swift package clean
	rm -f ./wxkeep
