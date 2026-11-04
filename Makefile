# wxkeep Makefile — 开发与单文件分发
#
#   make            同 make build
#   make build      debug 构建 + 测试
#   make release    单文件分发产物 ./wxkeep（universal + stripped + ad-hoc 签名）
#   make clean

.PHONY: build release clean test verify-isa verify-confusion evidence-ledger \
	evidence-recheck engine-twin family-invariants monoid-ledger kill-ledger hooks
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

# L12 真切片混淆矩阵（133 轮）：合成矩阵已在 swift test 常跑；本目标跑
# 真语料普查（config.json × var/wxarm，inspect 只读 + python 独立复核）。
verify-confusion:
	@if [ -x var/venv/bin/python ]; then \
	  var/venv/bin/python tools/verify_confusion_matrix.py; \
	else python3 tools/verify_confusion_matrix.py; fi

# L14 证明随行（133 轮）：各 L 族台账 → evidence-ledger.json（发版门；
# tag 前必跑，接线见 MAINTAINING 发版策略节）。
evidence-ledger:
	python3 tools/gen_evidence_ledger.py

# L19 台账复算门（134 轮）：重跑各族生成命令并断言判定行复现（SOAK=
# 用户窗口族如实登记；L9/L12/L13 真件语料族首版域外）。
evidence-recheck:
	python3 tools/gen_evidence_ledger.py --recheck

# L15/L16 台账生成（swift Suite 行；TestingMacros 显式装载——本机
# macOS 27 CLT 插件发现间歇失效的可靠解）。
TM = /Library/Developer/CommandLineTools/usr/lib/swift/host/plugins/testing/libTestingMacros.dylib
monoid-ledger:
	swift test --disable-sandbox -Xswiftc -load-plugin-library -Xswiftc $(TM) \
	  --filter StateMachineMonoidTests 2>&1 | tee var/logs/monoid-closure-$$(date +%Y%m%d-%H%M%S).txt

kill-ledger:
	swift test --disable-sandbox -Xswiftc -load-plugin-library -Xswiftc $(TM) \
	  --filter KillMatrixTests 2>&1 | tee var/logs/kill-matrix-$$(date +%Y%m%d-%H%M%S).txt

# L17 差分引擎孪生（134 轮）：Python 独立实现 vs 真 CLI 随机差分
# （--trials 加大 = 本地 SOP 档）。
engine-twin:
	python3 tools/diff_engine_twin.py --trials $${WXKEEP_TWIN_TRIALS:-60}

# L18 目录自洽审计（134 轮）：家族指纹 + 语义不变量 + 白名单。
family-invariants:
	python3 tools/verify_family_invariants.py

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
