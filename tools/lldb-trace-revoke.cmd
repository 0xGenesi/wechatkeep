# wxkeep 撤回链动态追踪脚本 — build 269602 x86_64 专用（VA 随构建变化，勿跨版本用）
#
# 目的：在原生（未打补丁/restore 后）微信上记录撤回处理的完整运行路径，
#       捕获「删除原消息」虚派发调用的真实位置（静态分析断链处）。
#
# 用法（详见 docs/V2-PLAN.md）：
#   sudo lldb -b -s tools/lldb-trace-revoke.cmd -- /Applications/WeChat.app/Contents/MacOS/WeChat 2>&1 | tee /tmp/wxre-trace.log
#   登录微信 → 让另一账号：私聊撤回 1 条 + 群聊撤回 1 条 → 等 1 分钟 → Ctrl-C 退出
#   然后把 /tmp/wxre-trace.log 交给分析。

settings set target.disable-aslr false
# 模块相对断点（ASLR 安全；wechat.dylib 加载后自动挂上）
breakpoint set -s wechat.dylib -a 0x36dbae0
breakpoint command add 1 -o "echo ===== HIT executor 0x36dbae0 =====" -o "bt 18" -o "continue"
breakpoint set -s wechat.dylib -a 0x50a67b0
breakpoint command add 2 -o "echo ===== HIT post-parse 0x50a67b0 =====" -o "bt 12" -o "continue"
breakpoint set -s wechat.dylib -a 0x50b4f10
breakpoint command add 3 -o "echo ===== HIT tip-builder 0x50b4f10 =====" -o "bt 12" -o "continue"
breakpoint set -s wechat.dylib -a 0x36db710
breakpoint command add 4 -o "echo ===== HIT tip-insert 0x36db710 =====" -o "bt 12" -o "continue"
breakpoint set -s wechat.dylib -a 0x32abd90
breakpoint command add 5 -o "echo ===== HIT trampoline 0x32abd90 =====" -o "bt 12" -o "continue"
run
