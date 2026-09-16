settings set target.disable-aslr true
process launch --stop-at-entry
breakpoint set -n WeChatMain
continue
breakpoint delete 1
command script import /tmp/wxre/drive3.py
drive3
