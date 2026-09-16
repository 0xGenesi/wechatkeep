settings set target.disable-aslr true
process launch --stop-at-entry
breakpoint set -n WeChatMain
continue
breakpoint delete 1
script print('===== VERIFY ground truth at 0x11fbcd940 =====')
memory read -c 9 -f x 0x11fbcd940
breakpoint set -a 0x11e2b3d90
breakpoint command add 2 -o "script print(\'===== HIT trampoline =====\')" -o "thread backtrace 16" -o "continue"
breakpoint set -a 0x11e6e3ae0
breakpoint command add 3 -o "script print(\'===== HIT executor =====\')" -o "thread backtrace 16" -o "continue"
breakpoint set -a 0x11e6fceb0
breakpoint command add 4 -o "script print(\'===== HIT task-body =====\')" -o "thread backtrace 16" -o "continue"
breakpoint set -a 0x11edbe3d0
breakpoint command add 5 -o "script print(\'===== HIT revokemessage-query =====\')" -o "thread backtrace 16" -o "continue"
breakpoint set -a 0x121c3a760
breakpoint command add 6 -o "script print(\'===== HIT service-post =====\')" -o "thread backtrace 16" -o "script print('--- task-obj:')" -o "memory read -format x -size 8 -count 6 $rsi" -o "script print('--- vtable:')" -o "memory read -format x -size 8 -count 8 *(unsigned long long*)$rsi" -o "continue"
breakpoint set -a 0x1200bcf10
breakpoint command add 7 -o "script print(\'===== HIT tip-builder =====\')" -o "thread backtrace 16" -o "continue"
breakpoint set -a 0x11e6e3710
breakpoint command add 8 -o "script print(\'===== HIT tip-insert =====\')" -o "thread backtrace 16" -o "continue"
continue
