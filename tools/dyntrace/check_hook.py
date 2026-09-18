import lldb
def check(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    proc = target.GetProcess()
    base = None
    for m in target.modules:
        if m.GetFileSpec().GetFilename() == "wechat.dylib":
            base = m.GetObjectFileHeaderAddress().GetLoadAddress(target)
            break
    if base is None:
        print('NODYLIB'); return
    err = lldb.SBError()
    pro = proc.ReadMemory(base + 0x537d910, 12, err)
    print(f'base={base:#x} wrapper12={pro.hex()}', flush=True)
    print('ARMED' if pro.hex().startswith('48b8') else 'NOT-ARMED', flush=True)
def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f check_hook.check check')
