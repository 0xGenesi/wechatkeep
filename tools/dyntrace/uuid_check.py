import lldb, struct
def check(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    proc = target.GetProcess()
    base = None
    for m in target.modules:
        if m.GetFileSpec().GetFilename() == "wechat.dylib":
            base = m.GetObjectFileHeaderAddress().GetLoadAddress(target)
            print('uuid-str(lldb):', m.GetUUIDString())
            break
    if base is None:
        print('NODYLIB'); return
    err = lldb.SBError()
    hdr = proc.ReadMemory(base, 64, err)
    ncmds, = struct.unpack_from('<I', hdr, 16)
    sizeofcmds, = struct.unpack_from('<I', hdr, 20)
    print(f'base={base:#x} magic={struct.unpack_from("<I",hdr,0)[0]:#x} '
          f'cputype={struct.unpack_from("<I",hdr,4)[0]:#x} ncmds={ncmds} sizeofcmds={sizeofcmds}')
    blob = proc.ReadMemory(base, 32 + sizeofcmds, err)
    if not err.Success():
        print('read fail', err); return
    p = 32
    for _ in range(ncmds):
        cmd, size = struct.unpack_from('<II', blob, p)
        if cmd == 0x1b:  # LC_UUID
            u = blob[p+8:p+24]
            print('LC_UUID bytes:', u.hex())
            print('as str:       ', end=' ')
            hexs = ''.join('%02x' % b for b in u)
            print(f'{hexs[0:8]}-{hexs[8:12]}-{hexs[12:16]}-{hexs[16:20]}-{hexs[20:32]}')
            return
        p += size
    print('NO LC_UUID FOUND')
def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f uuid_check.check check')
