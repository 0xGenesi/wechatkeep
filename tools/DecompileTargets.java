import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import java.io.PrintWriter;

// 定点反编译（spike 快路同款）：地址列表 → C 伪代码落盘。
public class DecompileTargets extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();   // [outPath, addrListPath]
        java.io.BufferedReader tr = new java.io.BufferedReader(new java.io.FileReader(args[1]));
        java.util.List<String> addrs = new java.util.ArrayList<>();
        String ln;
        while ((ln = tr.readLine()) != null) if (!ln.trim().isEmpty()) addrs.add(ln.trim());
        tr.close();
        PrintWriter out = new PrintWriter(args[0]);
        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);
        for (String addr : addrs) {
            Address a = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(Long.parseUnsignedLong(addr, 16));
            Function f = getFunctionAt(a);
            if (f == null) { out.println("// no function at " + addr); continue; }
            DecompileResults r = di.decompileFunction(f, 120, monitor);
            out.println("// ===== " + addr + " =====");
            if (r.decompileCompleted() && r.getDecompiledFunction() != null) {
                out.println(r.getDecompiledFunction().getC());
            } else {
                out.println("// decompile failed: " + r.getErrorMessage());
            }
        }
        out.close();
        di.dispose();
    }
}
