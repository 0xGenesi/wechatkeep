import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import java.io.BufferedReader;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

// FUNCTION_STARTS 播种·第二版（77 续⑲）：入口 1 字节函数已就位（v1），
// 这里按地址**降序** setBody 扩到相邻起点（降序保证扩体永不与已扩体重叠），
// 单事务批量。
public class SeedFunctionStarts extends GhidraScript {
    @Override
    public void run() throws Exception {
        String startsPath = getScriptArgs()[0];
        List<Long> starts = new ArrayList<>();
        try (BufferedReader br = new BufferedReader(new FileReader(startsPath))) {
            String line;
            while ((line = br.readLine()) != null)
                if (line.trim().length() > 0) starts.add(Long.parseUnsignedLong(line.trim(), 16));
        }
        Collections.sort(starts);
        Program prog = currentProgram;
        FunctionManager fm = prog.getFunctionManager();
        long textEndOff = 0;
        ghidra.program.model.mem.MemoryBlock[] blocks = prog.getMemory().getBlocks();
        for (int bi = 0; bi < blocks.length; bi++)
            if (blocks[bi].isExecute() && blocks[bi].getEnd().getOffset() > textEndOff)
                textEndOff = blocks[bi].getEnd().getOffset() + 1;
        println("starts=" + starts.size() + " textEnd=0x" + Long.toHexString(textEndOff));
        int tx = prog.startTransaction("SeedBodies");
        int set = 0, miss = 0;
        try {
            for (int i = starts.size() - 1; i >= 0; i--) {
                long a = starts.get(i);
                long end = (i + 1 < starts.size()) ? starts.get(i + 1) : textEndOff;
                if (end > textEndOff) end = textEndOff;
                Function f = fm.getFunctionAt(toAddr(a));
                if (f == null) { miss++; continue; }
                try {
                    f.setBody(new AddressSet(toAddr(a), toAddr(end - 1)));
                    set++;
                } catch (Exception ex) { miss++; }
                if (set > 0 && set % 50000 == 0) println("progress " + set);
            }
        } finally {
            prog.endTransaction(tx, true);
        }
        println("bodySet=" + set + " miss=" + miss);
    }
}
