import Testing
import Foundation
@testable import WxkeepRuntime

/// 三武装 naked thunk 执行级覆盖（129 轮，收口 124① 原文：可注入 base 的
/// 测试缝——缝 = runtime.m 内 driver（从全局装 x0..x8/x19/q0/q1 → 按 which
/// bl 目标 thunk）+ far 端 capture stub；Swift 侧只装配输入/断言输出）。
///
/// 生产合同逐面：
/// - **cm**（R14 consumer_main 直挂）：x0/x1 → g_cm_consumer/msg 快照 +
///   参数穿透 ldar 尾跳（蹦床收到的 x0/x1 与入口恒等——thunk 全程零
///   寄存器落盘，落错一个字节 = 生产每消息状态错位）。
/// - **lu**（R15 lookup 直挂）：x0/x1 快照 + ldaddal 原子序号（六 consumer
///   族共用汇点，多线程真实并发）+ 参数穿透。
/// - **clone**（V3-M2 写点 thunk）：0xE0 帧全量保存/恢复——x0..x8 + q0/q1
///   逐寄存器恒等（错一个 ldp 偏移 = 生产写点参数静默损坏）+ x19/sp
///   快照 + bl body（g_clone_message 关 → 纯透传零解引用）→ epilogue →
///   尾跳。capture-hit == 1 = prologue→body→restore→尾跳全链走通。
/// x64：cm/lu 行 inert（不带组）；clone 平 C 直驱弱覆盖。
/// serialized：三条 thunk 共享 driver 全局装载体（g_test_arm_*），并行用例
/// 会互相覆盖装载体（首跑实证：clone 的 cx 混入 cm/lu 的字面量尾巴）。
@Suite(.serialized)
struct ArmThunkTests {
    @Test func cmThunkSnapshotsAndArgPassthrough() {
        #if arch(arm64)
        wxkeep_runtime_test_arm_thunk_setup(0)   // cm
        var x: [UInt64] = [0xA5A5_0001, 0xB7B7_0002, 3, 4, 5, 6, 7, 8, 9, 0x1977]
        wxkeep_runtime_test_arm_thunk_invoke(0, &x, nil)
        var cx = [UInt64](repeating: 0, count: 9)
        var cq = [UInt64](repeating: 0, count: 4)
        let hit = wxkeep_runtime_test_arm_thunk_capture(&cx, &cq)
        #expect(hit == 1, "far 端到达（thunk→ldar 尾跳→capture→ret 全链）")
        #expect(cx[0] == x[0] && cx[1] == x[1],
                "参数穿透尾跳：蹦床收到的 x0/x1 与入口恒等")
        var st = [UInt64](repeating: 0, count: 4)
        let n = wxkeep_runtime_test_arm_thunk_state(0, &st, 4)
        #expect(n == 2, "cm 快照两槽")
        #expect(st[0] == x[0] && st[1] == x[1],
                "g_cm_consumer/msg 快照与入口恒等")
        #else
        #expect(Bool(true))
        #endif
    }

    @Test func luThunkAtomicSeqAndPassthrough() {
        #if arch(arm64)
        var st = [UInt64](repeating: 0, count: 4)
        _ = wxkeep_runtime_test_arm_thunk_state(1, &st, 4)   // 读基线 seq
        let seq0 = st[2]
        wxkeep_runtime_test_arm_thunk_setup(1)   // lu
        var x: [UInt64] = [0x5E1C_0001, 0x4E1D_0002, 3, 4, 5, 6, 7, 8, 9, 0x1977]
        wxkeep_runtime_test_arm_thunk_invoke(1, &x, nil)
        wxkeep_runtime_test_arm_thunk_invoke(1, &x, nil)   // 两次 → seq +2（ldaddal 路径）
        var cx = [UInt64](repeating: 0, count: 9)
        var cq = [UInt64](repeating: 0, count: 4)
        let hit = wxkeep_runtime_test_arm_thunk_capture(&cx, &cq)
        #expect(hit == 1)
        #expect(cx[0] == x[0] && cx[1] == x[1], "参数穿透尾跳")
        _ = wxkeep_runtime_test_arm_thunk_state(1, &st, 4)
        #expect(st[0] == x[0] && st[1] == x[1], "g_lu_svc/keyptr 快照")
        #expect(st[2] == seq0 + 2, "lu_seq 原子加两次（124 轮 P3 ldaddal 缝执行面）")
        #else
        #expect(Bool(true))
        #endif
    }

    @Test func cloneThunkFullRegisterContract() {
        #if arch(arm64)
        wxkeep_runtime_test_arm_thunk_setup(2)   // clone
        // x0..x8 全异值 + x19=0x1977；q0/q1 各两词异值——逐寄存器恒等断言
        // 的前提（同值会掩盖错位 ldp 的混洗）。x1=非零垃圾：body 纯透传
        //（g_clone_message 关）不触碰。
        var x: [UInt64] = [
            0xA000_0000_0000_0001, 0xA000_0000_0000_0002, 0xA000_0000_0000_0003,
            0xA000_0000_0000_0004, 0xA000_0000_0000_0005, 0xA000_0000_0000_0006,
            0xA000_0000_0000_0007, 0xA000_0000_0000_0008, 0xA000_0000_0000_0009,
            0x1977,
        ]
        var q: [UInt64] = [
            0x1111_1111_1111_1111, 0x2222_2222_2222_2222,   // q0
            0x3333_3333_3333_3333, 0x4444_4444_4444_4444,   // q1
        ]
        wxkeep_runtime_test_arm_thunk_invoke(2, &x, &q)
        var cx = [UInt64](repeating: 0, count: 9)
        var cq = [UInt64](repeating: 0, count: 4)
        let hit = wxkeep_runtime_test_arm_thunk_capture(&cx, &cq)
        #expect(hit == 1, "prologue→bl body（纯透传）→epilogue→尾跳全链走通")
        for i in 0..<9 {
            #expect(cx[i] == x[i], "x\(i) 经 0xE0 帧保存/恢复后恒等（错位 ldp 在此现形）")
        }
        for i in 0..<4 {
            #expect(cq[i] == q[i], "q0/q1 第 \(i) 词经保存/恢复恒等")
        }
        var st = [UInt64](repeating: 0, count: 4)
        let n = wxkeep_runtime_test_arm_thunk_state(2, &st, 4)
        #expect(n == 2)
        #expect(st[0] == 0x1977, "x19 快照 = thunk 入口值（R6 证据步合同）")
        #expect(st[1] != 0, "caller_sp 快照在场")
        #else
        #expect(Bool(true))
        #endif
    }

    @Test func x64ClonePlainCPassthrough() {
        #if arch(x86_64)
        // x64 行不带 cm/lu 组（inert 桩）；clone thunk 平 C——透传弱覆盖。
        wxkeep_runtime_test_arm_thunk_setup(2)
        var x: [UInt64] = [0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666, 0, 0, 0, 0]
        wxkeep_runtime_test_arm_thunk_invoke(2, &x, nil)
        var cx = [UInt64](repeating: 0, count: 9)
        var cqLocal = [UInt64](repeating: 0, count: 4)
        let hit = wxkeep_runtime_test_arm_thunk_capture(&cx, &cqLocal)
        #expect(hit == 1)
        for i in 0..<6 {
            #expect(cx[i] == x[i], "x64 clone 直驱参数透传")
        }
        #else
        #expect(Bool(true))
        #endif
    }
}
