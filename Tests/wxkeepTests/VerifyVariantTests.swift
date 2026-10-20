import Foundation
import Testing
@testable import wxkeep

/// verify spec 按构建变体（verify_variants）：stubs/zero_regions 是绝对 VA、
/// 逐构建漂移——legacy `verify` 只覆盖 270099 族，新构建各自派生变体。
/// 选中规则：本构建命中变体优先，回落 legacy；两者皆无 → nil（CLI 报
/// no verify spec）。旧格式（无 verify_variants 键）必须照常解码。
struct VerifyVariantTests {
    private func load(_ json: String, name: String = "s-\(UUID().uuidString)") throws -> Signatures {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(name)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        try json.write(to: dir.appendingPathComponent("signatures.json"),
                       atomically: true, encoding: .utf8)
        return try Signatures.load(explicit: dir.appendingPathComponent("signatures.json").path)
    }

    /// 变体命中 → 变体 spec；未命中 → legacy verify；无 verify → nil。
    /// 68 轮实证教训：RecipeSpec 不带 CodingKeys 时 Swift 合成键是
    /// `verifyVariants`，JSON 的 `verify_variants` 被当未知键忽略、optional
    /// 静默解码成 nil → 永远走 legacy（arm64 验收 worker 报旧族桩 VA 拦下）。
    @Test func variantSelectionAndLegacyFallback() throws {
        let sig = try load("""
        {"recipes":{"revoke_x64":{
          "arch":"x86_64","anchor":"imm64:revokems","derive":"padding-boundary",
          "expected":"554889E553504889FB","asm":"31C0C3909090909090",
          "verify":{"stubs":{"7A23CE4":"strlen","7A2373E":"memcmp"},
                    "zero_regions":[["AD2C3F8","16"]],
                    "probes":[["revokemsg","1"]]},
          "verify_variants":[
            {"builds":["270131","270132"],
             "stubs":{"7BC1E64":"strlen","7BC18BE":"memcmp"},
             "zero_regions":[["AF1C268","16"],["AF1C278","16"]],
             "probes":[["revokemsg","1"],["sysmsg","0"]]}]}}}
        """)
        let recipe = try #require(sig.recipes["revoke_x64"])

        let variant = try #require(recipe.verifySpec(for: "270131"))
        #expect(Set(variant.stubs.keys) == ["7BC1E64", "7BC18BE"])
        #expect(variant.zeroRegions.count == 2)
        #expect(variant.probes.count == 2)

        // 同一变体覆盖 builds 列表内的每个构建（字典无序，断言集合而非 .first）
        let alsoVariant = try #require(recipe.verifySpec(for: "270132"))
        #expect(alsoVariant.stubs.keys.contains("7BC1E64"))

        // 未命中构建回落 legacy（270099 族语义不变，worker 形态门继续兜底）
        let legacy = try #require(recipe.verifySpec(for: "270100"))
        #expect(Set(legacy.stubs.keys) == ["7A23CE4", "7A2373E"])
        #expect(legacy.zeroRegions == [["AD2C3F8", "16"]])
    }

    /// 旧格式（update-data 分发历史 + 270099 时代文件）：无 verify_variants
    /// 键 → verifyVariants 为 nil，legacy verify 照常可用。
    @Test func oldFormatWithoutVariantsStillDecodes() throws {
        let sig = try load("""
        {"recipes":{"revoke_x64":{
          "arch":"x86_64","anchor":"imm64:revokems","derive":"padding-boundary",
          "expected":"554889E553504889FB","asm":"31C0C3909090909090",
          "verify":{"stubs":{"7A23CE4":"strlen"},"zero_regions":[],"probes":[["revokemsg","1"]]}}}}
        """)
        let recipe = try #require(sig.recipes["revoke_x64"])
        #expect(recipe.verifyVariants == nil)
        let old = try #require(recipe.verifySpec(for: "270099"))
        #expect(old.stubs.keys.first == "7A23CE4" && old.stubs.count == 1)

        // 无 verify 亦无变体的配方 → nil（CLI 的 no-verify-spec 报错路径）
        let bare = try load("""
        {"recipes":{"revoke_x64":{
          "arch":"x86_64","anchor":"imm64:revokems","derive":"padding-boundary",
          "expected":"554889E553504889FB","asm":"31C0C3909090909090"}}}
        """)
        #expect(try #require(bare.recipes["revoke_x64"]).verifySpec(for: "270131") == nil)
    }

    /// 仓库数据契约：270131-135 双架构变体在位且与 legacy spec 不同源
    /// （绝对 VA 逐构建漂移——若哪个变体抄了 legacy 的 VA，worker 会以
    /// exit 4 优雅跳过、行为验证静默失效，这个测试把数据错误前移到 CI）。
    @Test func repoSignaturesCarryVariantsForLateFamily() throws {
        let here = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        let sig = try Signatures.load(
            explicit: here.appendingPathComponent("signatures.json").path)

        for (recipeName, archNote) in [("revoke_x64", "x64"), ("revoke_arm64_gen3", "arm64")] {
            let recipe = try #require(sig.recipes[recipeName], "\(recipeName) 缺失")
            let legacy = try #require(recipe.verify, "\(recipeName) legacy verify 缺失")
            for build in ["270131", "270132", "270133", "270134", "270135"] {
                let spec = try #require(recipe.verifySpec(for: build),
                                        "\(recipeName) 无 \(build) 的 \(archNote) 变体")
                #expect(!spec.stubs.isEmpty, "\(build) 变体必须带桩表")
                #expect(!spec.zeroRegions.isEmpty, "\(build) 变体必须带懒初始化清零区")
                #expect(spec.probes.contains { $0.first == "revokemsg" },
                        "\(build) 变体必须带家族地面真值探针")
                #expect(spec.stubs != legacy.stubs,
                        "\(build) 变体桩 VA 与 legacy 相同——疑似抄错（绝对 VA 逐构建漂移）")
            }
        }
    }
}
