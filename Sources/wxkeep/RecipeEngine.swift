import Foundation

/// Locates patch points from recipes — location methodology as DATA.
///
/// A recipe produces one patch-site VA; the Patcher's expected-byte gate then
/// decides whether anything is written (a recipe only picks WHERE, never
/// whether). Grammar (kept deliberately small — precise-VA entries stay the
/// first-class representation for curated data):
///
///   anchor : "imm64:<8 ascii>"      movabs immediate, e.g. imm64:revokems (x64)
///          | "bytes:<hex>"          raw byte pattern, e.g. bytes:40100034 (arm64 cbz)
///   derive : "padding-boundary"     site = function entry above the anchor
///                                   (scan back to ret/jmp + CC/90/66-90 padding)
///          | "self"                 site = the anchor itself
///   confirm: "unique-hit"                       exactly one anchor occurrence
///           | "unique-positive-callers"         exactly one candidate has ≥1
///                                               direct E8 rel32 callers (x64)
///           | "bytes@<+hexoff>:<hex>[:mask<hex>]" word at site+offset matches
///                                               (masked) — arm64 geometric 2nd anchor
struct RecipeEngine {
    enum RecipeError: Error, CustomStringConvertible {
        case malformed(String)
        case noHit(anchor: String)
        case ambiguous(Int, anchor: String)
        case confirmFailed(String)
        case unsupportedArch(String)

        var description: String {
            switch self {
            case .malformed(let detail): return "malformed recipe: \(detail)"
            case .noHit(let a): return "anchor \(a) not found — new signature generation? needs human analysis"
            case .ambiguous(let n, let a): return "anchor \(a) hit \(n) sites after confirmation — refusing to guess"
            case .confirmFailed(let c): return "confirmation '\(c)' failed on all candidates"
            case .unsupportedArch(let a): return "recipe primitive not available for \(a)"
            }
        }
    }

    struct Recipe {
        let anchor: String
        let derive: String
        let confirms: [String]

        init(anchor: String, derive: String, confirm: [String]) {
            self.anchor = anchor
            self.derive = derive
            self.confirms = confirm
        }

        init(dict: [String: String]) throws {
            guard let a = dict["anchor"], let d = dict["derive"] else {
                throw RecipeError.malformed("needs anchor and derive")
            }
            self.anchor = a
            self.derive = d
            self.confirms = dict["confirm"].map { $0.split(separator: ";").map(String.init) } ?? []
        }
    }

    /// Resolves a recipe to the single patch-site VA within `image`.
    static func resolve(recipe: Recipe, image: MachImage, arch: Config.Arch) throws -> UInt64 {
        let pattern = try anchorPattern(recipe.anchor)
        let text = try image.section("__text")
        let hits = try image.offsets(of: pattern, in: "__text")
        guard !hits.isEmpty else { throw RecipeError.noHit(anchor: recipe.anchor) }
        let hitVAs = hits.map { text.addr + UInt64($0 - text.offset) }

        // Derive candidate sites from anchors.
        var candidates: [UInt64]
        switch recipe.derive {
        case "self":
            candidates = hitVAs
        case "padding-boundary":
            guard arch == .x86_64 else { throw RecipeError.unsupportedArch(arch.rawValue) }
            // First TWO boundaries per anchor: on an already-patched binary the
            // patch's own ret+NOPs form the first boundary — the real entry is
            // the next one back (predecessor projects hit the same trap).
            candidates = hitVAs.flatMap { entryVAs(aboveAnchorVA: $0, image: image) }
        default:
            throw RecipeError.malformed("unknown derive \(recipe.derive)")
        }
        guard !candidates.isEmpty else { throw RecipeError.noHit(anchor: recipe.anchor) }

        // Apply confirmations; each must narrow to ≥1 candidate.
        var survivors = candidates
        for confirm in recipe.confirms {
            var next: [UInt64] = []
            for site in survivors {
                if try passes(confirm: confirm, site: site, image: image, arch: arch) { next.append(site) }
            }
            guard !next.isEmpty else { throw RecipeError.confirmFailed(confirm) }
            survivors = next
        }
        guard survivors.count == 1 else { throw RecipeError.ambiguous(survivors.count, anchor: recipe.anchor) }
        return survivors[0]
    }

    // MARK: - Primitives

    private static func anchorPattern(_ spec: String) throws -> Data {
        if spec.hasPrefix("imm64:") {
            let ascii = String(spec.dropFirst(6))
            guard let data = ascii.data(using: .ascii), data.count == 8 else {
                throw RecipeError.malformed("imm64 anchor needs exactly 8 ascii bytes: \(spec)")
            }
            return data
        }
        if spec.hasPrefix("bytes:") {
            guard let data = Data(hex: String(spec.dropFirst(6))) else {
                throw RecipeError.malformed("bad hex in \(spec)")
            }
            return data
        }
        throw RecipeError.malformed("unknown anchor \(spec)")
    }

    /// x64 function entry: scan back to a ret/jmp followed by CC/90/66-90 padding.
    /// x64 function entries: scan back to ret/jmp boundaries followed by
    /// CC/90/66-90 padding. Returns the first two boundaries (see resolve()).
    private static func entryVAs(aboveAnchorVA va: UInt64, image: MachImage) -> [UInt64] {
        guard let off = image.sliceRelativeOffset(va: va) else { return [] }
        var out: [UInt64] = []
        var o = off
        while o > 0 && out.count < 2 {
            o -= 1
            let b = image.data[o]
            if b == 0xC3 || b == 0xE9 || b == 0xEB {
                var e = o + 1
                while e < image.data.count {
                    if image.data[e] == 0xCC || image.data[e] == 0x90 { e += 1 }
                    else if image.data[e] == 0x66 && e + 1 < image.data.count && image.data[e+1] == 0x90 { e += 2 }
                    else { break }
                }
                // hot-patch dispatch stub (4.1.6-era): `mov rax,[rip+d]; test;
                // je +2; jmp rax` (14 bytes) precedes the real prologue — the
                // boundary lands on the stub, the real entry is right after.
                if e + 14 <= image.data.count,
                   image.data[e] == 0x48, image.data[e+1] == 0x8B, image.data[e+2] == 0x05,
                   image.data[e+7] == 0x48, image.data[e+8] == 0x85, image.data[e+9] == 0xC0,
                   image.data[e+10] == 0x74, image.data[e+11] == 0x02,
                   image.data[e+12] == 0xFF, image.data[e+13] == 0xE0 {
                    e += 14
                }
                if let text = try? image.section("__text"),
                   e >= text.offset && e < text.offset + Int(text.size) {
                    out.append(text.addr + UInt64(e - text.offset))
                }
            }
        }
        return out
    }

    private static func passes(confirm: String, site: UInt64, image: MachImage, arch: Config.Arch) throws -> Bool {
        if confirm == "unique-hit" {
            return true // handled by the final count check
        }
        if confirm == "unique-positive-callers" {
            guard arch == .x86_64 else { throw RecipeError.unsupportedArch(arch.rawValue) }
            var count = callerCount(of: site, in: image)
            // stub-era callers invoke the 14-byte hot-patch stub, not the real
            // body — count both sides of the same logical function
            if let stub = stubSite(forRealEntry: site, in: image) {
                count += callerCount(of: stub, in: image)
            }
            return count > 0
        }
        // bytes@+7A0:60E600F9:maskFFFFFFE0
        if confirm.hasPrefix("bytes@") {
            let parts = confirm.dropFirst(6).split(separator: ":").map(String.init)
            guard parts.count >= 2,
                  let off = UInt64(parts[0].hasPrefix("+") ? String(parts[0].dropFirst()) : parts[0], radix: 16),
                  let want = Data(hex: parts[1])
            else { throw RecipeError.malformed("bad bytes@ confirm \(confirm)") }
            var mask = Data(repeating: 0xFF, count: want.count)
            if parts.count == 3, parts[2].hasPrefix("mask"), let m = Data(hex: String(parts[2].dropFirst(4))) {
                mask = m
            }
            guard let got = image.bytes(va: site + off, count: want.count) else { return false }
            for i in 0..<want.count {
                if got[i] & mask[i % mask.count] != want[i] & mask[i % mask.count] { return false }
            }
            return true
        }
        throw RecipeError.malformed("unknown confirm \(confirm)")
    }

    /// If `site` is a real entry preceded by the 14-byte hot-patch stub,
    /// returns the stub's VA (its callers are the function's callers).
    private static func stubSite(forRealEntry site: UInt64, in image: MachImage) -> UInt64? {
        guard let off = image.sliceRelativeOffset(va: site), off >= 14 else { return nil }
        let stub = off - 14
        let d = image.data
        guard stub + 14 <= d.count,
              d[stub] == 0x48, d[stub+1] == 0x8B, d[stub+2] == 0x05,
              d[stub+7] == 0x48, d[stub+8] == 0x85, d[stub+9] == 0xC0,
              d[stub+10] == 0x74, d[stub+11] == 0x02,
              d[stub+12] == 0xFF, d[stub+13] == 0xE0 else { return nil }
        guard let text = try? image.section("__text"),
              stub >= text.offset, stub < text.offset + Int(text.size) else { return nil }
        return text.addr + UInt64(stub - text.offset)
    }

    /// Direct E8 rel32 callers of `site` inside __text (x64).
    static func callerCount(of site: UInt64, in image: MachImage) -> Int {
        guard let text = try? image.section("__text") else { return 0 }
        var count = 0
        var o = text.offset
        let end = min(text.offset + Int(text.size), image.data.count - 5)
        while o < end {
            if image.data[o] == 0xE8 {
                let disp = image.data.subdata(in: (o+1)..<(o+5)).withUnsafeBytes {
                    $0.loadUnaligned(fromByteOffset: 0, as: Int32.self)
                }
                let callVA = text.addr + UInt64(o - text.offset)
                if Int64(callVA) + 5 + Int64(disp) == Int64(site) { count += 1 }
            }
            o += 1
        }
        return count
    }
}
