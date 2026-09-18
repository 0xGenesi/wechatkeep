import Foundation

/// An `expected` byte variant that tolerates per-build drift: `?` marks a
/// don't-care nibble, an optional `:maskHEX` suffix ANDs out further bits
/// (the mask idea of RecipeEngine's `bytes@…:mask` confirm, extended to the
/// write gate). One catalog entry can then cover a site family whose branch
/// displacements / rebuilt immediates differ per build — e.g. the x64
/// parse-guard `test al,al; je rel32`:
///
///     expected: "84C00F84????????"   disp32 is don't-care
///     asm:      "30C0"               xor al,al ⇒ ZF=1 ⇒ je always taken
///
/// Matching is nibble-granular: a nibble is don't-care when wildmarked OR
/// its mask nibble is zero; otherwise it must equal (sub-nibble masks such
/// as E0 round toward the strict side — a gate may refuse, never overmatch).
/// Restore can only write back what is fully concrete: `concretePrefix`
/// materializes the leading bytes and returns nil at the first cared wildcard.
struct ExpectedPattern: Equatable {
    let spec: String
    /// One entry per nibble; nil = don't-care.
    private let nibbles: [Int?]
    /// Per-byte AND mask (cycled over the pattern), or nil = compare everything.
    private let mask: [UInt8]?

    var byteCount: Int { nibbles.count / 2 }
    var isFullyConcrete: Bool { concretePrefix(byteCount) != nil }

    init?(spec: String) {
        var body = spec
        var mask: [UInt8]? = nil
        if let colon = spec.firstIndex(of: ":") {
            body = String(spec[spec.startIndex..<colon])
            let tail = String(spec[colon...].dropFirst())
            guard tail.hasPrefix("mask"),
                  let m = Data(hex: String(tail.dropFirst(4))), !m.isEmpty else { return nil }
            mask = [UInt8](m)
        }
        let scalars = Array(body.unicodeScalars)
        guard !scalars.isEmpty, scalars.count % 2 == 0 else { return nil }
        var nibbles = [Int?]()
        nibbles.reserveCapacity(scalars.count)
        for s in scalars {
            if s == "?" { nibbles.append(nil); continue }
            guard let v = s.hexValue else { return nil }
            nibbles.append(v)
        }
        self.spec = spec
        self.nibbles = nibbles
        self.mask = mask
    }

    /// `data` (≥ byteCount bytes) matches the pattern.
    func matches(_ data: Data) -> Bool {
        guard data.count >= byteCount else { return false }
        for i in 0..<byteCount {
            let m = mask?[i % mask!.count] ?? 0xFF
            let hiWild = nibbles[2 * i] == nil || (m >> 4) == 0
            let loWild = nibbles[2 * i + 1] == nil || (m & 0xF) == 0
            if hiWild && loWild { continue }
            let got = data[i]
            if !hiWild && (got >> 4) != nibbles[2 * i]! { return false }
            if !loWild && (got & 0xF) != nibbles[2 * i + 1]! { return false }
        }
        return true
    }

    /// First `n` bytes as concrete data — nil if any wildcard or masked-out
    /// bit lies within them (0 < n ≤ byteCount).
    func concretePrefix(_ n: Int) -> Data? {
        guard n >= 0, n <= byteCount else { return nil }
        var out = [UInt8]()
        out.reserveCapacity(n)
        for i in 0..<n {
            let m = mask?[i % mask!.count] ?? 0xFF
            guard let hi = nibbles[2 * i], let lo = nibbles[2 * i + 1], m == 0xFF else { return nil }
            out.append(UInt8(hi << 4 | lo))
        }
        return Data(out)
    }
}
