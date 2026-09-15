import Foundation

/// Behavioral verification: prove a patch's EFFECT by calling the patched
/// function out-of-process (mini-loader route — no dyld, no initializers,
/// no app bundle deps; validated by the M2-3 spike on real 269602 x64).
///
/// Architecture: the CLI re-execs itself as a hidden `__verify-worker` so a
/// crash inside mapped code kills only the worker; the parent interprets the
/// exit status (0 = probes ran; signal = crash / environment blocks unsigned
/// executable memory).
///
/// The worker exploits this image family's layout invariants:
///   - file offset == VA across __TEXT/__DATA_CONST/__DATA → base+VA indexing
///   - imports the target calls go through PLT stubs (`ff 25 <rel32>`) whose
///     GOT slots can be redirected to native harness functions
///   - C++ magic-static regions start zeroed at runtime; raw file bytes are
///     not the runtime state → explicit zero prep
///   - arguments use WeChat's custom SSO string layout (size<<1 in byte 0,
///     LSB = long flag; short data at +1; long: size@+8, ptr@+0x10)
enum Verifier {
    enum VerifyError: Error, CustomStringConvertible {
        case noVerifySpec(arch: String)
        case workerCrashed(signal: Int32)
        case environmentBlocked
        case mismatch(detail: String)

        var description: String {
            switch self {
            case .noVerifySpec(let arch):
                "no verify spec for \(arch) in signatures.json — behavior check unavailable for this build"
            case .workerCrashed(let sig):
                "verification worker crashed (signal \(sig)) — the function touched state we didn't model"
            case .environmentBlocked:
                "environment blocked executing mapped code (AMFI on / SIP on). "
                + "Behavioral verification needs a relaxed machine (this project's docs explain the trade-off)"
            case .mismatch(let detail):
                "behavior mismatch: \(detail)"
            }
        }
    }

    struct VerifySpec: Codable {
        /// hex stub VA → "strlen" / "memcmp" (native replacements)
        let stubs: [String: String]
        /// [[hexVA, byteLen], ...] regions to zero before probing (magic statics)
        let zeroRegions: [[String]]
        /// [text, expectedOnPristine(0/1), ...]
        let probes: [[String]]

        enum CodingKeys: String, CodingKey {
            case stubs, probes
            case zeroRegions = "zero_regions"
        }
    }

    struct ProbeResult {
        let text: String
        let returned: Bool
    }

    // MARK: - Parent side

    /// Runs behavioral probes against `dylib` (thin or fat; fat slices are
    /// extracted via lipo). Returns one result per probe, in spec order.
    static func run(binary: URL, targetVA: UInt64, spec: VerifySpec,
                    executable: URL? = nil) throws -> [ProbeResult] {
        // Fat → thin slice (worker assumes VA == file offset of a thin image).
        let magic = (try? Data(contentsOf: binary, options: .alwaysMapped).prefix(4))
        var thin = binary
        var tempThin: URL?
        if let m = magic, m == Data([0xCA, 0xFE, 0xBA, 0xBE]) {
            let out = FileManager.default.temporaryDirectory
                .appendingPathComponent("wxkeep-verify-\(UUID().uuidString).x64")
            let lipo = Shell.run("/usr/bin/lipo", ["-thin", "x86_64", binary.path, "-output", out.path])
            guard lipo.status == 0 else { throw VerifyError.workerCrashed(signal: 0) }
            thin = out
            tempThin = out
        }
        defer { if let tempThin { try? FileManager.default.removeItem(at: tempThin) } }

        let stubsJSON = jsonString(spec.stubs) ?? "{}"
        let zerosJSON = jsonString(spec.zeroRegions) ?? "[]"
        let probesJSON = jsonString(spec.probes) ?? "[]"
        let exe = executable ?? URL(fileURLWithPath: CommandLine.arguments[0])
        let result = Shell.run(exe.path, [
            "__verify-worker", thin.path, String(targetVA, radix: 16),
            stubsJSON, zerosJSON, probesJSON,
        ])
        if result.status != 0 {
            if result.status > 128 { throw VerifyError.workerCrashed(signal: result.status - 128) }
            if result.status == 126 || result.status == 137 { throw VerifyError.environmentBlocked }
            throw VerifyError.workerCrashed(signal: result.status)
        }
        return result.stdout.split(separator: "\n").compactMap { line in
            // probe|<text>|<0|1>
            let parts = line.split(separator: "|", omittingEmptySubsequences: false)
            guard parts.count == 3, parts[0] == "probe" else { return nil }
            return ProbeResult(text: String(parts[1]), returned: parts[2] == "1")
        }
    }

    private static func jsonString<T: Encodable>(_ value: T) -> String? {
        guard let data = try? JSONEncoder().encode(value) else { return nil }
        return String(data: data, encoding: .utf8)
    }

    // MARK: - Worker side (runs in the forked copy of this executable)

    /// Entry for `wxkeep __verify-worker <dylib> <va> <stubs> <zeros> <probes>`.
    /// Prints `probe|<text>|<0|1>` lines and exits 0; crashes on bad state.
    static func workerMain(_ args: [String]) -> Never {
        guard args.count >= 5,
              let data = try? Data(contentsOf: URL(fileURLWithPath: args[0])),
              let va = UInt64(args[1], radix: 16),
              let stubs = try? JSONDecoder().decode([String: String].self, from: Data(args[2].utf8)),
              let zeros = try? JSONDecoder().decode([[String]].self, from: Data(args[3].utf8)),
              let probes = try? JSONDecoder().decode([[String]].self, from: Data(args[4].utf8))
        else { exit(2) }

        // Map the whole thin image RWX (VA == file offset invariant).
        let mapped = data.withUnsafeBytes { raw -> UnsafeMutableRawPointer in
            let base = mmap(nil, raw.count, PROT_READ | PROT_WRITE | PROT_EXEC,
                            MAP_PRIVATE | MAP_ANON, -1, 0)
            guard let base = base, base != UnsafeMutableRawPointer(bitPattern: -1) else { exit(126) }
            memcpy(base, raw.baseAddress, raw.count)
            return base
        }

        // Zero magic-static regions to their runtime-start state.
        for region in zeros {
            guard region.count == 2, let vaHex = UInt64(region[0], radix: 16),
                  let len = Int(region[1]) else { continue }
            memset(mapped + Int(vaHex), 0, len)
        }

        // Redirect PLT GOT slots: `ff 25 <rel32>` → slot offset = stubVA + 6 + disp.
        for (stubHex, kind) in stubs {
            guard let stubVA = UInt64(stubHex, radix: 16) else { continue }
            let stub = UnsafeRawPointer(mapped + Int(stubVA))
            guard stub.load(as: UInt8.self) == 0xFF,
                  stub.load(fromByteOffset: 1, as: UInt8.self) == 0x25 else { continue }
            // swift load() enforces alignment — assemble the unaligned rel32 byte-wise
            var dispValue: UInt32 = 0
            for i in 0..<4 {
                dispValue |= UInt32(stub.load(fromByteOffset: 2 + i, as: UInt8.self)) << (8 * i)
            }
            let disp = Int32(bitPattern: dispValue)
            let slot = mapped + Int(stubVA) + 6 + Int(disp)
            let sym = kind == "memcmp" ? "memcmp" : "strlen"
            if let fn = dlsym(dlopen(nil, RTLD_LAZY), sym) {
                slot.assumingMemoryBound(to: UnsafeMutableRawPointer?.self).pointee = fn
            }
        }

        // WeChat SSO string ABI: pass 24 CONTIGUOUS bytes. Array's own
        // withUnsafeMutableBytes yields the element buffer — never &array
        // (that is the array header: pointer+count, not the data).
        let fn: @convention(c) (UnsafeMutableRawPointer) -> Bool =
            unsafeBitCast(mapped + Int(va), to: (@convention(c) (UnsafeMutableRawPointer) -> Bool).self)

        var out = ""
        for probe in probes {
            guard let text = probe.first else { continue }
            let bytes = Array(text.utf8)
            // Short-SSO probes only (<23 bytes); long-string construction is
            // deliberately unsupported (no current spec needs it).
            guard bytes.count < 23 else { continue }
            var storage = [UInt8](repeating: 0, count: 24)
            storage[0] = UInt8(bytes.count << 1)
            for (i, byte) in bytes.enumerated() { storage[1 + i] = byte }
            let r = storage.withUnsafeMutableBytes { raw in fn(raw.baseAddress!) }
            out += "probe|\(text)|\(r ? 1 : 0)\n"
        }
        FileHandle.standardOutput.write(out.data(using: .utf8)!)
        exit(0)
    }


    // MARK: - Verdict

    /// Compares probe results against the expected behavior for the given
    /// on-disk state (pristine expects the spec's expecteds; patched expects
    /// every probe to return the neutralized value).
    static func verdict(
        results: [ProbeResult], spec: VerifySpec, state: Patcher.Inspection.State
    ) -> VerifyError? {
        let expecteds: [Bool?] = spec.probes.map { $0.count > 1 ? $0[1] == "1" : nil }
        switch state {
        case .pristine:
            for (result, expected) in zip(results, expecteds) {
                if let expected, result.returned != expected {
                    return .mismatch(detail: "pristine image: isRevokemsg(\"\(result.text)\") = \(result.returned ? 1 : 0), expected \(expected ? 1 : 0)")
                }
            }
        case .patched:
            for (result, expected) in zip(results, expecteds) {
                if expected == true && result.returned {
                    return .mismatch(detail: "patched image still classifies \"\(result.text)\" as revokemsg — patch ineffective")
                }
            }
        case .unknown:
            return .mismatch(detail: "patch point holds unknown bytes — verify against pristine/patched expectations is undefined")
        }
        return nil
    }
}
