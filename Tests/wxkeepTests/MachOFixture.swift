import Foundation
import Testing
@testable import wxkeep

/// Synthetic Mach-O builders for offline tests — no real WeChat binaries needed.
/// Layout: mach_header_64 + one LC_SEGMENT_64 (`__TEXT` spanning the whole file,
/// vmaddr 0, fileoff 0) so **VA == slice-relative file offset** in every fixture.
struct MachOFixture {
    static let arm64CPU: Int32 = 0x0100000C
    static let x64CPU: Int32 = 0x01000007

    static func thin(cputype: Int32, size: Int = 0x400, code: [(offset: Int, bytes: [UInt8])] = []) -> Data {
        var data = Data(count: size)
        func put32(_ offset: Int, _ value: UInt32) {
            withUnsafeBytes(of: value.littleEndian) { raw in
                data.replaceSubrange(offset..<offset + 4, with: Data(raw))
            }
        }
        func put64(_ offset: Int, _ value: UInt64) {
            withUnsafeBytes(of: value.littleEndian) { raw in
                data.replaceSubrange(offset..<offset + 8, with: Data(raw))
            }
        }
        // mach_header_64
        put32(0, 0xFEEDFACF)
        put32(4, UInt32(bitPattern: cputype))
        put32(8, 0)      // cpusubtype
        put32(12, 6)     // MH_DYLIB
        put32(16, 1)     // ncmds
        put32(20, 72)    // sizeofcmds
        put32(24, 0)
        put32(28, 0)
        // LC_SEGMENT_64
        put32(32, 0x19)  // cmd
        put32(36, 72)    // cmdsize
        data.replaceSubrange(40..<56, with: Data(repeating: 0, count: 16))
        data.replaceSubrange(40..<45, with: Data("__TEXT".utf8))
        put64(56, 0)                  // vmaddr
        put64(64, UInt64(size))       // vmsize
        put64(72, 0)                  // fileoff
        put64(80, UInt64(size))       // filesize
        put32(88, 7); put32(92, 7); put32(96, 0); put32(100, 0)
        for (offset, bytes) in code {
            data.replaceSubrange(offset..<offset + bytes.count, with: Data(bytes))
        }
        return data
    }

    /// Wraps two thin images in a big-endian fat container.
    /// Returns the fat image plus each slice's absolute file offset.
    static func fat(arm64: Data, x64: Data) -> (image: Data, arm64Offset: Int, x64Offset: Int) {
        let armOffset = 0x400
        let x64Offset = (armOffset + arm64.count + 0xFFF) & ~0xFFF
        var out = Data()
        func append32(_ value: UInt32) {
            out.append(UInt8((value >> 24) & 0xFF))
            out.append(UInt8((value >> 16) & 0xFF))
            out.append(UInt8((value >> 8) & 0xFF))
            out.append(UInt8(value & 0xFF))
        }
        append32(0xCAFEBABE)
        append32(2)
        append32(UInt32(bitPattern: arm64CPU)); append32(0)
        append32(UInt32(armOffset)); append32(UInt32(arm64.count)); append32(12)
        append32(UInt32(bitPattern: x64CPU)); append32(0)
        append32(UInt32(x64Offset)); append32(UInt32(x64.count)); append32(12)
        out.append(Data(repeating: 0xCC, count: armOffset - out.count))
        out.append(arm64)
        out.append(Data(repeating: 0xCC, count: x64Offset - out.count))
        out.append(x64)
        return (out, armOffset, x64Offset)
    }

    static func entry(
        _ arch: Config.Arch, addr: String, asm: String,
        expected: [String]? = nil, source: String? = nil
    ) -> Config.PatchEntry {
        Config.PatchEntry(
            arch: arch, addr: addr, recipe: nil,
            expected: expected.map(Config.ExpectedVariants.init),
            asm: asm, source: source)
    }
}

// MARK: - assertion helpers

/// Asserts that `body` throws. Returns the error for optional further checks.
@discardableResult
func expectThrows<T>(_ body: @autoclosure () throws -> T, sourceLocation: SourceLocation = #_sourceLocation) -> any Error {
    do {
        _ = try body()
        Issue.record("expected an error but the call succeeded", sourceLocation: sourceLocation)
        return DummyError()
    } catch {
        return error
    }
}

struct DummyError: Error {}
