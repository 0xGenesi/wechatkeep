// Top-level entry (this file MUST be main.swift for top-level statements).
// The verify workers run BEFORE ArgumentParser so a crash inside mapped code
// kills only this process; they are not part of the public CLI surface.
if CommandLine.arguments.count > 1, CommandLine.arguments[1] == "__verify-worker" {
    Verifier.workerMain(Array(CommandLine.arguments.dropFirst(2)))
}
if CommandLine.arguments.count > 1, CommandLine.arguments[1] == "__parse-oracle-worker" {
    ParseOracle.workerMain(Array(CommandLine.arguments.dropFirst(2)))
}

Wxkeep.main()
