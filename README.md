# plan9asm

[![Build Status](https://github.com/xgo-dev/plan9asm/actions/workflows/go-ci.yml/badge.svg)](https://github.com/xgo-dev/plan9asm/actions/workflows/go-ci.yml)
[![GitHub release](https://img.shields.io/github/v/tag/xgo-dev/plan9asm.svg?label=release)](https://github.com/xgo-dev/plan9asm/releases)
[![Coverage Status](https://codecov.io/gh/xgo-dev/plan9asm/branch/main/graph/badge.svg)](https://codecov.io/gh/xgo-dev/plan9asm)
[![GoDoc](https://pkg.go.dev/badge/github.com/xgo-dev/plan9asm.svg)](https://pkg.go.dev/github.com/xgo-dev/plan9asm)
[![XGo](https://img.shields.io/badge/project-XGo-blue.svg)](https://github.com/goplus/xgo)

`github.com/xgo-dev/plan9asm`

Plan 9 assembly parser and LLVM IR translator, extracted as an independent module.

## Repository layout

- `github.com/xgo-dev/plan9asm`: parser + lowering library.
- `cmd/plan9asm`: package/file oriented helper (`list`, `transpile`), moved from `llgo-stdlib-opt/chore/plan9asm`.
- `cmd/plan9asmll`: stdlib-oriented converter/test tool (`.s -> .ll`, optional `llc` compile).

## Current status

- Library parser/lowering targets: `386`, `amd64`, `arm`, `arm64`, `wasm`.
- Tool targets (`cmd/plan9asmll -all-targets`):
  - `darwin/amd64`, `darwin/arm64`
  - `linux/386`, `linux/amd64`, `linux/arm`, `linux/arm64`
  - `windows/386`, `windows/amd64`, `windows/arm64`
  - `js/wasm`, `wasip1/wasm`
- The package-oriented `cmd/plan9asm` and coverage-oriented
  `cmd/plan9asmscan` support the same five Plan 9 assembly architectures.
- `386` currently reuses the x86 lowering path from `amd64` backend logic.
- `arm64` does not include `arm` (32-bit). They are separate architectures.
- Instruction coverage is tracked for all five LLGo Plan 9 assembly GOARCH
  targets by architecture, level, family, opcode, and operand form against Go's
  official opcode/encoder sources, positive GOROOT assembly, and executable
  real-world regressions. See
  [Plan 9 assembly instruction coverage](doc/plan9asm-corpus.md).

## LLVM backend

- LLVM 22 is the only supported object-code toolchain; LLVM 23 and older
  releases are intentionally rejected instead of used as fallbacks.
- `TranslateModule` builds an in-memory `llvm.Module` (`github.com/xgo-dev/llvm`).
- `Translate` keeps compatibility and returns textual IR from that module.
- The root module uses `github.com/xgo-dev/llvm` for LLVM bindings.
- Both `cmd/plan9asm` and `cmd/plan9asmll` use `golang.org/x/tools/go/packages`
  in their separate modules.
- `cmd/plan9asm` does not depend on `llgo/internal/build` or `llgo/internal/packages`.

## Quick test

```bash
go test ./...
```

Some tests require local LLVM 22 tools (`llc`, `clang`) and skip when unavailable.

The executable cases under `testdata/conformance` use the native Go
assembler as an oracle, then compile and run the same assembly through
plan9asm/LLVM. Run them with:

```bash
go test . -run 'Test.*Conformance'
```

The separate cross-version instruction coverage gate compares Go's assembler
corpus and encoder forms against the checked-in baseline:

```bash
scripts/check-go-asm-coverage.sh
```

On a Linux/amd64 host with the Debian cross GCC toolchains and QEMU user-mode
emulators installed, run the cross-architecture link and execution smoke test:

```bash
PLAN9ASM_CROSS_EXEC=1 go test . -run '^TestCrossLinuxRuntimeMatrix$' -count=1 -v
```

## `cmd/plan9asmll` usage

Show flags:

```bash
go run -C cmd/plan9asmll . -h
```

List selected asm files only:

```bash
go run -C cmd/plan9asmll . -patterns=std -goos=linux -goarch=386 -list-only
```

Convert one target (`.s -> .ll`):

```bash
go run -C cmd/plan9asmll . \
  -patterns=std \
  -goos=linux -goarch=amd64 \
  -out _out/plan9asmll/linux-amd64 \
  -report /tmp/plan9asmll-linux-amd64.json
```

Convert and compile (`.ll -> .o`) via `llc`:

```bash
go run -C cmd/plan9asmll . \
  -all-targets \
  -patterns=std \
  -compile \
  -out _out/plan9asmll/all-targets \
  -report /tmp/plan9asmll-all-targets.json
```

Run only x86 (`386`) targets:

```bash
go run -C cmd/plan9asmll . \
  -patterns=std \
  -targets=linux/386,windows/386 \
  -compile \
  -out _out/plan9asmll/x86 \
  -report /tmp/plan9asmll-x86.json
```

For an ordinary external module, `-feature-profile` explicitly consumes a
private `actual_go_cpu_profile_consumer_v1` invocation artifact. It re-observes
the actual Go marker/environment/tool identity, loads that same environment,
checks selected source hashes and package-role macros, and records CPP/LLVM
output hashes. Source directories and module replacements must match the
artifact's exact source root. Special and test-only package roles remain
outside this mode. Without the flag, existing CLI behavior is unchanged.
The external runner in [llgo-compat/plan9asm](https://github.com/llgo-compat/plan9asm)
owns module discovery, ledger records and third-party compatibility CI. It pins
this translator and the shared `gotoolprofile` package; translation/object
checks remain distinct from operand-form and runtime coverage.

## Output behavior

- Every asm file is printed with explicit status (`OK` or `FAIL`).
- On failure, tool prints:
  - the primary reason line,
  - unsupported opcode set (if detected),
  - per-hit location as file line number + source line.
- `-keep-going=true` (default) continues through all files and summarizes at the end.

## Notes

- The stdlib asm corpus depends on your local Go toolchain version (`go tool dist list`, `GOROOT` content).
- If `-compile` is enabled, LLVM 22's `llc-22` (or a version-verified `llc`)
  must be discoverable in `PATH` or set via `-llc`.
- Design notes and migration details are in `doc/llvm-module-migration.md`.

## `cmd/plan9asm` usage

List packages/files containing `.s`:

```bash
go run -C cmd/plan9asm . list -goos=linux -goarch=amd64 std
```

`transpile` package mode uses positional patterns (`go build/test` style) and supports multiple patterns.

Transpile package selected `.s` files:

```bash
go run -C cmd/plan9asm . transpile \
  -dir _out/plan9asm/runtime-linux-amd64 \
  -goos=linux -goarch=amd64 \
  runtime
```

Transpile one `.s` file:

```bash
go run -C cmd/plan9asm . transpile \
  -i /path/to/file.s \
  -o /tmp/file.ll \
  -goos=linux -goarch=amd64
```

## Native Darwin/ARM64 assembly

`TranslateNativeARM64Source` emits native assembly directly from a bounded Plan 9
subset for raw callbacks and trampolines. It preserves explicitly written register
interfaces without synthesizing LLVM function signatures or using Go assembler
objects. The driver invokes the native assembler, binds the returned DATA globals,
and supplies imported symbols and library link arguments.

`ForeignARM64Functions` is a routing hint for files containing only local TEXT;
it does not establish a C ABI. Unsupported frames, flags, instructions, operands,
and references produce errors. Go-declared functions retain typed LLVM translation;
unresolved local signatures require explicit metadata instead of a `void()` guess.

See [the native backend contract](doc/native-arm64.md) for the exact source,
instruction, data and runtime boundaries. The former `TranslateNativeARM64Object`
API has been removed; callers pass source to `TranslateNativeARM64Source` instead.
