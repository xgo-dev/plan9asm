# plan9asm

[![Build Status](https://github.com/xgo-dev/plan9asm/actions/workflows/go.yml/badge.svg)](https://github.com/xgo-dev/plan9asm/actions/workflows/go.yml)
[![GitHub release](https://img.shields.io/github/v/tag/xgo-dev/plan9asm.svg?label=release)](https://github.com/xgo-dev/plan9asm/releases)
[![Coverage Status](https://codecov.io/gh/xgo-dev/plan9asm/branch/main/graph/badge.svg)](https://codecov.io/gh/xgo-dev/plan9asm)
[![GoDoc](https://pkg.go.dev/badge/github.com/xgo-dev/plan9asm.svg)](https://pkg.go.dev/github.com/xgo-dev/plan9asm)

`github.com/xgo-dev/plan9asm`

Plan 9 assembly parser and LLVM IR translator, extracted as an independent module.

## Repository layout

- `github.com/xgo-dev/plan9asm`: parser + lowering library.
- `cmd/plan9asm`: package/file oriented helper (`list`, `transpile`), moved from `llgo-stdlib-opt/chore/plan9asm`.
- `cmd/plan9asmll`: stdlib-oriented converter/test tool (`.s -> .ll`, optional `llc` compile).

## Current status

- Library parser/lowering targets: `amd64`, `arm64`.
- Tool targets (`cmd/plan9asmll -all-targets`):
  - `darwin/amd64`, `darwin/arm64`
  - `linux/amd64`, `linux/arm64`, `linux/386`
  - `windows/amd64`, `windows/arm64`, `windows/386`
- `386` currently reuses the x86 lowering path from `amd64` backend logic.
- `arm64` does not include `arm` (32-bit). They are separate architectures.

## LLVM backend

- `TranslateModule` builds an in-memory `llvm.Module` (`github.com/xgo-dev/llvm`).
- `Translate` keeps compatibility and returns textual IR from that module.
- Root module dependency stays small (`goplus/llvm`).
- `golang.org/x/tools/go/packages` is used only in `cmd/plan9asmll` submodule.
- `cmd/plan9asm` does not depend on `llgo/internal/build` or `llgo/internal/packages`.

## Quick test

```bash
go test ./...
```

Some tests require local LLVM/Clang tools (`llc`, `clang`) and skip when unavailable.

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

## Output behavior

- Every asm file is printed with explicit status (`OK` or `FAIL`).
- On failure, tool prints:
  - the primary reason line,
  - unsupported opcode set (if detected),
  - per-hit location as file line number + source line.
- `-keep-going=true` (default) continues through all files and summarizes at the end.

## Notes

- The stdlib asm corpus depends on your local Go toolchain version (`go tool dist list`, `GOROOT` content).
- If `-compile` is enabled, `llc` must be discoverable in `PATH` or set via `-llc`.
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
