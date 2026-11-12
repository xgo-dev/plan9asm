# plan9asm development

plan9asm translates Go Plan 9 assembly to LLVM IR. This repository owns the
translator, shared Go source/tool observations, official instruction coverage
and independent regression tests. External scanning, ledgers and compatibility
batches live in [llgo-compat/plan9asm](https://github.com/llgo-compat/plan9asm).

## Start here

1. Inspect `git status --short`, `git worktree list` and `git remote -v`.
   Preserve existing work and reuse a persistent idle worktree.
2. Read [architecture](docs/development/architecture.md), [current work](docs/development/current-work.md),
   [instruction families](docs/development/instructions.md) and
   [validation](docs/development/validation.md) for the task.

## Rules

- Push only to an allowed `cpunion` or `dastai` fork. Create/update the
  contribution PR; do not directly push, merge, approve or close upstream PRs.
- Use current Go 1.27 and LLVM 22. Never fall back to another LLVM version;
  missing required tools/backends fail, never skip.
- Support all five architectures: 386, amd64, arm, arm64 and wasm.
  Host-inapplicable runtime tests require an explicit cross-runtime counterpart.
  Never generate LLVM `blockaddress` for wasm.
- Use TDD. Consult complete official Go tables and implement typed instruction
  families and operand formats. Each ecosystem-discovered defect must have an
  independent regression and a rule-class fix, not a library-specific patch.
- Run tests with Go while llgo support is incomplete; do not add `!llgo` tags.
- Keep rejection, source context, translation, LLVM compilation and executed
  semantics distinct. Infrastructure failures never establish source rejection.
- Use `apply_patch`, readable multi-line code and moderate blank lines, then
  `gofmt`. Release LLVM objects and owned subprocess resources promptly.
- Do not commit private paths/hosts, package caches, binaries or reports.
  Keep evidence under ignored `_out/`; preserve failed reports as failed.
- Freeze source and tools during validation, even documentation. Never edit a
  running snapshot or reuse its report to certify a changed revision.
- Commit verified batches promptly. Stage repairs in the allowed fork; retain
  draft status until current-head tests, CI, review and coverage pass.
- Before publishing test-helper or workflow changes, run the complete Node
  policy suite and the Go `ci_policy` selector described in validation.

## Commands

After selecting the tools documented in validation:

```sh
go test . -run '<focused-family-regex>' -count=1
go test ./... -count=1 -timeout=45m
(cd cmd/plan9asm && go test ./... -count=1)
(cd cmd/plan9asmll && go test ./... -count=1)
scripts/check-go-asm-coverage.sh
scripts/check-arm64-plan9-corpus.sh
scripts/check-stdlib-corpus.sh --instructions-only
```

Instruction checks retain complete WASM source/object compilation. Default
full-source corpus and strict benchmark belong to the independent
[SDK/runtime integration workflow](docs/development/validation.md#official-forms-and-benchmark).

Do not reintroduce external discovery jobs or ledger gates into translator CI.
Keep this entry point short; durable procedures belong in linked documents.
