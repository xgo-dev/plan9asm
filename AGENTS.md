# plan9asm development guide

plan9asm translates Go Plan 9 assembly to LLVM IR. A change is complete only
when its accepted forms match Go, LLVM 22 compiles the affected targets, and
tests establish the relevant runtime semantics.

## Start here

1. Inspect `git status --short`, `git worktree list`, and `git remote -v`.
   Preserve existing changes and use a persistent development worktree.
2. Read [current work](docs/development/current-work.md) when continuing PR 40.
3. Read the guide for the task before editing:
   - [Instruction families](docs/development/instructions.md): TDD, Go tables,
     typed grammars, raw decoding, platform and semantic tests.
   - [Validation and PR completion](docs/development/validation.md): tool setup,
     full tests, benchmark, frozen reports, CI and review gates.
   - [Discovery operations](testdata/discovery/README.md): scanning, automatic
     deduplication/sorting, bidirectional cursors, traffic and ledger format.
   - [Discovery verification](docs/development/discovery-verification.md):
     standalone inventory, imports, applicability, cache cleanup and provenance.

## Non-negotiable rules

- Inspect the destination remote before writing. Push this contribution only
  to the allowed `cpunion` fork, never to `origin` or `xgo-dev`. Do not merge,
  approve or close upstream PRs, publish tags/releases, or change upstream
  settings. Creating/updating this contribution PR is allowed.
- Keep code and fixtures readable: use multi-line control flow and moderate
  blank lines between logical phases. Use `apply_patch`, then `gofmt`.
- Never commit personal paths, private hostnames/accounts or deployment
  settings. Use relative paths, configurable variables and placeholders.
- Develop with current Go 1.27 and LLVM 22 **only**. Never fall back to another
  LLVM release. Missing required compilers, linkers or backends fail tests.
- All five architectures are supported: `386`, `amd64`, `arm`, `arm64`,
  `wasm`. Do not skip a form because it differs from the host architecture.
  Host-inapplicable runtime tests need a required cross-runtime counterpart.
- Run tests with Go while llgo support is incomplete; do not add `!llgo` tags.
  Never generate LLVM `blockaddress` for wasm.
- Use TDD and implement complete instruction families and Go operand formats,
  not just an observed spelling. Consult full Go tables before implementation.
- Never disguise unsupported instructions, translation/LLVM failures, missing
  tools or infrastructure errors as success or source N/A.
- An exact external module version may be `skipped_invalid_source` only when
  `testdata/corpus/invalid-machine-code.json` pins the source SHA-256 and
  executable evidence: either LLVM 22 rejects the evaluated raw ARM64 WORD,
  or Go's own object places an unrelocated raw AMD64 RIP target outside every
  TEXT symbol with its named constant absent. The report/ledger retain the
  reason. A skip is never a pass.
- A frozen historical mirror/fork may be `skipped_superseded` only when
  `testdata/corpus/superseded-modules.json` names an exact newer version
  already in the scan ledger and gives reviewable project-identity evidence.
  This is separate from both source N/A and assembly success; the replacement
  is independently scanned and, if it has assembly, tested.
- A private-extension gap may be `skipped_private_extension` only for the
  exact file and target pinned in `testdata/corpus/private-extensions.json`.
  Verify the source hash and current Go assembler, compile every other
  applicable file, and count the candidate separately from passes.
- Freeze source, tools and ledger during corpus verification. A changed input
  invalidates the run. Do not rebase, rewrite or import records into that tree
  while tests are running; use a separate persistent worktree for development.
- Keep reports/binaries under ignored `_out/`. Never commit caches, ZIPs,
  compressed discovery results or obsolete per-run ledgers, even in history.
- Commit verified development promptly. Keep PR 40 draft until current-head
  tests, CI, review and coverage meet the completion gates.

## Common commands

Run from the repository root after selecting the tools described in
[validation](docs/development/validation.md). Keep focused red/green logs.

```sh
go test . -run '<focused-family-regex>' -count=1
go test ./... -count=1 -timeout=20m
(cd cmd/plan9asm && go test ./... -count=1)
(cd cmd/plan9asmll && go test ./... -count=1)

scripts/check-go-asm-coverage.sh
scripts/check-arm64-plan9-corpus.sh
scripts/check-stdlib-corpus.sh
scripts/benchmark-compile.sh

go run ./cmd/plan9asmdiscover -status -out-dir testdata/discovery/ledger
bash scripts/discovery-status.sh
scripts/update-assembly-ledger.sh
```

New external-library scans and compilation use current Go 1.27, not the whole
Go 1.20–1.27 matrix. That compatibility matrix belongs to the official corpus.
Discovery records prove inspection; corpus reports prove translation/object
compilation; runtime tests prove only their executed semantics. Keep these
claims separate.

## Documentation maintenance

Keep this file a short entry point. Put durable procedures in the linked
guides and replace, rather than append to, the current-work checkpoint. Keep
scan/coverage funnel tables in the PR body; derive them from validated reports.
Old progress narratives remain in Git history, not in this guide.
