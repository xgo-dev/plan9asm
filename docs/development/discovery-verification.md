# Discovery verification and standalone inventory

Read [Discovery operations](../../testdata/discovery/README.md) for the canonical
ledger format, scan commands, version ordering, traffic accounting and cursors.
Do not hand-append JSONL: `plan9asmdiscover` validates, deduplicates, semver-sorts
and publishes records automatically.

## Inventory versus testing

`scanned` proves successful exact-version inspection, including no-assembly
results. `matched` additionally retains assembly paths. `failure` remains
retryable and does not prove absence. Retain all architecture hints for future
platform queries, not only currently supported targets.

The standalone inventory runs outside this repository and also collects direct
cgo imports. Keep its program, cgo records, deployment settings and traffic
reports outside plan9asm. Its server inventories source only: do not compile or
execute downloaded code there. Consult that checkout's own `AGENTS.md` for
service/synchronization commands; never hard-code a host or local workspace.

The standalone scanner persists successful latest resolutions with a
conservative freshness boundary. Older history reuses them across restarts;
incremental updates, higher module-path majors and retries remain eligible.
Resolving latest does not mark a failed ZIP inspection complete. Its assembly-
only export omits cgo and latest metadata for compatibility with this
repository's three record kinds.

## Cursors and safe publication

- Derive history from the first manifest range's start and incremental from
  the last range's end. An empty ledger starts at captured current time.
  Never invent a manual resume token.
- Reverse scans consume complete windows and retain equal-timestamp groups;
  incremental scans drain their entire captured interval. Reject gaps,
  overlaps and inconsistent repeated ranges.
- Prefer module-path major, then Go semver. Historical `/v3` still upgrades an
  already-seen `/v2`; later older `/v2` records are skipped. A future `/v4`
  remains discoverable incrementally.
- Concurrent network workers feed one publisher. Do not start a competing
  writer, remove a live lock, or overwrite a ledger being tested.
- Remote snapshots/imports validate checksums, counts, sorting and ranges.
  The standalone CLI waits on snapshot/writer contention without discarding
  an inspected batch; integrity failures are not lock retries.

## Importing an assembly-only checkpoint

First finish current corpus runs. Validate the export without network access:

```sh
go run ./cmd/plan9asmdiscover -status -out-dir "$ASSEMBLY_LEDGER"
```

Inspect ranges and records against the committed checkpoint and keep an ignored
recovery copy. The writer merges with the existing destination under its writer
lock, retaining the highest major/semver and rejecting discontinuous ranges.

For a validated checkpoint, the converter normalizes, merges, and atomically
publishes the destination. It is not a file-copy replacement:

```sh
go run ./cmd/plan9asmdiscover \
  -convert-report "$ASSEMBLY_LEDGER" \
  -out-dir testdata/discovery/ledger

go test ./cmd/plan9asmdiscover ./cmd/plan9asmcorpus -count=1
go run ./cmd/plan9asmdiscover -status -out-dir testdata/discovery/ledger
git diff --stat -- testdata/discovery/ledger
```

Review newly selected/retired versions and retries. Commit the normalized
checkpoint, then test every selected assembly-bearing version. Only one
manifest and 256 module-hashed JSONL shards belong in Git, never gzip/run trees.

## Applicability is evidence, not an escape hatch

Select by Go filename GOOS/GOARCH suffixes and `go/build.Context.MatchFile`.
Probe unsuffixed architecture-specific assembly with the current Go assembler.
Future-target queries conservatively retain unsuffixed/custom-suffixed paths
before reevaluating source constraints.

For each target/tag/package group:

1. Build that exact package with current Go, not `package/...`.
2. Run `go vet -asmdecl`. Only concrete argument-size/FP offset/FP width
   mismatches are ABI N/A. Generic vet errors must not hide translation.
3. Translate every applicable saved `.s` file and compile every result with
   LLVM 22 at `-O0`. IR is verified before `llc`, and an object must be
   generated; optimization is unnecessary for this compile-only corpus and
   costly for large generated files. Unsupported instructions, parser/LLVM
   errors and missing tools fail. Other gates retain their normal `llc` level.

Deterministic current-Go compiler/assembler rejection may be structured source
N/A for that package/target only. Network, proxy, timeout, process or filesystem
failures remain failures. Every N/A needs an allowed kind, affected files,
attempted targets and a diagnostic. Omitted `TEXT -args` is not explicit zero.

Keep regressions for test-only declarations, concrete referenced `go_asm.h`
layouts, undeclared tail-forwarding ABI inference and exact-package asmdecl.
Never accept arbitrary frame mismatches just to make historical modules pass.

## Reports and provenance

Corpus sharding is `sha256(module@version) % 32`, independent of module-hashed
ledger files. Parallel shards read one frozen ledger and write distinct reports:

```sh
PLAN9ASM_DISCOVERY_PARALLELISM=4 \
  scripts/check-discovered-library-corpus.sh all 32
scripts/verify-discovered-library-corpus.sh _out/discovered-library-corpus
```

The `all` command replaces stale canonical reports; save evidence elsewhere
under `_out/` first when needed. Download, applicability and each target
translation/compile operation each have a 60-minute deadline. Diagnostic
override: `PLAN9ASM_DISCOVERY_CANDIDATE_TIMEOUT`. A timeout fails.
The `all` command also gives its parallel shards one temporary Go build cache
and removes it after every shard exits. Independently invoked shards keep their
own build caches unless `PLAN9ASM_DISCOVERY_BUILD_CACHE` names an existing
absolute directory; an independently supplied cache is never deleted by the
runner.

The aggregate checks exact ledger ownership/inventory and these identities:

- `selected = passed + not_applicable + skipped_invalid_source + skipped_superseded + skipped_private_extension + failed`;
- each target's `total_asm = success + not_applicable + failed`;
- final `failed = 0`, each candidate appearing exactly once.

A passing candidate needs a successful target and no failed applicable target.
A global N/A candidate has no applicable target. Translation counts are
per-target; applicable assembly files form a unique set.

Only an exact module version with pinned source SHA-256 and independently
checked evidence can be `skipped_invalid_source`: either LLVM 22 rejects the
evaluated raw ARM64 WORD, or an AMD64 raw RIP instruction names an absent
file-local constant and Go's own assembled object places its fixed target
outside every TEXT symbol. The exception manifest is
`testdata/corpus/invalid-machine-code.json`. The runner downloads the exact
version into a disposable workspace and rechecks every witness. A changed
file, decodable ARM64 word, missing constant proof or required tool fails the
candidate; a skip
never contributes to passed candidates or translation counts. Reports and
the assembly ledger retain the reason and witnesses; progress and aggregate
verification compare them with the current pinned manifest.

An obsolete exact mirror/fork may instead be `skipped_superseded` when the
reviewed `testdata/corpus/superseded-modules.json` pins its replacement module
and a strictly newer version already recorded as scanned. Evidence links must
establish project identity, not just a similar name. The runner does not
download or translate the old version; the report and assembly ledger retain
its reason and replacement. This is not a pass. If the replacement has
assembly, it remains a separate corpus candidate and must pass the same gate.

`skipped_private_extension` is a file/target exception, not a module-wide
translation exemption. The reviewed `testdata/corpus/private-extensions.json`
pins an exact source SHA-256, raw opcode, target and source link. The runner
requires current Go to assemble that file, excludes only the pinned
file/target from LLVM translation, and still compiles all other applicable
files. Its successful translations are retained, but the module is counted
as skipped rather than passed. A changed file, failed Go assembly or failed
other translation makes the candidate fail.

Schema 6 binds Git revision/content/dirty state, full ledger fingerprint,
translator bytes/VCS metadata, matching Go build/runtime versions and LLVM 22
version/llc bytes. Before/after capture detects mutations. All shards need
identical provenance. Dirty builds are diagnostic-only; schema-2, stale tools,
mixed revisions or missing reports cannot pass. Resolve CLI repository/tool
paths before candidate working-directory changes.
GitHub PR merge and branch revisions may differ while their complete tracked
source trees are identical. The importer accepts that exact content hash match;
the translator must still match the revision recorded in its own report.

Reports prove translation/object compilation, not execution of every external
library's own test suite. Required runtime oracles remain separate.

## Progress without false completion

Query the frozen ledger and available shard reports, including a run with no
reports yet:

```sh
bash scripts/discovery-status.sh [reports-directory] [shard-count]
```

The defaults are `_out/discovered-library-corpus` and 32. `scan-status.json`
contains validated contiguous index endpoints and scan counts.
`assembly-progress.json` binds the ledger/source and lists every selected exact
version as `pending`, `passed`, `not_applicable`, `skipped_invalid_source`,
`skipped_superseded`, `skipped_private_extension` or `failed`. Its invariant
includes every one of those categories exactly once. Missing whole shards
remain pending, including in-progress shards not yet published.

The progress reader and final passing gate share the same provenance, inventory,
target and accounting checks. Stale/mixed reports or a truncated shard fail the
query instead of silently becoming coverage. `complete` means all shards and
candidates are accounted for; only `verified` additionally requires no failures.
Status-query success is not test success: the final verifier still exits
nonzero for failures or missing reports. CI publishes this view even when a
shard fails. Reports are atomically published for concurrent status readers.
Windows publication coordinates local readers and retries transient sharing/
deletion errors for at most two seconds; persistent errors still fail and keep
the previous complete report. The required Windows job runs these concurrent
publication and external-reader regressions before the full suite.

Long shard jobs publish a partial report before the first candidate and every
eight completed candidates. A runner cancellation can therefore leave
auditable passed/failed/N/A results instead of losing the entire shard.
Partial reports mark all unreported candidates and the shard itself pending;
they never satisfy the complete-coverage gate. Publication remains atomic,
and each checkpoint rechecks the frozen source, ledger and tool provenance.

Keep test evidence separate from immutable scan records: writing a pass flag
into the hashed input ledger would invalidate that report's own provenance.
Assembly-ledger files are excluded from the source-content and dirty-worktree
fingerprints because they are derived output. To publish progress while shards
run, use a separate worktree at the same source revision for the evidence
update; leave the runner worktree and its Go binaries untouched. Do not change
the source revision or scan ledger during a shard run. After auditing the frozen
reports, publish the
diff-friendly assembly status snapshot with `scripts/update-assembly-ledger.sh`.
It writes `testdata/discovery/assembly-ledger/manifest.json` and module-hashed
JSONL shards, then reads them back against the current scan and semantic
source fingerprints. Statuses include pending and failed; `verified=true`
requires complete shard coverage and zero failures. Do not promote the
snapshot to a current pass after source or scan-ledger changes. cgo scan
records remain in the separate inventory, never in this repository.

## Traffic and cleanup

Inspection reads ZIP metadata/ranges and candidate sources; only matched
versions are materialized for corpus tests. Successful exact versions avoid
repeat ZIP inspection. ZIPs up to 64 KiB are fetched whole; larger ZIPs start
with the 22-byte EOCD and exact directory ranges, with 64 KiB read-ahead.
Larger EOCD scans are fallbacks. Change thresholds only with measured evidence.

The corpus uses the shared Go download cache as a read-only file proxy. New
downloads, extracted sources and LLVM outputs live in a private candidate cache
removed on success or failure. Build caches last one shard or one coordinated
`all` run, as described above. Keep diagnostics, not full packages. Replaying
an uncached exact version can download
it again; that is distinct from repeated inventory work.
Each buildable Go package is translated in its own child process. This keeps
large multi-package modules from accumulating LLVM objects across packages;
the exact version is downloaded once and candidate-level file/target counts
are still aggregated and validated. Target outputs are removed after each
successful package compilation.
Public module fetches ignore the user's global Git URL rewrites and disable
interactive Git credential prompts. A failed direct fallback remains a failure
to retry, never proof that assembly is inapplicable.

Traffic counts response-body bytes with identity encoding, not headers/TLS/IP
overhead, separating index, latest, ZIP HEAD/range and whole-ZIP requests. Do
not attribute every speedup to deduplication without accounting for changing
numbers and sizes of newly encountered modules.
