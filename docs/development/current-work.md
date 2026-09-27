# Current work: PR 40 CI repair

Read [instruction development](instructions.md), [validation](validation.md)
and [report provenance](discovery-verification.md). Repair CI before starting
another module-index inventory scan.

## Contribution and worktrees

- PR 40 remains OPEN/DRAFT. Stack repair `b05c9ee` was pushed after its
  678-second full suite passed. Its CI exposed 10 standard-library job
  failures (unexpanded ARM64 displacement macros and runtime-sized syscall
  frames) plus one Windows test job with four fixture failures. All those
  logs were inspected; the repairs were pushed as `0d96d26`. Its run
  `36307233650` has passed all 10 standard-library lanes, the Linux/Windows root
  matrix, race, cross-runtime, benchmark, coverage and Codecov patch checks.
  At 09:57 UTC on 2026-09-27, 63 jobs passed, one failed, eight external
  shards were running and 20 were queued. All 11 preceding failed jobs are
  repaired. The new shard-3 failure is fixed by `a7e98cc` below; the 32-shard
  replay and aggregate are still incomplete.
  Inspect live results; this is not a complete green CI run.
  Earlier ledger, FFR-oracle and Go-download-bootstrap repairs have passed
  the affected build, cross-runtime and old-Go root CI checks. Inspect live
  checks rather than treating partial results as green CI.
- Push only to `cpunion:codex/expand-ecosystem-corpus-20260913`. Never push to
  `origin` or `xgo-dev`. The latest request is to push verified CI repairs
  promptly, inspect the new checks and continue fixing; keep the PR draft.
- Develop on `codex/pr40-arm64-raw-20260926`. Upstream main `7cc8c0f` is
  already an ancestor. Inspect status, worktrees and processes first.
- `codex/pr40-shard25-replay-20260926` retains frozen `8134b3e` diagnostics.
  All its runners have finished; shard 29's final report was audited.
- A separate persistent verification worktree is frozen at `1c42a95`.
  Root `go test ./... -count=1 -timeout=20m` passed in 1,040 seconds; both
  nested CLI suites passed. Official five-architecture classification and
  strict benchmark passed: 184/184 files, no N/A, 25 target-seconds plus six
  seconds for driver build. Shards 4, 6, 10, 16 and 26 passed; all its runners
  finished. Preserve the reports. They predate the affine proof work below.
- `codex/pr40-evidence-20260927` separately records validated progress for
  that snapshot: 649 passed, 152 source N/A, two invalid-source skips, zero
  failures and 3,980 pending. The updater also reads back its own output.
  Evidence commit `16c4685`: five complete shards, 13,882 translations and
  43 target N/A; no partial shards. The complete/verified flags remain false.
  This is incomplete historical evidence, not current-development success;
  do not import it into a changed source snapshot as current proof.
- `codex/pr40-ci-evidence-0d96d26` preserves current CI artifacts separately:
  shards 2/6/7 pass, shard 3 has the single-character stack-slot failure.
  Evidence commit `cc69e2c` records 495 passed, 96 source N/A, one failed and
  4,191 pending, with 8,682 successful translations. All four reports were
  audited by the updater and read back; complete/verified remain false.
  Do not import these reports into the changed development snapshot.
- The affine verification worktree completed the full root suite at
  `198307f` in 835 seconds, `487fed6` in 753 seconds, `8eab02c` in
  824 seconds and `a740c74` in 822 seconds. Both nested CLI suites passed
  at `a740c74`; those runners finished. Its strict benchmark passed
  184/184 files, zero N/A, 60 target-seconds plus four seconds build.
  Official five-architecture classification also passed again at
  `487fed6`. Check the actual frozen revision and running processes before
  changing that worktree.
- Use Go 1.27.1 and LLVM 22 for external modules. Put the actual Go binary in
  PATH; setting only GOTOOLCHAIN can select a different child compiler.
  Required cross execution uses checksum-pinned QEMU 10.2.3.

## Latest committed repairs

- `997aaf7`: classify unresolved ARM64 displacement macros as requiring
  header context, while full translation rejects unexpanded offsets instead
  of silently using zero. Preserve concrete pseudo-SP annotations and SVE
  VL units. All seven integer load/store spellings, both directions and
  hardware-SP/GP bases have Go-oracle and three-OS LLVM 22 tests.
- `75eba97`: one proved private runtime-sized stack extension uses real
  dynamic storage, copies the original frame and relocates all live SP
  aliases together. This preserves old data, saved SPs and address
  differences. A straight-line incoming prefix must not expose the old
  address; calls, escapes, numeric observations, unknown effects, multiple
  extensions and re-entry reject. Size arithmetic is overflow-checked;
  positive and negative register displacements preserve the original frame.
  This is not a general arbitrary-pointer memory-safety proof.
  Full root suite passed in 665 seconds; both nested CLIs, vet, Go 1.20
  focused tests, Darwin execution, required Linux/QEMU, three-OS objects,
  official five-architecture coverage and benchmark passed. Benchmark:
  184/184 files, zero N/A, 28 target-seconds plus one second build.
  Darwin/Windows ARM64 standard-library corpora passed on Go 1.27 (49/46
  IR files) and Go 1.20 (43/40), using the prebuilt current-Go CLI for the
  old compiler lane. Logs use `_out/arm64-dynamic-*` and
  `_out/root-tests-dynamic-stack.log` in the CI-hotfix worktree.
- Windows fixture repair `ebf6579` adds the executable suffix, tests both
  LF/CRLF workflow content, and builds a native fake Go executable whose
  selection and auto/local behavior are asserted. Focused Go 1.20/1.27 and
  the full corpus-tool suite pass locally. Actual Windows CI now passes:
  root 1,566.780 seconds with 89.6% statement coverage, and both CLI suites
  passed. The previous Windows failures were fixture gaps.
- The next verified push batch includes `735fa37`, which rejects effective-address aliases such as
  `$8(RSP)` before moving a dynamic stack. The prefix must account for every
  live address, not just explicit register copies. Red/green and runtime
  regressions passed; no escape exception was introduced.
- Local scalable pool batch: `79e31ac` adds bounded ADDVL/ADDPL aliases;
  `fe70f20` partitions proofs over every architectural VL (16..256 bytes in
  16-byte increments). RDVL, ADDVL/ADDPL and scalar CNT/INC/DEC use the typed
  decoders and exact pattern/multiplier values within each partition. Unknown
  effects or vector-length mode changes reject. Tests cover all address
  immediates and 6,144 count forms at every VL; 96 runtime cases execute at
  all 16 lengths. Three-OS LLVM 22 objects, Go 1.20, vet, required Linux/QEMU,
  official coverage, both CLI suites and the full root suite passed at
  `fe70f20` (656 seconds). Benchmark: 184/184, zero N/A, 25 target-seconds.
- `38305da`, `b0f4b05`, `bc67343` share typed unpack, multiply-accumulate and
  integer-reduction effects with the pool proof. Each family has retained
  red/green evidence and complete-format checks. This changes effect
  classification, not instruction semantics or unknown-op acceptance.
- `6104e5f` bounds whole Z/P pool loads with their actual VL or VL/8 footprint.
  All 512 signed displacements and 16 vector lengths are checked. Three-OS
  objects and 128 Linux/QEMU byte-and-canary cases pass. Stores, short pools,
  negative/oversized footprints and mode changes reject. Focused pool tests,
  Go 1.20 and vet pass. The development worktree completed another full suite
  at this revision in 616 seconds (`_out/root-tests-sve-pool-memory.log`),
  plus the official five-architecture and ARM64 Go/x/arch gates. Its runners
  have finished. These changes are included in the next batch push. Refresh
  derived provenance after the final source checkpoint and before pushing.
- `a7e98cc` fixes shared parsing of Go-valid single-character named stack
  displacements such as `n-8(SP)`. CI shard 3 exposed the failure in
  `gopkg.in/agiledragon/gomonkey.v2@v2.14.3`; both assembly files now compile
  in an exact-candidate diagnostic. Identifier/offset red/green tests,
  Go 1.20/1.27, three-OS objects, Darwin and required Linux/QEMU runtime pass.
  Its frozen full root suite passed in 631 seconds and both CLI suites passed
  (`_out/root-tests-stack-single-name.log` in the CI-hotfix worktree).
- `6b3a20ca` keeps scalar NZCV provenance through typed SVE unpack,
  multiply-accumulate, integer reduction and vector/predicate logical families.
  Predicate S variants, SVE comparisons, PTEST, unknown/system instructions
  and bypassed comparisons remain barriers. LLVM 22 encoder tables and
  red/green tests cover 131 preserving forms plus flag-writing siblings;
  131 forms x nine inputs x 16 vector lengths pass required Linux/QEMU checks.
  Three-OS objects, Go 1.20, complete operand-field tests, vet and all pool
  regression tests pass. The pre-fix overlay fails the new integration fixture.
- Metadata-download bootstrap and its synthetic retry fixture use the root
  Go 1.20 floor; actual corpus build plans still require Go 1.27. The old
  bootstrap required Go 1.27 before making even one proxy request, failing
  older compatibility jobs. Go 1.20, 1.25 and 1.27 corpus tool suites pass.
- The SVE memory-offset runtime oracle now compares FFR as well as values.
  Pinned QEMU deliberately stops non-faulting loads at the second page, even
  for mapped memory. A deterministic cross-page fixture reproduced CI's
  VL=256 failure with identical native/translated bytes and a wrong scalar
  expectation. Both aligned/full-load and cross-page/valid-prefix layouts
  now run; all seven non-faulting mnemonics and ordinary loads/stores pass.
  No instruction, vector length or page-crossing case is skipped.
- The ARM64 stack-allocation repair includes named/raw manual SP adjustments,
  pre/post-indexed transfers, saved-SP aliases, alignment and ADDVL/ADDPL at
  every architectural VL. Static-offset overflow fails before allocation.
  Widen changing GP aliases to unknown so pointer walks converge, but never
  silently treat an unknown restored local SP as external storage. Require
  bounds when SP is used again; an unused final restore before RET needs no
  further allocation. This is allocation sizing, not a general memory-safety
  proof for arbitrary pointer dereferences. Its real NEON parser crash is
  repaired: 130 parsing and 65 formatting runtime cases pass, and the full
  NEON bytes file compiles on all three OS targets. Focused Go 1.27/1.20,
  Darwin runtime, Linux/QEMU and vet pass. Strict benchmark: 184/184 files,
  zero N/A, 29 target-seconds. Rebuild frozen full-suite and corpus evidence;
  these diagnostics are not complete external-module or shard passes.
- Its first full gate exposed 67 official SVE form regressions plus raw
  structure-form writeback failures. Fixed allocation sizing for scalable
  displacements/predicate units and up to four maximum-width vectors. A small
  whole-function proof recognizes untouched zero-initialized GP registers
  used in post-indexing; calls and writes invalidate it. Dynamic address
  indexes are not frame-size declarations. All affected family tests and the
  five-architecture official gate pass again without changing the baseline:
  ARM64 1,980 supported forms, 68 context forms, zero unsupported forms.
  The frozen full suite passed before pushing `b05c9ee`; the subsequent
  standard-library integration failures are handled by the repairs above.
- `cc307d5`: reject Go command/compiler/assembler version mismatches as
  infrastructure failures, never source N/A. The shard script pins its child
  Go binary to the recorded GOROOT and checks all three versions.
- `ba157c3`: pin discovery and aggregate CI jobs to Go 1.27.1.
- `f151495`: track every bounded ARM64 constant-pool pointer alias separately.
  MOV and 64-bit ADD/SUB immediate, shifted and extended-register forms
  propagate inclusive offset ranges. Killing an original does not kill its
  copies. Loads must fit at both range endpoints. Escapes, truncation,
  address-dependent flags, unknown indexes and changing-offset joins fail.
- `0f08122`: retry transient module-download failures as well as dependency
  build failures. At most three attempts share the original deadline. A
  synthetic local proxy establishes red/green recovery, persistent failure,
  no retry on 404, cancellation and workspace cleanup. Checksum, compiler,
  resource and toolchain failures are not retried.
- `596b147`: follow actual CFG edges when proving integer index bounds.
  An adjacent CMP must dominate B.cond; CBZ/CBNZ zero edges are also modeled.
  A W comparison does not bound an X register. Bypassed guards, changed flags,
  signed-negative possibilities and converging unconstrained edges fail.
- `c2567c6`: fold proven private x86 threaded TEXT helpers into one CFG. Keep
  GP/vector/flag/FP state across direct and indirect jumps. CLI proof rejects
  Go calls/address uses, linkname/other-file references, incomplete or escaping
  tables, and paths bypassing table-base initialization. Initializers and
  continuations stay in one LLVM module; wasm cannot use this mechanism.
  Also honor GLOBL RODATA instead of making every global constant, and retain
  file-local linkage for `<>` data. The former caused an actual runtime crash.
- `43a576e`: fix the whole VPBROADCASTB/W/D/Q family's overlapping X/Y/Z views
  and inactive masked memory reads. Its 108 source/width/mask cases compile
  on three OS targets and execute on Darwin/Rosetta and required Linux tests.
- `c9122cf` through `e9f131a`: add bounded modular-affine pool analysis,
  guarded CMN ranges, exact AND results, transient address cancellation,
  independent origin offsets, TBZ/TBNZ path constraints and pre-projection
  intersections. Preserve exactly one relocation origin: two address aliases
  added together must be rejected. Unknown effects/cycles and exhausted proof
  budgets remain failures. See `arm64_raw_pool_affine*.go` and
  `arm64_raw_pool_symbolic.go`; do not treat an ADR as an ordinary constant.
- `9acb690`: retain CMP/CMN/ADDS/SUBS provenance through known NZCV-preserving
  instructions; avoid speculative residual recursion on almost-full ranges.
- `487fed6`: prove single-entry counter loops, eliminate only proved-impossible
  edges, and validate the full scalar/pair pre/post-indexed load footprints.
  Positive unit countdowns retain an induction bound; a proved one-iteration
  loop does not invent further pointer updates. Seed proofs make a prior body
  execution through an enclosing loop opaque. Invariant-origin queries use
  separate cached proofs and reject changing recurrences. Predecessor order is
  deterministic. Overlap, overrun, wrong-step, zero-entry and side-entry tests
  fail closed. See `arm64_raw_pool_{loop,invariant,memory}.go`.
- `4ed0872`: trace flags across long integer-multiply and SIMD schedules, with
  an explicit preserving-family whitelist. A TST/unknown effect still stops
  the proof. The runtime oracle includes 48 instructions between SUBS and B.NE.
- `8eab02c`: multiple ADRs may reacquire the same pool at a branch join. Affine
  expressions retain a relocation count and reject a sum of two origins,
  including distinct ADRs. Resolve stable origins exposed after transient-index
  cancellation without collecting unrelated loop predicates. Join/overrun
  regressions and three-OS/native/Linux-QEMU runtime oracles passed.
- `3ed6437`, `c043b91`, `b41c426`: avoid cyclic residual speculation, retry
  inconclusive caches with a fresh proof budget, and try direct guards before
  residual decomposition. Compact tautologies/duplicate predicates and retain
  already-proved mask constants for later comparisons. The real unsigned
  parser's length proof fell from exhausting 16,384 steps to 334 steps.
- `c0652bb`: retain nonconstant AND intervals and prove disjoint-bit ORR/EOR
  relationships across immediate/register/all shifted-register forms. Numeric
  bit proofs must not interpret a relocated pool offset as physical address
  bits. Overlap, truncation and unrelated-mask regressions remain conservative.
- `22ffd2d`: certify unit-step ordered loops, both directions, all eight
  signed/unsigned strict/inclusive conditions and reversed operands. Prove
  entry ordering, invariant limits, flag provenance and no arithmetic wrap.
- `4fe7c89`: comparisons constrain values at their defining program point,
  including operands reused before the branch. Pending historical predicates
  cannot constrain replacement values. Intersect mask/guard bounds before
  applying negative displacements. Bypasses and newer flags still reject.
- `99fbba8`: infer carried address/count relationships from certified loop
  deltas and prove the whole invariant at external entries. Only this entry
  proof enables full affine arithmetic in the unguarded invariant walker;
  speculative residuals keep the cheap mode. Increasing/decreasing post-index
  runtime loops preserve the relationship instead of multiplying independent
  ranges. The focused Go 1.27/1.20, three-OS LLVM 22, Darwin-native,
  required Linux/QEMU and vet gates passed for every batch above.
- `a9000c0`: rewind ordinary 64-bit scalar/pair stack reloads to the exact
  dominating save only when every other queried GP value is preserved.
  Overlaps, possible aliasing stores, calls, SP changes, width mismatches,
  joins and unknown effects reject; direct nonoverlapping SP stores are safe.
  Rewinding uses the saved source value, never its later replacement.
  An enclosing-loop entry barrier may preserve only registers that the
  certified body never writes. Focused Go 1.27/1.20, three-OS LLVM 22,
  Darwin-native, required Linux/QEMU and vet tests passed.
- `5bbda9b`: correct Go's Rm, Ra, Rn, Rd operand order across all eight
  integer multiply-accumulate operations. One typed spec replaces duplicated
  ordinary/word branches. Named/raw forms, all source/destination aliases and
  zero operands cover 768 results against both native Go and LLVM, including
  required Linux/QEMU. The prior long-multiply fixture also had the wrong
  source order; the corrected fixture demonstrated the old lowering failure.
- `7f5f838`: prove exact reciprocal division with full 128-bit arithmetic,
  UDIV/MSUB remainders, MOVK constant construction and LSR guard preimages.
  Historical value identities reject changed/truncated operands; a guard on
  an in-place quotient cannot constrain its old numerator. Focused Go 1.27
  and Go 1.20 suites, three-OS LLVM 22 objects, Darwin-native, Linux/QEMU,
  supported-op extraction and vet passed. Full NEON bytes assembly compiled
  on all three OS targets in diagnostics; rebuild for final corpus evidence.

The pointer/guard batches passed all focused pool tests on Go 1.27.1,
focused Go 1.20 compatibility, LLVM 22 ARM64 objects for Darwin/Linux/Windows,
Darwin native runtime and the required Linux/QEMU runtime counterparts.
The existing cross container uses Go 1.27.0 for these root runtime tests.
Both nested CLI test suites and vet passed again after the guarded-index
commit. Corpus unit tests and focused race tests passed for download retry.
Logs in the development worktree use `raw-pool-alias*`,
`raw-pool-guard*` and `discovery-download-retry*`.
The continuation batch additionally passed amd64 native-Go/LLVM runtime
oracles, required Linux amd64 and 386/QEMU execution, five x86 object targets,
Go 1.20 compatibility, both CLI suites and vet. Canonical KnoxDB's four
previously failing files passed all 12 three-OS object compilations. A separate
Linux scalar oracle passed 40 scenarios per Uint8/16/32/64 decoder (160 total),
covering all 16 selectors and mixed helper transitions. Diagnostic artifacts
are under `_out/knox-continuation-*`; these are not final shard/ledger evidence.
The affine batch passed all focused pool tests, Go 1.20 compatibility, vet,
three-OS LLVM 22 objects and Darwin/Linux-QEMU runtime oracles (80 input pairs).
TBZ/TBNZ guard tests cover all 64 bits and both edge directions. At `e9f131a`,
official classification, the ARM64 decoder-corpus gate and the strict benchmark
passed again: 184/184 files, zero N/A, 31 target-seconds plus two seconds build.
These classification and compilation gates do not establish every instruction's
runtime semantics. Keep the final full-suite and external-corpus gates separate.
The loop batches passed focused Go 1.27/1.20 tests, three-OS LLVM 22 objects,
Darwin native and required Linux/QEMU oracles. At `4ed0872`, strict benchmark
passed 184/184 files, zero N/A, 30 target-seconds plus seven seconds build.

## External evidence and remaining real failures

A passing fixture or one target replay is not a passing module or shard.
The latest three-OS SIMD replay (`_out/simd-division.json`) compiled the full
NEON bytes file, including both integer parsers and formatting. The SVE bytes
file still fails at `parseIntsSVE2`. These dirty-build diagnostics are not
passing module evidence. Do not upgrade its assembly ledger.

- **SIMD**: `github.com/sebishogun/simd@v1.21.1` and its mirror have 45/47
  applicable ARM64 files passing in earlier three-OS diagnostics. NEON bytes
  now compiles; SVE bytes needs further proof work. Signed NEON proves both
  vector loops run once and the tail counter stays in 1..7, including pair
  writeback. Unsigned NEON's two vector loops are also proved one-iteration,
  and the ascending signed-comparison tail now has a certified remaining
  interval of 1..19. The saved SP+8 index (instruction 181 to 323) now proves
  the carried pointer/count invariant is exactly 144 bytes relative to the
  pool. Both integer parsers translate. Formatting's instruction 59 two-digit
  table read is now bounded by a general UMULH/shift reciprocal-division and
  MSUB-remainder proof, plus historical right-shift guard bounds. The proof
  is not special-cased to divisor 100. The expanded runtime oracle exposed
  and now guards the independent multiply-accumulate operand-order bug.
  Inspect `_out/format-ints-neon-disasm.log` and `pool-format-neon.log`.
  Repeated ADRs retain relocation cardinality. The ignored function probe's
  scratch mask now has explicit parentheses; its earlier missing parentheses
  caused a diagnostic-only false return-escape failure.
  Signed SVE's instruction 23 now has all-VL address semantics and all its GP
  effects are recognized. Typed SVE flag preservation is now implemented.
  It still needs indexed predicated pool-load footprints and relational
  loop bounds. In the current diagnostic, instruction 76's `R12+8*R20`
  footprint is still unknown at every checked VL; do not accept it merely
  because the typed load is supported. Ignored `pool-function-*` probes and
  disassemblies retain diagnostics; regenerate any traced walker after edits.
  The apparent branch
  word `0x540be400` is numeric pool data, not invalid source. Implement in
  `arm64_raw_pool_*.go`; do not relax the proof merely to relocate the pool.
- **KnoxDB**: all three complete v0.2.9 candidates (`blockwatch.cc/knoxdb`,
  `github.com/blockwatch-cc/knoxdb`, `github.com/os2357/knx`) passed at `1c42a95`:
  each has 29 applicable files and 87 object translations. Shards 6/16/26
  passed. Empty Go declarations do not imply callable helpers: private
  entry proof is essential. Never apply signature widening to ordinary calls.
- **Native-layout/JIT**: GopherJRE, GoJIT and both case-distinct Sharkie module
  paths still fail. Their source observes exact code offsets or transfers
  registers/stack through generated machine code. Widening raw branch
  boundaries alone is insufficient. There is no authorized generic
  native-layout skip. A newer GoJIT version was downloaded diagnostically but
  has not been imported or verified as a replacement.
- Exact invalid-source skips (including both go-highway versions), historical
  gVisor/Skywire superseded skips and the pinned fiber/ai private AMX exception
  remain distinct from passes. Their manifests and executable proof tests are
  authoritative. Do not extend their scope without evidence/authorization.

The frozen `8134b3e` diagnostics are stored under
`_out/ci-repair-8134-shardN/shard-N.json`. Completed shards 1, 13, 20, 22,
23, 24, 25 and 29 have zero failures and individually audited reports. Shards
0, 6, 9, 14, 15, 16, 17, 26 and 28 retain the real failure classes above
(shard 16 also predates the dev9 invalid-source fix). Shard 4 completed
168 candidates = 123 passed + 35 source N/A + one invalid-source skip +
nine download TLS-timeout failures; its integrity audit passed, not its
coverage gate. Shard 10 completed 173 candidates with 133 passed, 29 N/A and
11 proxy TLS-timeout failures; its large spanneranalyzer p0/p6 candidates
passed. Shard 29 completed 151 candidates = 127 passed + 23 source N/A + one
invalid-source skip, with 2,052 object translations and three target N/A files.

A separate clean `cc307d5` shard 16 report has 132 passed + 30 N/A + one
go-highway invalid-source skip + one KnoxDB failure. It is not compatible
with the older frozen reports. Keep all of these as diagnostic evidence.

## Next actions and completion gates

1. Preserve the validated 4/6/10/16/26 evidence in its same-source tree.
   Shard 4 passed 168 candidates: 130 passed, 37 N/A, one invalid-source skip,
   4,152 translations and 25 target N/A. Never relabel network failures as N/A.
   Shard 10 passed 173 candidates: 142 passed, 31 N/A, 2,889 translations and
   six target N/A. Both retry runs and their ledger updates are complete.
2. Continue real semantic fixes above with red/green and runtime tests.
   NEON bytes now compiles; SVE bytes and native-layout/JIT failures remain.
3. Run full root, both nested CLIs, vet/build, official five-architecture
   coverage, ARM64/stdlib corpus, cross runtime and strict benchmark after
   the final implementation. Preserve evidence by exact source snapshot.
4. Freeze source/tools/ledger, run all 32 shards on identical provenance,
   then use the validated updater to refresh the assembly ledger. Even doc
   commits change provenance; do not combine old reports into the final run.
5. Batch-push the allowed fork, update PR body with validated scan/coverage
   funnels, and inspect current-head CI/review/coverage before making ready.

The current-source assembly evidence remains incomplete: all 4,783 candidates
are pending until compatible frozen shard reports exist. Earlier passes are
preserved in their own snapshots, not promoted to this source. Refresh the
derived ledger with its validated updater before pushing; never hand-edit it
to match diagnostic counts. Reports/binaries belong in ignored
`_out/`; clean only owned generated files and candidate caches, never shared
module caches or unrelated containers. Old progress narratives remain in Git
history instead of accumulating in this checkpoint.
