# Plan 9 assembly instruction coverage

This document defines the path to complete support for the Go assembler's Plan
9 syntax. Coverage is measured by architecture, instruction family, opcode,
and operand form. An opcode name by itself is not a support claim.

The library targets 386, amd64, arm, arm64, and wasm, which is the complete set
of independent Go architectures consumed by LLGo's Plan 9 assembly path. Named
embedded targets may use other physical LLVM backends, but they borrow an arm
or wasm GOARCH for source selection and are not additional Go Plan 9 assembly
instruction sets. The cross-version official inventory and semantic gates
cover all five architectures. The 386 and amd64 lowerers share x86
implementation code, but their registers, address widths, valid opcodes, and
runtime ABI differ. ARM and ARM64 are separate instruction sets. ARM64 also
distinguishes scalar, NEON, and SVE families.

## Sources of truth

There is no version-independent "Plan 9 instruction set" that can be imported
as a complete oracle. Go's assembler uses Plan 9 syntax for a distinct,
semi-abstract instruction set, and its accepted language evolves with the Go
toolchain. Coverage therefore uses the union of Go 1.20 through the latest
supported release, through these increasingly strong layers:

1. Official opcode namespace
   - `cmd/internal/obj/x86/anames*.go`
   - `cmd/internal/obj/arm/anames*.go`
   - `cmd/internal/obj/arm64/anames*.go`
   - `cmd/internal/obj/wasm/anames*.go`
2. Official architecture encoder tables
   - x86 `optab`, `ytab`, `ymovtab`, and generated AVX/EVEX tables
   - ARM and ARM64 `optab` rows and their alias mappings
   - generated ARM64 instruction encoders, including SVE
   - these tables are the authority for legal abstract operand classes
   - wasm is emitted directly by `wasmobj.go` and has no equivalent operand-
     class table, so its inventory rows are explicitly opcode-only
   - reference tree: <https://github.com/golang/go/tree/go1.27.1/src/cmd/internal/obj>
3. Official positive assembler testdata
   - `cmd/asm/internal/asm/testdata`
   - this supplies concrete, architecture-valid operand forms
   - Go has no wasm file in this directory, so the wasm positive corpus is the
     official `.s` set selected from GOROOT for `js/wasm`
   - reference tree: <https://github.com/golang/go/tree/go1.27.1/src/cmd/asm/internal/asm/testdata>
4. Go architecture decoder corpora
   - `golang.org/x/arch/<arch>/<arch>asm/testdata`
   - these contain a substantially larger encoding-to-Plan-9-printing corpus
     than the compiler's positive assembler tests
   - decoder output is supplemental rather than syntax authority, so every
     candidate form must first pass the matching native `go tool asm`
   - pinned reference: <https://github.com/golang/arch/tree/v0.31.0/arm64/arm64asm/testdata>
5. Selected standard-library assembly
   - lower-case `.s` files selected by `go list -json std` for each
     GOOS/GOARCH
6. Reduced real-world issue and pull-request regressions
   - each case links back to its report in the conformance manifest
   - the reduced instruction must first be accepted by the native Go assembler
7. Public Go module ecosystem assembly
   - `index.golang.org` supplies the chronological public module-version feed
   - `proxy.golang.org/cached-only` supplies ZIP metadata without executing code
   - discovered modules are resolved to `@latest`, then their complete package
     and target matrix is checked before a version is pinned
8. Executable semantic conformance cases
   - `testdata/conformance`
   - the same assembly is run once with the native Go assembler and once after
     plan9asm-to-LLVM translation

The x86 opcode and encoder tables are shared by 386 and amd64 and are therefore
a common inventory, not proof that every listed form is legal in both modes.
Native assembly of generated concrete cases supplies that mode check. Positive
testdata is useful but not complete: for example, the Go 1.27 386 corpus
observes only 21 opcodes from the shared 1,600-name x86 namespace.

`x/arch` is deliberately not treated as a second assembler specification. Its
Plan 9 case files originate from instruction decoding and formatting, and can
therefore contain reserved encodings or printed operands that the Go assembler
correctly rejects. The ARM64 supplemental gate scans the complete pinned
decoder corpus, then separately filters the completed scalar families through
Go's native assembler before requiring plan9asm lowering support.

## Coverage states

- name claimed: a lowerer contains the opcode name; this is informational only
- supported form: an instruction with this operand shape passes the real
  lowering pipeline
- context required: the instruction depends on a frame slot, a preceding flag
  write, a REP successor, or a function-local PC target and must be judged by
  full-file compilation
- unsupported form: parsing succeeded but the real lowerer rejected it
- runtime verified: a manifest case is compiled and run through both the Go
  assembler and plan9asm/LLVM with identical expected results
- compile-only policy: privileged, trapping, or environment-dependent
  instructions; these require parser, lowering, and object compilation checks
  but are never executed merely for coverage

The scanner reports name, encoder-table, form-lowering, context-required,
unsupported, and runtime-verified coverage separately. Compile-only is an
execution policy recorded by conformance metadata rather than a lowering
status. In particular, `XORB reg,reg` does not imply `XORB reg,mem`.

## Definition of complete

A runnable user-mode operand form is complete only when:

1. the Go assembler accepts its conformance source;
2. plan9asm parses and lowers it;
3. LLVM compiles the emitted IR;
4. both native Go assembly and the LLVM object execute and produce the same
   checked result; and
5. the form is listed in `testdata/conformance/manifest.json`.

A context-dependent form must additionally pass the full standard-library or
package corpus compiler. A compile-only form must have an explicit reason and
must pass object compilation where the target supports it.

Complete architecture support means every encoder-table operand class in the
Go 1.20-to-latest union has at least one native-Go-accepted concrete case, zero
unexpected parser failures, and zero unsupported runnable forms. Every safe
user-mode form must compile, link, and execute against the native Go oracle;
compile-only forms must carry an explicit reason and still compile and link.
The complete opcode and encoder-form catalogs remain visible even where
implementation or concrete-case generation is still pending.

## Commands

Generate a complete JSON opcode, encoder-table form, and observed concrete-form
report:

    go run ./cmd/plan9asmscan \
      -corpus go-asm \
      -goroot "$(go env GOROOT)" \
      -goos linux \
      -goarch amd64 \
      -repo-root . \
      -format json \
      -out /tmp/go-asm-amd64.json

Generate the human-readable family summary by changing `-format` to
`md`. Repeat with `386`, `arm`, `arm64`, and `wasm`; use `-goos js` for wasm.

Run the cross-version regression gate:

    scripts/check-go-asm-coverage.sh

Run the selected standard-library corpus through parser, form-level lowering,
whole-file translation, and LLVM object compilation:

    scripts/check-stdlib-corpus.sh

Run the pinned, complete `x/arch` ARM64 Plan 9 decoder corpus and the
native-Go-accepted family subset:

    scripts/check-arm64-plan9-corpus.sh

Discover public modules containing Go assembly from the official index:

    go run ./cmd/plan9asmdiscover \
      -limit 2000 \
      -out-dir testdata/discovery/ledger

This starts at the current time and selects the newest records first. Continue
backwards from the ledger-derived earliest covered endpoint, down to the fixed
`2019-04-10T00:00:00Z` cutoff:

    go run ./cmd/plan9asmdiscover \
      -limit 2000 \
      -out-dir testdata/discovery/ledger

The range ledger is the cursor: every update must attach exactly to its earliest
or latest endpoint, and reads/writes reject gaps, overlaps, and conflicting
range counts. To reuse completed exact versions from an additional legacy
report, load it as scan state:

    go run ./cmd/plan9asmdiscover \
      -before 2025-01-01T00:00:00Z \
      -limit 2000 \
      -seen-report /tmp/plan9asm-discovery.json \
      -out /tmp/plan9asm-discovery-resumed.json

Each report's `scanned` array records every successfully inspected exact
`module@version`, including modules with no assembly. `-seen-report` skips only
that exact version, so a newly published `@latest` version is still inspected
and replaces the obsolete version. Failed versions are listed with their
version in `failures`, are not added to `scanned`, and are retried on a later
run. Sharded ledgers retain one exact, contiguous range chain and reject gaps,
overlaps, or conflicting range counts.

Within a logical module family, selection is ordered by module-path major and
then Go semver. Thus an older index window can upgrade `/v2` to `/v3`, while
subsequent `/v2` records are skipped. The same rule lets a future incremental
window discover `/v4` or a newer version within the retained major.

Use `-limit 0` to continue backwards to the 2019 cutoff. Scan newly published
index records independently whenever needed with:

    go run ./cmd/plan9asmdiscover \
      -scan-mode incremental \
      -out-dir testdata/discovery/ledger

Incremental mode uses the greatest covered upper bound as its lower bound and
always drains the full new head interval; `-limit` is ignored so a high-water
mark cannot hide an unfinished gap.
The discovery step reads ZIP directory metadata with ranged requests, retries transient
index/proxy failures, ignores `testdata`, zero-byte, and comment-only assembly
placeholders, and requires a `.go` file beside a `.s` file so vendored non-Go
assembler trees are not reported as packages.
Its architecture field is a filename-based triage hint; the corpus runner's
`go list` result is the authoritative source-selection check.

After discovery, run every pinned third-party library suite:

    scripts/check-reported-library-corpus.sh

The machine-readable manifest is
`testdata/corpus/reported-libraries.json`. Each entry records whether it came
from an llgo issue or the ecosystem scan, the module version, and the exact
assembly package/file inventory for every target in the complete 386, amd64,
ARM, ARM64, and WebAssembly matrix.
The runner first verifies that the pinned version is still the module's
`@latest`, then uses `<module>/...` so every package in the module is examined.
It translates and LLVM-compiles every selected `.s` file. Missing target
reports, newly added or removed assembly packages/files, package-load errors,
translation errors, and object-compilation errors all fail the suite.
Package ownership is matched by exact module path, so a v1 suite cannot
silently include a nested `/v2` module that happens to share its import prefix.

The currently tracked reports are:

- `xgo-dev/llgo#2464`: `github.com/coder/websocket v1.8.15`
- `xgo-dev/llgo#2552`: `github.com/klauspost/compress v1.20.0`
- `xgo-dev/llgo#2576`: `github.com/tmthrgd/go-hex` at its latest pseudo-version

The ecosystem scan also pins these latest modules:

- `github.com/RoaringBitmap/roaring v1.9.4`
- `github.com/aead/siphash v1.0.1`
- `github.com/anacrolix/mmsg v1.1.1`
- `github.com/btcsuite/fastsha256 v0.0.0-20160815193821-637e65642941`
- `github.com/cespare/xxhash v1.1.0`
- `github.com/cespare/xxhash/v2 v2.3.0`
- `github.com/chain/txvm v0.0.0-20190422181059-ff6bfbe53892`
- `github.com/dchest/siphash v1.2.3`
- `github.com/dgryski/go-bits v0.0.0-20180113010104-bd8a69a71dc2`
- `github.com/dgryski/go-marvin32 v0.0.0-20240117220238-0d39e8c5a8a9`
- `github.com/golang/snappy v1.0.0`
- `github.com/klauspost/cpuid v1.3.1`
- `github.com/klauspost/cpuid/v2 v2.4.0`
- `github.com/klauspost/crc32 v1.3.0`
- `github.com/klauspost/reedsolomon v1.14.2`
- `github.com/minio/highwayhash v1.0.4`
- `github.com/modern-go/gls v0.0.0-20250215024828-78308f6bb19d`
- `github.com/pierrec/lz4/v4 v4.1.30`
- `github.com/phuslu/log v1.0.134`
- `github.com/stevvooe/resumable v0.0.0-20180830230917-22b14a53ba50`
- `github.com/tmthrgd/go-bitwise v0.0.0-20190904053232-1430ee983fca`
- `github.com/tmthrgd/go-popcount v0.0.0-20190904054823-afb1ace8b04f`
- `github.com/zeebo/this v1.0.0`
- `golang.org/x/net v0.59.0`
- `golang.org/x/sys v0.48.0`

Run one library independently by its manifest id:

    scripts/check-reported-library-corpus.sh coder-websocket

The compatibility wrappers remain available:

    scripts/check-coder-websocket.sh
    scripts/check-klauspost-compress.sh
    scripts/check-go-hex.sh

For an offline run against the reproducibly pinned versions, disable only the
online `@latest` comparison; the complete package and target scan still runs:

    PLAN9ASM_CORPUS_CHECK_LATEST=false \
      scripts/check-reported-library-corpus.sh

CI derives an independent, non-fail-fast matrix job for every manifest entry,
so adding an issue-reported or ecosystem-discovered library automatically
creates its own test suite.

Select an explicit cross-target subset with `PLAN9ASM_CORPUS_TARGETS`, for
example:

    PLAN9ASM_CORPUS_TARGETS=linux/386,linux/amd64,linux/arm,linux/arm64 \
      scripts/check-stdlib-corpus.sh

An unversioned Linux architecture expands to every Go architecture setting
supported by the selected toolchain. The authoritative level matrix covers
`GO386={sse2,softfloat}`, `GOAMD64=v1..v4`, `GOARM=5/6/7` plus each available
hardfloat/softfloat counterpart, `GOARM64=v8.0..v8.9` and `v9.0..v9.5` plus
the `lse` and `crypto` extension boundaries, and all four combinations of
`GOWASM={satconv,signext}` for both `js/wasm` and `wasip1/wasm`. Go 1.20 and
Go 1.21 use their implicit ARM64 v8.0 baseline; GOARM64 became configurable in
Go 1.23, while GOARM float suffixes became configurable in Go 1.22.

Run the executable semantic cases:

    go test . -run 'Test.*Conformance' -count=1

On Linux/amd64, the opt-in cross-execution smoke translates for all four native
conformance architectures, emits target objects with LLVM, links them with the
matching Linux cross compiler, and executes 386/ARM/ARM64 through QEMU:

    PLAN9ASM_CROSS_EXEC=1 \
      go test . -run '^TestCrossLinuxRuntimeMatrix$' -count=1 -v

CI treats Linux as the authoritative coverage host. Go 1.20 through Go 1.27
each scan, translate, and object-compile the complete Linux architecture-level,
Darwin, Windows, `js/wasm`, and `wasip1/wasm` target matrix from Linux. Every
supported Go version runs the root compile/link/run conformance suite and its
official architecture inventory. The latest Go additionally runs the four-
architecture Linux link/execution smoke. macOS and Windows jobs on the latest
Go release are auxiliary host-integration checks, not the only source of
target coverage.
Cross object compilation and cross execution are reported separately:
successful `.o` generation alone is not an executable conformance claim.

## Go 1.20 through Go 1.27 differences

The checked baseline stores a fingerprint for every Go minor version and
architecture. It detects any form changing among supported, context-required,
unsupported, or parser-failed states.

This version range describes the union of official namespaces, encoder tables,
and assembler source corpora. The executable conformance cases are shared when
Go versions accept the same form; they are not duplicated once per Go release.
Linux/amd64 CI compiles, links, and runs the root conformance suite with every
Go version from 1.20 through 1.27. `cmd/plan9asm` and `cmd/plan9asmll` retain
their own Go 1.24 module requirement, so older validation lanes build the
package-oriented tool once with the latest Go and then run it against the
selected older GOROOT.

The encoder-table union across Go 1.20 through Go 1.27 is:

| GOARCH | encoder opcodes | encoder operand forms |
|---|---:|---:|
| 386 | 1603 shared x86 opcodes | 4998 shared x86 forms |
| amd64 | 1603 shared x86 opcodes | 4998 shared x86 forms |
| arm | 144 | 528 |
| arm64 | 1255 | 4396 |
| wasm | 464 opcode names | 464 opcode-only inventory rows |

These are abstract encoder forms, not runtime support claims. The larger ARM64
union is intentional: operand-class names and generated SVE encoders evolve
between releases, so using only the newest tree would lose forms that existed
in earlier supported releases.

The Go 1.27 snapshot currently reports:

| GOARCH | official names | encoder forms | observed ops | observed forms | supported | context | unsupported | runtime verified | parse failures |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 386 | 1600 shared x86 names | 4997 shared x86 forms | 21 | 60 | 41 | 6 | 13 | 0 | 0 |
| amd64 | 1600 shared x86 names | 4997 shared x86 forms | 1456 | 6742 | 804 | 6 | 5932 | 51 | 0 |
| arm | 181 | 528 | 135 | 500 | 312 | 34 | 154 | 0 | 0 |
| arm64 | 1417 including SVE | 2964 | 1281 | 1980 | 457 | 47 | 1476 | 62 | 0 |
| wasm | 463 | 463 opcode-only rows | 71 | 120 | 0 | 120 | 0 | 0 | 0 |

These numbers describe current implementation progress, not completion.
Encoder forms use Go's internal operand classes and are a complete machine-
readable inventory of the encoder rows; the wasm count is deliberately an
opcode-only inventory because its Go backend has no such table. Observed forms
use plan9asm's concrete shape classification and can outnumber encoder rows
because generated testdata varies registers, address shapes, and concrete
encodings. The large amd64 gap is mostly the exhaustive legacy/SIMD/AVX test
matrix. Go 1.27 adds the ARM64 SVE corpus and encoder tables; SVE register
lists are parsed and every currently unsupported lowering form is reported
explicitly instead of being hidden as a parse failure.

The machine-readable cross-version snapshots are in
`testdata/coverage/go-asm-baseline.json`. A CI mismatch is blocking and
must be investigated at form level before the snapshot is intentionally
updated.

## Adding or changing an instruction

1. Locate the opcode and operand classes in the official encoder inventory.
2. Locate or generate native-Go-accepted concrete cases for every relevant
   operand class and classify the opcode family.
3. Add parser and lowering unit tests.
4. Add or extend a runnable conformance routine and manifest entry.
5. Run the native Go and plan9asm/LLVM semantic checks.
6. Run the standard-library corpus gate.
7. Generate all five architecture reports and inspect changes.
8. Update the cross-version fingerprint only after the change is understood.

For third-party failures, first reduce the source to its official operand form,
record the issue URL in the conformance manifest, and verify that the native Go
assembler accepts it. The Go encoder tables and official tests define the
family and permitted forms; the third-party project is only a final regression
consumer. Fix the instruction family once and add a semantic conformance case
rather than adding a project-specific workaround. The `xgo-dev/llgo#2464`
regression for `XORB reg,mem` and `PUNPCKLQDQ` is the first case tracked this
way.
