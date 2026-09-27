# Go module assembly discovery ledger

`ledger/` is the repository-owned checkpoint for newest-to-oldest scans of the
official Go module index. The history pass stops at 2019-04-10. Within one
logical module family, `/vN` major has priority first and Go semantic version
second: discovering `/v3` replaces `/v2` even if the `/v3` index record is
older, and still older `/v2` records are then skipped. It records the selected
exact `module@latest` version, including modules without Plan 9 assembly.
Assembly matches retain every `.s` path and architecture hint for all current
Go ports, including architectures plan9asm does not support yet; failures
remain eligible for retry.

Results are deliberately stored as uncompressed, line-oriented JSON instead
of a binary gzip blob:

```text
ledger/
  manifest.json
  records/00.jsonl ... records/ff.jsonl
assembly-ledger/
  manifest.json
  records/00.jsonl ... records/ff.jsonl
```

`sha256(module)[0]` selects one of 256 shards, so all records for a module stay
in one stable file. Records are sorted by module, Go semantic version, and
result kind. Updating the ledger replaces obsolete exact versions; a later
success also clears the corresponding retryable failure. Repository tests
validate the layout, shard ownership, ordering, and counts, and reject
committed `.gz` discovery results.

The scan ledger's `scanned` records include inspected versions with no
assembly; `matched` records retain assembly candidates. The separate
`assembly-ledger/` records each matched exact version as `pending`, `passed`,
`failed`, evidence-backed `not_applicable`, or a distinct audited skip
(`skipped_invalid_source`, `skipped_superseded`, or
`skipped_private_extension`). Private-extension skips identify one exact
file/target and retain successful translations of other files without counting
the module as passed. Its manifest binds the scan
fingerprint, frozen report/tool provenance and source content. It is an
audited status snapshot, not input to discovery or corpus compilation. A
change to the scanner/compiler source or scan ledger makes the snapshot
stale; updating only the evidence snapshot does not. Direct cgo-import
inventory remains outside this repository.

Continue from this checkpoint without downloading completed versions again:

```sh
go run ./cmd/plan9asmdiscover \
  -limit 20000 \
  -workers 64 \
  -traffic-report _out/discovery-traffic.json \
  -out-dir testdata/discovery/ledger
```

When `-out-dir` already exists, it is validated, used as the completed
exact-version checkpoint, and updated in place. The history upper bound is
derived from the earliest `index_ranges[].since`; a new ledger starts at the
current time. Because the official index only offers an ascending `since`
API, the scanner brackets complete time windows internally and selects their
newest records. It never splits a timestamp group, so a batch may contain
slightly more than `-limit` records without making the next reverse cursor lose
entries. Every committed interval and its exact entry count is retained in
`manifest.json` under `index_ranges`. Parsed-time ordering, identical adjacent
endpoints, and aggregate entry counts are checked whenever the ledger is read
or written; gaps, overlaps, and conflicting repeats are rejected. Thus no
manual cursor copying is part of normal operation. `-seen-report` remains
available for additional legacy JSON, gzip-compressed JSON, or sharded import
sources and is repeatable. Every selected module discovered in the index is
resolved to an exact `@latest` version before ZIP inspection. A completed exact
version is reused without another ZIP request. A higher module-path major, or a
higher Go semver within the current major, crosses the family checkpoint and is
resolved; lower majors and older versions do not cause metadata or ZIP traffic.
If `@latest` resolves to a higher-priority exact version, the old family's
scanned, matched, and failure records are removed.
For a new exact version, Discovery uses HEAD and range requests to read the ZIP
directory and candidate `.s` contents; it does not materialize the complete
module. Only `matched` versions are downloaded through the Go module cache by
the later corpus translation/LLVM compilation stage.

`-traffic-report` writes one sorted JSON entry for every module that actually
made a request. It separates `@latest`, ZIP HEAD, ZIP range, and whole-small-ZIP
traffic, including retries, and gives per-module and run totals. Bytes mean
HTTP response entity bytes read with `Accept-Encoding: identity`; HTTP headers
and TLS/IP overhead are outside this application-level measurement. Index
traffic is reported separately because it does not belong to one module. A
module absent from the report made zero proxy requests.

List the largest modules in one batch:

```sh
jq -r '.modules[] | [.total_body_bytes, .total_requests, .module,
  .resolved_version, .outcome] | @tsv' _out/discovery-traffic.json |
  sort -nr | head -20
```

`outcome` is `scanned`, `matched`, `failure`, `reused_scanned`, or
`reused_matched`. Reused modules normally make only the `@latest` metadata
request; their previously inspected exact ZIP is not fetched again. GitHub
pseudo-versions at the same commit also share successful ZIP inspection across
repository-path case aliases, including aliases encountered concurrently in
one batch. Semantic tags and case-sensitive module subdirectories are never
folded.

`-workers` parallelizes module inspection inside one Discovery process. Ledger
publication remains single-writer and is protected by a sibling writer lock;
never launch concurrent processes targeting the same `-out-dir`, and do not
rewrite a ledger while corpus shards are reading it. Corpus shards themselves
may run in parallel because the ledger is read-only and each shard has a unique
report path.

Run an incremental head scan whenever needed; it does not depend on the history
scan having reached 2019:

```sh
go run ./cmd/plan9asmdiscover \
  -scan-mode incremental \
  -workers 64 \
  -out-dir testdata/discovery/ledger
```

Incremental mode derives its lower bound from the greatest committed
`index_ranges[].before` value and scans only up to the new current-time upper
bound. It always drains that interval and ignores `-limit`, so it cannot
publish a new high-water mark while leaving an unrecorded gap. A newly
published `/v3` is therefore processed even when `/v2` is the current family
checkpoint. Empty intervals are recorded with an exact zero count so the same
head window is not fetched repeatedly. History extends the earliest range and
incremental scanning extends the latest range, preserving one continuous
coverage chain in both directions.

Retry retained failures without rereading the module index:

```sh
go run ./cmd/plan9asmdiscover \
  -scan-mode retry \
  -workers 64 \
  -out-dir testdata/discovery/ledger
```

Validate the complete ledger and print both derived endpoints plus the funnel
counts at any time without network access:

```sh
go run ./cmd/plan9asmdiscover -status \
  -out-dir testdata/discovery/ledger
```

The status read checks range continuity, the sum of range entry counts, all
manifest/record counts, shard ownership, semantic ordering, and duplicates.

After adding a new supported target, its external assembly corpus can be
replayed directly from the saved exact versions without reading the module
index or revisiting no-assembly modules:

```sh
for shard in $(seq 0 31); do
  PLAN9ASM_DISCOVERY_TARGETS=linux/riscv64 \
    scripts/check-discovered-library-corpus.sh "$shard" 32 \
    "_out/discovered-library-corpus/riscv64-shard-$shard.json"
done
```

The target filter uses the recorded file paths. It conservatively retains
unsuffixed and custom-suffixed files, then fetches only those matched exact
versions and applies the current Go source/build-constraint checks before
translation and LLVM 22 compilation.

The external-library discovery and compilation corpus uses Go 1.27 only. The
Go 1.20–1.27 matrix belongs exclusively to the separate official Go
toolchain/standard-library assembly corpus.
