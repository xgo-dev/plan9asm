# Executable instruction conformance cases

This directory is the semantic oracle for instruction forms. An opcode is not
considered fully verified merely because its name appears in a lowerer or a
single operand form emits LLVM IR.

Each case must:

1. use assembly accepted by the Go assembler for its GOARCH;
2. execute the native Go assembly and check exact results;
3. translate the same assembly with plan9asm, compile it with LLVM, execute it,
   and check the same results; and
4. list every form it claims to verify in manifest.json.

Reduced regressions from user reports should also list the originating GitHub
issue or pull request in the manifest's `references` field. The reduced source
must still be accepted by the native Go assembler; issue provenance is a
real-world regression layer, not a replacement for the official encoder
tables or semantic oracle.

Every manifest case must set `validation` to `execute` or `compile-only`.
Compile-only is reserved for privileged, trapping, or environment-dependent
forms and requires a non-empty `reason`. Runnable forms may not use
compile-only merely because they are inconvenient to test. Cases whose native
hardware execution requires optional CPU ISA extensions (such as `adx`,
`sse4.2`, or `sha-ni`) record them in `hw_features` so `cmd/plan9asmscan`
tracks them explicitly in `hw_pending_by_form` while their target-independent
LLVM IR is still verified against Go reference outputs on every host.

One assembly routine may exercise several related forms. Setup instructions
used only to feed the instruction under test do not need to be claimed. Tests
must avoid undefined flags, uninitialized registers, host-specific accidental
state, and unsupported CPU features unless they feature-detect and skip.

Privileged, trapping, or environment-dependent instructions use the explicit
compile-only policy instead of being executed. They still require parser,
lowering, and LLVM compile checks where applicable.
