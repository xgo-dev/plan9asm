# Instruction-family development

Read the repository [rules](../../AGENTS.md) first. This guide describes the
workflow, not a list of already completed instruction families.

## Sources of truth

- Use the supported Go toolchain's assembler tables under
  `$(go env GOROOT)/src/cmd/internal/obj/<arch>` as the authority for opcode,
  operand, register, suffix, masking, broadcast, and rounding forms.
- For x86 AVX/EVEX instructions, inspect both the referenced `ytab` and every
  opcode attribute in `avx_optabs.go`. A shared `ytab` does not imply that
  rounding, SAE, broadcast, or zeroing flags are identical.
- Confirm uncertain forms with the Go assembler. Do not infer a form solely
  from Intel syntax or from a third-party source file.
- Treat `386`, `amd64`, `arm`, `arm64`, and `wasm` as supported architectures.
  A form must not be classified as unsupported merely because the host has a
  different architecture.

## Instruction-family workflow

Use test-driven development for every instruction change:

1. Reproduce the unsupported instruction or incorrect operand-form behavior in
   a focused test and run it to observe the expected failure.
2. Before implementing the opcode, enumerate its complete family and all forms
   in the current Go assembler tables. Add positive and negative form tests.
3. Implement a coherent instruction family, not only the single spelling that
   exposed the gap. Cover every X/Y/Z width, register and memory source,
   architecture restriction, mask/zero form, broadcast form, and rounding/SAE
   form present in the Go tables.
4. Compile generated IR with LLVM 22 for every affected target. Add runtime
   conformance when an instruction's lane preservation, operand order, flags,
   masking, NaN behavior, or memory effects are not established by compilation.
5. Rerun the discovering external-library shard or official corpus that exposed
   the problem. One fixed mnemonic must not hide another form from the same
   family.

Prefer typed, table-driven grammars over mnemonic-specific branches. Separate
orthogonal axes such as operation, lane/stack width, operand class, encoding
generation, architecture mode, masks/broadcast/rounding, implicit registers,
and semantic effect. The parser/validator, register-liveness scan, lowering,
supported-op extraction, and completeness test should consume the same spec
where practical. A completeness test must compare the whole spec table with
the current Go encoder family so adding one observed spelling cannot leave
sibling forms unmodeled.

For a newly discovered instruction, update all four layers before calling it
complete: the family-specific lowerer, positive/negative Go-table form tests,
LLVM 22 object compilation for every affected supported architecture, and the
architecture's supported-op extraction test in `cmd/plan9asmll/main_test.go`.
The external corpus uses that extraction result in its diagnostics, so omitting
the last layer can make a supported instruction look unsupported.

A typical x86 investigation starts with the Go 1.27 tables and an assembler
probe:

```sh
goroot=$(go env GOROOT)
rg -n 'A?VADDPS|yvaddps' "$goroot/src/cmd/internal/obj/x86"
sed -n '<start>,<end>p' "$goroot/src/cmd/internal/obj/x86/avx_optabs.go"
GOOS=linux GOARCH=amd64 go tool asm -o _out/form.o _out/form_amd64.s
GOOS=linux GOARCH=386 go tool asm -o _out/form.o _out/form_386.s
```

Record the initial failure in test output before adding the lowering. Focused
form tests normally belong in `amd64_ecosystem_test.go`,
`amd64_operand_forms_test.go`, or the corresponding ARM file. Add the opcode to
`TestExtractSupportedOpsFindsCompleteAddedInstructionFamilies` so external
corpus diagnostics recognize it. Semantic fixtures live under
`testdata/conformance/<arch>` and must be checked against both native Go and the
LLVM runtime oracle where supported.

The main implementation entry points are:

- x86/386/amd64: `amd64_blocks.go`, `amd64_needed.go`, `amd64_translate.go`,
  then the family-specific `amd64_lower_*.go` file;
- ARM: `arm_blocks.go`, `arm_needed.go`, `arm_translate_cfg.go`, then
  `arm_lower_*.go` and frame/register handling in `arm_eval.go`;
- ARM64: `arm64_translate.go`, `arm64_eval.go`, and `arm64_lower_*.go`;
- wasm: opcode families in `wasm_ops.go`, lowering in `wasm_translate.go`, and
  intrinsic declarations in `translate_prelude.go`;
- command-side package signature, ABI, include, and target handling:
  `cmd/plan9asmll/main.go` with tests in its nested module.

Supported-opcode reporting scans opcode-keyed package maps as well as explicit
switches. Every newly introduced opcode map must have an architecture-specific
extraction regression in `cmd/plan9asmll/main_test.go`; otherwise a real
translator failure can be misreported as an unknown instruction.

For x86 form tests, cover at least these targets:

- `darwin/amd64` — `x86_64-apple-darwin`
- `linux/amd64` — `x86_64-unknown-linux-gnu`
- `windows/amd64` — `x86_64-pc-windows-msvc`
- `linux/386` — `i386-unknown-linux-gnu`
- `windows/386` — `i686-pc-windows-msvc`

Do not add an `unsupported_forms` skip for a supported target. Context-dependent
forms may be classified separately only when translation genuinely requires
information unavailable to the scanner.

## Semantic and raw-encoding checks

- Distinguish physical encoding rules from Go frontend acceptance, especially
  for 386 VEX/EVEX registers and ignored VEX.W bits. Check primary architecture
  specifications in addition to Go tables.
- Validate operand order, implicit inputs/outputs, destination aliases, flags,
  width extension and lane boundaries. Keep every overlapping X/Y/Z view
  coherent; preserve legacy upper lanes and clear VEX/EVEX upper lanes.
- Test dynamic masks, irrelevant high mask bits, unaligned addresses, null
  inactive sources and guard pages. Consume results so optimization cannot
  remove the memory access under test.
- Check count masking versus saturating shifts, signedness, NaNs and
  out-of-range conversions. Avoid LLVM poison and undefined arithmetic.
- Native access width is not internal register-slot width. A 386 Q spelling
  can still require a four-byte memory read.
- Validate independent frame slots and spans; do not relax ABI checks just to
  compile an external library.
- Unknown raw VEX/EVEX instructions must fail closed, never become unrelated
  legacy instructions. Test truncated and reserved encodings.
- Demonstrate that the old implementation fails the new runtime oracle where
  practical. Use an isolated checkout/overlay, not a running frozen tree.

Use independent-axis tests for shared operand grammars rather than repeating
the same huge Cartesian product for every mnemonic. See
[validation](validation.md) for the required gates.
