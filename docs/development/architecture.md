# Translator architecture

This is a navigation guide, not a coverage certificate. Start with the
[family workflow](instructions.md) and [validation commands](validation.md).

The current development order is [amd64 architecture convergence](x86-convergence.md):
finish one architecture's implementation, efficiency and independent coverage
before expanding another. Existing cross-architecture regression gates remain.

## Translation path

1. Parsing/preprocessing retains assembly instructions, labels, DATA/GLOBL and
   the source architecture. GoModule additionally derives signatures and frame
   fields from Go declarations. Already-preprocessed input is not expanded again.
2. Source and ABI binding establish any extra facts needed by complete functions:
   parameter/result roles, private continuations, external storage and special
   runtime entries. An opcode spelling alone cannot establish these facts.
3. Architecture-local typed parsers validate complete operand forms. Named and
   raw-encoded forms should converge on the same numerical lowerer and effects.
   Effects describe reads, writes, widths, flags and preserved register aliases.
4. Lowerers emit LLVM IR. ARM64 and x86 fallback declarations are selected from
   immutable catalogs by the generated module's actual global references, not a second
   opcode-to-intrinsic table. Comments and string data do not select declarations.
   X86 keeps ordinary declarations and source helpers on their existing path;
   direct module success needs no catalog lookup or text scan.
5. The shared module return path checks backend restrictions for every API,
   including special early returns, and disposes rejected modules. The caller
   owns a successful module and must dispose it before its LLVM context.

Generated IR enters LLVM through a copied memory buffer, without temporary
files. LLVM's parser consumes the buffer on success and error. Default buffer
identities remain independent through a process prefix and atomic sequence;
explicit IR `source_filename` values are preserved. These names supply no
source or memory permissions.

`Goarch` selects source encoding/ABI rules. `TargetTriple` selects the LLVM
backend. They need not be identical for portable operations. Backend-specific
requirements remain explicit: SVE needs AArch64; wasm cannot use blockaddress.
Used LLVM `llvm.x86.*` intrinsics require a matching x86 source mode and target,
except MXCSR load/store, whose i32 memory operand works in either x86 mode.
The guard checks LLVM intrinsic IDs, not an opcode list; unused declarations,
ordinary functions and generic portable intrinsics impose no such restriction.
Actual native inline-assembly uses and nonempty module assembly also require
the matching source backend. The guard follows LLVM values rather than source
mnemonics, comments or unused constants. Empty portable compiler barriers retain
their independently compiled generic constraints. Matching native requests avoid
the additional instruction walk.

## Family and format normalization

The implementation should scale with the **sum of legal format groups per
source family, plus lowering strategies per semantic family**. It must not
enumerate source opcodes times destination opcodes times operand formats.
LLVM selects destination instructions for portable IR. Target-specific
intrinsics or exact native instructions are explicit exceptions.

The existing amd64 implementation can be inventoried by the following groups.
These are design groups, not a count of supported opcodes or encoding rows.

| Source semantic group | Shared format axes | Existing representation |
|---|---|---|
| Scalar integer, bit operations and conditions | Operand width, explicit/implicit roles, immediate interpretation, FLAGS | GP typed forms and `x86TypedByteEffect` |
| Packed integer arithmetic and comparisons | Element/input/result widths, vector width, saturation, encoding, masks | `x86PackedBinaryForm`; four-family `x86PackedPhysicalForm` |
| Shifts, shuffles and permutations | Count kind, lane boundaries, selection indices, old destination | Family forms with common vector input/effect records |
| Floating point and conversions | Input/output kinds, scalar/packed shape, rounding and exceptions | `x86FloatBinaryForm` and conversion forms |
| Moves and memory operations | Direction, access width, alignment, masked access, alias writes | Move forms and typed memory/effect projections |
| Control flow and machine state | Branch inputs, implicit registers, ordering, x87/MMX state | Dedicated forms and the existing function CFG |

Inventory the destination by **emission strategy**, not target opcode names:
ordinary LLVM IR, portable/constrained intrinsics, target intrinsics and exact
native assembly. A family can share arithmetic across strategies while retaining
an explicit memory or machine-state contract. Target instruction selection is
LLVM's job; a new backend should not duplicate every source-format rule.

The work therefore scales with shared format grammars, family-specific semantics
and exceptional lowering contracts. It need not even be a complete
family-by-format product: each family declares which shared formats are legal.
Keep the independent official-row inventory exhaustive for tests, including
overlapping rows; compact implementation is not a reason to sample away rows.

| Layer | Shared representation | Separate concerns |
|---|---|---|
| Source grammar | Semantic operation, legal operand group and original encoding | Named/raw source identity and mode restrictions |
| Format | Operand roles; element, carrier, active, memory and result widths; immediate interpretation | Only combinations admitted by the official encoder |
| Machine effects | Ordered inputs/outputs, FLAGS, alias writes, masks, memory access and ordering | Alignment faults, inactive-lane suppression and FP exceptions |
| Source binding | ABI entry/results, frame layout, actual storage and source lifetime | These facts are not granted by parsing a legal instruction |
| LLVM lowering | Scalar/vector arithmetic, comparisons, shuffles, conversions, memory/control or intrinsics | Native-only operations require a compatible target |

Widths are parameters, but not interchangeable: a broadcast can read four
bytes into a 64-byte vector, and an extract can write fewer bytes than its
register carrier. Likewise, merging a masked result reads the old destination;
zeroing does not. Represent these distinctions once instead of rediscovering
them in each consumer. Floating-point and machine-state operations must retain
their special semantics rather than being grouped solely by operand count.

Use small typed records for semantic groups, reusing existing forms such as
`x86PackedBinaryForm` and `x86FloatBinaryForm`. Keep the parsed form through
effect analysis and lowering. A translation-local plan may retain immutable
syntax; it must not cache mutable source permissions or retain stale operands.
Do not build a universal optional-field structure, another LLVM-like IR, or a
second opcode registry beside the existing grammar.

The first complete migration should use a packed binary group: normalize its
format once, feed effects, memory shape and lowering from that record, then
delete those families' old consumer selectors in the same batch. Adding a GP
effect cache alone does not complete this migration. In particular, a numeric
LEA analyzer may reject a static-symbol LEA accepted by source binding; eager
analysis must not turn that distinction into a translation regression.

Validate independent official rows and initialized functions, preserve previous
acceptances and meaningful rejections, compile LLVM 22 objects and retain runtime
oracles. Measure production line delta, parse/analysis allocations and complete
translation time separately. Neither a faster rejection nor smaller test scope
counts as an efficiency improvement.

## Terms used in family notes

| Term | Meaning and limit |
|---|---|
| Typed grammar | A validated instruction-family form, including operand roles and widths; not proof that arbitrary inputs are initialized. |
| Numerical value / NUM | Defined bytes usable as a number. A pointer's frame occupancy alone does not grant this role. |
| Raw continuation | Lowering of instructions following original encoded bytes, with their exact operands and physical-mode effects retained. Decoding alone does not prove caller, frame or memory contracts. |
| Producer replay | Checking that the source/tool observation which supplied extra facts still matches the consumed input. It is separate from numerical instruction semantics. |
| Native backing | Concrete storage with the required extent and access contract. A logical frame field or a pointer-shaped value alone does not establish contiguous storage. |
| Source owner / lease | The bounded lifetime of a captured source/tool observation. Expiry, mutation or closure invalidates its facts. |
| Context | A probe lacks facts required to decide or translate the form. This is neither support nor successful validation. |

An immutable declaration table may be shared. Mutable source verification and
caller facts must not be cached merely to hide repeated subprocess cost. Move
capture outside repeated translation when its owner and lifetime can be made
explicit; measure complete-source performance and retain invalidation tests.

## Evidence levels

| Evidence | What it establishes | What it does not establish |
|---|---|---|
| Go opcode/encoding table | Names, forms and machine encodings | Translator implementation |
| Official-corpus classification | Outcome for observed probe inputs | Unobserved forms or initialized-context success |
| IR generation and verification | Well-formed LLVM module for supplied inputs | Backend acceptance or correct execution |
| LLVM 22 object compilation | Backend accepts that module/target | Correct calling convention or values at runtime |
| Executed differential test | Observed values/effects agree with an independent oracle | Every unexecuted form, target or hardware feature |

Never promote `context`, a hardware skip, or zero observed `unsupported` forms
to object/runtime coverage. Re-test context forms with justified initialized
inputs, and retain whole-file regressions independently of instruction probes.
