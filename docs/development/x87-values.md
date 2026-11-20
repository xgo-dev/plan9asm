# x87 value lowering

Read the [family workflow](instructions.md) and [validation rules](validation.md)
first. This guide explains the value representation and backend boundaries;
the contribution description records current qualification results.

## One grammar, separate emission strategies

`x86X87ValueForm` selects the semantic family, operands, memory width, reverse
order and pop count. `lowerX87Value` consumes that form for both hardware and
portable lowering. New operations belong in this grammar and dispatcher, not
in another opcode table for each backend or width.

`x87Value` names an LLVM `{ i64, i16 }` aggregate: a 64-bit significand with an
explicit integer bit, followed by the sign and 15-bit exponent. The layout is
private; it is not a C `long double` ABI. Copies, conditional moves, swaps and
stack rotations preserve the whole value. A private allocation may occupy
16 bytes, but an extended or packed-BCD source memory operand occupies 10.
The allocation's padding never grants extra external access.

The shared path handles scalar float/integer conversions, constants,
comparison, classification, basic arithmetic and integer rounding. Conversion
to binary32/64 belongs at the corresponding source store, rather than before
every arithmetic operation. Software math without an exact binary80 provider
returns explicit Context, including dead Void results. This deliberately
tightens the former admission of such Void functions; it does not turn an
unimplemented numerical effect into a successful translation.

## Hardware and portable values

On a matching x86 source/target, Auto and Hardware use native instructions with
balanced temporary x87 stack operations and complete-value private storage.
Original source control-word operations retain their existing contracts.
Native mathematical forms check their implicit inputs and stack effects in
the same source-value transfer. Conditional tangent/sine-cosine pushes need
a proven input range to expose both results; uncertain pushes do not establish
a second initialized value or a balanced return. Remainder instructions do not
grant quotient-status bits merely because their inputs are initialized.
These numerical helpers do not establish a complete runtime entry, saved
environment, TLS or arbitrary physical-stack contract.

Software and portable Auto paths use integer operations on the same aggregate.
The provider receives the existing emulated control word; it does not read an
ambient host FPU state. Precision control (24/53/64 significant bits), rounding
direction, storage format and exponent range are distinct axes. Reserved PC=01
and full software exception/status emulation require separate qualification.
Value agreement alone does not prove those contracts.

Native BCD/extended memory uses the original ten-byte instruction. Portable
ten-byte codecs remain unqualified, and segment-address-space cases require
their own emitter evidence. A grammar or explicit Context result must not be
reported as a successful object compilation.

## Source facts remain independent

Lowering a legal form grants no initialized register, source memory, caller or
result fact. The existing numerical-byte, pointer, stack-depth, control-word
and result checks still decide whether a complete function can use the form.
An implementation slot initialized to zero is not an initialized source value.
In particular, ordinary queries do not inherit a paired native emitter's memory
permission, and another unused argument cannot discharge a source obligation.

Keep tests that call a private emitter clearly labeled. They may verify grammar
and object shape without supplying executable inputs. Complete public APIs need
their own positive and rejection tests, followed by independent execution.

## Validation and extension

Start a family change with a complete public program that reproduces the value
or effect error. Keep the original Go encoding, source ABI, all three APIs and
LLVM22 O0/O2 objects distinct from runtime observations. Reuse exact native
observations or independent integer/rational oracles; IR substrings cannot
prove arithmetic semantics. Test signed zero, NaNs, precision/rounding controls
and meaningful exponent boundaries as a class.

Preserve the complete affected current/minimum SDK test union and publication
policies. Required Linux runtime owners must actually execute; another host's
object test is not their runtime pass. Compiler-generated integer runtime
dependencies also need a real link/execution check with the target runtime.
Do not duplicate compiler-rt merely because an object has undefined symbols.

Measure complete-source translation and generated IR separately. Share bounded
integer primitives and family semantics, release LLVM objects promptly, and
delete replaced consumers once their remaining call paths are accounted for.
