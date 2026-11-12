# Native physical-register backend

`TranslateNativeModule` takes an LLVM context and explicit `NativeOptions`
(`GOOS`, `GOARCH`, `PackagePath`, `Imports`, and optional `CodeEntries`). It lowers each restricted Plan 9
TEXT to a naked LLVM function containing function-local inline assembly, and
DATA/GLOBL to LLVM global definitions. Linux and Darwin on amd64 and arm64 are
supported. The caller owns the returned module. LLGo serializes it as LLVM IR
and uses the same `.ll` compilation, object/archive and LTO pipeline as ordinary
Plan 9 assembly. Native carriers bypass signature-based ABI rewrites. Other
consumers may link the module into a larger LLVM module before optimization.
No module-level assembly, separate native assembler invocation, Go object reader
or Go toolchain is needed.

`TranslateNativeSource` remains available for consumers needing standalone native
assembly. It shares source validation and instruction lowering with the module
backend; `TranslateNativeARM64Source` is its Darwin/ARM64 compatibility wrapper.

The contract is **physical register preservation**, not inferred C typing. A
caller of an entry point must arrange exactly the registers expected by its
source. The source must implement the platform ABI itself, including stack
alignment, saving/restoring the link register, callee-saved registers and any
required native frame. This backend supplies no Go ABI wrappers, stack growth,
GC stack maps, exception/unwind metadata or transitions into the Go runtime.

`ForeignNativeFunctions` is only a routing hint: it reports a file composed entirely
of file-local TEXT definitions. Local linkage does not prove a C ABI. A driver
must explicitly choose native translation in a foreign-call context and report
native translation errors rather than retrying with invented signatures.
Package-visible Go functions remain on the typed LLVM path. An unresolved local
function on that path now requires `ManualSig` or a supported inferred signature;
it no longer silently receives `void()`.

An explicit `CodeEntries` binding may instead identify a bare source-native
TEXT address token. It supplies a distinct object-code symbol, not a Go/C
signature or a pointer-variable initializer. This bounded role accepts only
`NOSPLIT|NOFRAME`, `$0`/`$0-0`, and an exact direct `JMP` (`B` also on ARM64) to
a declared native import, optionally followed by an unreachable operand-free
`RET`. No data instruction, register operation, local call or implicit frame is
admitted, even on a dead path. Missing bindings remain errors. Import identities,
import aliases, DATA and other exported entries cannot collide with the bound
code symbol. Consumers must bind a real source declaration's address to this
entry; ordinary Go functions still require their declaration-driven ABI.

## Source contract

- The output target is explicit and independent of the build host. Unsupported
  target pairs are errors. `TranslateNativeARM64Source` remains a compatibility
  wrapper for Darwin/ARM64.
- Every `TEXT` is file-local (`name<>`), has `NOSPLIT`, and declares `$0` or `$0-0`.
  `NOFRAME` is also required if the body uses `BL` or `CALL`. No implicit Go
  prologue or epilogue is generated, including for zero-frame functions.
- Other TEXT flags are rejected. The source manages any native frame explicitly.
- Only `#include "textflag.h"` is accepted. Other includes, macros, conditional
  preprocessing, and block comments are currently rejected. Line comments and
  constant integer expressions are accepted.
- On ARM64, integer registers are `R0`–`R30` except `R18` (reserved conservatively on both OSes), plus `ZR`.
  `RSP` is accepted in supported stack-pointer forms; `SP`, `FP`, `g`, `R31`,
  `Wn` aliases, and platform aliases are rejected. Floating registers are `F0`–`F31`.
- Local function/branch/import identifiers use ASCII letters, digits and `_`,
  beginning with a letter or `_`. Data definitions use `·name` for a package global.
- Local labels and function addresses are renamed per assembly file. Naked
  modules use LLVM symbol operands and inline-asm unique IDs across module merges. Foreign
  symbols are resolved only through the driver's explicit import map; no Go
  package/runtime call, symbol addend, computed branch or indirect call is accepted.
- `DATA` supports constant integers of 1/2/4/8 bytes and 8-byte addresses of selected
  local functions, defined data or declared imports. Each initializer must fit its
  `GLOBL` allocation and must not overlap another initializer. Gaps are zero-filled.
- `GLOBL` requires a constant size from 1 byte to 64 MiB. Supported flags are `0`,
  `RODATA` and `NOPTR`. Definitions are 8-byte aligned. Naked modules use packed LLVM constants with
  pointer-typed address initializers and explicit zero-filled gaps; RODATA sets
  LLVM's global constant flag. LLVM selects the target data sections. The driver
  checks the storage size against the Go definition before module linking.
  The standalone source emitter uses `__DATA_CONST,__const` on Mach-O and
  `.data.rel.ro` on ELF for RODATA; mutable definitions use `.data`.

## ARM64 instruction and operand forms

| Plan 9 operation | Supported forms and native semantics |
| --- | --- |
| `MOVD` | Integer register/register, integer constant/register, register/base+offset memory in either direction. Constants expand to `movz`/`movk` using only the destination and preserving flags. |
| `MOVW`, `MOVWU` | Register/register or register/base+offset memory. `MOVW` register/load sign-extends to 64 bits; `MOVWU` zero-extends. Stores write 32 bits. Immediate forms are rejected. |
| `FMOVD` | Integer/FP register bit transfers or FP/FP register copies. No numeric conversion or memory form. |
| `ADD`, `SUB` | Two or three operands: register or nonnegative 12-bit immediate, source, destination. Register forms involving SP are rejected. No hidden scratch-register expansion. |
| `CMP`, `CMPW` | Register or nonnegative 12-bit immediate against a register; 64-bit and 32-bit comparisons respectively. |
| `LSL` | Two or three operands, with a register or immediate shift from 0 through 63. |
| `B`, `JMP` | A defined local label, selected local function or declared import. |
| `BL`, `CALL` | A defined local label, selected local function or declared import; the containing function must have `NOFRAME`. |
| `BEQ`, `BNE`, `BLT`, `BLE`, `BGT`, `BGE`, `BHS`, `BLO`, `BHI`, `BLS`, `BMI`, `BPL`, `BVS`, `BVC` | Defined local labels, preserving the corresponding hardware condition. |
| `CBZ`, `CBNZ` | 64-bit integer register and defined local label. |
| `RET` | No operands; returns through the native link register. |

Memory operands use a single base register and constant byte offset. An offset
must fit the instruction's unsigned scaled 12-bit or signed unscaled 9-bit field.
Index registers, symbolic memory operands, pre/post-indexing and larger offsets
are rejected. Raw instruction directives (`WORD`, `BYTE`) and all unlisted
instructions are rejected. Validation errors return no partial assembly or DATA.

## Validation

Tests compile generated assembly to Mach-O on all hosts with Clang, check data
section placement, and execute C harnesses on Darwin/ARM64. The harnesses cover
foreign-call parameters/results, integer-to-FP trampoline arguments, physical
register copies, signed and unsigned loads, constant expansion, negative and
unaligned memory offsets, and local control flow. Rejection tests exercise the
unsupported forms above. The parser retains address initializers explicitly;
they are never inferred by decoding an object relocation.

## AMD64 instruction and operand forms

The native ABI is SysV AMD64 on Linux and the corresponding Darwin x86-64 ABI
on macOS. Physical registers are AX/BX/CX/DX/SI/DI/BP/SP and R8 through R15;
MOVQ also supports bit transfers between X0 through X15 and integer registers
or base+offset memory. MOVL writes zero-extend the destination register.
`SP` means the physical stack pointer only: named Go stack slots and `FP` are
rejected. Callers and source code own stack alignment and callee-saved registers.

The bounded instruction set is MOVQ/MOVL, LEAQ (memory to register),
ADD/SUB/AND/OR/XOR/CMP/TEST in Q and L widths, immediate SHL/SHR/SAR in Q and L
widths, CALL/JMP, RET, and JEQ/JNE/JLT/JLE/JGT/JGE/JCS/JCC/JHI/JLS/JMI/JPL/JOS/JOC.
CMP reverses operands when emitting AT&T syntax to preserve Go comparison order.
Memory has one base and a signed 32-bit constant displacement; indices, segment
registers, named offsets, indirect calls, byte/word operations, and other forms
are rejected. Q-width arithmetic immediates must fit signed 32 bits; MOVQ to a
register can load a full 64-bit value. Shifts require counts below operand width.
No implicit prologue, scratch register, Go ABI wrapper, or unwind metadata is added.

## Target format and execution matrix

Shared validation, TEXT/DATA/GLOBL handling and symbol resolution are separate
from instruction lowering. Darwin symbols receive a leading underscore. ELF
symbols do not; AMD64 imported calls use PLT references, ARM64 imported calls use
native CALL26/JUMP26 relocations. ELF emits function type/size and non-executable
GNU-stack metadata. Native assemblers and linkers perform instruction encoding
and relocations; the backend does not read or depend on Go object files.

`TestNativeTargetMatrix` cross-assembles all four combinations, checks object
headers/data placement, and executes the C ABI harness on the matching host.
Linux harnesses may also run locally via explicitly configured Docker images:
`PLAN9ASM_NATIVE_DOCKER` (amd64), `PLAN9ASM_NATIVE_DOCKER_ARM64` (arm64).
They verify foreign calls, integer/FP argument shuffles, returns, physical stack
frames, and data-address relocation in PIE executables. Unsupported targets such
as Windows require their own ABI/format qualification before being enabled.

## Naked LLVM function contract

Each TEXT becomes an internal `void ()` function with `naked noinline`. This is
an address/code carrier, **not an inferred C or Go prototype**. Its only body is
one side-effecting inline-asm call followed by `unreachable`. All entry parameters,
return values, stack alignment and callee-saved registers remain the source's
physical-register contract. Call sites keep their own actual calling convention
and types. Go has already marshalled syscall arguments before entering these
stubs; no Go parameter slot or LLVM formal argument is read by the carrier.

LLVM 22 explicitly exempts naked functions from prototype-based call rewriting
in `InstCombineCalls.cpp` because their assembly may consume parameters absent
from the prototype. This differs from synthesizing a typed `call void()` for an
unknown assembly callee, which remains forbidden in typed LLVM translation.
The backend must not mark a carrier `noreturn`: assembly RET returns to the
machine caller even though it does not fall through to the IR terminator.
Every body must end in RET or an unconditional branch; implicit fallthrough
between TEXT functions is rejected by the module backend.

Function and imported-symbol references are constant inline-asm operands (`s`
on AMD64 PIC, `i` on ARM64). Imports are external byte-address declarations,
not guessed foreign function prototypes. Native CALL/JMP still executes inside
assembly. LLVM therefore sees dependencies for module renaming and DCE without
lowering the call's arguments. Local branch labels use `${:uid}`; literal AMD64
immediate `$` characters are escaped before adding LLVM template operands.
The assembly call conservatively clobbers memory. It does not request compiler
stack alignment, argument moves, or a generated prologue/epilogue.

Module tests execute optimized IR consumers of the void() carriers with actual
integer/pointer parameters, integer and floating-point results, external calls,
register shuffles and tail calls. They run O2 and full-LTO optimization pipelines;
merge identically named local functions/labels from separate files; check that
referenced functions survive and unreachable carriers disappear; and resolve an
external assembly address to a typed LLVM function definition. Packed DATA tests
cover forward references, address relocations, gaps, truncation and mutable data.
LLGo integration also exercises complete off/thin/full LTO links on Darwin/ARM64.

The assembly instructions themselves remain opaque to IR optimization. This
backend does not introduce Go ABI adapters, stack maps, unwinding or runtime
transitions.
