# Caller-address CMP predicates

The ordinary x86 result observer reuses the independent typed caller-address
must-domain for CMPB/W/L/Q. A register/register row requires two complete
caller-address origins, including full-word copies of the same input pointer.
A register/immediate row requires the original caller address and a resolved
Go immediate in CMP's right-hand position. A numerical register cannot stand
in for the second address. Numerical-only comparisons retain their old transfer.

The complete `x86ScalarCompareProperties` grammar supplies Go's original
immediate truncation/sign extension and high-byte/REX physical views. Full actual
ABI0 pointer imports and ordinary scalar AMD64 register-entry pointers seed the
domain. Existing validated full-word MOV aliases, address LEA and numerical
ADD/SUB transforms preserve it. Partial/full overwrites and CFG joins retain
their existing independent revocation/intersection rules. Unwritten g/DX, raw,
literal/alignment, opaque non-caller or unknown address state cannot participate.
An explicitly copied caller address in a scratch register is data provenance,
not hidden closure/thread/native-entry permission. Physical SP/BP stay Context.

CMP defines original CF/OF/Z/S/P/AF and changes no numerical/canonical GP byte,
pointer, frame, storage, lifetime, extent, alignment, noalias or native-entry
fact. The complete must-flow and unchanged canonical zero/one AL requirement
remain mandatory at every logical bool RET. Source-wide shape validation is
separate from reaching caller provenance; it never seeds an actual CFG state.
Other flag consumers retain their own typed effects: LAHF is not newly admitted
to the whole bool-result proof merely because CMP defines AF.

Independent Go objects cover complete GP byte/native-word views, immediate
transitions and all existing typed SETcc/CMOV/Jcc consumers. Three LLVM APIs,
three AMD64 targets and O0/O2 preserve the original typed source. The two required
Linux/amd64 execution roots compare complete original Go encoder bytes against
LLVM with the same actual pointer arguments, raw upper-byte/stack/GP/arena
canaries and an explicit i1-to-i32 shim, and independently exercise genuine
owned Go ABI0 callers with raw return-word and input-pointer canaries.
Encoder-fixture selector permission is not SDK/native Go caller ownership.
Emulated Linux diagnostics and native fork execution are separate evidence;
host-inapplicable builds or missing tools are not runtime passes.

This class does not close same-file tail helpers, native closure carriers,
no-DATA SDK observations, numeric index-only LEA or complete equal translation.
