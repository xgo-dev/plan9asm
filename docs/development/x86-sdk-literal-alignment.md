# Original SDK literal minimum alignment

`CaptureGoX86SDKLiteralAlignment` is an independent, live data-layout observer.
It borrows a genuine SDK ASM source and its private readonly initializer owner;
it cannot be constructed from JSON, names, bytes or object alignment alone.
It has no instruction binding, pointer, numerical address, native entry,
execution, caller-memory or logical bool-return API.

The first registered profile is the original Go 1.27.2 SDK on Linux x86,
Darwin AMD64 and Windows x86. The actual CGO setting is retained, including
CGO=1 when the complete selected SDK graph is independently ordinary/uncgo.
Default executable/PIE and compiler shared settings are checked against the
complete original Go profile rule, rather than borrowed from another GOOS.

The observer retains the actual linker/compiler routes, binaries and reported
versions; complete linker/loader rule sources; the candidate and runtime source/
export graph; every named object-local definition in every selected archive;
its generated main, compiler object, import configuration and linked image.
Internal candidates are not imported by the generated main and receive no
linkname or `-E` bypass. They must be naturally retained by the ordinary runtime
link. Public candidates may use a genuine permitted blank import. Linker-native
dead stripping is only an observation boundary, never a whole-module pass.

Go's `SymAlign=0` means unset. The registered complete `ld.symalign` rule and
x86 minimum/maximum values are audited before applying the existing
`goAssemblyDataAlignment` size rule. A uniquely identified private, relocation-
free readonly object must also match its original linked bytes, extent, section
permissions and section/symbol placement. Same-named definitions anywhere in the
selected graph cannot be selected by equal bytes or hashes. Ambiguous or absent
objects receive no minimum-alignment row. Reports expose only that guaranteed
minimum, not the observed address or any stronger accidental alignment.

All original source functions and archive members remain bound. The two 256-byte
original maps tables have independently observed minimum 32 on all five targets.
The four naturally retained CRC32 tables give minimums 8, 16 and 32 for their
different extents. This is a data-layout witness, not execution of maps' alignment
check or a C `_Bool` ABI claim. The existing emitters' alignment rule is unchanged.

The complete producer/alignment cohort passes with Go 1.27.2 and LLVM 22 in
105.560 seconds, including actual image mutations, duplicate-name controls,
source/tool/object/profile/generation/deadline rejection, copy/Close disposal
and all Err/Done/Deadline reentry cases. Go 1.20 portable rule/emit/object/literal
controls pass in 1.334 seconds. Its complete original five-architecture alignment
test remains failed: the downloaded Go 1.20.14 SDK lacks both
`misc/wasm/wasm_exec.js` and `misc/wasm/go_js_wasm_exec` (and the alternate lib
runtime). No skip, substitute runtime or module-cache change was used.

Masked-low-bit instruction consumers and canonical Go bool-byte/register
transport require separate TDD batches. Until those consumers genuinely bind
this live role, the complete original maps source keeps its existing Context;
the observer does not waive deeper caller, pointer, loop or native-entry needs.
