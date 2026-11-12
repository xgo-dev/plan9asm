# Numerical x86 effective addresses

Go's LEAW/LEAL/LEAQ share the complete `ym_rl` row (`Zm_r`, byte advance one,
`Ym, Yrl`) and opcode 0x8d, with Pe/Px/Pw prefixes. Q has no 386 encoding.
The common LEA grammar retains Go's physical bank, SIB and displacement rules;
amd64 LEAL truncates its displacement, while W/Q require signed int32 and 386
also admits uint32. A bare resolved integer expression has NAME_NONE memory
syntax but LEA computes its displacement without reading memory. Its local
operand normalization preserves original opcode, Raw and certificate identity.

The typed numerical effect reads only the actual base/index register bytes and
writes the destination after every read. Modulo-W/L/Q results need only those
low input bytes; W preserves the remaining destination bytes and L clears its
upper32. FLAGS are neither read nor changed. Initialization, canonical bool,
caller-address overwrite and carry consumers share that same effect. Computed
bytes are not canonical zero/one; unrelated canonical bytes survive and L's
cleared high bytes remain known zero. Existing complete CFG joins and budgets
are unchanged.

Decoded physical forms and valid physical SP/BP operands remain delegated to
their already registered exact source-stack/native consumers. This numerical
registration supplies none of those facts and does not intercept their FLAGS
handling. Unbound public paths still require Context.

Only initialized numerical registers participate. FP/AUTO/SP/BP, SB/PC,
segment/TLS, decoder/address-size overrides, native/opaque/literal addresses,
unknown register inputs and unknown displacements obtain no numerical value,
memory extent, alignment, backing, entry or native g/closure permission.
The separate full-word typed caller-address LEA remains independent; a numeric
base cannot launder a pointer index. Dead unknown LEA cannot borrow the ordinary
pure-GP unknown-value fallback. The complete original source is still checked.

ABI0 result queries also require each parameter slot's index and scalar leaf
type to agree with its supplied argument, including the actual nested struct
or array extract path. Official flattened scalar parts remain valid. Duplicate
leaf roles and contradictory pointer/integer metadata grant no entry facts;
this consistency check supplies no declaration or physical-layout authority.

Tests bind both actual Go SDKs' complete LEA rows and accept/reject forms,
physical banks, W/L/Q aliases, initialization holes, canonical results, FLAGS,
source identity and all three APIs/five x86 targets/O0/O2 objects. The required
Linux AMD64 root is
`TestCrossLinuxRuntimeMatrixX86NumericalLEAOriginalBytesAndLLVM`.
It executes original Go bytes through an explicit AX/BX adapter and compares
independent numerical and six-FLAGS references with LLVM on all three APIs and
O0/O2. Its LAHF status diagnostic uses the existing scalar lowerer; it does not
extend LAHF's must-defined or canonical-result contract. Each owned batch has
at most 64 functions, releases LLVM objects/processes and retains stack/GP
canaries. Host-inapplicable build selection is not execution evidence; emulated
local execution is not native ISA certification. This closes no whole SDK
equal helper graph, hidden DX closure or native-entry contract.
