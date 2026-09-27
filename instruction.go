package plan9asm

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// InstructionDescriptor is the stable identity used by coverage reports.
// Opcode-only coverage is insufficient: an opcode can accept one operand form
// while rejecting another valid Go assembly form.
type InstructionDescriptor struct {
	Arch     Arch     `json:"arch"`
	Goarch   string   `json:"goarch"`
	Family   string   `json:"family"`
	Opcode   string   `json:"opcode"`
	Operands []string `json:"operands"`
	Form     string   `json:"form"`
}

// DescribeInstruction classifies an instruction without claiming that its
// lowering is implemented. Use ProbeInstruction to check lowering support.
func DescribeInstruction(arch Arch, goarch string, ins Instr) InstructionDescriptor {
	op := normalizeInstructionOpcode(ins.Op)
	operands := make([]string, len(ins.Args))
	for i, arg := range ins.Args {
		operands[i] = operandClass(arch, goarch, arg)
	}
	return InstructionDescriptor{
		Arch:     arch,
		Goarch:   goarch,
		Family:   InstructionFamily(arch, op),
		Opcode:   op,
		Operands: operands,
		Form:     op + " " + strings.Join(operands, ","),
	}
}

func normalizeInstructionOpcode(op Op) string {
	s := strings.ToUpper(strings.TrimSpace(string(op)))
	if i := strings.IndexByte(s, '.'); i >= 0 {
		s = s[:i]
	}
	return s
}

// InstructionFamily groups opcodes by architectural function. The family is
// deliberately independent of current plan9asm support so unsupported forms
// remain visible in the same family as their supported peers.
func InstructionFamily(arch Arch, opcode string) string {
	op := strings.ToUpper(strings.TrimSpace(opcode))
	if i := strings.IndexByte(op, '.'); i >= 0 {
		op = op[:i]
	}
	if isInstructionDirective(op) {
		return "directive"
	}
	switch arch {
	case ArchAMD64:
		return x86InstructionFamily(op)
	case ArchARM64:
		return arm64InstructionFamily(op)
	case ArchARM:
		return armInstructionFamily(op)
	case ArchWASM:
		return wasmInstructionFamily(op)
	default:
		return "unknown"
	}
}

func wasmInstructionFamily(op string) string {
	switch {
	case op == "GET" || op == "SET" || op == "TEE" || op == "DROP" || op == "SELECT":
		return "stack-local"
	case op == "BLOCK" || op == "LOOP" || op == "IF" || op == "ELSE" || op == "END" || op == "BR" || op == "BRIF" || op == "WASMRETURN" || op == "WASMCALL" || op == "CALL" || op == "CALLNORESUME" || op == "CALLINDIRECT" || op == "RET" || op == "RETUNWIND" || op == "JMP":
		return "control-flow"
	case strings.Contains(op, "LOAD") || strings.Contains(op, "STORE") || strings.HasPrefix(op, "MEMORY") || op == "CURRENTMEMORY" || op == "GROWMEMORY":
		return "memory"
	case strings.HasPrefix(op, "F32") || strings.HasPrefix(op, "F64"):
		return "floating"
	case strings.HasPrefix(op, "I32") || strings.HasPrefix(op, "I64") || op == "NOT":
		return "integer"
	case op == "UNDEF" || op == "UNREACHABLE" || op == "NOP":
		return "system"
	default:
		return "misc"
	}
}

func x86InstructionFamily(op string) string {
	switch {
	case op == "CALL" || op == "RET" || op == "JMP" || strings.HasPrefix(op, "J") || strings.HasPrefix(op, "LOOP"):
		return "control-flow"
	case strings.HasPrefix(op, "CMOV") || strings.HasPrefix(op, "SET") || strings.HasPrefix(op, "CMP"):
		return "compare-conditional"
	case strings.HasPrefix(op, "MOV") || strings.HasPrefix(op, "LEA") || op == "XCHG" || op == "BSWAP":
		return "move-convert"
	case strings.HasPrefix(op, "PUSH") || (strings.HasPrefix(op, "POP") && !strings.HasPrefix(op, "POPCNT")) || op == "ENTER" || op == "LEAVE":
		return "stack"
	case strings.HasPrefix(op, "LOCK") || strings.Contains(op, "CMPXCHG") || strings.HasPrefix(op, "XADD") || strings.HasSuffix(op, "FENCE") || op == "PAUSE":
		return "atomic-memory"
	case strings.HasPrefix(op, "AES"):
		return "crypto-aes"
	case strings.HasPrefix(op, "SHA"):
		return "crypto-sha"
	case strings.Contains(op, "GF2P8") || strings.Contains(op, "CLMUL"):
		return "crypto-carryless"
	case strings.Contains(op, "CRC32"):
		return "checksum"
	case strings.HasPrefix(op, "ADCX") || strings.HasPrefix(op, "ADOX") || strings.HasPrefix(op, "MULX") || strings.HasPrefix(op, "RORX") || strings.HasPrefix(op, "SHLX") || strings.HasPrefix(op, "SHRX") || strings.HasPrefix(op, "SARX"):
		return "bmi-adx"
	case strings.HasPrefix(op, "PDEP") || strings.HasPrefix(op, "PEXT") || strings.HasPrefix(op, "BEXTR") || strings.HasPrefix(op, "BLS") || strings.HasPrefix(op, "BZHI"):
		return "bmi-adx"
	case strings.HasPrefix(op, "PREFETCH") || strings.HasPrefix(op, "CLFLUSH") || op == "CLWB" || op == "INVLPG" || op == "WBINVD":
		return "cache-memory"
	case strings.HasPrefix(op, "V") || strings.HasPrefix(op, "K"):
		return "avx"
	case strings.HasPrefix(op, "SHUF") || op == "ANDPS" || op == "ANDPD" || op == "ORPS" || op == "ORPD" || op == "XORPS" || op == "XORPD":
		return "sse-mmx"
	case strings.HasPrefix(op, "SH") || strings.HasPrefix(op, "SA") || strings.HasPrefix(op, "RO") || strings.HasPrefix(op, "BT") || strings.HasPrefix(op, "BS") || strings.HasPrefix(op, "LZCNT") || strings.HasPrefix(op, "TZCNT") || strings.HasPrefix(op, "POPCNT"):
		return "bit-shift"
	case strings.HasPrefix(op, "P") || strings.HasPrefix(op, "MASKMOV") || strings.HasPrefix(op, "UNPCK"):
		return "sse-mmx"
	case strings.HasPrefix(op, "F"):
		return "x87-floating"
	case strings.HasPrefix(op, "MUL") || strings.HasPrefix(op, "IMUL") || strings.HasPrefix(op, "DIV") || strings.HasPrefix(op, "IDIV"):
		return "multiply-divide"
	case strings.HasPrefix(op, "ADD") || strings.HasPrefix(op, "ADC") || strings.HasPrefix(op, "SUB") || strings.HasPrefix(op, "SBB") || strings.HasPrefix(op, "INC") || strings.HasPrefix(op, "DEC") || strings.HasPrefix(op, "NEG"):
		return "integer-arithmetic"
	case strings.HasPrefix(op, "AND") || strings.HasPrefix(op, "OR") || strings.HasPrefix(op, "XOR") || strings.HasPrefix(op, "NOT") || strings.HasPrefix(op, "TEST"):
		return "logical"
	case strings.HasPrefix(op, "REP") || strings.HasPrefix(op, "SCAS") || strings.HasPrefix(op, "STOS") || strings.HasPrefix(op, "LODS") || strings.HasPrefix(op, "CMPS"):
		return "string"
	case op == "CPUID" || op == "XGETBV" || strings.HasPrefix(op, "RD") || strings.HasPrefix(op, "WR") || op == "SYSCALL" || op == "SYSENTER" || op == "HLT":
		return "system"
	default:
		return "misc"
	}
}

func arm64InstructionFamily(op string) string {
	switch {
	case isARM64BranchOpcode(op):
		return "control-flow"
	case strings.HasPrefix(op, "CAS") || strings.HasPrefix(op, "SWP") || strings.Contains(op, "XR") || strings.Contains(op, "XP"):
		return "atomic-memory"
	case strings.HasPrefix(op, "LD") || strings.HasPrefix(op, "ST") || strings.HasPrefix(op, "MOV"):
		return "load-store-move"
	case strings.HasPrefix(op, "AES") || strings.HasPrefix(op, "SHA"):
		return "crypto"
	case strings.HasPrefix(op, "V"):
		return "neon"
	case strings.HasPrefix(op, "Z") || (strings.HasPrefix(op, "P") && !strings.HasPrefix(op, "PAC") && !strings.HasPrefix(op, "PRF")):
		return "sve"
	case strings.HasPrefix(op, "F"):
		return "floating"
	case strings.HasPrefix(op, "ADD") || strings.HasPrefix(op, "ADC") || strings.HasPrefix(op, "SUB") || strings.HasPrefix(op, "SBC") || strings.HasPrefix(op, "NEG"):
		return "integer-arithmetic"
	case strings.HasPrefix(op, "AND") || strings.HasPrefix(op, "ORR") || strings.HasPrefix(op, "EOR") || strings.HasPrefix(op, "BIC"):
		return "logical"
	case strings.HasPrefix(op, "CMP") || strings.HasPrefix(op, "CMN") || strings.HasPrefix(op, "CCM") || strings.HasPrefix(op, "CSEL") || strings.HasPrefix(op, "CSET") || strings.HasPrefix(op, "CINC") || strings.HasPrefix(op, "CNEG"):
		return "compare-conditional"
	case strings.HasPrefix(op, "LS") || strings.HasPrefix(op, "ASR") || strings.HasPrefix(op, "ROR") || strings.HasPrefix(op, "RBIT") || strings.HasPrefix(op, "REV") || strings.HasPrefix(op, "CL") || strings.HasPrefix(op, "BF") || strings.HasPrefix(op, "EXTR"):
		return "bit-shift"
	case strings.HasPrefix(op, "MUL") || strings.HasPrefix(op, "MADD") || strings.HasPrefix(op, "MSUB") || strings.HasPrefix(op, "DIV"):
		return "multiply-divide"
	case op == "MRS" || op == "MSR" || op == "DMB" || op == "DSB" || op == "ISB" || op == "SVC":
		return "system"
	default:
		return "misc"
	}
}

func armInstructionFamily(op string) string {
	switch {
	case isARMBranchOpcode(op):
		return "control-flow"
	case strings.HasPrefix(op, "SWP"):
		return "atomic-memory"
	case strings.HasPrefix(op, "MOV") || strings.HasPrefix(op, "LD") || strings.HasPrefix(op, "ST"):
		return "load-store-move"
	case strings.HasPrefix(op, "ADD") || strings.HasPrefix(op, "ADC") || strings.HasPrefix(op, "SUB") || strings.HasPrefix(op, "SBC") || strings.HasPrefix(op, "RSB"):
		return "integer-arithmetic"
	case strings.HasPrefix(op, "AND") || strings.HasPrefix(op, "ORR") || strings.HasPrefix(op, "EOR") || strings.HasPrefix(op, "BIC"):
		return "logical"
	case strings.HasPrefix(op, "CMP") || strings.HasPrefix(op, "CMN") || strings.HasPrefix(op, "TST") || strings.HasPrefix(op, "TEQ"):
		return "compare-conditional"
	case strings.HasPrefix(op, "SLL") || strings.HasPrefix(op, "SRL") || strings.HasPrefix(op, "SRA") || strings.HasPrefix(op, "ROR"):
		return "bit-shift"
	case strings.HasPrefix(op, "MUL") || strings.HasPrefix(op, "DIV"):
		return "multiply-divide"
	case strings.HasPrefix(op, "F"):
		return "floating"
	case op == "MRC" || op == "MCR" || op == "SWI" || op == "UNDEF":
		return "system"
	default:
		return "misc"
	}
}

func isARM64BranchOpcode(op string) bool {
	switch op {
	case "B", "BL", "BR", "BLR", "RET", "ERET":
		return true
	}
	if strings.HasPrefix(op, "B.") || strings.HasPrefix(op, "CB") || strings.HasPrefix(op, "TB") {
		return true
	}
	if len(op) == 3 && op[0] == 'B' {
		switch op[1:] {
		case "CC", "CS", "EQ", "GE", "GT", "HI", "HS", "LE", "LO", "LS", "LT", "MI", "NE", "PL", "VC", "VS":
			return true
		}
	}
	return false
}

func isARMBranchOpcode(op string) bool {
	switch op {
	case "B", "BL", "BX", "BLX", "RET":
		return true
	}
	if len(op) == 3 && op[0] == 'B' {
		switch op[1:] {
		case "CC", "CS", "EQ", "GE", "GT", "HI", "HS", "LE", "LO", "LS", "LT", "MI", "NE", "PL", "VC", "VS":
			return true
		}
	}
	return false
}

func isInstructionDirective(op string) bool {
	switch op {
	case "TEXT", "DATA", "GLOBL", "BYTE", "WORD", "LONG", "QUAD", "PCALIGN", "FUNCDATA", "PCDATA":
		return true
	default:
		return false
	}
}

func operandClass(arch Arch, goarch string, op Operand) string {
	switch op.Kind {
	case OpImm:
		if op.ImmRaw != "" {
			return "symbolic-immediate"
		}
		return "immediate"
	case OpReg:
		return registerClass(arch, goarch, op.Reg)
	case OpRegExtend:
		return registerClass(arch, goarch, op.Reg) + ".extend-" + strings.ToLower(string(op.Ext))
	case OpRegShift:
		amount := "immediate"
		if op.ShiftReg != "" {
			amount = "register"
		}
		return registerClass(arch, goarch, op.Reg) + ".shift-" + shiftClass(op.ShiftOp) + "-" + amount
	case OpFP:
		return "fp-slot"
	case OpFPAddr:
		return "fp-address"
	case OpIdent:
		return "identifier"
	case OpSym:
		s := strings.TrimSpace(op.Sym)
		if strings.HasPrefix(s, "$") {
			if mem, ok := parseMem(strings.TrimSpace(strings.TrimPrefix(s, "$"))); ok {
				return "address." + memoryClass(arch, goarch, mem)
			}
		}
		return "symbol"
	case OpLabel:
		return "label"
	case OpMem:
		return memoryClass(arch, goarch, op.Mem)
	case OpRegList:
		return "register-list"
	default:
		return "invalid"
	}
}

func registerClass(arch Arch, goarch string, reg Reg) string {
	r := strings.ToUpper(string(reg))
	if arch == ArchAMD64 {
		switch {
		case strings.HasPrefix(r, "X"):
			return "xmm"
		case strings.HasPrefix(r, "Y"):
			return "ymm"
		case strings.HasPrefix(r, "Z"):
			return "zmm"
		case strings.HasPrefix(r, "K"):
			return "mask-register"
		case strings.HasPrefix(r, "M"):
			return "mmx"
		case r == "FS" || r == "GS":
			return "segment-register"
		case strings.HasPrefix(r, "F"):
			return "x87"
		case r == "AL" || r == "AH" || r == "BL" || r == "BH" || r == "CL" || r == "CH" || r == "DL" || r == "DH":
			return "gpr-byte"
		case r == "SP":
			return "stack-pointer"
		default:
			if goarch == "386" {
				return "gpr32"
			}
			return "gpr64"
		}
	}
	if arch == ArchARM64 {
		if r == "ZR" {
			return "zero-register"
		}
		if r == "RSP" {
			return "stack-pointer"
		}
		if prefix, index, _, ok := regRangeParts(Reg(r)); ok {
			switch {
			case prefix == "Z" && index <= 31:
				return "scalable-vector"
			case prefix == "P" && index <= 15:
				return "predicate-register"
			}
		}
	}
	if strings.HasPrefix(r, "V") {
		if strings.Contains(r, "[") {
			return "vector-lane"
		}
		return "vector"
	}
	if strings.HasPrefix(r, "F") {
		return "floating-register"
	}
	if r == "SP" {
		return "stack-pointer"
	}
	if strings.HasPrefix(r, "R") {
		if _, err := strconv.Atoi(strings.TrimPrefix(r, "R")); err == nil {
			return "gpr"
		}
	}
	return "register"
}

func memoryClass(arch Arch, goarch string, mem MemRef) string {
	parts := []string{"memory"}
	if mem.Sym != "" {
		parts = append(parts, "symbol")
	}
	if mem.Base != "" {
		parts = append(parts, registerClass(arch, goarch, mem.Base)+"-base")
	}
	if mem.Index != "" {
		indexClass := registerClass(arch, goarch, mem.Index) + "-index"
		if mem.IndexExt != "" {
			indexClass += "-" + strings.ToLower(string(mem.IndexExt))
		}
		parts = append(parts, indexClass)
	}
	if mem.Segment != "" {
		parts = append(parts, "segment")
	}
	if mem.Off != 0 {
		parts = append(parts, "offset")
	}
	return strings.Join(parts, ".")
}

func shiftClass(op ShiftOp) string {
	switch op {
	case ShiftLeft:
		return "left"
	case ShiftRight:
		return "right"
	case ShiftArith:
		return "arithmetic"
	case ShiftRotate:
		return "rotate"
	default:
		return "unknown"
	}
}

// ErrProbeNeedsContext means an instruction cannot be judged in isolation.
// The full-file corpus compiler remains authoritative for these forms.
var ErrProbeNeedsContext = errors.New("instruction probe needs function context")

// ProbeInstruction runs one instruction through the real lowering pipeline.
// It is intended for coverage tooling; executable conformance tests are still
// required before a form is considered semantically verified.
func ProbeInstruction(arch Arch, goarch string, ins Instr) error {
	if arch == ArchWASM {
		// WebAssembly instructions share a typed operand stack, structured
		// control stack, physical function signature, and (for Go code) the
		// linear-memory SP/PC_B state. An isolated instruction cannot prove a
		// form valid or invalid. The corpus gate therefore compiles every full
		// wasm assembly file after treating per-instruction probes as contextual.
		return fmt.Errorf("%w: wasm instructions require their full function", ErrProbeNeedsContext)
	}
	if strings.HasPrefix(normalizeInstructionOpcode(ins.Op), "REP") {
		return fmt.Errorf("%w: REP prefix must be probed with its following instruction", ErrProbeNeedsContext)
	}
	if arch == ArchAMD64 && goarch == "386" && normalizeInstructionOpcode(ins.Op) == "JMP" &&
		len(ins.Args) == 1 && ins.Args[0].Kind == OpImm && ins.Args[0].ImmRaw == "" {
		return fmt.Errorf("%w: %s uses the 386 assembler's legacy numeric branch relocation and requires final text layout", ErrProbeNeedsContext, ins.Raw)
	}
	if arch == ArchARM && normalizeInstructionOpcode(ins.Op) == "RFE" {
		return fmt.Errorf("%w: %s returns through privileged exception state", ErrProbeNeedsContext, ins.Raw)
	}
	if arch == ArchARM64 {
		op := normalizeInstructionOpcode(ins.Op)
		if op == "ADR" || op == "ADRP" {
			return fmt.Errorf("%w: %s requires the final function-local label layout", ErrProbeNeedsContext, ins.Raw)
		}
		switch op {
		case "TLBI", "SYS", "SYSL", "DCPS1", "DCPS2", "DCPS3", "DRPS", "ERET", "HLT", "HVC", "SMC":
			return fmt.Errorf("%w: %s depends on privileged ARM64 execution state", ErrProbeNeedsContext, ins.Raw)
		}
	}
	for _, arg := range ins.Args {
		switch arg.Kind {
		case OpFP, OpFPAddr:
			return fmt.Errorf("%w: %s uses an FP frame slot", ErrProbeNeedsContext, ins.Raw)
		case OpImm:
			if arg.ImmRaw != "" {
				return fmt.Errorf("%w: %s uses a symbolic immediate", ErrProbeNeedsContext, ins.Raw)
			}
		case OpMem:
			if arg.Mem.Base == PC {
				return fmt.Errorf("%w: %s uses a PC-relative target", ErrProbeNeedsContext, ins.Raw)
			}
			if arch == ArchARM && armMemoryOffsetNeedsContext(arg.Mem) ||
				arch == ArchARM64 && arm64MemoryOffsetNeedsContext(arg.Mem) {
				return fmt.Errorf("%w: %s uses an unresolved memory-offset macro", ErrProbeNeedsContext, ins.Raw)
			}
		case OpIdent:
			if InstructionFamily(arch, string(ins.Op)) == "control-flow" {
				return fmt.Errorf("%w: %s uses a function-local target", ErrProbeNeedsContext, ins.Raw)
			}
		}
	}

	err := probeInstructionSequence(arch, goarch, []Instr{ins})
	if arch == ArchARM && ins.Op == OpWORD && err != nil {
		return fmt.Errorf("%w: %s requires surrounding instruction, register, and control-flow state: %v", ErrProbeNeedsContext, ins.Raw, err)
	}
	return err
}

// ProbeInstructionSequence runs a self-contained instruction sequence through
// the real lowering pipeline. Coverage scanners use this for forms whose
// meaning spans source directives, such as consecutive x86 BYTE/WORD/LONG/QUAD
// directives that encode one or more machine instructions.
func ProbeInstructionSequence(arch Arch, goarch string, instrs []Instr) error {
	if len(instrs) == 0 {
		return fmt.Errorf("empty instruction probe sequence")
	}
	if arch == ArchWASM {
		return fmt.Errorf("%w: wasm instructions require their full function", ErrProbeNeedsContext)
	}
	return probeInstructionSequence(arch, goarch, instrs)
}

func probeInstructionSequence(arch Arch, goarch string, instrs []Instr) error {
	fn := Func{Sym: "plan9asm.probe", Instrs: append([]Instr(nil), instrs...)}
	labels := map[string]struct{}{}
	definedLabels := map[string]struct{}{}
	sigs := map[string]FuncSig{
		fn.Sym: {Name: fn.Sym, Ret: Void},
	}
	for _, ins := range instrs {
		for _, arg := range ins.Args {
			if arg.Kind == OpLabel {
				labels[arg.Sym] = struct{}{}
				if ins.Op == OpLABEL {
					definedLabels[arg.Sym] = struct{}{}
				}
			}
			if arg.Kind == OpSym && (ins.Op == OpCALL || ins.Op == OpJMP || normalizeInstructionOpcode(ins.Op) == "CALLNORESUME") {
				name := strings.TrimSuffix(arg.Sym, "(SB)")
				sigs[name] = FuncSig{Name: name, Ret: Void}
			}
		}
	}
	for label := range labels {
		if _, ok := definedLabels[label]; ok {
			continue
		}
		fn.Instrs = append(fn.Instrs, Instr{Op: OpLABEL, Args: []Operand{{Kind: OpLabel, Sym: label}}, Raw: label + ":"})
	}
	fn.Instrs = append(fn.Instrs, Instr{Op: OpRET, Raw: "RET"})
	file := &File{Arch: arch, Funcs: []Func{fn}}
	triple := ""
	switch goarch {
	case "386":
		triple = "i386-unknown-linux-gnu"
	case "amd64":
		triple = "x86_64-unknown-linux-gnu"
	case "arm":
		triple = "armv7-unknown-linux-gnueabihf"
	case "arm64":
		triple = "aarch64-unknown-linux-gnu"
	}
	wasmABI := WASMABIDirect
	if arch == ArchWASM {
		wasmABI = WASMABIGo
	}
	_, err := translateIRText(file, Options{Goarch: goarch, TargetTriple: triple, Sigs: sigs, WASMABI: wasmABI})
	return err
}
