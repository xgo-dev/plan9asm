package asm

import (
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
	op := NormalizeInstructionOpcode(ins.Op)
	operands := make([]string, len(ins.Args))
	for i, arg := range ins.Args {
		operands[i] = OperandClass(arch, goarch, arg)
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

func NormalizeInstructionOpcode(op Op) string {
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
	case strings.HasPrefix(op, "LD") || strings.HasPrefix(op, "ST") || strings.HasPrefix(op, "MOV"):
		return "load-store-move"
	case strings.HasPrefix(op, "CAS") || strings.HasPrefix(op, "SWP") || strings.Contains(op, "XR"):
		return "atomic-memory"
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

func OperandClass(arch Arch, goarch string, op Operand) string {
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
			if mem, ok := ParseMem(strings.TrimSpace(strings.TrimPrefix(s, "$"))); ok {
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
		if prefix, index, _, ok := RegRangeParts(Reg(r)); ok {
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
	if r == "SP" || r == "RSP" {
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

// ProbeInstructionWith runs one instruction through the provided lowering pipeline.
// It is intended for coverage tooling; executable conformance tests are still
// required before a form is considered semantically verified.
func ProbeInstructionWith(arch Arch, goarch string, ins Instr, translateFn func(*File, Options) (string, error)) error {
	if arch == ArchWASM {
		return probeWASMInstructionWith(ins, translateFn)
	}
	if strings.HasPrefix(NormalizeInstructionOpcode(ins.Op), "REP") {
		return fmt.Errorf("%w: REP prefix must be probed with its following instruction", ErrProbeNeedsContext)
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
		case OpIdent:
			if InstructionFamily(arch, string(ins.Op)) == "control-flow" {
				return fmt.Errorf("%w: %s uses a function-local target", ErrProbeNeedsContext, ins.Raw)
			}
		}
	}

	fn := Func{Sym: "plan9asm.probe", Instrs: []Instr{ins}}
	labels := map[string]struct{}{}
	sigs := map[string]FuncSig{
		fn.Sym: {Name: fn.Sym, Ret: Void},
	}
	for _, arg := range ins.Args {
		if arg.Kind == OpLabel {
			labels[arg.Sym] = struct{}{}
		}
		if arg.Kind == OpSym && (ins.Op == OpCALL || ins.Op == OpJMP || NormalizeInstructionOpcode(ins.Op) == "CALLNORESUME") {
			name := strings.TrimSuffix(arg.Sym, "(SB)")
			sigs[name] = FuncSig{Name: name, Ret: Void}
		}
	}
	for label := range labels {
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
	_, err := translateFn(file, Options{Goarch: goarch, TargetTriple: triple, Sigs: sigs, WASMABI: wasmABI})
	return err
}

// probeWASMInstructionWith actually invokes the real WebAssembly lowerer instead
// of unconditionally classifying all wasm instructions as context-required.
// Structured control flow and frame/ABI-dependent instructions still return
// ErrProbeNeedsContext, while stack instructions are probed with typed dummy
// stack seeds so unsupported ops (e.g. MemoryInit, DataDrop, Table*) are
// reported honestly as unsupported.
func probeWASMInstructionWith(ins Instr, translateFn func(*File, Options) (string, error)) error {
	op := NormalizeInstructionOpcode(ins.Op)
	// Structured control flow and call/frame-context ops require their enclosing function.
	switch op {
	case "BLOCK", "LOOP", "IF", "ELSE", "END", "BR", "BRIF", "BRTABLE",
		"CALL", "CALLINDIRECT", "CALLNORESUME", "WASMCALL", "JMP",
		"RET", "RETURN", "WASMRETURN", "RETUNWIND":
		return fmt.Errorf("%w: wasm control-flow instruction %s requires enclosing function context", ErrProbeNeedsContext, ins.Op)
	}
	for _, arg := range ins.Args {
		switch arg.Kind {
		case OpFP, OpFPAddr:
			return fmt.Errorf("%w: %s uses an FP frame slot", ErrProbeNeedsContext, ins.Raw)
		case OpMem:
			if arg.Mem.OffRaw != "" {
				return fmt.Errorf("%w: %s uses a symbolic memory offset", ErrProbeNeedsContext, ins.Raw)
			}
		case OpImm:
			if arg.ImmRaw != "" {
				return fmt.Errorf("%w: %s uses a symbolic immediate", ErrProbeNeedsContext, ins.Raw)
			}
		}
	}

	// Build typed operand stack seeds matching the instruction's stack signature.
	seedInstrs, dropCount := wasmProbeStackSeeds(op, ins)
	instrs := make([]Instr, 0, len(seedInstrs)+2+dropCount)
	instrs = append(instrs, seedInstrs...)
	instrs = append(instrs, ins)
	for i := 0; i < dropCount; i++ {
		instrs = append(instrs, Instr{Op: "Drop", Raw: "Drop"})
	}
	instrs = append(instrs,
		Instr{Op: "I32Const", Args: []Operand{{Kind: OpImm, Imm: 0}}, Raw: "I32Const $0"},
		Instr{Op: "Return", Raw: "Return"},
	)

	fn := Func{Sym: "plan9asm.probe", Instrs: instrs}
	sigs := map[string]FuncSig{
		fn.Sym: {Name: fn.Sym, Ret: Void},
	}
	file := &File{Arch: ArchWASM, Funcs: []Func{fn}}
	_, err := translateFn(file, Options{
		Goarch:       "wasm",
		TargetTriple: "wasm32-unknown-unknown",
		Sigs:         sigs,
		WASMABI:      WASMABIGo,
	})
	return err
}

func wasmProbeStackSeeds(op string, ins Instr) (seeds []Instr, drops int) {
	i32Seed := Instr{Op: "I32Const", Args: []Operand{{Kind: OpImm, Imm: 1}}, Raw: "I32Const $1"}
	i64Seed := Instr{Op: "I64Const", Args: []Operand{{Kind: OpImm, Imm: 1}}, Raw: "I64Const $1"}
	f32Seed := Instr{Op: "F32Const", Args: []Operand{{Kind: OpImm, Imm: 0x3f800000}}, Raw: "F32Const $1065353216"}
	f64Seed := Instr{Op: "F64Const", Args: []Operand{{Kind: OpImm, Imm: 0x3ff0000000000000}}, Raw: "F64Const $4607182418800017408"}
	v128Seed := Instr{Op: "V128Const", Args: []Operand{{Kind: OpImm, Imm: 0}, {Kind: OpImm, Imm: 0}}, Raw: "V128Const $0, $0"}

	switch op {
	case "NOP", "UNREACHABLE", "DATADROP", "ELEMDROP", "RESUMEPOINT", "WORD", "MOVB", "MOVH", "MOVW", "MOVD":
		return nil, 0
	case "DROP":
		return []Instr{i64Seed}, 0
	case "SELECT":
		return []Instr{i64Seed, i64Seed, i32Seed}, 1
	case "NOT":
		return []Instr{i32Seed}, 1
	case "I32CONST", "I64CONST", "F32CONST", "F64CONST", "V128CONST",
		"GET", "LOCALGET", "GLOBALGET", "CURRENTMEMORY", "MEMORYSIZE", "TABLESIZE":
		return nil, 1
	case "SET", "LOCALSET", "GLOBALSET":
		return []Instr{i64Seed}, 0
	case "TEE", "LOCALTEE":
		return []Instr{i64Seed}, 1
	case "GROWMEMORY", "MEMORYGROW":
		return []Instr{i32Seed}, 1
	case "MEMORYCOPY", "MEMORYFILL", "MEMORYINIT", "TABLEINIT", "TABLECOPY", "TABLEFILL":
		return []Instr{i32Seed, i32Seed, i32Seed}, 0
	case "TABLEGROW":
		return []Instr{i32Seed, i32Seed}, 1
	case "V128BITSELECT":
		return []Instr{v128Seed, v128Seed, v128Seed}, 1
	case "V128NOT", "V128ANYTRUE":
		return []Instr{v128Seed}, 1
	case "V128AND", "V128ANDNOT", "V128OR", "V128XOR":
		return []Instr{v128Seed, v128Seed}, 1
	case "V128STORE":
		return []Instr{i32Seed, v128Seed}, 0
	case "V128LOAD8LANE", "V128LOAD16LANE", "V128LOAD32LANE", "V128LOAD64LANE":
		return []Instr{i32Seed, v128Seed}, 1
	case "V128STORE8LANE", "V128STORE16LANE", "V128STORE32LANE", "V128STORE64LANE":
		return []Instr{i32Seed, v128Seed}, 0
	}
	if strings.HasPrefix(op, "V128LOAD") {
		return []Instr{i32Seed}, 1
	}
	// Scalar loads/stores
	if strings.Contains(op, "LOAD") && !strings.HasPrefix(op, "V128") {
		return []Instr{i32Seed}, 1
	}
	if strings.Contains(op, "STORE") && !strings.HasPrefix(op, "V128") {
		val := i32Seed
		switch {
		case strings.HasPrefix(op, "I64"):
			val = i64Seed
		case strings.HasPrefix(op, "F32"):
			val = f32Seed
		case strings.HasPrefix(op, "F64"):
			val = f64Seed
		}
		return []Instr{i32Seed, val}, 0
	}
	// SIMD128 lane/vector ops
	if strings.HasPrefix(op, "I8X16") || strings.HasPrefix(op, "I16X8") ||
		strings.HasPrefix(op, "I32X4") || strings.HasPrefix(op, "I64X2") ||
		strings.HasPrefix(op, "F32X4") || strings.HasPrefix(op, "F64X2") {
		suffix := op[5:]
		elemSeed := i32Seed
		switch {
		case strings.HasPrefix(op, "I64X2"):
			elemSeed = i64Seed
		case strings.HasPrefix(op, "F32X4"):
			elemSeed = f32Seed
		case strings.HasPrefix(op, "F64X2"):
			elemSeed = f64Seed
		}
		switch {
		case suffix == "SPLAT":
			return []Instr{elemSeed}, 1
		case suffix == "REPLACELANE":
			return []Instr{v128Seed, elemSeed}, 1
		case suffix == "SHL" || suffix == "SHRS" || suffix == "SHRU":
			return []Instr{v128Seed, i32Seed}, 1
		case suffix == "RELAXEDMADD" || suffix == "RELAXEDNMADD" ||
			suffix == "RELAXEDLANESELECT" || suffix == "RELAXEDDOTI8X16I7X16ADDS":
			return []Instr{v128Seed, v128Seed, v128Seed}, 1
		case strings.HasPrefix(suffix, "EXTRACTLANE") ||
			suffix == "ALLTRUE" || suffix == "BITMASK" ||
			suffix == "ABS" || suffix == "NEG" || suffix == "POPCNT" ||
			suffix == "SQRT" || suffix == "CEIL" || suffix == "FLOOR" ||
			suffix == "TRUNC" || suffix == "NEAREST" ||
			strings.HasPrefix(suffix, "EXTEND") ||
			strings.HasPrefix(suffix, "EXTADDPAIRWISE") ||
			strings.HasPrefix(suffix, "CONVERT") ||
			strings.HasPrefix(suffix, "DEMOTE") ||
			strings.HasPrefix(suffix, "PROMOTE") ||
			strings.HasPrefix(suffix, "TRUNCSAT") ||
			strings.HasPrefix(suffix, "RELAXEDTRUNC"):
			return []Instr{v128Seed}, 1
		default:
			return []Instr{v128Seed, v128Seed}, 1
		}
	}
	// Scalar unary/conversion/reinterpret/extend ops
	switch {
	case strings.HasSuffix(op, "EQZ") || strings.HasSuffix(op, "CLZ") ||
		strings.HasSuffix(op, "CTZ") || strings.HasSuffix(op, "POPCNT") ||
		strings.HasSuffix(op, "ABS") || strings.HasSuffix(op, "NEG") ||
		strings.HasSuffix(op, "CEIL") || strings.HasSuffix(op, "FLOOR") ||
		strings.HasSuffix(op, "TRUNC") || strings.HasSuffix(op, "NEAREST") ||
		strings.HasSuffix(op, "SQRT") || strings.Contains(op, "EXTEND8") ||
		strings.Contains(op, "EXTEND16") || strings.Contains(op, "EXTEND32"):
		switch {
		case strings.HasPrefix(op, "I64"):
			return []Instr{i64Seed}, 1
		case strings.HasPrefix(op, "F32"):
			return []Instr{f32Seed}, 1
		case strings.HasPrefix(op, "F64"):
			return []Instr{f64Seed}, 1
		default:
			return []Instr{i32Seed}, 1
		}
	case op == "I32WRAPI64":
		return []Instr{i64Seed}, 1
	case strings.HasPrefix(op, "I64EXTENDI32"):
		return []Instr{i32Seed}, 1
	case strings.Contains(op, "TRUNCF32") || strings.Contains(op, "TRUNCSATF32") ||
		op == "I32REINTERPRETF32" || op == "F64PROMOTEF32":
		return []Instr{f32Seed}, 1
	case strings.Contains(op, "TRUNCF64") || strings.Contains(op, "TRUNCSATF64") ||
		op == "I64REINTERPRETF64" || op == "F32DEMOTEF64":
		return []Instr{f64Seed}, 1
	case strings.Contains(op, "CONVERTI32") || op == "F32REINTERPRETI32":
		return []Instr{i32Seed}, 1
	case strings.Contains(op, "CONVERTI64") || op == "F64REINTERPRETI64":
		return []Instr{i64Seed}, 1
	}
	// Remaining scalar binary ops
	switch {
	case strings.HasPrefix(op, "I64"):
		return []Instr{i64Seed, i64Seed}, 1
	case strings.HasPrefix(op, "F32"):
		return []Instr{f32Seed, f32Seed}, 1
	case strings.HasPrefix(op, "F64"):
		return []Instr{f64Seed, f64Seed}, 1
	default:
		return []Instr{i32Seed, i32Seed}, 1
	}
}
