package plan9asm

import (
	"errors"
	"testing"
)

func TestDescribeInstructionDistinguishesOperandForms(t *testing.T) {
	reg := DescribeInstruction(ArchAMD64, "amd64", Instr{
		Op:   "XORB",
		Args: []Operand{{Kind: OpReg, Reg: SI}, {Kind: OpReg, Reg: AX}},
	})
	mem := DescribeInstruction(ArchAMD64, "amd64", Instr{
		Op:   "XORB",
		Args: []Operand{{Kind: OpReg, Reg: SI}, {Kind: OpMem, Mem: MemRef{Base: AX}}},
	})
	if reg.Form == mem.Form {
		t.Fatalf("register and memory forms collapsed to %q", reg.Form)
	}
	if mem.Family != "logical" {
		t.Fatalf("XORB family = %q, want logical", mem.Family)
	}
}

func TestInstructionFamiliesAreArchitectureAware(t *testing.T) {
	cases := []struct {
		arch Arch
		op   string
		want string
	}{
		{ArchAMD64, "PUSHQ", "stack"},
		{ArchAMD64, "PUNPCKLQDQ", "sse-mmx"},
		{ArchAMD64, "SHUFPS", "sse-mmx"},
		{ArchAMD64, "ORPS", "sse-mmx"},
		{ArchAMD64, "POPCNTQ", "bit-shift"},
		{ArchAMD64, "PREFETCHT0", "cache-memory"},
		{ArchAMD64, "VGF2P8AFFINEQB", "crypto-carryless"},
		{ArchAMD64, "PCALIGN", "directive"},
		{ArchAMD64, "PCALIGNMAX", "directive"},
		{ArchARM64, "VLD1", "neon"},
		{ArchARM64, "ZADD", "sve"},
		{ArchARM64, "CASAL", "atomic-memory"},
		{ArchARM64, "BIC", "logical"},
		{ArchARM64, "BEQ", "control-flow"},
		{ArchARM, "MRC", "system"},
		{ArchARM, "BIC", "logical"},
		{ArchWASM, "Get", "stack-local"},
		{ArchWASM, "CallIndirect", "control-flow"},
		{ArchWASM, "I64Load32U", "memory"},
		{ArchWASM, "F64Floor", "floating"},
		{ArchWASM, "I32Add", "integer"},
		{ArchWASM, "Unreachable", "system"},
		{ArchWASM, "Dispatch", "misc"},
	}
	for _, tc := range cases {
		if got := InstructionFamily(tc.arch, tc.op); got != tc.want {
			t.Errorf("InstructionFamily(%s, %s) = %q, want %q", tc.arch, tc.op, got, tc.want)
		}
	}
}

func TestInstructionFamiliesCoverArchitectureGroups(t *testing.T) {
	cases := []struct {
		arch Arch
		op   string
		want string
	}{
		{ArchAMD64, "JNE", "control-flow"},
		{ArchAMD64, "CMOVQEQ", "compare-conditional"},
		{ArchAMD64, "MOVQ", "move-convert"},
		{ArchAMD64, "LOCK", "atomic-memory"},
		{ArchAMD64, "AESENC", "crypto-aes"},
		{ArchAMD64, "SHA256RNDS2", "crypto-sha"},
		{ArchAMD64, "CRC32Q", "checksum"},
		{ArchAMD64, "MULXQ", "bmi-adx"},
		{ArchAMD64, "PDEPQ", "bmi-adx"},
		{ArchAMD64, "VADDPD", "avx"},
		{ArchAMD64, "FLD1", "x87-floating"},
		{ArchAMD64, "IMULQ", "multiply-divide"},
		{ArchAMD64, "ADDQ", "integer-arithmetic"},
		{ArchAMD64, "REP", "string"},
		{ArchAMD64, "CPUID", "system"},
		{ArchAMD64, "UNKNOWN", "misc"},
		{ArchARM64, "MOVD", "load-store-move"},
		{ArchARM64, "SHA256H", "crypto"},
		{ArchARM64, "FADDD", "floating"},
		{ArchARM64, "ADD", "integer-arithmetic"},
		{ArchARM64, "CSEL", "compare-conditional"},
		{ArchARM64, "RBIT", "bit-shift"},
		{ArchARM64, "MADD", "multiply-divide"},
		{ArchARM64, "DMB", "system"},
		{ArchARM64, "UNKNOWN", "misc"},
		{ArchARM, "SWP", "atomic-memory"},
		{ArchARM, "MOVW", "load-store-move"},
		{ArchARM, "ADD", "integer-arithmetic"},
		{ArchARM, "CMP", "compare-conditional"},
		{ArchARM, "SLL", "bit-shift"},
		{ArchARM, "MUL", "multiply-divide"},
		{ArchARM, "FADDD", "floating"},
		{ArchARM, "UNKNOWN", "misc"},
		{ArchAMD64, "TEXT", "directive"},
		{ArchAMD64, "MOVQ.P", "move-convert"},
		{Arch("unknown"), "MOVQ", "unknown"},
	}
	for _, tc := range cases {
		if got := InstructionFamily(tc.arch, tc.op); got != tc.want {
			t.Errorf("InstructionFamily(%s, %s) = %q, want %q", tc.arch, tc.op, got, tc.want)
		}
	}
}

func TestDescribeInstructionClassifiesOperands(t *testing.T) {
	cases := []struct {
		name   string
		arch   Arch
		goarch string
		op     Operand
		want   string
	}{
		{"immediate", ArchAMD64, "amd64", Operand{Kind: OpImm, Imm: 1}, "immediate"},
		{"symbolic immediate", ArchAMD64, "amd64", Operand{Kind: OpImm, ImmRaw: "$const"}, "symbolic-immediate"},
		{"extended register", ArchARM64, "arm64", Operand{Kind: OpRegExtend, Reg: "R1", Ext: ExtendUXTW}, "gpr.extend-uxtw"},
		{"left shift", ArchARM64, "arm64", Operand{Kind: OpRegShift, Reg: "R1", ShiftOp: ShiftLeft}, "gpr.shift-left-immediate"},
		{"right shift", ArchARM64, "arm64", Operand{Kind: OpRegShift, Reg: "R1", ShiftOp: ShiftRight, ShiftReg: "R2"}, "gpr.shift-right-register"},
		{"arithmetic shift", ArchARM64, "arm64", Operand{Kind: OpRegShift, Reg: "R1", ShiftOp: ShiftArith}, "gpr.shift-arithmetic-immediate"},
		{"rotate", ArchARM64, "arm64", Operand{Kind: OpRegShift, Reg: "R1", ShiftOp: ShiftRotate}, "gpr.shift-rotate-immediate"},
		{"unknown shift", ArchARM64, "arm64", Operand{Kind: OpRegShift, Reg: "R1", ShiftOp: "?"}, "gpr.shift-unknown-immediate"},
		{"fp slot", ArchAMD64, "amd64", Operand{Kind: OpFP}, "fp-slot"},
		{"fp address", ArchAMD64, "amd64", Operand{Kind: OpFPAddr}, "fp-address"},
		{"identifier", ArchARM64, "arm64", Operand{Kind: OpIdent}, "identifier"},
		{"symbol address", ArchAMD64, "amd64", Operand{Kind: OpSym, Sym: "$global(SB)(AX*1)"}, "address.memory.symbol.gpr64-index"},
		{"symbol", ArchAMD64, "amd64", Operand{Kind: OpSym, Sym: "global(SB)"}, "symbol"},
		{"label", ArchAMD64, "amd64", Operand{Kind: OpLabel}, "label"},
		{"memory parts", ArchAMD64, "amd64", Operand{Kind: OpMem, Mem: MemRef{Sym: "global(SB)", Base: AX, Index: "X1", Segment: FS, Off: 8}}, "memory.symbol.gpr64-base.xmm-index.segment.offset"},
		{"pc-relative memory", ArchARM64, "arm64", Operand{Kind: OpMem, Mem: MemRef{Base: PC, Off: 4}}, "memory.register-base.offset"},
		{"register list", ArchARM, "arm", Operand{Kind: OpRegList}, "register-list"},
		{"invalid", ArchAMD64, "amd64", Operand{}, "invalid"},
		{"xmm", ArchAMD64, "amd64", Operand{Kind: OpReg, Reg: "X1"}, "xmm"},
		{"ymm", ArchAMD64, "amd64", Operand{Kind: OpReg, Reg: "Y1"}, "ymm"},
		{"zmm", ArchAMD64, "amd64", Operand{Kind: OpReg, Reg: "Z1"}, "zmm"},
		{"mask", ArchAMD64, "amd64", Operand{Kind: OpReg, Reg: "K1"}, "mask-register"},
		{"mmx", ArchAMD64, "amd64", Operand{Kind: OpReg, Reg: "M1"}, "mmx"},
		{"x87", ArchAMD64, "amd64", Operand{Kind: OpReg, Reg: "F1"}, "x87"},
		{"byte", ArchAMD64, "amd64", Operand{Kind: OpReg, Reg: "AL"}, "gpr-byte"},
		{"segment", ArchAMD64, "amd64", Operand{Kind: OpReg, Reg: FS}, "segment-register"},
		{"amd64 stack", ArchAMD64, "amd64", Operand{Kind: OpReg, Reg: SP}, "stack-pointer"},
		{"386 gpr", ArchAMD64, "386", Operand{Kind: OpReg, Reg: AX}, "gpr32"},
		{"vector lane", ArchARM64, "arm64", Operand{Kind: OpReg, Reg: "V1.B[0]"}, "vector-lane"},
		{"vector", ArchARM64, "arm64", Operand{Kind: OpReg, Reg: "V1"}, "vector"},
		{"floating", ArchARM64, "arm64", Operand{Kind: OpReg, Reg: "F1"}, "floating-register"},
		{"sve vector", ArchARM64, "arm64", Operand{Kind: OpReg, Reg: "Z22.B"}, "scalable-vector"},
		{"sve predicate", ArchARM64, "arm64", Operand{Kind: OpReg, Reg: "P10.H"}, "predicate-register"},
		{"program counter", ArchARM64, "arm64", Operand{Kind: OpReg, Reg: PC}, "register"},
		{"arm stack", ArchARM64, "arm64", Operand{Kind: OpReg, Reg: SP}, "stack-pointer"},
		{"zero", ArchARM64, "arm64", Operand{Kind: OpReg, Reg: "ZR"}, "zero-register"},
		{"arm gpr", ArchARM64, "arm64", Operand{Kind: OpReg, Reg: "R12"}, "gpr"},
		{"generic", ArchARM64, "arm64", Operand{Kind: OpReg, Reg: "Rbad"}, "register"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := DescribeInstruction(tc.arch, tc.goarch, Instr{Op: "NOP", Args: []Operand{tc.op}})
			if len(got.Operands) != 1 || got.Operands[0] != tc.want {
				t.Fatalf("operands = %v, want [%s]", got.Operands, tc.want)
			}
		})
	}
}

func TestProbeInstructionChecksFormsThroughLowerer(t *testing.T) {
	cases := []Instr{
		{Op: "PUNPCKLQDQ", Raw: "PUNPCKLQDQ X0, X0", Args: []Operand{{Kind: OpReg, Reg: "X0"}, {Kind: OpReg, Reg: "X0"}}},
	}
	for _, ins := range cases {
		if err := ProbeInstruction(ArchAMD64, "amd64", ins); err != nil {
			t.Errorf("ProbeInstruction(%q) error = %v", ins.Raw, err)
		}
	}

	// An isolated memory RMW has neither a reaching address nor source bytes.
	// The same form must still lower when actual typed source supplies both.
	rmw := Instr{Op: "XORB", Raw: "XORB SI, (AX)", Args: []Operand{
		{Kind: OpReg, Reg: SI}, {Kind: OpMem, Mem: MemRef{Base: AX}},
	}}
	if err := ProbeInstruction(ArchAMD64, "amd64", rmw); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("unbound memory RMW probe error = %v, want ErrProbeNeedsContext", err)
	}
	const source = "TEXT ·probe(SB),4,$0-16\nMOVQ p+0(FP),AX\nMOVQ value+8(FP),SI\nXORB SI,(AX)\nRET\n"
	goAssemblerOracleOutput(t, "amd64", source, "", true)
	for _, api := range []string{"text", "module", "Go"} {
		ir, err := x86ScalarFPBitViewAPI(t, source, "func probe(p *byte,value uint64)",
			"amd64", "x86_64-unknown-linux-gnu", api)
		if err != nil || ir == "" {
			t.Errorf("%s: initialized memory RMW failed: %v", api, err)
		}
	}

	fp := Instr{Op: "MOVQ", Raw: "MOVQ x+0(FP), AX", Args: []Operand{{Kind: OpFP, FPName: "x"}, {Kind: OpReg, Reg: AX}}}
	if err := ProbeInstruction(ArchAMD64, "amd64", fp); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("FP probe error = %v, want ErrProbeNeedsContext", err)
	}

	cond := Instr{Op: "CSET", Raw: "CSET EQ, R1", Args: []Operand{{Kind: OpIdent, Ident: "EQ"}, {Kind: OpReg, Reg: "R1"}}}
	if err := ProbeInstruction(ArchARM64, "arm64", cond); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("conditional probe error = %v, want ErrProbeNeedsContext", err)
	}
}
