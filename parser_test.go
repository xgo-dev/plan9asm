package plan9asm

import (
	"errors"
	"math"
	"testing"
)

func TestParseBasic(t *testing.T) {
	src := `
// simple add
TEXT add(SB), NOSPLIT, $0-0
MOVQ a+0(FP), AX
ADDQ b+8(FP), AX
MOVQ AX, ret+16(FP)
RET
`
	file, err := Parse(ArchAMD64, src)
	if err != nil {
		t.Fatal(err)
	}
	if len(file.Funcs) != 1 {
		t.Fatalf("Funcs=%d, want 1", len(file.Funcs))
	}
	if file.Funcs[0].Sym != "add" {
		t.Fatalf("Sym=%q, want %q", file.Funcs[0].Sym, "add")
	}
	// TEXT + 3 ops + RET
	if len(file.Funcs[0].Instrs) != 5 {
		t.Fatalf("instrs=%d, want 5", len(file.Funcs[0].Instrs))
	}
}

func TestParseNormalizesLegacyZeroTextSymbolOffset(t *testing.T) {
	file, err := Parse(ArchAMD64, "TEXT ·Sqrtf+0(SB),NOSPLIT,$0-8\nRET\n")
	if err != nil {
		t.Fatal(err)
	}
	if got := file.Funcs[0].Sym; got != "·Sqrtf" {
		t.Fatalf("TEXT symbol = %q, want %q", got, "·Sqrtf")
	}
}

func TestParseDefineAndSemicolons(t *testing.T) {
	src := `
#define X BYTE $0x01; BYTE $0x02
TEXT ·Foo(SB),$0
X
RET
`
	file, err := Parse(ArchAMD64, src)
	if err != nil {
		t.Fatal(err)
	}
	if len(file.Funcs) != 1 {
		t.Fatalf("Funcs=%d, want 1", len(file.Funcs))
	}
	got := 0
	for _, ins := range file.Funcs[0].Instrs {
		if ins.Op == OpBYTE {
			got++
		}
	}
	if got != 2 {
		t.Fatalf("BYTE count=%d, want 2", got)
	}
}

func TestParseLegacyX86ColonOperand(t *testing.T) {
	src := `
TEXT ·shift(SB),NOSPLIT,$0
SHLL CX, R11:AX
SHLL $4, foo+4(SB):AX
RET
`
	file, err := Parse(ArchAMD64, src)
	if err != nil {
		t.Fatal(err)
	}
	first := file.Funcs[0].Instrs[1]
	if len(first.Args) != 3 || first.Args[1].Kind != OpReg || first.Args[1].Reg != AX || first.Args[2].Reg != Reg("R11") {
		t.Fatalf("SHLL register pair args = %#v", first.Args)
	}
	second := file.Funcs[0].Instrs[2]
	if len(second.Args) != 3 || second.Args[1].Kind != OpReg || second.Args[1].Reg != AX || second.Args[2].Kind != OpSym {
		t.Fatalf("SHLL symbol pair args = %#v", second.Args)
	}
}

func TestLegacyX86ColonOperandIsArchitectureAndOpcodeScoped(t *testing.T) {
	for _, tc := range []struct {
		arch Arch
		op   string
	}{
		{arch: ArchARM64, op: "SHLL"},
		{arch: ArchAMD64, op: "MOVL"},
	} {
		src := "TEXT ·f(SB),NOSPLIT,$0\n" + tc.op + " R1:R2\nRET\n"
		if _, err := Parse(tc.arch, src); err == nil {
			t.Fatalf("Parse(%s, %s with colon operand) unexpectedly succeeded", tc.arch, tc.op)
		}
	}
}

func TestParseX86ConditionalBranchRegisterNamedLabel(t *testing.T) {
	src := `
TEXT ·branch(SB),NOSPLIT,$0
JL V1
V1:
JMP AX
CALL AX
RET
`
	file, err := Parse(ArchAMD64, src)
	if err != nil {
		t.Fatal(err)
	}
	instrs := file.Funcs[0].Instrs
	if got := instrs[1].Args; len(got) != 1 || got[0].Kind != OpIdent || got[0].Ident != "V1" {
		t.Fatalf("JL target = %#v, want identifier V1", got)
	}
	if err := ProbeInstruction(ArchAMD64, "amd64", instrs[1]); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("ProbeInstruction(JL V1) error = %v, want ErrProbeNeedsContext", err)
	}
	for _, i := range []int{3, 4} {
		got := instrs[i].Args
		if len(got) != 1 || got[0].Kind != OpReg || got[0].Reg != AX {
			t.Fatalf("%s target = %#v, want register AX", instrs[i].Op, got)
		}
	}
}

func TestParseARMBranchRegisterNamedLabels(t *testing.T) {
	for _, tc := range []struct {
		name   string
		arch   Arch
		branch string
		label  string
	}{
		{name: "arm-conditional", arch: ArchARM, branch: "BEQ X7", label: "X7"},
		{name: "arm-unconditional", arch: ArchARM, branch: "B M1", label: "M1"},
		{name: "arm64-conditional", arch: ArchARM64, branch: "BEQ X7", label: "X7"},
		{name: "arm64-unconditional", arch: ArchARM64, branch: "B R7", label: "R7"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := "TEXT ·branch(SB),NOSPLIT,$0\n" + tc.branch + "\n" + tc.label + ":\nRET\n"
			file, err := Parse(tc.arch, src)
			if err != nil {
				t.Fatal(err)
			}
			got := file.Funcs[0].Instrs[1].Args
			if len(got) != 1 || got[0].Kind != OpIdent || got[0].Ident != tc.label {
				t.Fatalf("%s target = %#v, want identifier %s", tc.branch, got, tc.label)
			}
			if err := ProbeInstruction(tc.arch, map[Arch]string{ArchARM: "arm", ArchARM64: "arm64"}[tc.arch], file.Funcs[0].Instrs[1]); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("ProbeInstruction(%s) error = %v, want ErrProbeNeedsContext", tc.branch, err)
			}
		})
	}

	file, err := Parse(ArchARM, "TEXT ·indirect(SB),NOSPLIT,$0\nB (R11)\n")
	if err != nil {
		t.Fatal(err)
	}
	if got := file.Funcs[0].Instrs[1].Args; len(got) != 1 || got[0].Kind != OpMem || got[0].Mem.Base != Reg("R11") {
		t.Fatalf("B (R11) target = %#v, want memory base R11", got)
	}
}

func TestParseARM64BareRegisterCallRemainsIndirect(t *testing.T) {
	file, err := Parse(ArchARM64, "TEXT ·call(SB),NOSPLIT,$0\nBL R3\nRET\n")
	if err != nil {
		t.Fatal(err)
	}
	got := file.Funcs[0].Instrs[1].Args
	if len(got) != 1 || got[0].Kind != OpReg || got[0].Reg != "R3" {
		t.Fatalf("BL R3 target = %#v, want register operand", got)
	}
}

func TestParseImmediateExpr(t *testing.T) {
	src := `
TEXT ·ImmExpr(SB),NOSPLIT,$0
MOVQ $~(1<<63), DX
MOVQ $(1<<63), AX
RET
`
	file, err := Parse(ArchAMD64, src)
	if err != nil {
		t.Fatal(err)
	}
	if len(file.Funcs) != 1 {
		t.Fatalf("Funcs=%d, want 1", len(file.Funcs))
	}
	if len(file.Funcs[0].Instrs) < 3 {
		t.Fatalf("instrs=%d, want >=3", len(file.Funcs[0].Instrs))
	}
	immMask := file.Funcs[0].Instrs[1].Args[0].Imm
	if immMask != 0x7fffffffffffffff {
		t.Fatalf("mask imm=%#x, want %#x", uint64(immMask), uint64(0x7fffffffffffffff))
	}
	immSign := file.Funcs[0].Instrs[2].Args[0].Imm
	if immSign != int64(-9223372036854775808) {
		t.Fatalf("sign imm=%#x, want %#x", uint64(immSign), uint64(1<<63))
	}
}

func TestParseFloatImmediate(t *testing.T) {
	src := `
TEXT ·ImmFloat(SB),NOSPLIT,$0
MOVSD $1.5, X0
MOVSD $(-1.0), X1
RET
`
	file, err := Parse(ArchAMD64, src)
	if err != nil {
		t.Fatal(err)
	}
	if len(file.Funcs) != 1 || len(file.Funcs[0].Instrs) < 3 {
		t.Fatalf("unexpected parse shape: funcs=%d instrs=%d", len(file.Funcs), len(file.Funcs[0].Instrs))
	}
	got := uint64(file.Funcs[0].Instrs[1].Args[0].Imm)
	want := math.Float64bits(1.5)
	if got != want {
		t.Fatalf("float imm bits=%#x, want %#x", got, want)
	}
	gotNeg := uint64(file.Funcs[0].Instrs[2].Args[0].Imm)
	wantNeg := math.Float64bits(-1.0)
	if gotNeg != wantNeg {
		t.Fatalf("neg float imm bits=%#x, want %#x", gotNeg, wantNeg)
	}
}

func TestParseLegacyScaledOffsetMem(t *testing.T) {
	src := `
TEXT ·LegacyMem(SB),NOSPLIT,$0
MOVL (0*4)(BP), AX
MOVL (3*4)(SI), R8
RET
`
	file, err := Parse(ArchAMD64, src)
	if err != nil {
		t.Fatal(err)
	}
	if len(file.Funcs) != 1 {
		t.Fatalf("Funcs=%d, want 1", len(file.Funcs))
	}
	if len(file.Funcs[0].Instrs) < 3 {
		t.Fatalf("instrs=%d, want >=3", len(file.Funcs[0].Instrs))
	}

	mem0 := file.Funcs[0].Instrs[1].Args[0].Mem
	if mem0.Base != BP || mem0.Off != 0 {
		t.Fatalf("first mem=(base=%s,off=%d), want (BP,0)", mem0.Base, mem0.Off)
	}
	mem1 := file.Funcs[0].Instrs[2].Args[0].Mem
	if mem1.Base != SI || mem1.Off != 12 {
		t.Fatalf("second mem=(base=%s,off=%d), want (SI,12)", mem1.Base, mem1.Off)
	}
}

func TestParseArithmeticOffsetBeforeBaseRegister(t *testing.T) {
	file, err := Parse(ArchAMD64, `
TEXT arithmeticOffset(SB),NOSPLIT,$0-0
	ADDQ 0+(1*16)(BP), R10
	MOVQ (-64*1024+104)(SP), AX
	RET
`)
	if err != nil {
		t.Fatal(err)
	}
	first := file.Funcs[0].Instrs[1].Args[0]
	if first.Kind != OpMem || first.Mem.Base != BP || first.Mem.Off != 16 {
		t.Fatalf("first operand = %#v, want 16(BP)", first)
	}
	second := file.Funcs[0].Instrs[2].Args[0]
	if second.Kind != OpMem || second.Mem.Base != SP || second.Mem.Off != -65432 {
		t.Fatalf("second operand = %#v, want -65432(SP)", second)
	}
}

func TestParseX86TLSPseudoRegisterAndRelocationIndex(t *testing.T) {
	file, err := Parse(ArchAMD64, `
TEXT tlsforms(SB),NOSPLIT,$0-0
	MOVQ TLS, CX
	MOVQ 0(CX)(TLS*1), BX
	RET
`)
	if err != nil {
		t.Fatal(err)
	}
	loadBase := file.Funcs[0].Instrs[1].Args[0]
	if loadBase.Kind != OpReg || loadBase.Reg != Reg("TLS") {
		t.Fatalf("TLS source = %#v, want TLS pseudo-register", loadBase)
	}
	indexed := file.Funcs[0].Instrs[2].Args[0]
	if indexed.Kind != OpMem || indexed.Mem.Base != CX || indexed.Mem.Index != Reg("TLS") || indexed.Mem.Scale != 1 {
		t.Fatalf("TLS relocation memory = %#v, want 0(CX)(TLS*1)", indexed)
	}
}

func TestParseFunctionLikeMacroCall(t *testing.T) {
	src := `
#define ROUND1(a,b) MOVL a, b; ADDL $1, b
TEXT ·FnMacro(SB),NOSPLIT,$0
ROUND1(AX, BX);
RET
`
	file, err := Parse(ArchAMD64, src)
	if err != nil {
		t.Fatal(err)
	}
	if len(file.Funcs) != 1 {
		t.Fatalf("Funcs=%d, want 1", len(file.Funcs))
	}
	if len(file.Funcs[0].Instrs) < 4 {
		t.Fatalf("instrs=%d, want >=4", len(file.Funcs[0].Instrs))
	}
	if file.Funcs[0].Instrs[1].Op != OpMOVL {
		t.Fatalf("first expanded op=%s, want %s", file.Funcs[0].Instrs[1].Op, OpMOVL)
	}
	if file.Funcs[0].Instrs[2].Op != Op("ADDL") {
		t.Fatalf("second expanded op=%s, want %s", file.Funcs[0].Instrs[2].Op, Op("ADDL"))
	}
}

func TestParseZeroArgFunctionLikeMacroCall(t *testing.T) {
	src := `
#define CHECK() \
	CMP R1, R2 \
	BGT corrupt
TEXT ·FnMacro(SB),NOSPLIT,$0
CHECK()
corrupt:
RET
`
	file, err := Parse(ArchARM64, src)
	if err != nil {
		t.Fatal(err)
	}
	if len(file.Funcs) != 1 {
		t.Fatalf("Funcs=%d, want 1", len(file.Funcs))
	}
	var branchTarget string
	for _, ins := range file.Funcs[0].Instrs {
		if ins.Op == Op("BGT") && len(ins.Args) == 1 {
			branchTarget = ins.Args[0].Ident
		}
	}
	if branchTarget != "corrupt" {
		t.Fatalf("BGT target=%q, want %q", branchTarget, "corrupt")
	}
}
