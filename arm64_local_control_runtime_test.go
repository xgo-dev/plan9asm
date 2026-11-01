package plan9asm

import (
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
)

func TestCrossLinuxRuntimeMatrixARM64LocalControlConformance(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	type fixture struct {
		name, flags, frame, body string
		mul, add                 uint64
	}
	fixtures := []fixture{
		{"callerLink", "4", "0", `
CMP $0,R30
CSET NE,R0
MOVD R0,ret+8(FP)
RET
`, 0, 1},
		{"multiTarget", "4", "0", `
ADR helperA,R9
TBZ $0,R0,invoke
ADR helperB,R9
invoke:
CALL R9
ADD $2,R0
MOVD R0,ret+8(FP)
RET
helperA:
ADD $5,R0
B (R30)
helperB:
ADD $5,R0
B (R30)
`, 1, 7},
		{"multiContinuation", "4", "0", `
BL helper
BL helper
ADD $2,R0
MOVD R0,ret+8(FP)
RET
helper:
ADD $5,R0
B (R30)
`, 1, 12},
		{"named", "4", "0", `
BL helper
resume:
ADD $2,R0
MOVD R0,ret+8(FP)
RET
helper:
ADD $5,R0
B resume
`, 1, 7},
		{"savedRegister", "4", "0", `
BL outer
ADD $7,R0
MOVD R0,ret+8(FP)
RET
outer:
MOVD R30,R20
ADD $2,R0
BL inner
ADD $4,R0
MOVD R20,R30
JMP (LR)
inner:
ADD $3,R0
B (R30)
`, 1, 16},
		{"savedStackAlias", "4", "48", `
BL outer
ADD $7,R0
MOVD R0,ret+8(FP)
RET
outer:
ADD $24,RSP,R10
MOVD R30,(R10)
BL inner
MOVD (R10),R30
ADD $4,R0
B (R30)
inner:
ADD $3,R0
B (R30)
`, 1, 14},
		{"savedStackPair", "4", "48", `
BL outer
ADD $7,R0
MOVD R0,ret+8(FP)
RET
outer:
STP (R30,R0),24(RSP)
BL inner
LDP 24(RSP),(R20,R21)
MOVD R20,R30
ADD $4,R0
B (LR)
inner:
ADD $3,R0
B (R30)
`, 1, 14},
		{"savedFPParam", "4", "0", `
BL outer
ADD $7,R0
MOVD R0,ret+8(FP)
RET
outer:
MOVD R30,a+0(FP)
BL inner
MOVD a+0(FP),R30
ADD $4,R0
B (R30)
inner:
ADD $3,R0
B (R30)
`, 1, 14},
		{"savedFPParamAlias", "4", "0", `
BL outer
ADD $7,R0
MOVD R0,ret+8(FP)
RET
outer:
MOVD $a+0(FP),R10
MOVD R30,(R10)
BL inner
MOVD (R10),R30
ADD $4,R0
B (R30)
inner:
ADD $3,R0
B (R30)
`, 1, 14},
		{"savedFPResult", "4", "0", `
BL outer
ADD $7,R0
MOVD R0,ret+8(FP)
RET
outer:
MOVD R30,ret+8(FP)
BL inner
MOVD ret+8(FP),R30
ADD $4,R0
B (R30)
inner:
ADD $3,R0
B (R30)
`, 1, 14},
		{"abiAnchor", "4", "48", `
BL outer
ADD $7,R0
MOVD R0,ret+8(FP)
RET
outer:
MOVD R30,24(RSP)
MOVD R0,8(RSP)
BL ·localAnchor(SB)
MOVD 16(RSP),R0
MOVD 24(RSP),R30
ADD $4,R0
B (R30)
`, 3, 20},
		{"noFrameRET", "516", "0", `
MOVD R30,R19
BL helper
ADD $2,R0
MOVD R0,ret+8(FP)
MOVD R19,R30
RET
helper:
ADD $5,R0
RET
`, 1, 7},
		{"noFrameHardwareRETAlias", "516", "0", `
MOVD R30,R19
CALL helper
ADD $2,R0
MOVD R0,ret+8(FP)
WORD $0xd65f0260
helper:
ADD $5,R0
MOVD R30,R20
WORD $0xd65f0280
`, 1, 7},
		{"rawBLRBR", "516", "0", `
MOVD R30,R19
ADR helper,R9
WORD $0xd63f0120
ADD $2,R0
MOVD R0,ret+8(FP)
MOVD R19,R30
RET
helper:
ADD $5,R0
WORD $0xd61f03c0
`, 1, 7},
		{"rawRET", "516", "0", `
MOVD R30,R19
BL helper
ADD $2,R0
MOVD R0,ret+8(FP)
MOVD R19,R30
RET
helper:
ADD $5,R0
WORD $0xd65f03c0
`, 1, 7},
	}
	for _, op := range []string{"BL", "CALL"} {
		for _, operand := range []string{"R9", "(R9)", "R30", "(R30)"} {
			reg := strings.Trim(operand, "()")
			name := fmt.Sprintf("registerCall%d", len(fixtures))
			body := fmt.Sprintf(`ADR helper,%s
%s %s
ADD $2,R0
MOVD R0,ret+8(FP)
RET
helper:
ADD $5,R0
B (R30)`, reg, op, operand)
			fixtures = append(fixtures, fixture{name, "4", "0", body, 1, 7})
		}
	}
	for _, op := range []string{"B", "JMP"} {
		body := fmt.Sprintf(`ADR finish,R9
%s (R9)
MOVD $999,R0
finish:
ADD $13,R0
MOVD R0,ret+8(FP)
RET`, op)
		fixtures = append(fixtures, fixture{"jump" + op, "4", "0", body, 1, 13})
	}
	var source, goDecl, goChecks, cDecl, cChecks strings.Builder
	sigs := make(map[string]FuncSig)
	for _, tc := range fixtures {
		name := "localControl" + tc.name
		fmt.Fprintf(&source, "TEXT ·%s(SB),%s,$%s-16\nMOVD a+0(FP),R0\n%s\n", name, tc.flags, tc.frame, tc.body)
		sigs[name] = arm64LocalRegisterBranchSig(name)
		fmt.Fprintf(&goDecl, "func %s(uint64) uint64\n", name)
		fmt.Fprintf(&goChecks, `for _, x := range []uint64{0,1,123,0x8000000000000000,0xffffffffffffffff} {
	want := x*%d+%d
	if got := %s(x); got != want {
		println("%s",got,want)
		panic("local control mismatch")
	}
}
`, tc.mul, tc.add, name, name)
		fmt.Fprintf(&cDecl, "extern uint64_t %s(uint64_t);\n", name)
		fmt.Fprintf(&cChecks, `for (unsigned i=0; i<sizeof(inputs)/sizeof(inputs[0]); i++) {
	uint64_t x=inputs[i], want=x*%d+%d, got=%s(x);
	if (got!=want) {
		fprintf(stderr,"%s got=%%llx want=%%llx\n",(unsigned long long)got,(unsigned long long)want);
		return 1;
	}
}
`, tc.mul, tc.add, name, name)
	}
	source.WriteString(`TEXT ·localAnchor(SB),4,$0-16
MOVD a+0(FP),R0
MOVD R0,R1
ADD R0,R0
ADD R1,R0
ADD $9,R0
MOVD R0,ret+8(FP)
RET
`)
	goDecl.WriteString("func localAnchor(uint64) uint64\n")
	sigs["localAnchor"] = arm64LocalRegisterBranchSig("localAnchor")
	requireARM64GoAssemblerResult(t, source.String(), true)
	runARM64LocalRegisterGoOracle(t, source.String(), "package main\n"+goDecl.String()+"func main(){\n"+goChecks.String()+"}\n", len(runner) != 0)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple, ResolveSym: func(sym string) string { return strings.TrimPrefix(sym, "·") }, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(ir, "callbr") {
		t.Fatal("local code pointers must use real LLVM control-flow edges")
	}
	main := "#include <stdint.h>\n#include <stdio.h>\n" + cDecl.String() + "int main(void){ uint64_t inputs[]={0,1,123,UINT64_C(0x8000000000000000),UINT64_MAX};\n" + cChecks.String() + "return 0;}\n"
	compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "local_control", triple, ir, main, runner)
	t.Logf("%d local-call/return fixtures × 5 independent unsigned inputs passed native Go and LLVM 22", len(fixtures))
}

func TestCrossLinuxRuntimeMatrixARM64SelectedGoRETRegisterIdentity(t *testing.T) {
	_, _, _, runner := arm64FPPairRuntimeTools(t)
	probe := arm64ImmediateOriginalGoBytes(t, "TEXT retRegisterProbe(SB),516,$0-0\nRET R19\n", "linux")
	if len(probe) < 4 {
		t.Fatal("actual Go return-register object is absent")
	}
	word := binary.LittleEndian.Uint32(probe)
	if word & ^uint32(31<<5) != 0xd65f0000 {
		t.Fatalf("actual Go emitted an unknown RET encoding: %#08x", word)
	}
	register := (word >> 5) & 31
	want := 1
	if register == 19 {
		want = 2
	} else if register != 30 {
		t.Fatalf("actual Go RET R19 targets unexpected register R%d", register)
	}
	// Both continuations are safe, so the legacy encoder's ignored operand is
	// measured without running a program that would loop forever. This is an
	// actual selected-Go observation, not an LLVM or native-caller permission.
	const source = `TEXT ·ReturnTarget(SB),516,$0-8
MOVD R30,R20
ADR operandTarget,R19
MOVD $1,R0
MOVD R0,ret+0(FP)
RET R19
operandTarget:
MOVD $2,R0
MOVD R0,ret+0(FP)
MOVD R20,R30
RET
`
	main := fmt.Sprintf(`package main
func ReturnTarget() uint64
func main() {
    for i := 0; i < 5; i++ {
        if got := ReturnTarget(); got != %d {
            println(got)
            panic("selected Go RET register differs from its real object")
        }
    }
}
`, want)
	runARM64LocalRegisterGoOracle(t, source, main, len(runner) != 0, "1.20")
	t.Logf("actual Go RET R19 encodes R%d and its safe runtime witness returned %d; this does not claim legacy/current source equivalence", register, want)
}
