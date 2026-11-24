package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestTranslateARMBranchExchangeCompleteFormat(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, row := range []string{"BX (R4)", "BX.AL 0(R4)", "BX.NE (R4)(R5*2)", "BX (R11)", "BX (g)"} {
		t.Run(row, func(t *testing.T) {
			source := "TEXT invoke(SB),4,$4-8\nMOVW value+0(FP),R4\nCMP $0,R4\n" + row + "\nMOVW $19,R0\nMOVW R0,ret+4(FP)\nRET\n"
			requireARMGoAssemblerResult(t, source, true)
			ir := translateARMCompleteForms(t, source, map[string]FuncSig{"invoke": armLocalCallSignature("invoke")})
			if !strings.Contains(ir, "blx ") || !strings.Contains(ir, "~{lr}") || strings.Contains(ir, `asm sideeffect "bx $0"`) ||
				!strings.Contains(ir, "store i32 19,") || strings.Contains(ir, "load i32, ptr %reg_R5") {
				t.Fatalf("BX lost its call, continuation or register target:\n%s", ir)
			}
		})
	}
}

func TestTranslateARMBranchExchangeRejectsFormsOutsideGoOptab(t *testing.T) {
	for _, instruction := range []string{"BX R0", "BX R1,(R0)", "BX 4(R0)", "BX target(SB)", "BX.S (R0)", "BX 1(PC)"} {
		requireARMGoAssemblerResult(t, "TEXT bad(SB),4,$0-0\n"+instruction+"\nRET\n", false)
	}
	rejectARMFormsOutsideGo127Optabs(t, []string{"BX R0", "BX R1,(R0)", "BX 4(R0)", "BX target(SB)", "BX.S (R0)", "BX 1(PC)"})
	for _, instruction := range []string{"BX (R13)", "BX (R15)"} {
		source := "TEXT bad(SB),4,$0-0\n" + instruction + "\nRET\n"
		requireARMGoAssemblerResult(t, source, true)
		file, err := Parse(ArchARM, source)
		if err != nil {
			t.Fatal(err)
		}
		_, err = Translate(file, Options{TargetTriple: armOfficialVFPTriple, Goarch: "arm",
			Sigs: map[string]FuncSig{"bad": {Name: "bad", Ret: Void}}})
		if !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatalf("physical SP/PC became a logical branch address: %s: %v", instruction, err)
		}
	}
}

func TestARMBranchExchangeCallerSkipPreservesFlags(t *testing.T) {
	const source = `TEXT invoke(SB),516,$0-8
MOVW value+0(FP),R0
MOVW R0,ret+4(FP)
CMP $0,R0
BX.NE (R14)
ADD.EQ $5,R0
MOVW R0,ret+4(FP)
RET
`
	requireARMGoAssemblerResult(t, source, true)
	translateARMCompleteForms(t, source, map[string]FuncSig{"invoke": armLocalCallSignature("invoke")})
}

const armBranchExchangeFixture = `TEXT ·invoke(SB),516,$0-8
MOVW value+0(FP),R0
MOVW R14,R8
MOVW $helper<>(SB),R7
MOVW $4,R2
CMP $0,R0
BX.NE (R7)(R2*2)
ADD $2,R0
MOVW R0,ret+4(FP)
MOVW R8,R14
RET

TEXT ·scratch(SB),516,$0-8
MOVW value+0(FP),R0
MOVW R14,R8
MOVW $helper<>(SB),R11
MOVW R11,R7
BX (R11)
CMP R7,R11
ADD.EQ $2,R0
MOVW R0,ret+4(FP)
MOVW R8,R14
RET

TEXT helper<>(SB),516,$0-0
ADD $3,R0
RET
`

const armBranchExchangeDecl = "func invoke(value int32) int32\nfunc scratch(value int32) int32\n"

func armBranchExchangeFixtureIR(t *testing.T, api string) string {
	t.Helper()
	pkg := mustGoPackage(t, "bxcall", "package bxcall\n"+armBranchExchangeDecl)
	resolve := func(symbol string) string { return strings.TrimPrefix(goStripABISuffix(symbol), "·") }
	manual := func(name string) (FuncSig, bool) {
		if name != "helper" && name != "helper<>" {
			return FuncSig{}, false
		}
		return FuncSig{Name: name, Args: []LLVMType{I32}, ArgRegs: []Reg{"R0"}, Ret: I32}, true
	}
	if api == "Go" {
		module, err := TranslateGoModule(pkg, []byte(armBranchExchangeFixture), GoModuleOptions{
			GOOS: "linux", GOARCH: "arm", TargetTriple: armOfficialVFPTriple, ResolveSym: resolve, ManualSig: manual,
		})
		if err != nil {
			t.Fatal(err)
		}
		defer module.Module.Dispose()
		return module.Module.String()
	}
	file, err := Parse(ArchARM, armBranchExchangeFixture)
	if err != nil {
		t.Fatal(err)
	}
	sigs, err := goSigsForAsmFile(pkg, file, resolve, "arm", nil, nil, manual)
	if err != nil {
		t.Fatal(err)
	}
	opt := Options{Goarch: "arm", TargetTriple: armOfficialVFPTriple, ResolveSym: resolve, Sigs: sigs}
	if api == "module" {
		module, err := TranslateModule(file, opt)
		if err != nil {
			t.Fatal(err)
		}
		defer module.Dispose()
		return module.String()
	}
	ir, err := Translate(file, opt)
	if err != nil {
		t.Fatal(err)
	}
	return ir
}

func TestCrossLinuxRuntimeMatrixARMIndirectBranchExchange(t *testing.T) {
	llc := requireARMScalarRuntime(t)
	const goMain = `
package main
import "fmt"
` + armBranchExchangeDecl + `
func main() {
	for _, value := range []int32{-2, 0, 1, 17} {
		want := value + 5
		if value == 0 { want = 2 }
		if got := invoke(value); got != want { panic(got) }
		if got := scratch(value); got != value+5 { panic(got) }
	}
	fmt.Println("BX continuations matched")
}
`
	const cMain = `
extern int invoke(int), scratch(int);
int main(void) {
	int inputs[] = {-2, 0, 1, 17};
	for (unsigned i = 0; i < sizeof(inputs)/sizeof(inputs[0]); i++) {
		int value = inputs[i];
		if (invoke(value) != (value == 0 ? 2 : value + 5)) return 1;
		if (scratch(value) != value + 5) return 2;
	}
	return 0;
}
`
	runARMGoSourceOracle(t, armBranchExchangeFixture, goMain)
	for _, api := range []string{"text", "module", "Go"} {
		ir := armBranchExchangeFixtureIR(t, api)
		for _, level := range []int{0, 2} {
			t.Run(fmt.Sprintf("%s/O%d", api, level), func(t *testing.T) {
				compileAndRunRuntimeTestWithCompiler(t, llc, []string{"arm-linux-gnueabihf-gcc", "-no-pie"},
					"arm_indirect_bx", armOfficialVFPTriple, ir, cMain,
					[]string{"qemu-arm", "-L", "/usr/arm-linux-gnueabihf"}, level)
			})
		}
	}
}
