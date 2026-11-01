package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

type arm64VDUPPhysicalCase struct {
	spelling, arrangement string
	bits, lanes, index    int
}

func TestARM64VDUPPhysicalLaneCannotBorrowAnotherRowOrInput(t *testing.T) {
	for _, spelling := range []string{"B", "H", "S", "D"} {
		for _, arrangement := range []string{"B8", "B16", "H4", "H8", "S2", "S4", "D2"} {
			bits := map[byte]int{'B': 8, 'H': 16, 'S': 32, 'D': 64}[arrangement[0]]
			for _, index := range []int{-1, 128 / bits} {
				instruction := fmt.Sprintf("VDUP V20.%s[%d],V21.%s", spelling, index, arrangement)
				t.Run(instruction, func(t *testing.T) {
					goAssemblerOracleOutput(t, "arm64", "TEXT invalid(SB),4,$0-0\n"+instruction+"\nRET\n", "", false)
					if _, err := arm64VectorLaneTranslation(t, "func Pass(uint64) uint64", instruction+"\nRET\n"); err == nil {
						t.Fatal("physical destination bound did not reject invalid lane")
					}
				})
			}
		}
	}
	for _, instruction := range []string{
		"VMOV V20.D[15],R0", "VMOV V20.D[15],V21.D[0]", "VDUP V20.D[15],V21",
		"VDUP V20.Q[0],V21.B16", "VDUP V20.D[1],V21.D1", "VDUP V32.B[0],V21.B16",
	} {
		goAssemblerOracleOutput(t, "arm64", "TEXT invalid(SB),4,$0-0\n"+instruction+"\nRET\n", "", false)
		if _, err := arm64VectorLaneTranslation(t, "func Pass(uint64) uint64", instruction+"\nRET\n"); err == nil {
			t.Fatalf("case79 syntax leaked to another operand class: %s", instruction)
		}
	}
	for _, body := range []string{
		"VDUP V20.D[15],V21.B16\nVMOV V21.D[0],R0\nRET\n",
		"VMOV R0,V20.B[14]\nVDUP V20.D[15],V21.B16\nVMOV V21.D[0],R0\nRET\n",
		"VMOV R0,V20.B[15]\nVDUP V20.B[1],V21.D2\nVMOV V21.D[0],R0\nRET\n",
	} {
		if _, err := arm64VectorLaneTranslation(t, "func Pass(uint64) uint64", body); !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatalf("source suffix or adjacent lane supplied unknown physical bits: %v", err)
		}
	}
}

func arm64VDUPPhysicalProgram() (declarations, ordinary, internal string) {
	var decl, abi0, reg strings.Builder
	for i, tc := range arm64VDUPPhysicalCases() {
		name := fmt.Sprintf("Dup%d", i)
		fmt.Fprintf(&decl, "func %s(uint64) (uint64,uint64)\n", name)
		fmt.Fprintf(&abi0, "TEXT ·%s(SB),4,$0-24\nMOVD a+0(FP),R0\n%sMOVD R0,ret+8(FP)\nMOVD R1,ret1+16(FP)\nRET\n", name, arm64VDUPPhysicalBody(tc))
		fmt.Fprintf(&reg, "TEXT ·%s<ABIInternal>(SB),4,$0-24\n%sRET\n", name, arm64VDUPPhysicalBody(tc))
	}
	return decl.String(), abi0.String(), reg.String()
}

func arm64VDUPPhysicalIR(t *testing.T, target string) string {
	t.Helper()
	decl, _, source := arm64VDUPPhysicalProgram()
	pkg := mustGoPackage(t, "test/vdupphysical", "package vdupphysical\n"+decl)
	result, err := TranslateGoModule(pkg, []byte(source), GoModuleOptions{GOARCH: "arm64", TargetTriple: target,
		ResolveSym: func(symbol string) string { return strings.TrimPrefix(goStripABISuffix(symbol), "·") }})
	if err != nil {
		t.Fatal(err)
	}
	defer result.Module.Dispose()
	return result.Module.String()
}

func TestARM64VDUPPhysicalLaneObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-unknown-linux-musl", "aarch64-pc-windows-msvc", "aarch64-pc-windows-gnu"} {
		t.Run(target, func(t *testing.T) {
			compileLLVMToObject(t, llc, target, "physical-vdup.ll", "physical-vdup.o", arm64VDUPPhysicalIR(t, target))
		})
	}
}

func TestCrossLinuxRuntimeMatrixARM64VDUPPhysicalLanes(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	decl, original, _ := arm64VDUPPhysicalProgram()
	var goChecks, cDecl, cChecks, shims strings.Builder
	for i, tc := range arm64VDUPPhysicalCases() {
		mask := ^uint64(0)
		if tc.bits < 64 {
			mask = uint64(1)<<uint(tc.bits) - 1
		}
		multiplier := ^uint64(0) / mask
		fmt.Fprintf(&goChecks, `{
    var want uint64
    for shift := uint(0); shift < 64; shift += %d {
        want |= (a & %d) << shift
    }
    high := want
    if %d == 64 { high = 0 }
    lo, hi := Dup%d(a)
    if lo != want || hi != high { panic("Go physical VDUP case %d") }
}
`, tc.bits, mask, tc.bits*tc.lanes, i, i)
		for field, label := range []string{"Lo", "Hi"} {
			fmt.Fprintf(&shims, "define i64 @Dup%d%s(i64 %%a) {\n  %%r = call { i64, i64 } @Dup%d(i64 %%a)\n  %%v = extractvalue { i64, i64 } %%r, %d\n  ret i64 %%v\n}\n", i, label, i, field)
			fmt.Fprintf(&cDecl, "extern uint64_t Dup%d%s(uint64_t);\n", i, label)
		}
		high := "want"
		if tc.bits*tc.lanes == 64 {
			high = "0"
		}
		fmt.Fprintf(&cChecks, "{\n  uint64_t want = (a & UINT64_C(%d)) * UINT64_C(%d);\n  if (Dup%dLo(a) != want || Dup%dHi(a) != (%s)) { fprintf(stderr, \"VDUP case %d input %%u\\n\", i); return 1; }\n}\n", mask, multiplier, i, i, high, i)
	}
	goMain := "package main\n" + decl + `
func main() {
    for _, a := range []uint64{0, 1, 0x123456789abcdef0, 0x8000000000000000, ^uint64(0)} {
` + goChecks.String() + "\n}\n}\n"
	runARM64LocalRegisterGoOracle(t, original, goMain, len(runner) != 0, "1.20")
	cMain := "#include <stdint.h>\n#include <stdio.h>\n" + cDecl.String() + `
int main(void) {
    const uint64_t inputs[] = {0, 1, UINT64_C(0x123456789abcdef0),
        UINT64_C(0x8000000000000000), UINT64_MAX};
    const volatile uint64_t canary = UINT64_C(0x7432656876458798);
    for (unsigned i = 0; i < 5; i++) {
        uint64_t a = inputs[i];
` + cChecks.String() + `
    }
    if (canary != UINT64_C(0x7432656876458798)) return 2;
    return 0;
}
`
	compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "physical_vdup", triple, arm64VDUPPhysicalIR(t, triple)+shims.String(), cMain, runner)
}

func arm64VDUPPhysicalCases() []arm64VDUPPhysicalCase {
	var cases []arm64VDUPPhysicalCase
	for _, spelling := range []string{"B", "H", "S", "D"} {
		for _, destination := range []struct {
			name        string
			bits, lanes int
		}{{"B8", 8, 8}, {"B16", 8, 16}, {"H4", 16, 4}, {"H8", 16, 8}, {"S2", 32, 2}, {"S4", 32, 4}, {"D2", 64, 2}} {
			for index := 0; index < 128/destination.bits; index++ {
				cases = append(cases, arm64VDUPPhysicalCase{spelling: spelling, arrangement: destination.name,
					bits: destination.bits, lanes: destination.lanes, index: index})
			}
		}
	}
	return cases
}

func arm64VDUPPhysicalBody(tc arm64VDUPPhysicalCase) string {
	kind := map[int]string{8: "B", 16: "H", 32: "S", 64: "D"}[tc.bits]
	return fmt.Sprintf("VMOV R0,V20.%s[%d]\nVDUP V20.%s[%d],V21.%s\nVMOV V21.D[0],R0\nVMOV V21.D[1],R1\n", kind, tc.index, tc.spelling, tc.index, tc.arrangement)
}

func TestARM64VDUPPhysicalLaneUsesDestinationWidth(t *testing.T) {
	var ordinary strings.Builder
	for i, tc := range arm64VDUPPhysicalCases() {
		fmt.Fprintf(&ordinary, "TEXT lane%d(SB),4,$0-0\n%sRET\n", i, arm64VDUPPhysicalBody(tc))
	}
	// This actual object must succeed before the translator's independent
	// grammar/availability check; the source suffix is not a physical bound.
	arm64ImmediateOriginalGoBytes(t, ordinary.String(), "linux")
	for _, tc := range arm64VDUPPhysicalCases() {
		name := fmt.Sprintf("%s%d_%s", tc.spelling, tc.index, tc.arrangement)
		t.Run(name, func(t *testing.T) {
			pkg := mustGoPackage(t, "test/vdupphysical", "package vdupphysical\nfunc Pass(uint64) (uint64,uint64)\n")
			result, err := TranslateGoModule(pkg, []byte("TEXT ·Pass<ABIInternal>(SB),4,$0-24\n"+arm64VDUPPhysicalBody(tc)+"RET\n"), GoModuleOptions{GOARCH: "arm64"})
			if result != nil {
				result.Module.Dispose()
			}
			if err != nil {
				t.Fatalf("actual Go case79 physical source span lost: %v", err)
			}
		})
	}
}
