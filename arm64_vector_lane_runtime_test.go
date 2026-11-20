package plan9asm

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func TestARM64GoRegisterVectorLaneActualGoRows(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src", "cmd", "internal", "obj", "arm64", "asm7.go"))
	if err != nil {
		t.Fatal(err)
	}
	rows := regexp.MustCompile(`(?m)^\s*\{AV(?:MOV|DUP),[^\n]+\},`).FindAllString(string(data), -1)
	for i := range rows {
		rows[i] = strings.Join(strings.Fields(rows[i]), "")
	}
	want := []string{
		"{AVMOV,C_ELEM,C_NONE,C_NONE,C_ZREG,73,4,0,0,0},",
		"{AVMOV,C_ELEM,C_NONE,C_NONE,C_ELEM,92,4,0,0,0},",
		"{AVMOV,C_ELEM,C_NONE,C_NONE,C_VREG,80,4,0,0,0},",
		"{AVMOV,C_ZREG,C_NONE,C_NONE,C_ARNG,82,4,0,0,0},",
		"{AVMOV,C_ZREG,C_NONE,C_NONE,C_ELEM,78,4,0,0,0},",
		"{AVMOV,C_ARNG,C_NONE,C_NONE,C_ARNG,83,4,0,0,0},",
		"{AVDUP,C_ELEM,C_NONE,C_NONE,C_ARNG,79,4,0,0,0},",
		"{AVDUP,C_ELEM,C_NONE,C_NONE,C_VREG,80,4,0,0,0},",
		"{AVDUP,C_ZREG,C_NONE,C_NONE,C_ARNG,82,4,0,0,0},",
	}
	// The newer Optab adds a sixth operand class before the encoder case.
	// All nine audited rows leave it C_NONE; accept only these two complete
	// table shapes, not an arbitrary extra operand or a partial row match.
	modern := make([]string, len(want))
	for i, row := range want {
		fields := strings.Split(row, ",")
		modern[i] = strings.Join(fields[:5], ",") + ",C_NONE," + strings.Join(fields[5:], ",")
	}
	if !reflect.DeepEqual(rows, want) && !reflect.DeepEqual(rows, modern) {
		t.Fatalf("actual SDK vector transfer optab changed: got %v, want %v", rows, want)
	}
}

type arm64DefinedLaneCase struct {
	body string
	bits int
	zero bool
}

// Reuse the independently audited six-row format matrix, but initialize only
// the source span being consumed. No unrelated destination bytes are promised.
func arm64DefinedLaneCases() []arm64DefinedLaneCase {
	var cases []arm64DefinedLaneCase
	for _, tc := range arm64VMOVCases() {
		kind := map[int]string{1: "B", 2: "H", 4: "S", 8: "D"}[tc.bytes]
		instruction := strings.NewReplacer("R3", "R0", "R4", "R0").Replace(tc.instruction)
		body, destination := "", "V1"
		if tc.alias {
			destination = "V0"
		}
		switch tc.shape {
		case "lane", "scalar", "extract":
			body = fmt.Sprintf("VMOV R0,V0.%s[%d]\n", kind, tc.sourceLane)
		case "copy":
			body = "VMOV R0,V0.D[0]\n"
			if tc.bytes == 16 {
				body += "VMOV R0,V0.D[1]\n"
			}
		}
		body += instruction + "\n"
		readLane := tc.destinationLane
		if tc.shape == "scalar" || tc.shape == "duplicate" {
			readLane = 0
		}
		if tc.shape == "copy" {
			kind, readLane = "D", 0
		}
		if tc.shape != "extract" {
			body += fmt.Sprintf("VMOV %s.%s[%d],R0\n", destination, kind, readLane)
		}
		bits := tc.bytes * 8
		if bits > 64 {
			bits = 64
		}
		cases = append(cases, arm64DefinedLaneCase{body: body, bits: bits, zero: tc.zero})
	}
	return cases
}

func arm64DefinedLaneProgram() (declarations, ordinary, internal string) {
	var decl, abi0, reg strings.Builder
	for i, tc := range arm64DefinedLaneCases() {
		name := fmt.Sprintf("Lane%d", i)
		fmt.Fprintf(&decl, "func %s(uint64) uint64\n", name)
		fmt.Fprintf(&abi0, "TEXT ·%s(SB),4,$0-16\nMOVD a+0(FP),R0\n%sMOVD R0,ret+8(FP)\nRET\n", name, tc.body)
		fmt.Fprintf(&reg, "TEXT ·%s<ABIInternal>(SB),4,$0-16\n%sRET\n", name, tc.body)
	}
	return decl.String(), abi0.String(), reg.String()
}

func arm64DefinedLaneIR(t *testing.T, triple string) string {
	t.Helper()
	decl, _, source := arm64DefinedLaneProgram()
	pkg := mustGoPackage(t, "test/definedlane", "package definedlane\n"+decl)
	result, err := TranslateGoModule(pkg, []byte(source), GoModuleOptions{GOARCH: "arm64", TargetTriple: triple,
		ResolveSym: func(symbol string) string { return strings.TrimPrefix(goStripABISuffix(symbol), "·") }})
	if err != nil {
		t.Fatal(err)
	}
	defer result.Module.Dispose()
	return result.Module.String()
}

func TestARM64GoRegisterVectorLaneCompleteObjects(t *testing.T) {
	_, ordinary, _ := arm64DefinedLaneProgram()
	if bytes := arm64ImmediateOriginalGoBytes(t, ordinary, "linux"); len(bytes) < 4*len(arm64DefinedLaneCases()) {
		t.Fatal("actual stock Go transfer object was incomplete")
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{
		"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-unknown-linux-musl",
		"aarch64-pc-windows-msvc", "aarch64-pc-windows-gnu",
	} {
		t.Run(triple, func(t *testing.T) {
			compileLLVMToObject(t, llc, triple, "defined-lane.ll", "defined-lane.o", arm64DefinedLaneIR(t, triple))
		})
	}
	// VDUP's separate arranged/scalar rows consume the exact selected span.
	arm64ImmediateOriginalGoBytes(t, arm64VectorDuplicateForms, "linux")
}

func TestARM64GoRegisterVectorLaneAllTranslationAPIs(t *testing.T) {
	const source = "TEXT ·Pass<ABIInternal>(SB),4,$0-16\nVMOV R0,V21.D[1]\nVMOV V21.D[1],R0\nRET\n"
	pkg := mustGoPackage(t, "test/laneapis", "package laneapis\nfunc Pass(uint64) uint64\n")
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-unknown-linux-musl", "aarch64-pc-windows-msvc", "aarch64-pc-windows-gnu"} {
		t.Run(target, func(t *testing.T) {
			ctx := llvm.NewContext()
			defer ctx.Dispose()
			result, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{GOARCH: "arm64", TargetTriple: target, ResolveSym: testResolveSym(pkg.Path)})
			if err != nil {
				t.Fatal(err)
			}
			defer result.Module.Dispose()
			compileLLVMToObject(t, llc, target, "go-module.ll", "go-module.o", result.Module.String())
			options := Options{Goarch: "arm64", TargetTriple: target, Sigs: result.Signatures, ResolveSym: testResolveSym(pkg.Path)}
			ir, err := Translate(file, options)
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target, "text.ll", "text.o", ir)
			module, err := TranslateModuleInContext(ctx, file, options)
			if err != nil {
				t.Fatal(err)
			}
			defer module.Dispose()
			compileLLVMToObject(t, llc, target, "module.ll", "module.o", module.String())
		})
	}
}

func TestCrossLinuxRuntimeMatrixARM64GoRegisterDefinedVectorLanes(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	decl, original, _ := arm64DefinedLaneProgram()
	var goChecks, cDecl, cChecks strings.Builder
	for i, tc := range arm64DefinedLaneCases() {
		mask := ^uint64(0)
		if tc.bits < 64 {
			mask = uint64(1)<<uint(tc.bits) - 1
		}
		goWant, cWant := fmt.Sprintf("a&%d", mask), fmt.Sprintf("a & UINT64_C(%d)", mask)
		if tc.zero {
			goWant, cWant = "0", "0"
		}
		fmt.Fprintf(&goChecks, "if got := Lane%d(a); got != %s { panic(\"Go defined-lane case %d\") }\n", i, goWant, i)
		fmt.Fprintf(&cDecl, "extern uint64_t Lane%d(uint64_t);\n", i)
		fmt.Fprintf(&cChecks, "if (Lane%d(a) != (%s)) { fprintf(stderr, \"LLVM lane %d input %%u\\n\", i); return 1; }\n", i, cWant, i)
	}
	goMain := "package main\n" + decl + `
func main() {
    for _, a := range []uint64{0, 1, 0x123456789abcdef0, 0x8000000000000000, ^uint64(0)} {
` + goChecks.String() + "\n}\n}\n"
	// The ordinary caller and the translated register entry use the same lane
	// instructions but different explicit ABI transports. Neither observation
	// certifies a third-party caller, memory region or preserved unknown value.
	runARM64LocalRegisterGoOracle(t, original, goMain, len(runner) != 0, "1.20")
	cMain := "#include <stdint.h>\n#include <stdio.h>\n" + cDecl.String() + `
int main(void) {
    const uint64_t inputs[] = {0, 1, UINT64_C(0x123456789abcdef0),
        UINT64_C(0x8000000000000000), UINT64_MAX};
    const volatile uint64_t canary = UINT64_C(0x7498243681789876);
    for (unsigned i = 0; i < 5; i++) {
        uint64_t a = inputs[i];
` + cChecks.String() + `
    }
    if (canary != UINT64_C(0x7498243681789876)) return 2;
    return 0;
}
`
	compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "defined_lane", triple, arm64DefinedLaneIR(t, triple), cMain, runner)
}
