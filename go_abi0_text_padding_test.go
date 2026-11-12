package plan9asm

import (
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

const abi0PaddedSqrtDeclarations = `package padded
func Sqrtf(x float32) float32
func Sqrt(x float32) float32
func SqrtByAddress(x float32) float32
`

// Keep the original TEXT and FP spellings of barnex/fmath.Sqrtf and
// chran554/go3d/fmath.Sqrt. Logical data ends at 12; ABI0 allocates 16 bytes.
const abi0PaddedSqrtAssembly = `TEXT ·Sqrtf+0(SB),$0-16
	SQRTSS x+0(FP), X0
	MOVSS X0,r+8(FP)
	RET
TEXT ·Sqrt+0(SB),$0-16
	SQRTSS x+0(FP), X0
	MOVSS X0,r+8(FP)
	RET
// A regression for LEA's address-of-storage semantics, not a library fixture.
TEXT ·SqrtByAddress(SB),4,$0-16
	LEAQ x+0(FP), AX
	SQRTSS (AX), X0
	LEAQ r+8(FP), BX
	MOVSS X0,(BX)
	RET
`

func abi0PaddedSqrtIR(t *testing.T, triple string) string {
	t.Helper()
	pkg := mustGoPackage(t, "example.com/padded", abi0PaddedSqrtDeclarations)
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	translated, err := translateGoModuleInContext(ctx, pkg, []byte(abi0PaddedSqrtAssembly), GoModuleOptions{
		GOARCH: "amd64", TargetTriple: triple,
		ResolveSym: func(sym string) string { return strings.TrimPrefix(sym, "·") },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer translated.Module.Dispose()
	if err := llvm.VerifyModule(translated.Module, llvm.ReturnStatusAction); err != nil {
		t.Fatal(err)
	}
	return translated.Module.String()
}

func TestGoABI0PaddedSqrtObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	requireX86GoAssemblerResult(t, "amd64", abi0PaddedSqrtAssembly, true)
	for _, triple := range []string{"x86_64-unknown-linux-gnu", "x86_64-apple-darwin", "x86_64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			compileLLVMToObject(t, llc, triple, "padded-sqrt.ll", "padded-sqrt.o", abi0PaddedSqrtIR(t, triple))
		})
	}
}

func TestGoABI0PaddedSqrtRuntime(t *testing.T) {
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	var runPrefix []string
	if runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable() {
		triple, runPrefix = "x86_64-apple-macosx", []string{"/usr/bin/arch", "-x86_64"}
	} else if runtime.GOARCH != "amd64" {
		t.Skip("requires an amd64 execution host; the required Linux/amd64 suite runs this oracle")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	inputs := []uint32{
		0, 0x80000000, 1, 0x007fffff, 0x00800000, 0x3f000000,
		0x3f800000, 0x40000000, 0x40800000, 0x41100000, 0x7f7fffff,
		0x7f800000, 0xbf800000, 0xff800000, 0x7fc12345, 0x7f800123,
	}
	var goInputs, cCases strings.Builder
	for _, bits := range inputs {
		fmt.Fprintf(&goInputs, "0x%08x,\n", bits)
	}
	dir := t.TempDir()
	for name, source := range map[string]string{
		"go.mod":       "module example.com/padded\n\ngo 1.20\n",
		"sqrt_amd64.s": abi0PaddedSqrtAssembly,
		"main.go": `package main
import "fmt"
import "math"
` + strings.TrimPrefix(abi0PaddedSqrtDeclarations, "package padded\n") + `
func main() {
    for _, bits := range []uint32{` + goInputs.String() + `} {
        x := math.Float32frombits(bits)
        fmt.Println(math.Float32bits(Sqrtf(x)), math.Float32bits(Sqrt(x)), math.Float32bits(SqrtByAddress(x)))
    }
}
`,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
	}
	args := []string{"run"}
	if len(runPrefix) != 0 {
		args = append(args, "-exec", strings.Join(runPrefix, " "))
	}
	args = append(args, ".")
	cmd := exec.Command("go", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOARCH=amd64", "CGO_ENABLED=0", "GOWORK=off", "GOTOOLCHAIN=local")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("actual Go source runtime oracle: %v\n%s", err, output)
	}
	fields := strings.Fields(string(output))
	if len(fields) != len(inputs)*3 {
		t.Fatalf("unexpected Go runtime output: %s", output)
	}
	for i, input := range inputs {
		want := math.Float32bits(float32(math.Sqrt(float64(math.Float32frombits(input)))))
		for fn, name := range []string{"Sqrtf", "Sqrt", "SqrtByAddress"} {
			got, err := strconv.ParseUint(fields[3*i+fn], 10, 32)
			if err != nil {
				t.Fatal(err)
			}
			if !math.IsNaN(float64(math.Float32frombits(want))) && uint32(got) != want {
				t.Fatalf("Go %s(%08x) = %08x, want %08x", name, input, got, want)
			}
			if math.IsNaN(float64(math.Float32frombits(want))) && !math.IsNaN(float64(math.Float32frombits(uint32(got)))) {
				t.Fatalf("Go %s(%08x) did not produce NaN", name, input)
			}
			fmt.Fprintf(&cCases, "{ UINT32_C(%d), UINT32_C(%d), %s },\n", input, got, name)
		}
	}
	main := `#include <stdint.h>
#include <string.h>
#include <math.h>
extern float Sqrtf(float), Sqrt(float), SqrtByAddress(float);
int main(void) {
    struct { uint32_t input, expected; float (*call)(float); } cases[] = {
` + cCases.String() + `
    };
    for (unsigned repeat = 0; repeat < 64; repeat++) {
        for (unsigned i = 0; i < sizeof(cases)/sizeof(cases[0]); i++) {
            float input, result, expected;
            uint32_t actual;
            volatile uint64_t canary = UINT64_C(0x123456789abcdef0);
            memcpy(&input, &cases[i].input, 4);
            memcpy(&expected, &cases[i].expected, 4);
            result = cases[i].call(input);
            memcpy(&actual, &result, 4);
            if (isnan(expected) ? !isnan(result) : actual != cases[i].expected) return 1;
            if (canary != UINT64_C(0x123456789abcdef0)) return 2;
        }
    }
    return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "padded-sqrt", triple, abi0PaddedSqrtIR(t, triple), main, runPrefix)
}

func requireStaleNamedFPGoDiagnostic(t *testing.T, original string) {
	t.Helper()
	dir := t.TempDir()
	for name, source := range map[string]string{
		"go.mod": "module example.com/legacy\n\ngo 1.20\n",
		"legacy.go": `package legacy
func legacyresults(a, b, c, d, e, f, g uint32) (retax, retbx, retcx, retdx, retsi, retdi, retbp uint32)
`,
		// Bind only the fixture's standalone TEXT symbol into a Go package;
		// keep its original body, declared frame and all FP displacements.
		"legacy_386.s": "#include \"textflag.h\"\n" + strings.Replace(original, "TEXT legacyresults(SB)", "TEXT ·legacyresults(SB)", 1),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
	}
	env := append(os.Environ(), "GOOS=linux", "GOARCH=386", "CGO_ENABLED=0", "GOWORK=off", "GOTOOLCHAIN=local")
	build := exec.Command("go", "list", "-export", ".")
	build.Dir, build.Env = dir, env
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("Go assembler rejected the independently encodable fixture: %v\n%s", err, output)
	}
	vet := exec.Command("go", "vet", "-asmdecl", ".")
	vet.Dir, vet.Env = dir, env
	output, err := vet.CombinedOutput()
	if err == nil || !strings.Contains(string(output), "invalid offset retcx+40(FP); expected retcx+36(FP)") ||
		!strings.Contains(string(output), "invalid offset retbp+56(FP); expected retbp+52(FP)") {
		t.Fatalf("actual Go did not establish the original stale FP offsets: %v\n%s", err, output)
	}
}

func TestX86NamedFPDisplacementsRemainAuthoritative(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		resultOffset, triple := int64(8), "x86_64-unknown-linux-gnu"
		if arch == "386" {
			resultOffset, triple = 4, "i386-unknown-linux-gnu"
		}
		for _, test := range []struct {
			name, operand string
			wantErr       bool
		}{
			{"correct offset", fmt.Sprintf("r+%d(FP)", resultOffset), false},
			{"different descriptive name", fmt.Sprintf("other+%d(FP)", resultOffset), false},
			{"tail padding", fmt.Sprintf("r+%d(FP)", resultOffset+4), true},
		} {
			t.Run(arch+"/"+test.name, func(t *testing.T) {
				source := fmt.Sprintf("TEXT Copy(SB),4,$0-%d\nMOVL x+0(FP),AX\nMOVL AX,%s\nRET\n", resultOffset+4, test.operand)
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				opt := Options{Goarch: arch, TargetTriple: triple, Sigs: map[string]FuncSig{
					"Copy": {Name: "Copy", Args: []LLVMType{I32}, Ret: I32,
						Frame: FrameLayout{
							Params:  []FrameSlot{{Offset: 0, Type: I32, Index: 0, Field: -1, Name: "x"}},
							Results: []FrameSlot{{Offset: resultOffset, Type: I32, Index: 0, Field: -1, Name: "r"}},
						}},
				}}
				// Repeat on the same parsed file; lowering must not mutate the
				// source operand or depend on a prior signature's name mapping.
				for repeat := 0; repeat < 2; repeat++ {
					_, err := Translate(file, opt)
					if (err != nil) != test.wantErr {
						t.Fatalf("text API accepted/changed displacement: %v", err)
					}
					ctx := llvm.NewContext()
					module, err := TranslateModuleInContext(ctx, file, opt)
					if err == nil {
						module.Dispose()
					}
					ctx.Dispose()
					if (err != nil) != test.wantErr {
						t.Fatalf("module API accepted/changed displacement: %v", err)
					}
				}
				if got := file.Funcs[0].Instrs[2].Args[1].String(); got != test.operand {
					t.Fatalf("lowering changed original FP operand: %s", got)
				}
			})
		}
	}
}
