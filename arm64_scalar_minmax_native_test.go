package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

// Independent Go asm7 case-54 names and architectural scalar encodings.
// Half precision is an existing raw WORD role, not a named Go instruction.
type arm64MinMaxCase struct {
	name string
	bits int
	word uint32
}

func arm64MinMaxCases() []arm64MinMaxCase {
	var rows []arm64MinMaxCase
	for index, operation := range []string{"FMAX", "FMIN", "FMAXNM", "FMINNM"} {
		for _, width := range []struct {
			bits   int
			suffix string
			typeID uint32
		}{{32, "S", 0}, {64, "D", 1}, {16, "", 3}} {
			word := uint32(0x1e204800) | uint32(index)<<12 | width.typeID<<22
			if width.bits != 16 {
				rows = append(rows, arm64MinMaxCase{operation + width.suffix, width.bits, 0})
			}
			rows = append(rows, arm64MinMaxCase{operation + width.suffix, width.bits, word})
		}
	}
	return rows
}

func (row arm64MinMaxCase) instruction(left, right, destination int, destructive bool) string {
	if row.word != 0 {
		return fmt.Sprintf("WORD $%#08x", row.word|uint32(left)<<5|uint32(right)<<16|uint32(destination))
	}
	if destructive {
		return fmt.Sprintf("%s F%d,F%d", row.name, right, left)
	}
	return fmt.Sprintf("%s F%d,F%d,F%d", row.name, right, left, destination)
}

func arm64MinMaxDeadFixture() (string, map[string]FuncSig) {
	var source strings.Builder
	signatures := make(map[string]FuncSig)
	for index, row := range arm64MinMaxCases() {
		name := fmt.Sprintf("compareMinMaxDead%d", index)
		signatures[name] = arm64SM3Signature(name)
		fmt.Fprintf(&source, "TEXT %s(SB),4,$0-16\nMOVD in+0(FP),R0\nMOVD out+8(FP),R1\n", name)
		source.WriteString("MRS FPCR,R10\nMRS FPSR,R11\nMSR ZR,FPCR\nMSR ZR,FPSR\nFMOVD (R0),F0\n")
		source.WriteString(row.instruction(0, 0, 1, false) + "\n")
		// F1 is deliberately dead. Only architectural cumulative status escapes.
		source.WriteString("MRS FPSR,R2\nMOVD R2,(R1)\nMSR R10,FPCR\nMSR R11,FPSR\nRET\n")
	}
	return source.String(), signatures
}

func arm64MinMaxIRs(t *testing.T, source, triple string, signatures map[string]FuncSig) []string {
	t.Helper()
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	options := Options{Goarch: "arm64", TargetTriple: triple, Sigs: signatures}
	text, err := Translate(file, options)
	if err != nil {
		t.Fatal(err)
	}
	module, err := TranslateModule(file, options)
	if err != nil {
		t.Fatal(err)
	}
	direct := module.String()
	module.Dispose()
	context := llvm.NewContext()
	defer context.Dispose()
	module, err = TranslateModuleInContext(context, file, options)
	if err != nil {
		t.Fatal(err)
	}
	bound := module.String()
	module.Dispose()
	return []string{text, direct, bound}
}

func TestARM64ScalarMinMaxDeadNativeIR(t *testing.T) {
	source, signatures := arm64MinMaxDeadFixture()
	requireARM64GoAssemblerResult(t, source, true)
	for api, ir := range arm64MinMaxIRs(t, source, "aarch64-unknown-linux-gnu", signatures) {
		for _, optimized := range []bool{false, true} {
			t.Run(fmt.Sprintf("API%d/O2=%t", api, optimized), func(t *testing.T) {
				if optimized {
					ir = armFloatEffectOptimizedIR(t, ir)
				}
				for _, operation := range []string{"fmax", "fmin", "fmaxnm", "fminnm"} {
					if got := strings.Count(ir, `asm sideeffect "`+operation+" "); got != 5 {
						t.Errorf("dead %s lost native FPCR/FPSR operation: got %d, want 5", operation, got)
					}
				}
			})
		}
	}
}

func arm64MinMaxDeadRuntime(t *testing.T, triple, goos string, compiler, runner []string) {
	t.Helper()
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	source, signatures := arm64MinMaxDeadFixture()
	var original, driver strings.Builder
	original.WriteString("package main\nimport \"fmt\"\n")
	driver.WriteString("#include <stdint.h>\n#include <stdio.h>\n")
	for index := range arm64MinMaxCases() {
		fmt.Fprintf(&original, "func compareMinMaxDead%d(*uint64,*uint64)\n", index)
		fmt.Fprintf(&driver, "extern void compareMinMaxDead%d(uint64_t*,uint64_t*);\n", index)
	}
	original.WriteString("func main() {\n")
	driver.WriteString("int main(void) { uint64_t input,output; unsigned failures=0;\n")
	for index, row := range arm64MinMaxCases() {
		for _, signaling := range []bool{false, true} {
			value := uint64(0x7ff8000000000001)
			if row.bits == 32 {
				value = 0x7fc00001
			} else if row.bits == 16 {
				value = 0x7e01
			}
			want := 0
			if signaling {
				want = 1
				switch row.bits {
				case 16:
					value = 0x7c01
				case 32:
					value = 0x7f800001
				default:
					value = 0x7ff0000000000001
				}
			}
			fmt.Fprintf(&original, "{ input:=uint64(%#x); var output uint64; compareMinMaxDead%d(&input,&output); if output!=%d { panic(fmt.Sprintf(\"%s/%d signaling=%t status %%x want %d\",output)) } }\n", value, index, want, row.name, row.bits, signaling, want)
			fmt.Fprintf(&driver, "input=%#xULL;output=0;compareMinMaxDead%d(&input,&output);if(output!=%d){fprintf(stderr,\"%s/%d signaling=%t status %%llx want %d\\n\",(unsigned long long)output);failures++;}\n", value, index, want, row.name, row.bits, signaling, want)
		}
	}
	original.WriteString("fmt.Println(\"ARM64_COMPARE_ORIGINAL_PASS minmax dead NaN 40\")\n}\n")
	driver.WriteString("return failures?1:0;\n}\n")
	arm64ScalarCompareActualGo(t, source, original.String(), goos, runner)
	for api, ir := range arm64MinMaxIRs(t, source, triple, signatures) {
		for _, optimized := range []bool{false, true} {
			if optimized {
				ir = armFloatEffectOptimizedIR(t, ir)
			}
			for _, level := range []int{0, 2} {
				t.Run(fmt.Sprintf("API%d/IR_O2=%t/backend_O%d", api, optimized, level), func(t *testing.T) {
					compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "minmax_dead", triple, ir, driver.String(), runner, level)
				})
			}
		}
	}
}

func TestARM64ScalarMinMaxDeadNativeRuntime(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("Darwin native counterpart; required Linux/QEMU owner covers other hosts")
	}
	clang := findLLVM22Tool("clang")
	if clang == "" {
		t.Fatal("LLVM 22 clang required")
	}
	arm64MinMaxDeadRuntime(t, "aarch64-apple-darwin", "darwin", []string{clang}, nil)
}
