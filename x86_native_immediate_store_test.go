package plan9asm

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestX86NativeImmediateStoreVoidInputsCannotBorrowPrivateSlots(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		word, move := 8, "MOVQ"
		if target.arch == "386" {
			word, move = 4, "MOVL"
		}
		valid := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s p+0(FP),DI\n%s $3,BX\nMOVL $7,-1(DI)(BX*2)\nRET\n", word, move, move)
		for _, api := range []string{"text", "module", "Go"} {
			ir, err := x86ScalarFPBitViewAPI(t, valid, "func Value(p *byte)", target.arch, target.triple, api)
			if err != nil || strings.Count(ir, "store volatile i32 ") != 1 {
				t.Fatal("complete Void pointer/index control rejected", api, err)
			}
		}
		for _, row := range []struct {
			name, setup, address string
		}{
			{"unknown-base", "", "(DI)"},
			{"numeric-base", move + " $64,DI\n", "(DI)"},
			{"partial-base", "MOVB $1,DI\n", "(DI)"},
			{"unknown-index", move + " p+0(FP),DI\n", "(DI)(BX*2)"},
			{"pointer-index", move + " p+0(FP),DI\n" + move + " p+0(FP),BX\n", "(DI)(BX*2)"},
		} {
			source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%sMOVL $7,%s\nRET\n", word, row.setup, row.address)
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(target.triple+"/"+row.name+"/"+api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, "func Value(p *byte)", target.arch, target.triple, api)
					if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
						t.Fatal("Void native write acquired an unproved base/index", err)
					}
				})
			}
		}
	}
}

func TestX86NativeImmediateStoreRejectsOutsideGoEncodingClasses(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		instructions := []string{"MOVB $0.0,(DI)", "MOVW $0.0,(DI)", "MOVL $0.0,(DI)", "MOVQ $0.0,(DI)"}
		if target.arch == "amd64" {
			for _, op := range []string{"MOVB", "MOVW", "MOVL", "MOVQ", "MOVD", "MOVDQ2Q"} {
				for _, value := range []string{"-2147483649", "4294967296", "0x0123456789abcdef"} {
					instructions = append(instructions, op+" $"+value+",(DI)")
				}
			}
		} else {
			instructions = append(instructions, "MOVQ $1,(DI)", "MOVD $1,(DI)", "MOVDQ2Q $1,(DI)")
		}
		for _, instruction := range instructions {
			t.Run(target.triple+"/"+instruction, func(t *testing.T) {
				source := "TEXT ·Value(SB),4,$0-0\n" + instruction + "\nRET\n"
				requireX86GoAssemblerResult(t, target.arch, source, false)
				for _, api := range []string{"text", "module", "Go"} {
					if ir, err := x86ScalarFPBitViewAPI(t, source, "func Value()", target.arch, target.triple, api); err == nil || errors.Is(err, ErrProbeNeedsContext) || ir != "" {
						t.Fatal("native store accepted a non-Go immediate/mode row", api, err)
					}
				}
			})
		}
	}
}

// Independent witnesses for all four Go Yi32-to-memory rows, including the
// frontend's two MOVQ aliases. The qword row sign-extends its encoded imm32.
func x86NativeImmediateStoreFixture(arch string) (string, string, string, int) {
	word, move := 8, "MOVQ"
	if arch == "386" {
		word, move = 4, "MOVL"
	}
	var source, declarations, prototypes, checks strings.Builder
	count := 0
	for _, row := range []struct {
		op    string
		bytes int
	}{{"MOVB", 1}, {"MOVW", 2}, {"MOVL", 4}, {"MOVQ", 8}, {"MOVD", 8}, {"MOVDQ2Q", 8}} {
		if row.bytes > word {
			continue
		}
		values := []int64{-2147483648, -129, -1, 0, 127, 128, 255, 65535, 2147483647, 2147483648, 4294967295}
		if arch == "386" {
			values = append(values, -2147483649, 4294967296, 9223372036854775807)
		}
		for _, value := range values {
			name := fmt.Sprintf("ImmediateStore%d", count)
			count++
			fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n%s p+0(FP),DI\n%s $3,BX\n%s $%d,-1(DI)(BX*2)\nMOVL $7,ret+%d(FP)\nRET\n",
				name, word+4, move, move, row.op, value, word)
			fmt.Fprintf(&declarations, "func %s(p *byte) uint32\n", name)
			fmt.Fprintf(&prototypes, "extern uint32_t %s(uint8_t*);\n", name)
			// Reference uses the encoded value, not any lowering helper.
			encoded := uint64(value)
			if row.bytes == 8 {
				encoded = uint64(int64(int32(value)))
			}
			fmt.Fprintf(&checks, "memset(actual,0xa7,sizeof(actual));memcpy(expected,actual,sizeof(actual));\n"+
				"for(unsigned i=0;i<%d;i++)expected[5+i]=(UINT64_C(%d)>>(8*i))&255;\n"+
				"if(%s(actual)!=7||memcmp(actual,expected,sizeof(actual)))return %d;\n",
				row.bytes, encoded, name, count)
		}
	}
	driver := "#include <stdint.h>\n#include <string.h>\n" + prototypes.String() +
		"int main(void){uint8_t actual[32],expected[32];\n" + checks.String() + "return 0;}\n"
	return source.String(), declarations.String(), driver, count
}

func TestX86NativeImmediateStoreCompleteGoRowsAndObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			source, declarations, _, count := x86NativeImmediateStoreFixture(target.arch)
			want := 66
			if target.arch == "386" {
				want = 42
			}
			if count != want {
				t.Fatal("complete immediate-store denominator changed", count, want)
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, declarations, target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("complete original immediate-store source rejected", err)
					}
					for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
						if strings.Count(text, "store volatile i") != count {
							t.Fatal("an immediate native write lost its exact volatile effect")
						}
						for _, level := range []string{"-O0", "-O2"} {
							x86PackedStringCompileObject(t, llc, target.triple, text, level)
						}
					}
				})
			}
		})
	}
}

func TestX86NativeImmediateStorePortableValuesAndCanaries(t *testing.T) {
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM22 llc and clang required")
	}
	arch := "amd64"
	if runtime.GOARCH == "386" {
		arch = "386"
	}
	source, declarations, driver, _ := x86NativeImmediateStoreFixture(arch)
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source, declarations, arch, triple, api)
			if err != nil {
				t.Fatal(err)
			}
			for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
				for _, level := range []int{0, 2} {
					compileAndRunRuntimeTestWithCompiler(t, llc, []string{clang}, "native-immediate-store", triple, text, driver, nil, level)
				}
			}
		})
	}
}
