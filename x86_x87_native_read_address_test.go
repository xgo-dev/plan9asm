package plan9asm

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

func TestX86X87NativeReadsAcceptCompleteUintptr(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		word, move := 8, "MOVQ"
		if target.arch == "386" {
			word, move = 4, "MOVL"
		}
		for _, instruction := range []string{
			"FMOVF 7(AX),F0", "FMOVD 7(AX),F0",
			"FCOMW 7(AX),F0", "FCOMWP 7(AX),F0",
			"FCOML 7(AX),F0", "FCOMLP 7(AX),F0",
			"FCOMF 7(AX),F0", "FCOMFP 7(AX),F0",
			"FCOMD 7(AX),F0", "FCOMDP 7(AX),F0",
		} {
			source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s input+0(FP),AX\nFINIT\nFLD1\n%s\nFINIT\nMOVL $7,ret+%d(FP)\nRET\n", word+4, move, instruction, word)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(target.triple+"/"+instruction+"/"+api, func(t *testing.T) {
					ir, err := x86X87InitializedWordAPI(t, source, "func Value(input uintptr) uint32",
						target.arch, target.triple, api, X87Software)
					if err != nil || ir == "" {
						t.Fatal("complete numerical address rejected its paired exact native read", err)
					}
				})
			}
		}
	}
}

func TestX86OfficialX87CompareUintptrMemoryObjects(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, raw := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/raw%t", target.triple, raw), func(t *testing.T) {
				build := func(source goasmrules.X86LegacyCatalog, _ []goasmrules.X86AVXRule) ([]goasmrules.X86PackedBinaryRow, error) {
					return x86X87CompareNamedRows(source, target.arch)
				}
				x86OfficialPackedRowsObjectsForTarget(t, target.arch, target.triple, build, 20, 38, 0,
					func(cases []x86OfficialPackedCase) (string, string) {
						source, declaration := x86X87CompareAssembly(cases, target.arch, false, true, raw)
						return source, strings.ReplaceAll(declaration, "memory *byte", "memory uintptr")
					}, func(*testing.T, string, []x86OfficialPackedCase) {})
			})
		}
	}
}

func x86X87UintptrMoveProgram(arch string) (string, string) {
	var source, declarations strings.Builder
	for _, op := range []string{"FMOVF", "FMOVFP", "FMOVD", "FMOVDP"} {
		text, declaration := x86X87NativeMoveProgram(arch, op)
		source.WriteString(strings.ReplaceAll(text, "Value", op))
		declaration = strings.Replace(declaration, "src,dst *byte", "src uintptr,dst *byte", 1)
		declarations.WriteString(strings.ReplaceAll(declaration, "Value", op) + "\n")
	}
	return source.String(), declarations.String()
}

func TestX86X87UintptrFloatingReadObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc is required")
	}
	for _, target := range x86RawReturnTargets {
		source, declaration := x86X87UintptrMoveProgram(target.arch)
		requireX86GoAssemblerResult(t, target.arch, source, true)
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(target.triple+"/"+api, func(t *testing.T) {
				ir, err := x86X87InitializedWordAPI(t, source, declaration, target.arch, target.triple, api, X87Software)
				if err != nil || ir == "" {
					t.Fatal("complete uintptr read with pointer destination rejected", err)
				}
				for _, level := range []string{"-O0", "-O2"} {
					x86PackedStringCompileObject(t, llc, target.triple, ir, level)
				}
			})
		}
	}
}

func TestX86X87UintptrCompareSoftwareValues(t *testing.T) {
	for _, raw := range []bool{false, true} {
		t.Run(fmt.Sprint("raw", raw), func(t *testing.T) {
			x86X87CompareHostSoftwareValues(t, true, raw, true)
		})
	}
}

func TestX86X87UintptrCompareDeadReadWidthsAndFaults(t *testing.T) {
	x86X87CompareDeadReadWidthsAndFaults(t, true)
}

func TestX86X87UintptrFloatingReadSoftwareValues(t *testing.T) {
	execution := x86ScalarCountHostExecution(t)
	arch := "amd64"
	if strconv.IntSize == 32 {
		arch = "386"
	}
	source, declaration := x86X87UintptrMoveProgram(arch)
	driver := strings.ReplaceAll(x86X87NativeMoveValueDriver, "const uint8_t*,uint8_t*", "uintptr_t,uint8_t*")
	driver = strings.Replace(driver, "calls[op](input,output)", "calls[op]((uintptr_t)input,output)", 1)
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86X87InitializedWordAPI(t, source, declaration, arch, execution.triple, api, X87Software)
			if err != nil || ir == "" {
				t.Fatal("uintptr input did not reach the selected floating read", err)
			}
			for _, optimized := range []bool{false, true} {
				input := ir
				if optimized {
					input = x86MulDivRoundOptimize(t, ir)
				}
				for _, level := range []string{"-O0", "-O2"} {
					execution.compileAndRunLLVM(t, "x87-uintptr-floating-read", input, driver, level)
				}
			}
		})
	}
}

func TestX86X87UintptrReadsRetainAddressAndAuthorityGuards(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		word, move, triple := 8, "MOVQ", "x86_64-unknown-linux-gnu"
		if arch == "386" {
			word, move, triple = 4, "MOVL", "i386-unknown-linux-gnu"
		}
		for _, raw := range []bool{false, true} {
			compare := "FCOMD 7(AX),F0\n"
			if raw {
				compare = x86RawDisplacementDirectives([]byte{0xdc, 0x50, 7})
			}
			for _, address := range []struct{ name, body string }{
				{"missing", ""},
				{"partial", "MOVW input+0(FP),AX\n"},
			} {
				source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%sFINIT\nFLD1\n%sFINIT\nMOVL $7,ret+%d(FP)\nRET\n", word+4, address.body, compare, word)
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(fmt.Sprintf("%s/raw%t/%s/%s", arch, raw, address.name, api), func(t *testing.T) {
						ir, err := x86X87InitializedWordAPI(t, source, "func Value(input uintptr) uint32", arch, triple, api, X87Software)
						if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("incomplete numerical address invented its missing bytes", err)
						}
					})
				}
			}
		}

		state := x86ResultState{x87: &x86ResultX87State{depth: 1, slots: 1}}
		state.gp[0] = uint8(1<<uint(word)) - 1
		instruction := x86X87ValueInstruction(t, "FCOMD 7(AX),F0")
		consumer := &amd64Ctx{goarch: arch, x87Mode: X87Software}
		if accepted, known := consumer.x87NativeMemoryValueResultStep(instruction, &state, nil, 0, arch); !known || !accepted {
			t.Fatal("complete NUM address rejected paired read", arch)
		}
		if state.pointerGP[0] || x86ResultRead(instruction.Args[0], 8, &state, nil, arch) || state.literalMemoryOperand != nil {
			t.Fatal("conditional read granted a pointer or reusable backing", arch)
		}
		if accepted, _ := consumer.x87NativeMemoryValueResultStep(x86X87ValueInstruction(t, "FMOVD F0,7(AX)"), &state, nil, 0, arch); accepted {
			t.Fatal("numerical read authorization leaked to a floating store", arch)
		}
		source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s input+0(FP),AX\nFINIT\nFLD1\nFCOMD 7(AX),F0\nFINIT\nRET\n", word, move)
		file, err := Parse(ArchAMD64, source)
		if err != nil {
			t.Fatal(err)
		}
		pkg := mustGoPackage(t, "uintptrread", "package uintptrread\nfunc Value(input uintptr)")
		sigs, err := goSigsForAsmFile(pkg, file, func(s string) string { return strings.TrimPrefix(s, "·") }, arch, nil, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !errors.Is(CheckX86ABI0ResultInitialization(file.Funcs[0], sigs["Value"], arch), ErrProbeNeedsContext) {
			t.Fatal("standalone query acquired the conditional read", arch)
		}
	}
}
