package plan9asm

import (
	"fmt"
	"go/types"
	"math"
	"math/big"
	"runtime"
	"strings"
	"testing"
)

// Reuse the seven complete public comparison functions. The additional
// functions observe actual scalar stores, including their explicit CW, rather
// than returning parts directly from the private mathematical provider.
func x86X87PortablePublicConstantProgram(t *testing.T, arch string) (string, string) {
	t.Helper()
	source, declarations := x86X87NativeConstantProgram(t, arch)
	pkg := mustGoPackage(t, "narrowconstant", "package narrowconstant\nfunc Narrow(cw uint16) float64")
	function := pkg.Types.Scope().Lookup("Narrow").(*types.Func)
	signature, err := DeriveGoFuncABI0Signature("Narrow", function, arch, types.SizesFor("gc", arch))
	if err != nil {
		t.Fatal(err)
	}
	if len(signature.Frame.Params) != 1 || len(signature.Frame.Results) != 1 || signature.Frame.Results[0].Type != LLVMType("double") {
		t.Fatal("unexpected actual constant-store declaration", signature)
	}
	cw := signature.Frame.Params[0].Offset
	result := signature.Frame.Results[0].Offset
	for _, op := range x86X87NativeConstants {
		name := "Narrow" + string(op)
		source += fmt.Sprintf("TEXT ·%s(SB),4,$0-%d\nFINIT\nFLDCW cw+%d(FP)\n%s\nFMOVDP F0,ret+%d(FP)\nRET\n", name, result+8, cw, op, result)
		declarations += fmt.Sprintf("func %s(cw uint16) float64\n", name)
	}
	return source, declarations
}

func x86X87PortablePublicConstantOracle(t *testing.T) string {
	t.Helper()
	if len(x87PortableObservedConstants) != len(x86X87NativeConstants) {
		t.Fatal("incomplete original native constant inventory")
	}
	var main strings.Builder
	main.WriteString("#include <stdint.h>\n#include <stdio.h>\n")
	for index, row := range x87PortableObservedConstants {
		if row.op != x86X87NativeConstants[index] {
			t.Fatal("native constant observation order changed", row.op)
		}
		fmt.Fprintf(&main, "extern uint16_t Constant%s(uint16_t,double);\nextern double Narrow%s(uint16_t);\n", row.op, row.op)
	}
	main.WriteString("int main(void){\nunsigned checks=0;\nunion{uint64_t bits;double value;} input={UINT64_C(0x400921fb54442d18)},output;\n")
	input := new(big.Rat).SetFloat64(math.Float64frombits(0x400921fb54442d18))
	for _, row := range x87PortableObservedConstants {
		for _, precision := range []uint16{0, 0x200, 0x300} {
			for rounding, significand := range row.significand {
				value := x87PortableBits{significand, row.exponent}
				exact, finite := x87PortableRational(value)
				if !finite {
					t.Fatal("constant observation is not a finite rational", row.op)
				}
				status := uint16(0)
				if order := exact.Cmp(input); order < 0 {
					status = 0x100
				} else if order == 0 {
					status = 0x4000
				}
				word := uint16(0x7f) | precision | uint16(rounding)<<10
				fmt.Fprintf(&main, "{uint16_t got=Constant%s(%d,input.value);if(got!=%d){fprintf(stderr,\"Constant%s cw=%%x got=%%x want=%%x\\n\",%d,got,%d);return 1;}checks++;}\n", row.op, word, status, row.op, word, status)
				bits := x87PortableNarrowOracle(value, 64, rounding)
				fmt.Fprintf(&main, "output.value=Narrow%s(%d);if(output.bits!=UINT64_C(%d)){fprintf(stderr,\"Narrow%s cw=%%x got=%%llx want=%%llx\\n\",%d,(unsigned long long)output.bits,(unsigned long long)UINT64_C(%d));return 2;}checks++;\n", row.op, word, bits, row.op, word, bits)
			}
		}
	}
	main.WriteString("if(checks!=168)return 3;return 0;\n}\n")
	return main.String()
}

func TestX86X87PortablePublicConstantsObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc is required")
	}
	for _, arch := range []string{"386", "amd64"} {
		source, declarations := x86X87PortablePublicConstantProgram(t, arch)
		for _, target := range []string{"i386-unknown-linux-gnu", "x86_64-unknown-linux-gnu", "armv7-unknown-linux-gnueabihf", "aarch64-unknown-linux-gnu", "wasm32-unknown-unknown"} {
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(arch+"/"+target+"/"+api, func(t *testing.T) {
					ir, err := x86X87InitializedWordAPI(t, source, declarations, arch, target, api, X87Software)
					if err != nil || ir == "" {
						t.Fatal("complete public Software constant/store source", err)
					}
					if strings.Contains(ir, "asm sideeffect") || strings.Contains(ir, "x86_fp80") || strings.Contains(ir, "fp128") {
						t.Fatal("portable constant path emitted a target-specific or approximate carrier")
					}
					for _, level := range []string{"-O0", "-O2"} {
						x86PackedStringCompileObject(t, llc, target, ir, level)
					}
				})
			}
		}
	}
}

func TestCrossLinuxRuntimeMatrixX86X87PortablePublicConstantsAndNarrowing(t *testing.T) {
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM22 llc and clang are required")
	}
	target := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	oracle := x86X87PortablePublicConstantOracle(t)
	for _, arch := range []string{"386", "amd64"} {
		source, declarations := x86X87PortablePublicConstantProgram(t, arch)
		for _, api := range []string{"text", "module", "Go"} {
			ir, err := x86X87InitializedWordAPI(t, source, declarations, arch, target, api, X87Software)
			if err != nil || ir == "" {
				t.Fatal("complete public Software constant/store source", err)
			}
			for _, level := range []int{0, 2} {
				t.Run(fmt.Sprintf("%s/%s/backend%d", arch, api, level), func(t *testing.T) {
					compileAndRunRuntimeTestWithCompiler(t, llc, []string{clang}, "portable80-public-constants", target, ir, oracle, nil, level)
				})
			}
		}
	}
}

func x86X87PortablePublicIntegerProgram(t *testing.T, arch string) (string, string) {
	t.Helper()
	pkg := mustGoPackage(t, "integernarrow", "package integernarrow\nfunc Value(cw uint16,input int64) float64")
	function := pkg.Types.Scope().Lookup("Value").(*types.Func)
	signature, err := DeriveGoFuncABI0Signature("Value", function, arch, types.SizesFor("gc", arch))
	if err != nil {
		t.Fatal(err)
	}
	cw, input := signature.Frame.Params[0].Offset, signature.Frame.Params[1].Offset
	result := signature.Frame.Results[0].Offset
	var source, declarations strings.Builder
	for _, name := range []string{"IntegerNarrow", "IntegerRoundNarrow"} {
		fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\nFINIT\nFLDCW cw+%d(FP)\nFMOVV input+%d(FP),F0\n", name, result+8, cw, input)
		if name == "IntegerRoundNarrow" {
			source.WriteString("FRNDINT\n")
		}
		fmt.Fprintf(&source, "FMOVDP F0,ret+%d(FP)\nRET\n", result)
		fmt.Fprintf(&declarations, "func %s(cw uint16,input int64) float64\n", name)
	}
	return source.String(), declarations.String()
}

func x86X87PortableIntegerNarrowOracle(t *testing.T) string {
	t.Helper()
	var main strings.Builder
	main.WriteString("#include <stdint.h>\n#include <stdio.h>\nextern double IntegerNarrow(uint16_t,int64_t);\nextern double IntegerRoundNarrow(uint16_t,int64_t);\nint main(void){union{double value;uint64_t bits;} out;\n")
	for _, input := range []int64{math.MinInt64, math.MinInt64 + 1, -9007199254740993, -1, 0, 1, 9007199254740993, math.MaxInt64} {
		exact := new(big.Float).SetPrec(128).SetInt64(input)
		exact.Abs(exact)
		mantissa := new(big.Float).SetPrec(128)
		exponent := exact.MantExp(mantissa)
		mantissa.SetMantExp(mantissa, 64)
		significand, accuracy := mantissa.Uint64()
		if accuracy != big.Exact {
			t.Fatal("int64 did not have an exact independent binary80 value", input)
		}
		value := x87PortableBits{significand, uint16(exponent - 1 + 16383)}
		if input == 0 {
			value.signExponent = 0
		} else if input < 0 {
			value.signExponent |= 0x8000
		}
		for _, precision := range []uint16{0, 0x200, 0x300} {
			for rounding := 0; rounding < 4; rounding++ {
				word := uint16(0x7f) | precision | uint16(rounding)<<10
				want := x87PortableNarrowOracle(value, 64, rounding)
				for _, name := range []string{"IntegerNarrow", "IntegerRoundNarrow"} {
					fmt.Fprintf(&main, "out.value=%s(%d,(int64_t)UINT64_C(%d));if(out.bits!=UINT64_C(%d)){fprintf(stderr,\"%s cw=%%x input=%%llx got=%%llx want=%%llx\\n\",%d,(unsigned long long)UINT64_C(%d),(unsigned long long)out.bits,(unsigned long long)UINT64_C(%d));return 1;}\n", name, word, uint64(input), want, name, word, uint64(input), want)
				}
			}
		}
	}
	main.WriteString("return 0;}\n")
	return main.String()
}

func TestCrossLinuxRuntimeMatrixX86X87PortableIntegerRoundAndNarrowing(t *testing.T) {
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM22 llc and clang are required")
	}
	target := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	oracle := x86X87PortableIntegerNarrowOracle(t)
	for _, arch := range []string{"386", "amd64"} {
		source, declarations := x86X87PortablePublicIntegerProgram(t, arch)
		for _, api := range []string{"text", "module", "Go"} {
			ir, err := x86X87InitializedWordAPI(t, source, declarations, arch, target, api, X87Software)
			if err != nil || ir == "" {
				t.Fatal("complete public Software integer/round/store source", err)
			}
			for _, level := range []int{0, 2} {
				t.Run(fmt.Sprintf("%s/%s/backend%d", arch, api, level), func(t *testing.T) {
					compileAndRunRuntimeTestWithCompiler(t, llc, []string{clang}, "portable80-public-integers", target, ir, oracle, nil, level)
				})
			}
		}
	}
}
