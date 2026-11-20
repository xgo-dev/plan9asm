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

func x86X87PortableSqrtPublicProgram(t *testing.T, arch string) (string, string) {
	t.Helper()
	var source, declarations strings.Builder
	for _, shape := range []struct{ name, inputType, load, afterLoad string }{
		{"Scalar", "float64", "FMOVD", ""},
		{"Integer", "int64", "FMOVV", ""},
		{"Pi", "", "FLDPI", ""},
		{"Square", "float64", "FMOVD", "FMULD F0,F0\n"},
	} {
		for _, compare := range []bool{true, false} {
			suffix, resultType := "Narrow", "float64"
			parameters := "cw uint16"
			if shape.inputType != "" {
				parameters += ",input " + shape.inputType
			}
			if compare {
				suffix, resultType = "Status", "uint16"
				parameters += ",threshold float64"
			}
			name := "Sqrt" + shape.name + suffix
			declaration := fmt.Sprintf("func %s(%s) %s\n", name, parameters, resultType)
			pkg := mustGoPackage(t, "sqrtfixture", "package sqrtfixture\n"+declaration)
			sig, err := DeriveGoFuncABI0Signature(name, pkg.Types.Scope().Lookup(name).(*types.Func), arch, types.SizesFor("gc", arch))
			if err != nil || len(sig.Frame.Results) != 1 || len(sig.Frame.Params) < 1 {
				t.Fatal("complete actual square-root declaration", name, sig, err)
			}
			result, width := sig.Frame.Results[0], int64(8)
			if compare {
				width = 2
				if result.Type != I16 {
					t.Fatal("status result is not the derived word", result)
				}
			} else if result.Type != LLVMType("double") {
				t.Fatal("narrow result is not the derived float64", result)
			}
			fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\nFINIT\nFLDCW cw+%d(FP)\n", name, result.Offset+width, sig.Frame.Params[0].Offset)
			if compare {
				fmt.Fprintf(&source, "FMOVD threshold+%d(FP),F0\n", sig.Frame.Params[len(sig.Frame.Params)-1].Offset)
			}
			if shape.inputType == "" {
				source.WriteString(shape.load + "\n")
			} else {
				fmt.Fprintf(&source, "%s input+%d(FP),F0\n", shape.load, sig.Frame.Params[1].Offset)
			}
			source.WriteString(shape.afterLoad + "FSQRT\n")
			if compare {
				fmt.Fprintf(&source, "FCOMD F1,F0\nFSTSW AX\nANDW $0x4500,AX\nMOVW AX,ret+%d(FP)\nFMOVDP F0,F0\nFMOVDP F0,F0\nRET\n", result.Offset)
			} else {
				fmt.Fprintf(&source, "FMOVDP F0,ret+%d(FP)\nRET\n", result.Offset)
			}
			declarations.WriteString(declaration)
		}
	}
	return source.String(), declarations.String()
}

func x86X87PortableSqrtPublicOracle(t *testing.T) string {
	t.Helper()
	type input struct {
		shape string
		bits  uint64
		word  int64
	}
	var inputs []input
	for _, bits := range []uint64{
		0, 1 << 63, 0x3ff0000000000000, 0x4000000000000000, 0x4008000000000000,
		0x4010000000000000, 0x3fefffffffffffff, 0x3ff0000000000001,
		1, 0x0010000000000000, 0x7fefffffffffffff,
		0xbff0000000000000, 0x7ff0000000000000, 0xfff0000000000000,
		0x7ff8000000000001, 0xfff8000000000001, 0x7ff0000000000001,
	} {
		inputs = append(inputs, input{shape: "Scalar", bits: bits})
	}
	for _, word := range []int64{0, 1, 2, 3, 4, 1<<53 - 1, 1<<53 + 1, math.MaxInt64, -1, math.MinInt64} {
		inputs = append(inputs, input{shape: "Integer", word: word})
	}
	inputs = append(inputs, input{shape: "Pi"},
		input{shape: "Square", bits: uint64(1023+1000) << 52},
		input{shape: "Square", bits: uint64(1023-1000) << 52})
	var c strings.Builder
	c.WriteString("#include <stdint.h>\n#include <stdio.h>\n")
	for _, shape := range []string{"Scalar", "Integer", "Pi", "Square"} {
		argument := ",double"
		if shape == "Pi" {
			argument = ""
		} else if shape == "Integer" {
			argument = ",int64_t"
		}
		fmt.Fprintf(&c, "extern uint16_t Sqrt%sStatus(uint16_t%s,double);\nextern double Sqrt%sNarrow(uint16_t%s);\n", shape, argument, shape, argument)
	}
	c.WriteString("int main(void){unsigned errors=0,checks=0;union{uint64_t bits;double value;}input,threshold,output;\n")
	for index, item := range inputs {
		for _, precision := range []int{24, 53, 64} {
			pc := map[int]int{24: 0, 53: 0x200, 64: 0x300}[precision]
			for rounding := 0; rounding < 4; rounding++ {
				cw := 0x7f | pc | rounding<<10
				kind, negativeZero := "finite", item.bits == 1<<63 && item.shape == "Scalar"
				var exact *big.Rat
				switch item.shape {
				case "Pi":
					row := x87PortableObservedConstants[2]
					if row.op != "FLDPI" {
						t.Fatal("missing independent native pi observation")
					}
					exact, _ = x87PortableRational(x87PortableBits{row.significand[rounding], row.exponent})
				case "Integer":
					exact = new(big.Rat).SetInt64(item.word)
				default:
					x := math.Float64frombits(item.bits)
					switch {
					case math.IsNaN(x), math.IsInf(x, -1):
						kind = "nan"
					case math.IsInf(x, 1):
						kind = "inf"
					default:
						exact = new(big.Rat).SetFloat64(x)
						if item.shape == "Square" {
							exact.Mul(exact, exact)
						}
					}
				}
				if exact != nil && exact.Sign() < 0 {
					kind = "nan"
				}
				var comparison, narrow uint64
				status := uint16(0)
				if kind == "finite" {
					result := x87PortableSqrtSquareOracle(exact, precision, rounding)
					if negativeZero {
						result.signExponent = 0x8000
					}
					comparison = x87PortableNarrowOracle(result, 64, 0)
					narrow = x87PortableNarrowOracle(result, 64, rounding)
					value, _ := x87PortableRational(result)
					threshold := new(big.Rat).SetFloat64(math.Float64frombits(comparison))
					if order := value.Cmp(threshold); order == 0 {
						status = 0x4000
					} else if order < 0 {
						status = 0x100
					}
				} else if kind == "nan" {
					status = 0x4500
				} else {
					narrow = 0x7ff0000000000000
				}
				fmt.Fprintf(&c, "{input.bits=UINT64_C(%d);threshold.bits=UINT64_C(%d);", item.bits, comparison)
				argument := ",input.value"
				if item.shape == "Pi" {
					argument = ""
				} else if item.shape == "Integer" {
					argument = fmt.Sprintf(",((int64_t)UINT64_C(%d))", uint64(item.word))
				}
				fmt.Fprintf(&c, "uint16_t status=Sqrt%sStatus(%d%s,threshold.value);if(status!=%d){errors++;fprintf(stderr,\"sqrt case=%d %s p=%d rc=%d status=%%x want=%%x\\n\",status,%d);}checks++;", item.shape, cw, argument, status, index, item.shape, precision, rounding, status)
				fmt.Fprintf(&c, "output.value=Sqrt%sNarrow(%d%s);", item.shape, cw, argument)
				if kind == "nan" {
					// Exact payload/sign needs its own independent native FSQRT
					// anchors. This public check requires the actual quiet-NaN class.
					fmt.Fprintf(&c, "if((output.bits&UINT64_C(0x7ff8000000000000))!=UINT64_C(0x7ff8000000000000)){errors++;fprintf(stderr,\"sqrt case=%d did not produce a quiet NaN\\n\");}", index)
				} else {
					fmt.Fprintf(&c, "if(output.bits!=UINT64_C(%d)){errors++;fprintf(stderr,\"sqrt case=%d %s p=%d rc=%d bits=%%llx want=%%llx\\n\",(unsigned long long)output.bits,(unsigned long long)UINT64_C(%d));}", narrow, index, item.shape, precision, rounding, narrow)
				}
				c.WriteString("checks++;}\n")
			}
		}
	}
	fmt.Fprintf(&c, "if(checks!=%d)return 2;if(errors)fprintf(stderr,\"sqrt public checks=%%u errors=%%u\\n\",checks,errors);return errors!=0;}\n", len(inputs)*3*4*2)
	return c.String()
}

func TestX86X87PortableSqrtPublicObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc is required")
	}
	for _, arch := range []string{"386", "amd64"} {
		source, declarations := x86X87PortableSqrtPublicProgram(t, arch)
		for _, target := range []string{"i386-unknown-linux-gnu", "x86_64-unknown-linux-gnu", "armv7-unknown-linux-gnueabihf", "aarch64-unknown-linux-gnu", "wasm32-unknown-unknown"} {
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(arch+"/"+target+"/"+api, func(t *testing.T) {
					ir, err := x86X87InitializedWordAPI(t, source, declarations, arch, target, api, X87Software)
					if err != nil || ir == "" {
						t.Fatal("existing initialized FSQRT source rejected", err)
					}
					for _, level := range []string{"-O0", "-O2"} {
						x86PackedStringCompileObject(t, llc, target, ir, level)
					}
				})
			}
		}
	}
}

func TestCrossLinuxRuntimeMatrixX86X87PortableSqrtPublic(t *testing.T) {
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM22 llc/clang are required")
	}
	oracle, target := x86X87PortableSqrtPublicOracle(t), testTargetTriple(runtime.GOOS, runtime.GOARCH)
	for _, arch := range []string{"386", "amd64"} {
		source, declarations := x86X87PortableSqrtPublicProgram(t, arch)
		for _, api := range []string{"text", "module", "Go"} {
			ir, err := x86X87InitializedWordAPI(t, source, declarations, arch, target, api, X87Software)
			if err != nil || ir == "" {
				t.Fatal("complete initialized FSQRT program", err)
			}
			for _, level := range []int{0, 2} {
				t.Run(fmt.Sprintf("%s/%s/backend%d", arch, api, level), func(t *testing.T) {
					compileAndRunRuntimeTestWithCompiler(t, llc, []string{clang}, "portable-sqrt-public", target, ir, oracle, nil, level)
				})
			}
		}
	}
}
