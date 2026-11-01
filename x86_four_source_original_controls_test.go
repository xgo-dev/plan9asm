package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

const x86FourSourceOriginalDeclarations = `
func foursourcesemantics(in *[512]byte,out *[272]byte,mask uint64)
func foursourcefaultsuppression(memory *[16]byte,out *[144]byte,mask uint64)
`

func TestX86FourSourceOriginalCompleteProgramGoObjectsAndContext(t *testing.T) {
	source, _ := x86FourSourceOriginalProgram(t)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("the unchanged original program's format objects require exact LLVM22")
	}
	for _, target := range x86RawReturnTargets {
		if target.arch != "amd64" {
			continue // Original masked four-operand source is not Go's named 386 grammar.
		}
		t.Run(target.triple, func(t *testing.T) {
			x86LEAActualTargetGoObject(t, "amd64", target.triple, "#include \"textflag.h\"\n"+source)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, x86FourSourceOriginalDeclarations, "amd64", target.triple, api)
					if ir != "" || !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), "foursourcefaultsuppression") {
						t.Fatal("the complete original second TEXT must not borrow C's mask=0 call or implementation-slot zeros", err)
					}
				})
			}
			file, err := Parse(ArchAMD64, source)
			if err != nil || len(file.Funcs) != 2 {
				t.Fatal("the private original format object lost a complete TEXT", err)
			}
			ir := x86ScalarFormatObjectUnit(t, file, x86FourSourceOriginalSignatures(), "amd64", target.triple, 0)
			for _, body := range []string{ir, x86DwordProductIROptimize(t, ir)} {
				compileLLVMToObject(t, llc, target.triple, "four-source-original-format.ll", "four-source-original-format.o", body)
			}
		})
	}
}

func TestX86FourSourceOriginalInitializedFirstTEXTActualObjects(t *testing.T) {
	original, _ := x86FourSourceOriginalProgram(t)
	source, _, found := strings.Cut(original, "\nTEXT foursourcefaultsuppression(SB)")
	if !found || strings.Count(source, "TEXT ") != 1 || !strings.HasSuffix(source, "\tRET\n") {
		t.Fatal("the original initialized first TEXT was not retained in full")
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("the original initialized first TEXT requires exact LLVM22")
	}
	for _, target := range x86RawReturnTargets {
		if target.arch != "amd64" {
			continue // Independent legal 386 family counterparts are separate, not edited originals.
		}
		t.Run(target.triple, func(t *testing.T) {
			x86LEAActualTargetGoObject(t, "amd64", target.triple, "#include \"textflag.h\"\n"+source)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source,
						"func foursourcesemantics(in *[512]byte,out *[272]byte,mask uint64)", "amd64", target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("the original fully initialized source remains a public positive, not a format or Context fixture", err)
					}
					for _, body := range []string{ir, x86DwordProductIROptimize(t, ir)} {
						compileLLVMToObject(t, llc, target.triple, "four-source-original-inputs.ll", "four-source-original-inputs.o", body)
					}
				})
			}
		})
	}
}

func TestX86FourSourceHighBanksAndAlignedBlocksActualObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("complete physical register-bank counterparts require exact LLVM22")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			firsts, destination := []int{26, 28}, 31
			if target.arch == "386" {
				firsts, destination = []int{4}, 6
			}
			var source, declarations strings.Builder
			count := 0
			for _, member := range x86FourSourceOracle {
				for _, first := range firsts {
					for _, mode := range []string{"plain", "merge", "zero"} {
						if target.arch == "386" && mode != "plain" {
							continue
						}
						row := x86FourSourceOracleRow{op: member.op, scalar: member.scalar, dot: member.dot,
							first: first, dest: destination, mode: mode}
						body, declaration := x86FourSourceInitializedSource(row, target.arch, fmt.Sprint("HighFour", count), false)
						source.WriteString(body)
						declarations.WriteString(declaration)
						count++
					}
				}
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("the complete valid high/effective aligned block lost its actual original inputs", err)
					}
					for _, body := range []string{ir, x86DwordProductIROptimize(t, ir)} {
						compileLLVMToObject(t, llc, target.triple, "four-source-banks.ll", "four-source-banks.o", body)
					}
				})
			}
		})
	}
}

func TestX86FourSourceRequiresOriginalNativeBackingAndTarget(t *testing.T) {
	for _, member := range x86FourSourceOracle {
		row := x86FourSourceOracleRow{op: member.op, scalar: member.scalar, dot: member.dot, first: 2, dest: 6, mode: "plain"}
		for _, triple := range []string{"aarch64-unknown-linux-gnu", "armv7-unknown-linux-gnueabihf", "wasm32-unknown-unknown"} {
			t.Run(member.op+"/"+triple, func(t *testing.T) {
				source, declaration := x86FourSourceInitializedSource(row, "amd64", "Value", false)
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, source, declaration, "amd64", triple, api)
					if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("portable mathematics silently replaced original x86 exception/native-access behavior", api, err)
					}
				}
			})
		}
		for _, arch := range []string{"386", "amd64"} {
			t.Run(member.op+"/"+arch+"/logical FP", func(t *testing.T) {
				triple := "x86_64-unknown-linux-gnu"
				if arch == "386" {
					triple = "i386-unknown-linux-gnu"
				}
				var source strings.Builder
				source.WriteString("TEXT ·Value(SB),4,$0-16\n")
				for register := 0; register < 7; register++ {
					fmt.Fprintf(&source, "VPXORD Z%d,Z%d,Z%d\n", register, register, register)
				}
				source.WriteString(strings.Replace(row.instruction(), "(BX)", "a+0(FP)", 1) + "\nRET\n")
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), "func Value(a,b uint64)", arch, triple, api)
					if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("two initialized logical FP scalars acquired contiguous original m128 native storage", api, err)
					}
				}
			})
		}
	}
}
