package plan9asm

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

// Intel SDM Vol2A Table2-40 (2-44): EVEX.z on a store raises #UD,
// including the two named half conversions' E11 class (Vol2C 5-66).
// This is distinct from Go rejecting SAE with a memory ModRM operand.
func x86NamedHalfZeroStoreOriginalCodes(t *testing.T) [][]byte {
	t.Helper()
	var source strings.Builder
	for _, bank := range []string{"X", "Y", "Z"} {
		fmt.Fprintf(&source, "VCVTPS2PH $7,%s1,K1,(AX)\nVCVTPS2PH.Z $7,%s1,K1,(AX)\n", bank, bank)
	}
	code, pcs := x86NumericalBoundaryGoBytes(t, "amd64", source.String()+"RET\n")
	if len(pcs) != 7 {
		t.Fatal("Go did not emit all normal and zero-store opcode boundaries", pcs)
	}
	var result [][]byte
	for index := 0; index < 3; index++ {
		normal := code[pcs[2*index]:pcs[2*index+1]]
		zero := code[pcs[2*index+1]:pcs[2*index+2]]
		if len(normal) != len(zero) || len(zero) < 7 || normal[0] != 0x62 || normal[3]&0x80 != 0 ||
			zero[3]&0x80 == 0 || zero[3]>>5&3 != byte(index) || zero[5]>>6 == 3 || zero[len(zero)-1] != 7 {
			t.Fatal("actual Go zero-store lacks its independent width/memory/EVEX.z/imm witness", normal, zero)
		}
		for at := range normal {
			want := normal[at]
			if at == 3 {
				want |= 0x80
			}
			if zero[at] != want {
				t.Fatal("Go .Z changed more than the independent EVEX.z bit", normal, zero)
			}
		}
		result = append(result, append([]byte(nil), zero...))
	}
	return result
}

func TestX86NamedHalfZeroStoreOriginalGoAndLLVMEncodingPrior(t *testing.T) {
	codes := x86NamedHalfZeroStoreOriginalCodes(t)
	mc := findLLVM22Tool("llvm-mc")
	if mc == "" {
		t.Fatal("half zero-store physical prior requires LLVM22")
	}
	for _, triple := range []string{"x86_64-unknown-linux-gnu", "i386-unknown-linux-gnu"} {
		for index, code := range codes {
			for _, zero := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/width%d/zero=%t", triple, index, zero), func(t *testing.T) {
					var input strings.Builder
					for at, value := range code {
						if at == 3 && !zero {
							value &^= 0x80
						}
						fmt.Fprintf(&input, "0x%02x ", value)
					}
					stage, cancel := runtimeOracleStageContext(t)
					command := exec.CommandContext(stage, mc, "--disassemble", "--triple="+triple,
						"--mattr=+f16c,+avx512f,+avx512vl")
					command.Stdin = strings.NewReader(input.String())
					output, err := runtimeOracleCombinedOutput(stage, command)
					cancel()
					invalid := strings.Contains(string(output), "invalid instruction encoding")
					if err != nil || invalid != zero || !zero && !strings.Contains(string(output), "vcvtps2ph") {
						t.Fatalf("independent normal/store #UD distinction differs: %v\n%s", err, output)
					}
				})
			}
		}
	}
}

func TestX86NamedHalfZeroStoreFaultBeforeInputsThreeAPIFiveTargetObjects(t *testing.T) {
	codes := x86NamedHalfZeroStoreOriginalCodes(t)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("named half zero-store objects require LLVM22")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			var source, declarations strings.Builder
			var names []string
			for index, bank := range []string{"X", "Y", "Z"} {
				// Go386 rejects the named four-operand spelling. Exact original
				// low-bank physical bytes remain valid format inputs in mode32.
				if target.arch == "amd64" {
					fmt.Fprintf(&source, "TEXT NamedFault%d(SB),4,$0-0\nVCVTPS2PH.Z $7,%s1,K1,(AX)\nRET\n", index, bank)
					fmt.Fprintf(&declarations, "func NamedFault%d()\n", index)
					names = append(names, fmt.Sprint("NamedFault", index))
				}
				fmt.Fprintf(&source, "TEXT PhysicalFault%d(SB),4,$0-0\n%sRET\n", index, x86RawDisplacementDirectives(codes[index]))
				fmt.Fprintf(&declarations, "func PhysicalFault%d()\n", index)
				names = append(names, fmt.Sprint("PhysicalFault", index))
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
					if err != nil {
						t.Fatal("Go-accepted #UD required unknown data, mask, address or native entry before faulting", err)
					}
					for _, module := range []string{ir, x86DwordProductIROptimize(t, ir)} {
						const trap = `call void asm sideeffect "ud2", "~{memory}"()`
						if strings.Count(module, trap) != len(names) {
							t.Fatal("half zero-store lost its complete original function inventory")
						}
						for _, name := range names {
							// Unused module declarations are not executed stores.
							// Inspect every original function, including raw #UD.
							body := x86StringMemoryFunction(t, module, name)
							if strings.Count(body, trap) != 1 || !strings.Contains(body, "\n  unreachable\n") ||
								strings.Contains(body, "llvm.masked.store") || strings.Contains(body, "vcvtps2ph") ||
								strings.Contains(body, " = load ") {
								t.Fatal("half zero-store read inputs, performed a store or lost exact #UD", name, body)
							}
						}
						compileLLVMToObject(t, llc, target.triple, "half-zero-store.ll", "half-zero-store.o", module)
					}
				})
			}
		})
	}
}

func TestX86NamedHalfZeroStoreFaultPrecedesFPBoundsAndMaskReads(t *testing.T) {
	for _, bank := range []string{"X", "Y", "Z"} {
		for _, immediate := range []int64{0, 7, 255} {
			ins := x86ScalarLaneInstruction(t, fmt.Sprintf("VCVTPS2PH.Z $%d,%s1,K1,(AX)", immediate, bank))
			ins.Args[3] = Operand{Kind: OpFP, FPOffset: 1 << 20}
			context, output := newAMD64CtxWithFuncForTest(t, Func{}, FuncSig{Ret: Void}, nil)
			context.goarch = "amd64"
			before := output.Len()
			known, terminal, err := context.lowerPackedHalfConversion(ins.Op, ins)
			if !known || !terminal || err != nil || output.String()[before:] !=
				"  call void asm sideeffect \"ud2\", \"~{memory}\"()\n  unreachable\n" {
				t.Fatal("half #UD evaluated nonexistent FP bounds or unknown vector/K data", bank, immediate, known, terminal, err)
			}
		}
	}
}

func TestX86NamedHalfSAEMemoryHasActualGoRejectionNotStorePermission(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, line := range []string{"VCVTPH2PS.SAE (AX),Z1", "VCVTPS2PH.SAE $0,Z1,(AX)"} {
			t.Run(arch+"/"+line, func(t *testing.T) {
				goAssemblerOracleOutput(t, arch, "TEXT SAE(SB),4,$0-0\n"+line+"\nRET\n", "", false)
				ins := x86ScalarLaneInstruction(t, line)
				context, output := newAMD64CtxWithFuncForTest(t, Func{}, FuncSig{Ret: Void}, nil)
				context.goarch = arch
				before := output.Len()
				known, terminal, err := context.lowerPackedHalfConversion(ins.Op, ins)
				if !known || terminal || err == nil || output.Len() != before {
					t.Fatal("Go-invalid SAE memory emitted IR or acquired a native/mathematical input role", known, terminal, err)
				}
			})
		}
	}
}
