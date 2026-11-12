package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestX86PackedLowMultiplyThreeAPIsFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			rows := x86LowMultiplyFormatRows(target.arch)
			for begin := 0; begin < len(rows); begin += 64 {
				end := begin + 64
				if end > len(rows) {
					end = len(rows)
				}
				t.Run(fmt.Sprint(begin), func(t *testing.T) {
					var source, declarations strings.Builder
					for index, row := range rows[begin:end] {
						if strings.HasPrefix(row, "PMULLD ") && (strings.Contains(row, "(FP)") || strings.Contains(row, "(SP)")) {
							// These original-Go forms have an explicit rejection
							// regression below, not a successful object claim.
							continue
						}
						fmt.Fprintf(&declarations, "func Low%d(value [64]byte)\n", index)
						fmt.Fprintf(&source, "TEXT ·Low%d(SB),4,$64-64\n%s\nRET\n", index, row)
					}
					x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
					for _, api := range []string{"text", "module", "Go"} {
						ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
						if err != nil {
							t.Fatal(api, err)
						}
						x86ResultInitializationObject(t, llc, target.triple, ir, "low-multiply-"+api)
						x86ResultInitializationObject(t, llc, target.triple, x86MulDivRoundOptimize(t, ir), "low-multiply-"+api+"-optimized")
					}
				})
			}
		})
	}
}

func TestX86PackedLowMultiplyVirtualLegacyStorageRemainsContext(t *testing.T) {
	for _, row := range []string{"PMULLD value+0(FP),X1", "PMULLD local-16(SP),X1", "PMULLD (SP),X1", "PMULLD (BP),X1"} {
		for _, target := range x86RawReturnTargets {
			source := "TEXT ·Low(SB),4,$64-64\nPXOR X1,X1\n" + row + "\nRET\n"
			declaration := "func Low(value [64]byte)"
			address := strings.Fields(row)[1]
			address = strings.Split(address, ",")[0]
			if address == "(BP)" || address == "(SP)" {
				source = x86OrdinaryBPNativeSource(target.arch, "Low", row, address, 64)
				declaration = "func Low(p *byte)"
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(target.triple+"/"+row+"/"+api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, api)
					x86RequireOrdinaryBPNativeOutcome(t, target.arch, address, ir, err)
				})
			}
		}
	}
}

func TestX86PackedLowMultiplyResultMemoryAndMasks(t *testing.T) {
	for _, op := range []string{"VPMULLW", "VPMULLD", "VPMULLQ"} {
		for _, broadcast := range []bool{false, true} {
			if broadcast && op == "VPMULLW" {
				continue
			}
			row, width := op, 16
			if broadcast {
				row, width = row+".BCST", 4
				if op == "VPMULLQ" {
					width = 8
				}
			}
			row += ".Z value+0(FP),X1,K1,X2"
			goAssemblerOracleOutput(t, "amd64", "TEXT f(SB),4,$0-16\n"+row+"\nRET\n", "", true)
			ins := x86ScalarLaneInstruction(t, row)
			for missing := -1; missing < 16; missing++ {
				for _, maskKnown := range []bool{false, true} {
					state := x86ResultState{fp: make([]bool, 16)}
					owned := make([]bool, 16)
					for i := range owned {
						owned[i], state.fp[i] = true, i != missing
					}
					state.xmm[1], state.masks[1] = 0xffff, maskKnown
					accepted := x86ResultTransfer(ins, &state, owned, 16, "amd64")
					want := maskKnown && (missing < 0 || missing >= width)
					if accepted != want || accepted && state.vectorBytes(2) != ^uint64(0) || len(ins.x86CallerMemory) != 0 {
						t.Fatal("mask/tuple observation invented bytes or caller permission", row, missing, maskKnown, accepted)
					}
				}
			}
		}
	}
}

func TestX86PackedLowMultiplyResultThreeAPIs(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	var source, declarations strings.Builder
	for index, row := range []string{"PMULLW X0,X1", "VPMULLW X0,X1,X1", "PMULLD X0,X1", "VPMULLD X0,X1,X1", "VPMULLQ X0,X1,X1"} {
		fmt.Fprintf(&declarations, "func Low%d() uint32\n", index)
		fmt.Fprintf(&source, "TEXT ·Low%d(SB),4,$0-4\nMOVL $0x87654321,AX\n", index)
		for _, reg := range []string{"X0", "X1"} {
			for lane := 0; lane < 4; lane++ {
				fmt.Fprintf(&source, "PINSRD $%d,AX,%s\n", lane, reg)
			}
		}
		fmt.Fprintf(&source, "%s\nPEXTRD $0,X1,AX\nMOVL AX,ret0+0(FP)\nRET\n", row)
	}
	for _, target := range x86RawReturnTargets {
		x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
		for _, api := range []string{"text", "module", "Go"} {
			ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
			if err != nil {
				t.Fatal(target, api, err)
			}
			x86ResultInitializationObject(t, llc, target.triple, ir, "low-multiply-result-"+api)
		}
	}
}
