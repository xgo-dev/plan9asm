package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// yaddl's Yi32 rows have an absolute four-byte relocation sink on non-shared
// 386. TYPE_ADDR is still not a memory operand or a caller/frame capability.
func TestX86ScalarAbsoluteRelocationCompleteFamily(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	for _, stem := range []string{"ADD", "SUB", "ADC", "SBB", "AND", "OR", "XOR"} {
		for _, destination := range []string{"AX", "BX", "CX", "DX", "SI", "DI", "BP", "SP", "(AX)", "·sink(SB)"} {
			row := stem + "L $·cell+8(SB)," + destination
			t.Run(row, func(t *testing.T) {
				source := "TEXT ·Value(SB),4,$0-0\nMOVL $0,AX\nCLC\n" + row + "\nRET\n"
				goAssemblerOracleOutput(t, "386", source, "", true)
				ins := x86PureGPUnknownInstruction(t, row)
				if _, known, err := x86LockScalarRMWProperties(ins.Op, ins, "386"); !known || err != nil {
					t.Fatalf("Go-accepted absolute source was lost by typed grammar: %v", err)
				}
				// Physical SP/BP and native writes retain separate entry/storage
				// contracts. Their source rows above are Go-object observations.
				if destination == "SP" || destination == "BP" || destination == "(AX)" {
					return
				}
				for _, target := range x86AddressMemoryTargets("386") {
					for _, api := range []string{"text", "module", "go"} {
						ir, err := x86AddressMemoryAPI(t, api, source, "386", target)
						if destination == "·sink(SB)" {
							// The original source declares neither external object's
							// storage. Keep its complete Go/emitter objects, not a
							// fabricated public numerical-memory proof. Independent
							// initialized DATA counterparts exercise public lowering.
							if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
								t.Fatal("unbound original storage acquired public input facts", err)
							}
							if api != "text" {
								continue
							}
							file, parseErr := Parse(ArchAMD64, source)
							if parseErr != nil {
								t.Fatal(parseErr)
							}
							ir = x86ScalarFormatObjectUnit(t, file, map[string]FuncSig{"Value": {Name: "Value", Ret: Void}}, "386", target, 0)
						} else if err != nil {
							t.Fatalf("%s %s: %v", target, api, err)
						}
						if !strings.Contains(ir, "ptrtoint ptr") || strings.Contains(ir, "load i32, ptr @cell") {
							t.Fatal("relocated immediate became a source memory read")
						}
						x86ResultInitializationObject(t, llc, target, ir, "scalar-relocation")
					}
				}
			})
		}
	}
}

func TestX86ScalarAbsoluteRelocationSourceAxesAndBoundaries(t *testing.T) {
	for _, source := range []string{
		"$·cell(SB)", "$cell<>-8(SB)", "$other·cell+8(SB)", "$runtime·callbackasm(SB)",
		"$·cell(SB)(AX)", "$·cell(SB)(CX*4)", "$·cell(SB)(R8)(X1*4)",
	} {
		row := "SUBL " + source + ",AX"
		goAssemblerOracleOutput(t, "386", "TEXT ·Value(SB),4,$0-0\n"+row+"\nRET\n", "", true)
		ins := x86PureGPUnknownInstruction(t, row)
		if _, known, err := x86LockScalarRMWProperties(ins.Op, ins, "386"); !known || err != nil {
			t.Fatalf("relocation source axis %s: %v", source, err)
		}
	}
	for _, stem := range []string{"ADD", "SUB", "ADC", "SBB", "AND", "OR", "XOR"} {
		for _, arch := range []string{"386", "amd64"} {
			for _, width := range "BWLQ" {
				if arch == "386" && width == 'L' {
					continue
				}
				row := fmt.Sprintf("%s%c $·cell(SB),AX", stem, width)
				ins := x86PureGPUnknownInstruction(t, row)
				if _, known, err := x86LockScalarRMWProperties(ins.Op, ins, arch); !known || err == nil {
					t.Fatalf("relocation widened beyond its actual four-byte source-mode sink: %s %s", arch, row)
				}
				// B/W have no relocation sink; an assembler backend diagnostic
				// is not source-rejection evidence. AMD64 uses Yiauto, not Yi32.
				if arch == "amd64" {
					goAssemblerOracleOutput(t, arch, "TEXT ·Value(SB),4,$0-0\n"+row+"\nRET\n", "", false)
				}
			}
		}
	}
}
