package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestX86StackPushNamedAddressIsImmediateNotMemory(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	for _, operand := range []string{
		"$·cell(SB)", "$·cell+8(SB)", "$·cell-8(SB)",
		"$other·cell(SB)", "$cell<>(SB)", "$runtime·mainPC(SB)",
		"$·cell+8(SB)(AX)", "$·cell-8(SB)(CX*4)",
		"$·cell(SB)(R8)(X1*4)",
	} {
		t.Run(operand, func(t *testing.T) {
			source := "TEXT ·Value(SB),4,$0-0\nPUSHL " + operand + "\nPOPL AX\nRET\n"
			goAssemblerOracleOutput(t, "386", source, "", true)
			parsed, err := parseOperandForArch(ArchAMD64, operand)
			if err != nil || parsed.Kind != OpSym || isAMD64MemoryOperand(parsed) {
				t.Fatalf("named address lost its independent immediate identity: %#v: %v", parsed, err)
			}
			for _, target := range x86AddressMemoryTargets("386") {
				for _, api := range []string{"text", "module", "go"} {
					t.Run(target+"/"+api, func(t *testing.T) {
						ir, err := x86AddressMemoryAPI(t, api, source, "386", target)
						if err != nil {
							t.Fatal("Go-accepted absolute address immediate was rejected:", err)
						}
						if !strings.Contains(ir, "ptrtoint ptr") || strings.Contains(ir, "load i32, ptr @") {
							t.Fatal("PUSHL acquired a symbolic load instead of the relocation's address")
						}
						x86ResultInitializationObject(t, llc, target, ir, "push-address")
					})
				}
			}
		})
	}
}

func TestX86StackNamedAddressModeAndDestinationBoundaries(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range []string{"PUSHW", "PUSHL", "PUSHQ", "POPW", "POPL", "POPQ"} {
			if arch == "386" && (op == "PUSHL" || op == "PUSHW") {
				// Only PUSHL has a valid four-byte relocation emitter. The
				// selected assembler's PUSHW Pe path supplies no relocation
				// sink; table-class acceptance is not a source-object proof.
				continue
			}
			for _, operand := range []string{"$·cell(SB)", "$·cell+8(SB)"} {
				instruction := op + " " + operand
				t.Run(arch+"/"+instruction, func(t *testing.T) {
					source := "TEXT ·Value(SB),4,$0-0\n" + instruction + "\nRET\n"
					goAssemblerOracleOutput(t, arch, source, "", false)
					for _, target := range x86AddressMemoryTargets(arch) {
						for _, api := range []string{"text", "module", "go"} {
							t.Run(target+"/"+api, func(t *testing.T) {
								if _, err := x86AddressMemoryAPI(t, api, source, arch, target); err == nil {
									t.Fatal("named address granted a source mode or memory destination outside Go's rules")
								}
							})
						}
					}
				})
			}
		}
	}

	for _, arch := range []string{"386", "amd64"} {
		push, pop := "PUSHQ", "POPQ"
		if arch == "386" {
			push, pop = "PUSHL", "POPL"
		}
		for _, address := range []string{"$arg+0(FP)", "$local-8(SP)"} {
			instruction := push + " " + address
			t.Run(arch+"/"+instruction, func(t *testing.T) {
				source := fmt.Sprintf("TEXT ·Value(SB),4,$16-0\n%s\n%s AX\nRET\n", instruction, pop)
				goAssemblerOracleOutput(t, arch, source, "", false)
				for _, target := range x86AddressMemoryTargets(arch) {
					for _, api := range []string{"text", "module", "go"} {
						if _, err := x86AddressMemoryAPI(t, api, source, arch, target); err == nil {
							t.Fatal("AUTO/PARAM address acquired an absolute immediate or native stack contract")
						}
					}
				}
			})
		}
	}
}
