package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestX86StaticAddressValueCompleteMoveFormsAndObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc is required")
	}
	for _, target := range dataRelocationTargets {
		if target.arch != ArchAMD64 {
			continue
		}
		t.Run(target.triple, func(t *testing.T) {
			word, move := 8, "MOVQ"
			moves := []string{"MOVQ", "MOVD", "MOVDQ2Q"}
			operands := []string{"box<>+8(SB)", "$bytes<>+3(SB)", "$bytes<>-1(SB)", "$bytes<>+17(SB)"}
			if target.goarch == "386" {
				word, move, moves = 4, "MOVL", []string{"MOVL"}
				operands = append(operands, "box<>+8(SB)(SP)", "$bytes<>+3(SB)(AX)(CX*2)")
			}
			var source, declarations strings.Builder
			fmt.Fprintf(&source, "DATA bytes<>(SB)/8,$0x1122334455667788\nGLOBL bytes<>(SB),16,$16\n"+
				"DATA box<>+8(SB)/%d,$bytes<>+3(SB)\nGLOBL box<>(SB),16,$24\n", word)
			for _, opcode := range moves {
				for index, operand := range operands {
					name := fmt.Sprintf("Value%s%d", opcode, index)
					fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n%s %s,AX\n%s AX,ret+0(FP)\nRET\n", name, word, opcode, operand, move)
					fmt.Fprintf(&declarations, "func %s() uintptr\n", name)
				}
			}
			dataRelocationGoObject(t, source.String(), target.goos, target.goarch, true)
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.goarch, target.triple, api)
				if err != nil || ir == "" {
					t.Fatalf("complete native-word address forms: %s: %v", api, err)
				}
				for _, irLevel := range []string{"0", "2"} {
					objectIR := ir
					if irLevel == "2" {
						objectIR = x86DwordProductIROptimize(t, ir)
					}
					for _, backendLevel := range []string{"0", "2"} {
						t.Run(api+"/IR"+irLevel+"/backend"+backendLevel, func(t *testing.T) {
							x86PackedStringCompileObject(t, llc, target.triple, objectIR, "-O"+backendLevel)
						})
					}
				}
			}
		})
	}
}

func TestX86StaticAddressValueDoesNotAuthorizeNativeDereference(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		move := "MOVQ"
		if target.arch == "386" {
			move = "MOVL"
		}
		for _, form := range []string{"load", "address"} {
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(target.triple+"/"+form+"/"+api, func(t *testing.T) {
					source := x86RelocationResultSource(target.arch, form)
					source = strings.Replace(source, move+" AX,ret+0(FP)", "MOVB (AX),CX\n"+move+" AX,ret+0(FP)", 1)
					if ir, err := x86ScalarFPBitViewAPI(t, source, "func Value() uintptr", target.arch, target.triple, api); err == nil || ir != "" {
						t.Fatal("numerical DATA address acquired native-memory permission", err)
					}
				})
			}
		}
	}
}
