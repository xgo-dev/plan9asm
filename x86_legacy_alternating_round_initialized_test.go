package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

// Public initialized legacy objects, independently of bare private format
// units. Every function observes all 64 destination-alias bytes. The four FP
// variants consume declared numeric parameters, never native pointer reads.
func TestX86LegacyAlternatingRoundInitializedPublicFiveTargets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			move := "MOVQ"
			if target.arch == "386" {
				move = "MOVL"
			}
			var source, declarations strings.Builder
			appendFunction := func(name, declaration, body string) {
				// Reuse actual Go ABI0 derivation, including the target's FP
				// parameter offsets and TEXT extent; do not guess a layout.
				_, _, function := x86ScalarFPVoidSource(t, declaration, body, target.arch)
				source.WriteString(strings.Replace(function, "·view(SB)", "·"+name+"(SB)", 1))
				declarations.WriteString(strings.Replace(declaration, "func view(", "func "+name+"(", 1) + "\n")
			}
			const registerDeclaration = "func view(out *[64]byte)"
			_, registerSignature, _ := x86ScalarFPVoidSource(t, registerDeclaration, "", target.arch)
			if len(registerSignature.Frame.Params) != 1 {
				t.Fatal("actual output signature changed")
			}
			for index, op := range []string{"ADDSUBPS", "ADDSUBPD", "ROUNDPS", "ROUNDPD", "ROUNDSS", "ROUNDSD"} {
				instruction := op + " X0,X1"
				if strings.HasPrefix(op, "ROUND") {
					instruction = op + " $0,X0,X1"
				}
				body := fmt.Sprintf("%s out+%d(FP),AX\nVPXOR Y0,Y0,Y0\nVPXOR Y1,Y1,Y1\n%s\nVMOVUPS Z1,(AX)", move, registerSignature.Frame.Params[0].Offset, instruction)
				appendFunction(fmt.Sprint("InitializedLegacyRoundRegister", index), registerDeclaration, body)
			}
			for _, row := range []struct{ op, typ, scalarMove string }{
				{"ROUNDSS", "float32", "MOVSS"}, {"ROUNDSD", "float64", "MOVSD"},
			} {
				declaration := "func view(out *[64]byte,x " + row.typ + ")"
				_, signature, _ := x86ScalarFPVoidSource(t, declaration, "", target.arch)
				if len(signature.Frame.Params) != 2 {
					t.Fatal("actual scalar parameter signature changed")
				}
				for index, viaRegister := range []bool{false, true} {
					input := fmt.Sprintf("x+%d(FP)", signature.Frame.Params[1].Offset)
					body := fmt.Sprintf("%s out+%d(FP),AX\nVPXOR Y0,Y0,Y0\nVPXOR Y1,Y1,Y1\n", move, signature.Frame.Params[0].Offset)
					if viaRegister {
						body += row.scalarMove + " " + input + ",X0\n"
						input = "X0"
					}
					body += row.op + " $0," + input + ",X1\nVMOVUPS Z1,(AX)"
					appendFunction(fmt.Sprintf("InitializedLegacy%sFP%d", row.op, index), declaration, body)
				}
			}
			file, err := Parse(ArchAMD64, source.String())
			if err != nil || len(file.Funcs) != 10 {
				t.Fatal("six register plus four numeric-FP counterparts changed", err)
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("initialized legacy register/numeric-FP source rejected", api, err)
					}
					for _, level := range []string{"-O0", "-O2"} {
						x86PackedStringCompileObject(t, llc, target.triple, ir, level)
					}
				})
			}
		})
	}
}
