package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// The private helper receives two opaque input pointers and a distinct pointer
// to the canonical result byte. Their common LLVM type does not make these
// source roles interchangeable or turn the inputs into numerical register bits.
func x86CustomPointerHelperSource(t *testing.T, before, body string) (string, string, FuncSig) {
	t.Helper()
	declaration := "func Value(p,q *byte,n uint32) bool"
	_, _, _, source := x86ResultInitializationFixture(t, "386", declaration,
		"MOVL p+0(FP),SI\nMOVL q+4(FP),DI\nMOVL n+8(FP),BX\n"+
			"LEAL ret+12(FP),AX\n"+before+"\nJMP pointerbody<>(SB)")
	source += "TEXT pointerbody<>(SB),4,$0-0\n" + body + "\nRET\n"
	helper := FuncSig{Name: "pointerbody", Args: []LLVMType{Ptr, Ptr, I32, Ptr},
		Ret: Void, ArgRegs: []Reg{SI, DI, BX, AX}}
	return declaration, source, helper
}

func x86CustomPointerHelperAPI(t *testing.T, source, declaration, triple, api string, helper FuncSig) (string, error) {
	t.Helper()
	pkg := mustGoPackage(t, "pointerroles", "package pointerroles\n"+declaration)
	return x86ScalarFPBitViewPackageAPIWithManual(t, source, pkg, "386", triple, api,
		func(name string) (FuncSig, bool) { return helper, name == "pointerbody" })
}

func TestX86CustomHelperDistinctPointerRoles(t *testing.T) {
	bodies := map[string]string{
		"unused-inputs": "CMPL BX,$0\nSETEQ (AX)",
		"identity":      "CMPL SI,DI\nSETEQ (AX)",
	}
	// Complete ordinary scalar load/extension widths in physical 32-bit mode;
	// the wider Q forms remain independently rejected by the shared grammar.
	for _, row := range []struct{ move, compare, left, right string }{
		{"MOVB", "CMPB", "CL", "DL"},
		{"MOVW", "CMPW", "CX", "DX"},
		{"MOVL", "CMPL", "CX", "DX"},
		{"MOVBWSX", "CMPW", "CX", "DX"},
		{"MOVBWZX", "CMPW", "CX", "DX"},
		{"MOVBLSX", "CMPL", "CX", "DX"},
		{"MOVBLZX", "CMPL", "CX", "DX"},
		{"MOVWLSX", "CMPL", "CX", "DX"},
		{"MOVWLZX", "CMPL", "CX", "DX"},
	} {
		bodies[row.move] = fmt.Sprintf("%s (SI),%s\n%s (DI),%s\n%s %s,%s\nSETEQ (AX)",
			row.move, row.left, row.move, row.right, row.compare, row.left, row.right)
	}
	for _, triple := range []string{"i386-unknown-linux-gnu", "i686-pc-windows-msvc"} {
		for name, body := range bodies {
			t.Run(triple+"/"+name, func(t *testing.T) {
				declaration, source, helper := x86CustomPointerHelperSource(t, "", body)
				goAssemblerOracleOutput(t, "386", source, "", true)
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(api, func(t *testing.T) {
						ir, err := x86CustomPointerHelperAPI(t, source, declaration, triple, api, helper)
						if err != nil || !strings.Contains(ir, "call void @pointerbody(ptr") {
							t.Fatal("actual helper input and result pointers were not kept distinct", err)
						}
						llc := findLLVM22Tool("llc")
						if llc == "" {
							t.Fatal("LLVM22 llc required")
						}
						compileLLVMToObject(t, llc, triple, "helper.ll", "helper.o", ir)
					})
				}
			})
		}
	}
}

func TestX86CustomHelperPointerRoleBoundaries(t *testing.T) {
	for _, row := range []struct{ name, before, body string }{
		{"input-is-not-result", "MOVL SI,AX", "MOVB $1,(AX)"},
		{"literal-is-not-pointer", "MOVL $1,SI", "MOVB $1,(AX)"},
		{"partial-input", "MOVB $0,SI", "MOVB $1,(AX)"},
		{"result-is-not-input", "MOVL AX,SI", "MOVBLZX (SI),CX\nCMPL CX,$0\nSETEQ (AX)"},
		{"pointer-is-not-NUM", "", "MOVL SI,CX\nXORL DI,CX\nCMPL CX,$0\nSETEQ (AX)"},
		{"uninitialized-result-read", "", "MOVBLZX (AX),CX\nCMPL CX,$0\nSETEQ (AX)"},
		{"overwide-result-read", "", "MOVL (AX),CX\nCMPL CX,$0\nSETEQ (AX)"},
		{"unknown-input-address", "", "MOVBLZX (BP),CX\nCMPL CX,$0\nSETEQ (AX)"},
		{"mixed-path-address", "CMPL BX,$0\nJE joined\nMOVL $0,SI\njoined:", "MOVBLZX (SI),CX\nCMPL CX,$0\nSETEQ (AX)"},
		{"input-write", "", "MOVB $1,(SI)\nMOVB $1,(AX)"},
		{"result-padding", "", "MOVB $1,1(AX)"},
		{"noncanonical-result", "", "MOVB $2,(AX)"},
		{"undeclared-input", "", "CMPL BP,$0\nSETEQ (AX)"},
		{"caller-flags", "CMPL BX,$0", "SETEQ (AX)"},
	} {
		t.Run(row.name, func(t *testing.T) {
			declaration, source, helper := x86CustomPointerHelperSource(t, row.before, row.body)
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86CustomPointerHelperAPI(t, source, declaration, "i386-unknown-linux-gnu", api, helper)
				if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("helper pointer role escaped its actual source contract", api, err)
				}
			}
		})
	}
}

func TestX86CustomHelperWholeVectorInputPointers(t *testing.T) {
	for _, name := range strings.Fields("MOVOU MOVOA MOVO MOVUPS MOVAPS MOVUPD MOVAPD") {
		for _, triple := range []string{"i386-unknown-linux-gnu", "i686-pc-windows-msvc"} {
			t.Run(triple+"/"+name, func(t *testing.T) {
				body := fmt.Sprintf("%s (SI),X0\n%s (DI),X1\nPCMPEQB X1,X0\nPMOVMSKB X0,CX\nCMPL CX,$65535\nSETEQ (AX)", name, name)
				declaration, source, helper := x86CustomPointerHelperSource(t, "", body)
				goAssemblerOracleOutput(t, "386", source, "", true)
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(api, func(t *testing.T) {
						ir, err := x86CustomPointerHelperAPI(t, source, declaration, triple, api, helper)
						if err != nil || ir == "" {
							t.Fatal("complete original vector read lost its helper input pointer", err)
						}
						llc := findLLVM22Tool("llc")
						if llc == "" {
							t.Fatal("LLVM22 llc required")
						}
						compileLLVMToObject(t, llc, triple, "vector-helper.ll", "vector-helper.o", ir)
					})
				}
			})
		}
	}
}
