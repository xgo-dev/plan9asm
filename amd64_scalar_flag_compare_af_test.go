package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

type x86ScalarCompareAFCase struct {
	name, op string
	bits     int
	dst, src int
	memory   bool
}

// asm6.go's yxm is X/m,X. Each of the four avx_optabs.go entries
// independently has VEX X/m,X and EVEX X/m,X (N4/N8, SAE register only).
// Neither table grants masks, zeroing, broadcast, or a Y/Z operand.
func x86ScalarCompareAFCases(arch string, extended bool) []x86ScalarCompareAFCase {
	var cases []x86ScalarCompareAFCase
	for _, op := range []string{"COMISS", "COMISD", "UCOMISS", "UCOMISD", "VCOMISS", "VCOMISD", "VUCOMISS", "VUCOMISD"} {
		bits := 32
		if strings.HasSuffix(op, "D") {
			bits = 64
		}
		banks := []int{0, 7}
		if arch == "amd64" && extended {
			banks = append(banks, 8, 15)
			if strings.HasPrefix(op, "V") {
				banks = append(banks, 16, 31)
			}
		}
		for _, dst := range banks {
			src := 1
			if dst != 0 {
				src = dst - 1
			}
			for _, memory := range []bool{false, true} {
				cases = append(cases, x86ScalarCompareAFCase{fmt.Sprintf("status%d", len(cases)), op, bits, dst, src, memory})
			}
			cases = append(cases, x86ScalarCompareAFCase{fmt.Sprintf("status%d", len(cases)), op, bits, dst, dst, false})
			if strings.HasPrefix(op, "V") {
				cases = append(cases, x86ScalarCompareAFCase{fmt.Sprintf("status%d", len(cases)), op + ".SAE", bits, dst, src, false})
			}
		}
	}
	return cases
}

func x86ScalarCompareAFAssembly(arch string, cases []x86ScalarCompareAFCase) string {
	move, slot := "Q", 8
	if arch == "386" {
		move, slot = "L", 4
	}
	var source strings.Builder
	for _, row := range cases {
		fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n", row.name, 4*slot)
		fmt.Fprintf(&source, "MOV%s out+0(FP),DI\nMOV%s left+%d(FP),BX\nMOV%s right+%d(FP),DX\nMOV%s seed+%d(FP),CX\n", move, move, slot, move, 2*slot, move, 3*slot)
		load, store := "MOVUPS", "MOVUPS"
		if row.dst >= 16 || row.src >= 16 {
			load, store = "VMOVUPS", "VMOVUPS"
		}
		fmt.Fprintf(&source, "%s (BX),X%d\n", load, row.dst)
		if row.src != row.dst {
			fmt.Fprintf(&source, "%s (DX),X%d\n", load, row.src)
		}
		fmt.Fprintf(&source, "PUSH%s CX\nPOPF%s\n", move, move)
		operand := fmt.Sprintf("X%d", row.src)
		if row.memory {
			operand = "0(DX)"
		}
		fmt.Fprintf(&source, "%s %s,X%d\nPUSHF%s\nPOP%s CX\nMOV%s CX,0(DI)\nLAHF\nMOVB AH,8(DI)\n", row.op, operand, row.dst, move, move, move)
		source.WriteString("SETCS 9(DI)\nSETPS 10(DI)\nSETEQ 11(DI)\nSETMI 12(DI)\nSETOS 13(DI)\nSETLT 14(DI)\n")
		fmt.Fprintf(&source, "%s X%d,32(DI)\n%s X%d,48(DI)\nRET\n", store, row.dst, store, row.src)
	}
	return source.String()
}

func x86ScalarCompareAFOptions(arch, triple string, cases []x86ScalarCompareAFCase) Options {
	typ, slot := I64, int64(8)
	if arch == "386" {
		typ, slot = I32, 4
	}
	sigs := make(map[string]FuncSig, len(cases))
	for _, row := range cases {
		sigs[row.name] = FuncSig{Name: row.name, Args: []LLVMType{Ptr, Ptr, Ptr, typ}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1},
				{Offset: slot, Type: Ptr, Index: 1, Field: -1},
				{Offset: 2 * slot, Type: Ptr, Index: 2, Field: -1},
				{Offset: 3 * slot, Type: typ, Index: 3, Field: -1},
			}},
		}
	}
	return Options{Goarch: arch, TargetTriple: triple, Sigs: sigs,
		ResolveSym: func(symbol string) string { return strings.TrimPrefix(symbol, "·") },
	}
}

func TestX86ScalarCompareAFCompleteObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range []struct{ arch, triple string }{
		{"amd64", "x86_64-apple-darwin"},
		{"amd64", "x86_64-unknown-linux-gnu"},
		{"amd64", "x86_64-pc-windows-msvc"},
		{"386", "i386-unknown-linux-gnu"},
		{"386", "i686-pc-windows-msvc"},
	} {
		t.Run(target.triple, func(t *testing.T) {
			cases := x86ScalarCompareAFCases(target.arch, true)
			source := x86ScalarCompareAFAssembly(target.arch, cases)
			// This generic receipt helper really invokes the selected SDK on
			// every target, including Go 1.20; no current-table early return.
			receipt := x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
			if receipt == nil {
				t.Fatal("missing actual source/object receipt")
			}
			var declarations strings.Builder
			for _, row := range cases {
				fmt.Fprintf(&declarations, "func %s(*[96]byte,*[16]byte,*[16]byte,uintptr)\n", row.name)
			}
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, declarations.String(), target.arch, target.triple, api)
					if err != nil {
						t.Fatal(err)
					}
					for _, optimized := range []bool{false, true} {
						t.Run(fmt.Sprintf("IR_O2=%t", optimized), func(t *testing.T) {
							objectIR := ir
							if optimized {
								objectIR = x86MulDivRoundOptimize(t, objectIR)
							}
							compileLLVMToObject(t, llc, target.triple, "scalar-status.ll", "scalar-status.o", objectIR)
						})
					}
				})
			}
			t.Logf("%d eight-op register/memory/SAE kernels; physical mode32 bank stays X0-X7", len(cases))
		})
	}
}

func TestX86ScalarCompareAFMalformedFormsRemainRejected(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, op := range []string{"COMISS", "COMISD", "UCOMISS", "UCOMISD", "VCOMISS", "VCOMISD", "VUCOMISS", "VUCOMISD"} {
			for _, operands := range []string{"Y1,X0", "X1,Y0", "X1,(AX)", "X1,X0,X2"} {
				t.Run(arch+"/"+op+"/"+operands, func(t *testing.T) {
					source := "TEXT ·invalid(SB),4,$0-0\n" + op + " " + operands + "\nRET\n"
					// These common rejected forms invoke both actual SDKs.
					goAssemblerOracleOutput(t, arch, source, "", false)
					file, err := Parse(ArchAMD64, source)
					if err == nil {
						_, err = Translate(file, Options{Goarch: arch, Sigs: map[string]FuncSig{
							"invalid": {Name: "invalid", Ret: Void},
						}})
					}
					if err == nil {
						t.Fatalf("malformed %s acquired translation authority", source)
					}
				})
			}
		}
	}
}
