package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func x86FloatCompareOpcodes() []string {
	return []string{"CMPPS", "CMPPD", "CMPSS", "CMPSD", "VCMPPS", "VCMPPD", "VCMPSS", "VCMPSD"}
}

// Enumerate independently from the production grammar: yxcmpi has one
// signed-imm8 row, _yvcmppd has eight rows, and _yvcmpsd has three rows.
func x86FloatCompareGoForms(arch string) []string {
	var rows []string
	for _, opcode := range x86FloatCompareOpcodes() {
		scalar := strings.HasSuffix(opcode, "SS") || strings.HasSuffix(opcode, "SD")
		if !strings.HasPrefix(opcode, "V") {
			for _, source := range []string{"X0", "8(AX)", "(AX)(CX*4)"} {
				for _, immediate := range []int{-128, -1, 0, 7, 127} {
					rows = append(rows, fmt.Sprintf("%s %s,X1,$%d", opcode, source, immediate))
				}
			}
			continue
		}
		if arch == "386" {
			continue // Go rejects named VCMP; physical raw forms are separate.
		}
		widths := []string{"X", "Y"}
		if scalar {
			widths = widths[:1]
		}
		for _, width := range widths {
			for _, source := range []string{width + "0", "8(AX)", "(AX)(CX*4)"} {
				for _, immediate := range []int{0, 31, 255} {
					rows = append(rows, fmt.Sprintf("%s $%d,%s,%s1,%s2", opcode, immediate, source, width, width))
				}
			}
		}
		widths = []string{"X", "Y", "Z"}
		if scalar {
			widths = widths[:1]
		}
		for _, width := range widths {
			for _, mask := range []string{"", "K1,"} {
				for _, destination := range []string{"K0", "K7"} {
					for _, source := range []string{width + "20", "8(AX)", "(AX)(CX*4)"} {
						rows = append(rows, fmt.Sprintf("%s $255,%s,%s21,%s%s", opcode, source, width, mask, destination))
					}
					if !scalar {
						rows = append(rows, fmt.Sprintf("%s.BCST $31,8(AX),%s21,%s%s", opcode, width, mask, destination))
					}
					if scalar || width == "Z" {
						rows = append(rows, fmt.Sprintf("%s.SAE $31,%s20,%s21,%s%s", opcode, width, width, mask, destination))
					}
				}
			}
		}
	}
	return rows
}

func TestX86FloatingCompareCompleteGoGrammarFiveTargets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, arch := range []string{"386", "amd64"} {
		var source strings.Builder
		for index, row := range x86FloatCompareGoForms(arch) {
			name := fmt.Sprintf("compare_form%d", index)
			fmt.Fprintf(&source, "TEXT %s(SB),4,$0-0\n%s\nRET\n", name, row)
		}
		goAssemblerOracleOutput(t, arch, source.String(), "", true)
		triples := []string{"x86_64-unknown-linux-gnu", "x86_64-apple-macosx", "x86_64-pc-windows-msvc"}
		if arch == "386" {
			triples = []string{"i386-unknown-linux-gnu", "i686-pc-windows-msvc"}
		}
		for _, triple := range triples {
			ir := x86FloatingCompareUnboundFormatObject(t, source.String(), arch, triple)
			compileLLVMToObject(t, llc, triple, "compare-formats.ll", "compare-formats.o", ir)
		}
		t.Logf("%s: %d original Go compare formats; public Context and emitter-only objects", arch, len(x86FloatCompareGoForms(arch)))
	}
}

func TestX86FloatingCompareMalformedAndDispatchIdentityBeforeEmission(t *testing.T) {
	for _, row := range []string{
		"CMPPS X0,X1,$128", "CMPSD X0,Y1,$0", "CMPSS $0,X1,$0", "CMPPD.SAE X0,X1,$0",
		"VCMPPS $256,X0,X1,X2", "VCMPPD $0,X0,X1,Z2", "VCMPSS.Z $0,X0,X1,K2",
		"VCMPPD $0,X0,X1,K0,K2", "VCMPPS.BCST $0,X0,X1,K2", "VCMPSS.BCST $0,(AX),X1,K2",
		"VCMPPS.SAE $0,Y0,Y1,K2", "VCMPSS.SAE $0,(AX),X1,K2", "VCMPPS $0,X0,X1,X17",
		"CMPPS (AX)(SP*2),X1,$0", "VCMPPS $0,(AX)(SP*2),X1,X2", "VCMPPS $0,$data(SB),X1,X2",
	} {
		t.Run(row, func(t *testing.T) {
			goAssemblerOracleOutput(t, "amd64", "TEXT f(SB),4,$0-0\n"+row+"\nRET\n", "", false)
			file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
			if err != nil {
				return
			}
			context, output := newAMD64CtxWithFuncForTest(t, file.Funcs[0], FuncSig{Ret: Void}, nil)
			context.goarch = "amd64"
			instruction := file.Funcs[0].Instrs[1]
			before := output.Len()
			known, term, err := context.lowerFloatingCompare(instruction.Op, instruction)
			if !known || term || err == nil || output.Len() != before {
				t.Fatalf("malformed compare emitted IR: %t/%t/%v", known, term, err)
			}
		})
	}
	for _, opcode := range x86FloatCompareOpcodes() {
		row := opcode + " X0,X1,$0"
		if strings.HasPrefix(opcode, "V") {
			row = opcode + " $0,X0,X1,X2"
		}
		file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		context, output := newAMD64CtxWithFuncForTest(t, file.Funcs[0], FuncSig{Ret: Void}, nil)
		context.goarch = "amd64"
		instruction := file.Funcs[0].Instrs[1]
		instruction.Op = "MULSS"
		before := output.Len()
		if known, term, err := context.lowerFloatingCompare(Op(opcode), instruction); !known || term || err == nil || output.Len() != before {
			t.Fatalf("conflicting compare identity emitted IR: %s/%t/%t/%v", opcode, known, term, err)
		}
	}
}
