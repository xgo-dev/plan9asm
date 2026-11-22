package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestGoAMD64FixedLocalScalarMoveOriginalObjects(t *testing.T) {
	// Original amd64enc.s forms, including low-byte and widened register
	// spellings, preserve the native width of the memory access.
	rows := []struct{ operation, result string }{
		{"MOVW $61731, (BX)", "MOVQ 64(SP),AX"},
		{"MOVW DX, (BX)", "MOVQ 64(SP),AX"},
		{"MOVW (BX), DX", "MOVQ DX,AX"},
		{"MOVL $4045620583, (BX)", "MOVQ 64(SP),AX"},
		{"MOVL DX, (BX)", "MOVQ 64(SP),AX"},
		{"MOVL (BX), DX", "MOVQ DX,AX"},
		{"MOVQ $-249346713, (BX)", "MOVQ 64(SP),AX"},
		{"MOVQ DX, (BX)", "MOVQ 64(SP),AX"},
		{"MOVQ (BX), DX", "MOVQ DX,AX"},
		{"MOVB $7, (BX)", "MOVQ 64(SP),AX"},
		{"MOVB DL, (BX)", "MOVQ 64(SP),AX"},
		{"MOVB R11, (BX)", "MOVQ 64(SP),AX"},
		{"MOVB (BX), DL", "MOVQ DX,AX"},
		{"MOVB (BX), R11", "MOVQ R11,AX"},
		{"MOVNTIL DX, (BX)", "SFENCE\nMOVQ 64(SP),AX"},
		{"MOVNTIQ DX, (BX)", "SFENCE\nMOVQ 64(SP),AX"},
		{"MOVNTIL DX, 1(SP)", "SFENCE\nMOVL 1(SP),AX"},
		{"MOVNTIQ DX, 1(SP)", "SFENCE\nMOVQ 1(SP),AX"},
	}
	var assembly, declarations strings.Builder
	for index, row := range rows {
		name := fmt.Sprintf("Value%d", index)
		fmt.Fprintf(&assembly, "TEXT ·%s(SB),4,$128-16\nMOVQ a+0(FP),AX\n", name)
		assembly.WriteString("MOVQ AX,64(SP)\nNOTQ AX\nMOVQ AX,DX\nMOVQ AX,R11\nLEAQ 64(SP),BX\n")
		fmt.Fprintf(&assembly, "%s\n%s\nMOVQ AX,ret+8(FP)\nRET\n", row.operation, row.result)
		fmt.Fprintf(&declarations, "func %s(a uint64) uint64\n", name)
	}
	fixedLocalCompleteVectorObjects(t, assembly.String(), declarations.String(), len(rows))
}

func TestGoAMD64FixedLocalVectorToScalarIndexedOriginalObjects(t *testing.T) {
	var assembly, declarations strings.Builder
	rows := []string{
		"VMOVQ X20, (SP)(AX*2)",
		"VPEXTRW $17, X20, (SP)(AX*2)",
		"VPEXTRW $127, X20, (SP)(AX*2)",
	}
	setup := "LEAQ 112(CX),R10\nMOVQ R10,SP\nMOVQ $8,AX\n"
	for index, operation := range rows {
		name := fmt.Sprintf("Value%d", index)
		assembly.WriteString(fixedLocalAlignedAddressAssembly(t, name, operation, setup))
		fmt.Fprintf(&declarations, "func %s(a uint64) uint64\n", name)
	}
	fixedLocalCompleteVectorObjects(t, assembly.String(), declarations.String(), len(rows))
}

func TestGoAMD64FixedLocalMOVNTIStorageWidth(t *testing.T) {
	_, _, sig, _ := x86ResultInitializationFixture(t, "amd64", "func Value(a uint64) uint64", "RET")
	for _, row := range []struct {
		name, setup, store, load string
		accept                   bool
	}{
		{"unaligned dword", "", "MOVNTIL AX,1(SP)", "MOVL 1(SP),DX", true},
		{"unaligned qword", "", "MOVNTIQ AX,1(SP)", "MOVQ 1(SP),DX", true},
		{"last dword", "", "MOVNTIL AX,124(SP)", "MOVL 124(SP),DX", true},
		{"last qword", "", "MOVNTIQ AX,120(SP)", "MOVQ 120(SP),DX", true},
		{"overrun dword", "", "MOVNTIL AX,125(SP)", "MOVQ AX,DX", false},
		{"overrun qword", "", "MOVNTIQ AX,121(SP)", "MOVQ AX,DX", false},
		{"undefined source", "", "MOVNTIL DX,1(SP)", "MOVQ AX,DX", false},
		{"relocated source", "LEAQ 64(SP),DX\n", "MOVNTIQ DX,1(SP)", "MOVQ AX,DX", false},
		{"unwritten neighbor", "", "MOVNTIL AX,1(SP)", "MOVQ 1(SP),DX", false},
	} {
		t.Run(row.name, func(t *testing.T) {
			source := "TEXT ·Value(SB),4,$128-16\nMOVQ a+0(FP),AX\n" +
				row.setup + row.store + "\nSFENCE\n" + row.load + "\nMOVQ DX,ret+8(FP)\nRET\n"
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			_, err = proveX86FixedLocal(file.Funcs[0], sig)
			if row.accept && err != nil || !row.accept && !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("private MOVNTI transfer, accept=%t: %v", row.accept, err)
			}
		})
	}
}

func TestGoAMD64FixedLocalScalarLaneHighBanks(t *testing.T) {
	var cases []string
	for _, width := range []string{"B", "W", "D", "Q"} {
		for _, transfer := range []string{"AX", "65(BP)", "1(SI)"} {
			insert := fmt.Sprintf("VPINSR%s $255,%s,X17,X20", width, transfer)
			extract := fmt.Sprintf("VPEXTR%s $255,X20,AX\nMOVQ AX,128(BP)", width)
			cases = append(cases, insert+"\n"+extract)
			cases = append(cases, fmt.Sprintf("VMOVUPS X1,X20\nVPEXTR%s $255,X20,%s", width, transfer))
		}
	}
	var original strings.Builder
	for index, row := range cases {
		original.WriteString(strings.Replace(fixedLocalVEXAssembly(row), "·Value", fmt.Sprintf("·Value%d", index), 1))
	}
	requireX86GoAssemblerResult(t, "amd64", original.String(), true)
	for _, row := range cases {
		t.Run(row, func(t *testing.T) {
			fn, sig, _ := fixedLocalVEXFixture(t, row)
			if _, err := proveX86FixedLocal(fn, sig); err != nil {
				t.Fatalf("initialized high-bank scalar lane rejected: %v", err)
			}
		})
	}
}
