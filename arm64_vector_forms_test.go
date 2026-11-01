package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestARM64SharedVectorTransferCompleteRows(t *testing.T) {
	file, err := Parse(ArchARM64, arm64VectorDuplicateForms+arm64VMOVSource(arm64VMOVCases()))
	if err != nil {
		t.Fatal(err)
	}
	for _, function := range file.Funcs {
		for _, ins := range function.Instrs {
			if ins.Op != "VMOV" && ins.Op != "VDUP" {
				continue
			}
			if _, err := parseARM64VectorTransfer(ins.Op, ins); err != nil {
				t.Fatalf("complete existing actual-Go fixture lost %s: %v", ins.Raw, err)
			}
		}
	}
}

func TestARM64SharedVectorShiftFullBoundaries(t *testing.T) {
	var original strings.Builder
	original.WriteString("TEXT vectorShiftForms(SB),$0-0\n")
	// Four architectural variants have no named Go mnemonic. Their complete
	// decoder and shared lowering grammar are exercised with original WORDs,
	// not by claiming the corresponding internal spellings are Go aliases.
	bases := map[Op]uint32{
		"VSSHR": 0x0f000400, "VSSRA": 0x0f001400,
		"VSRSHR": 0x0f002400, "VSRSRA": 0x0f003400,
		"VUSHR": 0x2f000400, "VUSRA": 0x2f001400,
		"VURSHR": 0x2f002400, "VURSRA": 0x2f003400,
	}
	for _, arrangement := range []string{"B8", "B16", "H4", "H8", "S2", "S4", "D2"} {
		width := map[byte]int{'B': 8, 'H': 16, 'S': 32, 'D': 64}[arrangement[0]]
		for _, shift := range []int{0, width - 1} {
			fmt.Fprintf(&original, "VSHL $%d,V0.%s,V0.%s\n", shift, arrangement, arrangement)
		}
		for op := range arm64VectorShiftRightSpecs {
			for _, shift := range []int{1, width} {
				full := strings.HasSuffix(arrangement, "16") || strings.HasSuffix(arrangement, "8") && width == 16 ||
					strings.HasSuffix(arrangement, "4") && width == 32 || width == 64
				word := encodeARM64ImmediateShiftRight(bases[op], width, shift, full, 0, 0)
				fmt.Fprintf(&original, "WORD $%#08x\n", word)
			}
		}
	}
	original.WriteString("RET\n")
	requireARM64GoAssemblerResult(t, original.String(), true)
	file, err := Parse(ArchARM64, original.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, ins := range file.Funcs[0].Instrs {
		if ins.Op == OpRET || ins.Op == OpTEXT {
			continue
		}
		ins = arm64ControlDecode(ins)
		form, err := parseARM64VectorShift(ins.Op, ins)
		if err != nil {
			t.Fatal(err)
		}
		for _, badShift := range []int64{-1, int64(form.arrangement.elementBits + 1)} {
			changed := ins
			changed.Args = append([]Operand(nil), ins.Args...)
			changed.Args[0].Imm = badShift
			if _, err := parseARM64VectorShift(ins.Op, changed); err == nil {
				t.Fatalf("shift boundary mutation accepted: %s shift=%d", ins.Raw, badShift)
			}
		}
		changed := ins
		changed.Args = append([]Operand(nil), ins.Args...)
		changed.Args[0].ImmIsFloat = true
		if _, err := parseARM64VectorShift(ins.Op, changed); err == nil {
			t.Fatalf("float-class immediate accepted: %s", ins.Raw)
		}
	}
}
