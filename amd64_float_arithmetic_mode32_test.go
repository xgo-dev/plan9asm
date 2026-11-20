package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestX86FloatArithmeticMode32PhysicalRegisterBoundary(t *testing.T) {
	names := append(x86FloatAddSubOpcodes(), x86FloatMulDivOpcodes()...)
	for _, member := range x86FloatingMinMaxCases {
		names = append(names, member.op)
	}
	var rows []string
	for _, name := range names {
		if !strings.HasPrefix(name, "V") {
			continue
		}
		banks := []string{"X"}
		if strings.HasSuffix(name, "PS") || strings.HasSuffix(name, "PD") {
			banks = append(banks, "Y")
		}
		for _, bank := range banks {
			for high := 0; high < 3; high++ {
				registers := []string{bank + "0", bank + "1", bank + "2"}
				registers[high] = fmt.Sprint(bank, high+8)
				rows = append(rows, name+" "+strings.Join(registers, ","))
			}
		}
	}
	if len(rows) != 108 {
		t.Fatal("complete arithmetic operation/width/input-output role inventory changed", len(rows))
	}
	// A stock-Go spelling is not proof of physical high-register identity in
	// mode32. Keep that frontend observation separate from both source modes.
	assembly := "TEXT boundary(SB),4,$0-0\n" + strings.Join(rows, "\n") + "\nRET\n"
	requireX86GoAssemblerResult(t, "386", assembly, true)
	requireX86GoAssemblerResult(t, "amd64", assembly, true)
	for _, row := range rows {
		t.Run(row, func(t *testing.T) {
			file, err := Parse(ArchAMD64, "TEXT boundary(SB),4,$0-0\n"+row+"\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			instruction := file.Funcs[0].Instrs[1]
			if _, known, err := x86FloatArithmeticProperties(instruction, "386", ""); !known || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("mode32 spelling acquired physical high-register authority: known=%v err=%v", known, err)
			}
			if _, known, err := x86FloatArithmeticProperties(instruction, "amd64", ""); !known || err != nil {
				t.Fatalf("amd64 high-register positive control changed: known=%v err=%v", known, err)
			}
		})
	}
}
