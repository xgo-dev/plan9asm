package plan9asm

import (
	"fmt"
	"reflect"
	"testing"
)

func TestX86MMXWordGoBankMatchesOriginalBytes(t *testing.T) {
	for _, spelling := range []string{"MOVQ", "MOVD", "MOVDQ2Q"} {
		for index := 0; index < 8; index++ {
			instruction := fmt.Sprintf("%s M%d,M1", spelling, index)
			code := x86PackedShiftActualGoBytes(t, "amd64", "TEXT bank(SB),4,$0-0\n"+instruction+"\nRET\n")
			want := []byte{0x48, 0x0f, 0x6e, byte(0xc8 + index), 0xc3}
			if !reflect.DeepEqual(code, want) {
				t.Fatal("ordered Go Ymm/Ymr word row changed", instruction, code, want)
			}
			ins := x86ScalarLaneInstruction(t, instruction)
			form, known, err := x86MMXWordProperties(ins, "amd64")
			gp := []Reg{AX, CX, DX, BX, SP, BP, SI, DI}[index]
			if !known || err != nil || form.sourceM || !form.targetM || !form.gpSpelling ||
				form.source.Reg != gp || form.bytes != 8 || !reflect.DeepEqual(ins, x86ScalarLaneInstruction(t, instruction)) {
				t.Fatal("source spelling became the wrong physical bank", instruction, form, err)
			}
		}
	}
}

func TestX86MMXWordCompleteSourceRows(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range []struct {
			source string
			bytes  int64
			valid  bool
		}{
			{"MOVL AX,M0", 4, true}, {"MOVL M0,AX", 4, true},
			{"MOVL 1(AX),M0", 4, true}, {"MOVL M0,1(AX)", 4, true},
			{"MOVQ 1(AX),M0", 8, true}, {"MOVQ M0,1(AX)", 8, true},
			{"MOVQ X0,M0", 8, true}, {"MOVQOZX M0,X0", 8, true},
			{"MOVQ AX,M0", 8, arch == "amd64"}, {"MOVQ M0,AX", 8, arch == "amd64"},
			{"MOVQ M0,M1", 8, arch == "amd64"},
			{"MOVL M0,M1", 4, false}, {"MOVL X0,M0", 4, false},
			{"MOVQ M0,X0", 8, false}, {"MOVQOZX X0,M0", 8, false},
			{"MOVQ $7,M0", 8, false}, {"MOVQ.Z M0,AX", 8, false},
			{"MOVNTQ M0,1(AX)", 8, true}, {"MOVNTQ M7,1(AX)(CX*2)", 8, true},
			{"MOVNTQ M0,M1", 8, false}, {"MOVNTQ X0,1(AX)", 8, false},
			{"MOVNTQ AX,1(AX)", 8, false}, {"MOVNTQ.Z M0,1(AX)", 8, false},
		} {
			t.Run(arch+"/"+row.source, func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, row.source)
				before := ins
				form, known, err := x86MMXWordProperties(ins, arch)
				if !known || (err == nil) != row.valid || row.valid && form.bytes != row.bytes || !reflect.DeepEqual(before, ins) {
					t.Fatal("complete MMX word grammar changed", form, known, err, row.valid)
				}
				goAssemblerOracleOutput(t, arch, "TEXT bank(SB),4,$0-0\n"+row.source+"\nRET\n", "", row.valid)
			})
		}
	}
}
