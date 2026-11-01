package plan9asm

import (
	"fmt"
	"runtime"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

func x86ScalarCompareInitializedFunction(name, operation, arch string) (string, string) {
	word, move := goWordSize(arch), "Q"
	if word == 4 {
		move = "L"
	}
	source := fmt.Sprintf("TEXT ·%s(SB),4,$0-%d\nMOV%s memory+0(FP),SI\nMOV%s out+%d(FP),DI\n"+
		"MOV%s a+%d(FP),AX\nMOV%s b+%d(FP),BX\nMOV%s c+%d(FP),CX\n%s\n"+
		"MOV%s AX,0(DI)\nMOV%s BX,8(DI)\nMOV%s CX,16(DI)\n"+
		"SETCS DL\nMOVB DL,24(DI)\nSETEQ DL\nMOVB DL,25(DI)\nSETPS DL\nMOVB DL,26(DI)\n"+
		"SETMI DL\nMOVB DL,27(DI)\nSETOS DL\nMOVB DL,28(DI)\nRET\n",
		name, 5*word, move, move, word, move, 2*word, move, 3*word, move, 4*word, operation, move, move, move)
	return source, fmt.Sprintf("func %s(memory *[8]byte,out *[40]byte,a,b,c uintptr)\n", name)
}

func TestX86OfficialScalarCompareRowsOriginalBytesObjects(t *testing.T) {
	catalog, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	modes := map[string][]goasmrules.X86ScalarRMWRow{}
	for _, arch := range []string{"amd64", "386"} {
		rows, err := goasmrules.X86ScalarCompareRows(catalog, arch)
		if err != nil {
			t.Fatal(err)
		}
		modes[arch] = rows
		var cases []x86OfficialPackedCase
		for _, row := range rows {
			for _, witness := range row.Witnesses {
				cases = append(cases, x86OfficialPackedCase{row: row.ID,
					witness: goasmrules.X86PackedBinaryWitness{Instruction: witness.Instruction, Encoding: witness.Encoding}})
			}
		}
		want := 48
		if arch == "386" {
			want = 34
		}
		if len(rows) != 31 || len(cases) != want {
			t.Fatal("original compare/test source-mode union changed", arch, len(rows), len(cases))
		}
		x86Legacy127Objects(t, arch, cases, x86ScalarCompareInitializedFunction)
	}
	if !t.Failed() {
		x86Legacy127SaveIdentity(t, "PLAN9ASM_SCALAR_COMPARE_IDENTITY_OUTPUT", struct {
			Source goasmrules.X86LegacyCatalog
			Modes  map[string][]goasmrules.X86ScalarRMWRow
		}{catalog, modes})
	}
}
