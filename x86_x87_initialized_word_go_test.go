package plan9asm

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestX86X87InitClearWordCompleteGoRowsAndBytes(t *testing.T) {
	table, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []string{
		"var ynone = []ytab{\n\t{Zlit, 1, argList{}},\n}",
		"var ystsw = []ytab{\n\t{Zo_m, 2, argList{Ym}},\n\t{Zlit, 1, argList{Yax}},\n}",
		"var ysvrs_mo = []ytab{\n\t{Zm_o, 2, argList{Ym}},\n}",
		"var ysvrs_om = []ytab{\n\t{Zo_m, 2, argList{Ym}},\n}",
		"{AFCLEX, ynone, Px, opBytes{0xdb, 0xe2}}",
		"{AFINIT, ynone, Px, opBytes{0xdb, 0xe3}}",
		"{AFSTCW, ysvrs_om, Px, opBytes{0xd9, 07, 0xd9, 07}}",
		"{AFSTSW, ystsw, Px, opBytes{0xdd, 07, 0xdf, 0xe0}}",
		"{AFLDCW, ysvrs_mo, Px, opBytes{0xd9, 05, 0xd9, 05}}",
		"{AWAIT, ynone, Px, opBytes{0x9b}}",
	} {
		if !strings.Contains(string(table), row) {
			t.Fatal("selected complete Go init/clear/word grammar changed", row)
		}
	}
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range []struct {
			source string
			bytes  []byte
		}{
			{"FINIT", []byte{0xdb, 0xe3}},
			{"FCLEX", []byte{0xdb, 0xe2}},
			{"FSTCW (AX)", []byte{0xd9, 0x38}},
			{"FSTSW (AX)", []byte{0xdd, 0x38}},
			{"FSTSW AX", []byte{0xdf, 0xe0}},
			{"FLDCW (AX)", []byte{0xd9, 0x28}},
			{"WAIT\nFINIT", []byte{0x9b, 0xdb, 0xe3}},
			{"WAIT\nFCLEX", []byte{0x9b, 0xdb, 0xe2}},
			{"FSTCW -7(BX)(CX*4)", []byte{0xd9, 0x7c, 0x8b, 0xf9}},
			{"FSTSW -7(BX)(CX*4)", []byte{0xdd, 0x7c, 0x8b, 0xf9}},
			{"FLDCW -7(BX)(CX*4)", []byte{0xd9, 0x6c, 0x8b, 0xf9}},
		} {
			t.Run(arch+"/"+row.source, func(t *testing.T) {
				source := "TEXT probe(SB),4,$0-0\n" + row.source + "\nRET\n"
				got := x86OrderingHintGoBytes(t, arch, source)
				want := append(append([]byte(nil), row.bytes...), 0xc3)
				if !bytes.Equal(got, want) {
					t.Fatalf("actual Go word row bytes=%x want=%x", got, want)
				}
			})
		}
		for _, source := range []string{
			"FINIT AX", "FCLEX AX", "FSTCW AX", "FSTSW BX", "FLDCW AX",
			"FINIT.Z", "FSTSW.Z AX", "FNINIT", "FNCLEX",
		} {
			t.Run(arch+"/Go-rejects/"+source, func(t *testing.T) {
				goAssemblerOracleOutput(t, arch, "TEXT probe(SB),4,$0-0\n"+source+"\nRET\n", "", false)
			})
		}
	}
}
