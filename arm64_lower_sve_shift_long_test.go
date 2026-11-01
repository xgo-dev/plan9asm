package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateARM64SVEShiftLongCompleteGo127Family(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT sveshiftlong(SB),$0-0\n")
	widths := []struct {
		source      string
		destination string
		maxShift    int
	}{
		{source: "B", destination: "H", maxShift: 7},
		{source: "H", destination: "S", maxShift: 15},
		{source: "S", destination: "D", maxShift: 31},
	}
	for opIndex, op := range []string{"ZSSHLLB", "ZSSHLLT", "ZUSHLLB", "ZUSHLLT"} {
		for widthIndex, width := range widths {
			for boundaryIndex, shift := range []int{0, width.maxShift} {
				reg := (opIndex*6 + widthIndex*2 + boundaryIndex) % 32
				fmt.Fprintf(&source, "\t%s $%d, Z%d.%s, Z%d.%s\n", op, shift, reg, width.source, (reg+1)%32, width.destination)
			}
		}
	}
	source.WriteString("\tRET\n")
	requireARM64SVEGoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"sveshiftlong": {Name: "sveshiftlong", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`"target-features"="+sve,+sve2"`,
				"@llvm.aarch64.sve.sshllb.nxv8i16",
				"@llvm.aarch64.sve.sshllt.nxv4i32",
				"@llvm.aarch64.sve.ushllb.nxv2i64",
				"@llvm.aarch64.sve.ushllt.nxv8i16",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE shift-long lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-shift-long.ll", "arm64-sve-shift-long.o", ll)
		})
	}
}

func TestTranslateARM64SVEShiftLongRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZSSHLLB $8, Z1.B, Z2.H",
		"ZSSHLLT $16, Z1.H, Z2.S",
		"ZUSHLLB $32, Z1.S, Z2.D",
		"ZUSHLLT $-1, Z1.B, Z2.H",
		"ZSSHLLB $0, Z1.B, Z2.S",
		"ZUSHLLT $0, Z1.D, Z2.D",
		"ZSSHLLB.Z $0, Z1.B, Z2.H",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_", ",", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsveshiftlong(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsveshiftlong": {Name: "badsveshiftlong", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's SVE shift-long forms", instruction)
			}
		})
	}
}
