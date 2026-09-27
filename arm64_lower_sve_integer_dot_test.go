package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateARM64SVEIntegerDotCompleteGo127Family(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT sveintegerdotforms(SB),$0-0\n")
	for _, op := range []string{"ZSDOT", "ZUDOT"} {
		for _, widths := range [][2]string{{"B", "H"}, {"H", "S"}, {"B", "S"}, {"H", "D"}} {
			fmt.Fprintf(&source, "\t%s Z1.%s, Z2.%s, Z3.%s\n", op, widths[0], widths[0], widths[1])
		}
		for _, form := range []struct {
			source, destination string
			vector, lane        int
		}{{"B", "H", 7, 7}, {"H", "S", 7, 3}, {"B", "S", 7, 3}, {"H", "D", 15, 1}} {
			fmt.Fprintf(&source, "\t%s Z%d.%s[%d], Z2.%s, Z3.%s\n", op, form.vector, form.source, form.lane, form.source, form.destination)
		}
	}
	source.WriteString("\tZUSDOT Z1.B, Z2.B, Z3.S\n")
	source.WriteString("\tZUSDOT Z7.B[3], Z2.B, Z3.S\n")
	source.WriteString("\tZSUDOT Z7.B[3], Z2.B, Z3.S\n")
	source.WriteString("\tRET\n")
	requireARM64SVEGoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"sveintegerdotforms": {Name: "sveintegerdotforms", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`"target-features"="+i8mm,+sve,+sve2,+sve2p1,+sve2p3"`,
				`asm sideeffect "sdot $0.h, $2.b, $3.b"`,
				`asm sideeffect "udot $0.h, $2.b, $3.b[7]"`,
				"@llvm.aarch64.sve.sdot.nxv2i64",
				"@llvm.aarch64.sve.udot.lane.x2.nxv4i32",
				"@llvm.aarch64.sve.usdot.nxv4i32",
				"@llvm.aarch64.sve.sudot.lane.nxv4i32",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE integer dot lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-integer-dot.ll", "arm64-sve-integer-dot.o", ll)
		})
	}
}

func TestTranslateARM64SVEIntegerDotRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZSDOT Z1.B, Z2.H, Z3.S",
		"ZUDOT Z1.B, Z2.B, Z3.D",
		"ZSDOT Z8.B[0], Z2.B, Z3.S",
		"ZUDOT Z7.B[4], Z2.B, Z3.S",
		"ZSDOT Z16.H[0], Z2.H, Z3.D",
		"ZUDOT Z15.H[2], Z2.H, Z3.D",
		"ZSUDOT Z1.B, Z2.B, Z3.S",
		"ZUSDOT Z1.H, Z2.H, Z3.S",
		"ZSDOT.Z Z1.B, Z2.B, Z3.S",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_", ",", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsveintegerdot(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsveintegerdot": {Name: "badsveintegerdot", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's SVE integer dot forms", instruction)
			}
		})
	}
}
