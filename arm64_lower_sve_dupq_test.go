package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateARM64SVEDupQCompleteGo127Family(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT svedupq(SB),$0-0\n")
	for widthIndex, form := range []struct {
		width string
		max   int
	}{{"B", 15}, {"H", 7}, {"S", 3}, {"D", 1}} {
		for laneIndex, lane := range []int{0, form.max} {
			destination := widthIndex*2 + laneIndex
			fmt.Fprintf(&source, "\tZDUPQ Z%d.%s[%d], Z%d.%s\n", destination+16, form.width, lane, destination, form.width)
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
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"svedupq": {Name: "svedupq", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`"target-features"="+sve,+sve2p1"`,
				"@llvm.aarch64.sve.dupq.lane.nxv16i8",
				"@llvm.aarch64.sve.dupq.lane.nxv8i16",
				"@llvm.aarch64.sve.dupq.lane.nxv4i32",
				"@llvm.aarch64.sve.dupq.lane.nxv2i64",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s ZDUPQ lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-dupq.ll", "arm64-sve-dupq.o", ll)
		})
	}
}

func TestTranslateARM64SVEDupQRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZDUPQ Z1.B[16], Z2.B",
		"ZDUPQ Z1.H[8], Z2.H",
		"ZDUPQ Z1.S[4], Z2.S",
		"ZDUPQ Z1.D[2], Z2.D",
		"ZDUPQ Z1.H[2], Z2.S",
		"ZDUPQ Z1.Q[0], Z2.Q",
		"ZDUPQ.Z Z1.D[1], Z2.D",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_", ",", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsvedupq(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvedupq": {Name: "badsvedupq", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's ZDUPQ forms", instruction)
			}
		})
	}
}
