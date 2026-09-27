package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateARM64SVEEORInterleaveCompleteGo127Family(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT sveeorinterleaveforms(SB),$0-0\n")
	for _, op := range []string{"ZEORBT", "ZEORTB"} {
		for _, width := range []string{"B", "H", "S", "D"} {
			fmt.Fprintf(&source, "\t%s Z1.%s, Z2.%s, Z3.%s\n", op, width, width, width)
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
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"sveeorinterleaveforms": {Name: "sveeorinterleaveforms", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{`"target-features"="+sve,+sve2"`, "@llvm.aarch64.sve.eorbt.nxv16i8", "@llvm.aarch64.sve.eortb.nxv2i64"} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE EORBT/EORTB lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-eor-interleave.ll", "arm64-sve-eor-interleave.o", ll)
		})
	}
}

func TestTranslateARM64SVEEORInterleaveRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZEORBT Z1.B, Z2.H, Z3.B",
		"ZEORTB Z1.Q, Z2.Q, Z3.Q",
		"ZEORBT Z1.S, Z2.S",
		"ZEORTB.Z Z1.D, Z2.D, Z3.D",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_", ",", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsveeorinterleave(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsveeorinterleave": {Name: "badsveeorinterleave", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's SVE EORBT/EORTB forms", instruction)
			}
		})
	}
}
