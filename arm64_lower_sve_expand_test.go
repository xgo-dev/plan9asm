package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateARM64SVEExpandCompleteGo127Family(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT sveexpand(SB),$0-0\n")
	for index, width := range []string{"B", "H", "S", "D"} {
		fmt.Fprintf(&source, "\tZEXPAND Z%d.%s, P%d, Z%d.%s\n", index+1, width, index, index+8, width)
	}
	source.WriteString("\tRET\n")
	requireARM64SVEGoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"sveexpand": {Name: "sveexpand", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`"target-features"="+sve,+sve2p2"`,
				"@llvm.aarch64.sve.expand.nxv16i8",
				"@llvm.aarch64.sve.expand.nxv8i16",
				"@llvm.aarch64.sve.expand.nxv4i32",
				"@llvm.aarch64.sve.expand.nxv2i64",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE expand lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-expand.ll", "arm64-sve-expand.o", ll)
		})
	}
}

func TestTranslateARM64SVEExpandRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZEXPAND Z1.B, P8, Z2.B",
		"ZEXPAND Z1.H, P0.M, Z2.H",
		"ZEXPAND Z1.S, P0.Z, Z2.S",
		"ZEXPAND Z1.S, P0, Z2.D",
		"ZEXPAND Z1.Q, P0, Z2.Q",
		"ZEXPAND.Z Z1.D, P0, Z2.D",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_", ",", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsveexpand(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsveexpand": {Name: "badsveexpand", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's SVE expand forms", instruction)
			}
		})
	}
}
