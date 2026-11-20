package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateARM64SVEAddressGenerationCompleteGo127Family(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT sveaddressgenerationforms(SB),$0-0\n")
	for _, width := range []string{"S", "D"} {
		for amount := 0; amount <= 3; amount++ {
			fmt.Fprintf(&source, "\tZADR (Z1.%s<<%d)(Z2.%s), Z3.%s\n", width, amount, width, width)
		}
	}
	for _, extension := range []string{"SXTW", "UXTW"} {
		for amount := 0; amount <= 3; amount++ {
			fmt.Fprintf(&source, "\tZADR (Z4.D.%s<<%d)(Z5.D), Z6.D\n", extension, amount)
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
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"sveaddressgenerationforms": {Name: "sveaddressgenerationforms", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				"\"target-features\"=\"+sve\"",
				" shl <vscale x 4 x i32>",
				" shl <vscale x 2 x i64>",
				" sext <vscale x 2 x i32>",
				" zext <vscale x 2 x i32>",
				" add <vscale x ",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE address-generation lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-address-generation.ll", "arm64-sve-address-generation.o", ll)
		})
	}
}

func TestTranslateARM64SVEAddressGenerationRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZADR (Z1.H)(Z2.H), Z3.H",
		"ZADR (Z1.S)(Z2.D), Z3.D",
		"ZADR (Z1.S)(Z2.S), Z3.D",
		"ZADR (Z1.S<<4)(Z2.S), Z3.S",
		"ZADR (Z1.S.SXTW<<2)(Z2.S), Z3.S",
		"ZADR (Z1.D.UXTW<<2)(Z2.S), Z3.D",
		"ZADR.Z (Z1.S)(Z2.S), Z3.S",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsveaddressgeneration(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsveaddressgeneration": {Name: "badsveaddressgeneration", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's ZADR forms", instruction)
			}
		})
	}
}
