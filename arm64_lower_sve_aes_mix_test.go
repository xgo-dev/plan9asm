package plan9asm

import (
	"strings"
	"testing"
)

func TestTranslateARM64SVEAESMixCompleteGo127Family(t *testing.T) {
	source := "TEXT sveaesmixforms(SB),$0-0\n\tZAESIMC Z3.B, Z3.B\n\tZAESMC Z4.B, Z4.B\n\tRET\n"
	requireARM64SVEGoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"sveaesmixforms": {Name: "sveaesmixforms", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{`"target-features"="+sve2-aes"`, "@llvm.aarch64.sve.aesimc", "@llvm.aarch64.sve.aesmc"} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE AES MixColumns lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-aes-mix.ll", "arm64-sve-aes-mix.o", ll)
		})
	}
}

func TestTranslateARM64SVEAESMixRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZAESIMC Z1.H, Z1.H",
		"ZAESMC Z1.B, Z2.B",
		"ZAESIMC Z1.B",
		"ZAESMC.Z Z1.B, Z1.B",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_", ",", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsveaesmix(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsveaesmix": {Name: "badsveaesmix", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's SVE AES MixColumns forms", instruction)
			}
		})
	}
}
