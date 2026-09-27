package plan9asm

import (
	"strings"
	"testing"
)

func TestTranslateARM64SVEOptionalCryptoCompleteGo127Family(t *testing.T) {
	const source = `
TEXT sveoptionalcrypto(SB),$0-0
	ZRAX1 Z1.D, Z2.D, Z3.D
	ZSM4E Z4.S, Z5.S, Z5.S
	ZSM4EKEY Z6.S, Z7.S, Z8.S
	RET
`
	requireARM64SVEGoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"sveoptionalcrypto": {Name: "sveoptionalcrypto", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{`"target-features"="+sve2-sha3,+sve2-sm4"`, "@llvm.aarch64.sve.rax1", "@llvm.aarch64.sve.sm4e", "@llvm.aarch64.sve.sm4ekey"} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE optional crypto lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-optional-crypto.ll", "arm64-sve-optional-crypto.o", ll)
		})
	}
}

func TestTranslateARM64SVEOptionalCryptoRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZRAX1 Z1.S, Z2.S, Z3.S",
		"ZRAX1 Z1.D, Z2.D",
		"ZSM4E Z1.S, Z2.S, Z3.S",
		"ZSM4E Z1.D, Z2.D, Z2.D",
		"ZSM4EKEY Z1.S, Z2.S, Z3.D",
		"ZSM4EKEY.Z Z1.S, Z2.S, Z3.S",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_", ",", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsveoptionalcrypto(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsveoptionalcrypto": {Name: "badsveoptionalcrypto", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's SVE optional crypto forms", instruction)
			}
		})
	}
}
