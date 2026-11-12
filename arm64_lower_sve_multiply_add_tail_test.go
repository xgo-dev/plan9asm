package plan9asm

import (
	"strings"
	"testing"
)

func TestTranslateARM64SVEMultiplyAddTailCompleteGo127Family(t *testing.T) {
	source := `
TEXT svemultiplyaddtail(SB),$0-0
	ZMADPT Z7.D, Z6.D, Z23.D
	ZMLAPT Z8.D, Z9.D, Z24.D
	RET
`
	requireARM64SVEGoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"svemultiplyaddtail": {Name: "svemultiplyaddtail", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`"target-features"="+cpa,+sve"`,
				`asm sideeffect "madpt $0.d, $2.d, $3.d", "=&w,0,w,w"`,
				`asm sideeffect "mlapt $0.d, $2.d, $3.d", "=&w,0,w,w"`,
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE multiply-add-tail lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-multiply-add-tail.ll", "arm64-sve-multiply-add-tail.o", ll)
		})
	}
}

func TestTranslateARM64SVEMultiplyAddTailRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZMADPT Z1.S, Z2.S, Z3.S",
		"ZMADPT Z1.D, Z2.S, Z3.D",
		"ZMLAPT Z1.H, Z2.H, Z3.H",
		"ZMLAPT Z1.D, Z2.D",
		"ZMADPT.Z Z1.D, Z2.D, Z3.D",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_", ",", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsvemultiplyaddtail(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvemultiplyaddtail": {Name: "badsvemultiplyaddtail", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's multiply-add-tail forms", instruction)
			}
		})
	}
}
