package plan9asm

import (
	"strings"
	"testing"
)

func TestTranslateARM64CTERMCompleteGo127Family(t *testing.T) {
	source := `TEXT ctermforms(SB),$0-0
	CTERMEQ R3, R4
	CTERMEQ ZR, R25
	CTERMEQW R5, ZR
	CTERMNE R6, R7
	CTERMNE ZR, ZR
	CTERMNEW R8, R9
	RET
`
	requireARM64SVEGoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"ctermforms": {Name: "ctermforms", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`"target-features"="+sve"`,
				`asm sideeffect "ctermeq $0, $1"`,
				`asm sideeffect "ctermne $0, $1"`,
				"trunc i64",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s CTERM lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-cterm.ll", "arm64-cterm.o", ll)
		})
	}
}

func TestTranslateARM64CTERMRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"CTERMEQ R3",
		"CTERMEQ R3, R4, R5",
		"CTERMEQ RSP, R4",
		"CTERMEQ R3, RSP",
		"CTERMEQ $1, R4",
		"CTERMEQ R3, 8(R4)",
		"CTERMEQ.Z R3, R4",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badcterm(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badcterm": {Name: "badcterm", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's CTERM forms", instruction)
			}
		})
	}
}
