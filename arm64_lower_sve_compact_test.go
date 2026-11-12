package plan9asm

import (
	"strings"
	"testing"
)

func TestTranslateARM64SVECompactCompleteGo127Family(t *testing.T) {
	source := "TEXT svecompactforms(SB),$0-0\n" +
		"\tZCOMPACT Z0.B, P0, Z4.B\n" +
		"\tZCOMPACT Z1.H, P1, Z5.H\n" +
		"\tZCOMPACT Z2.S, P2, Z6.S\n" +
		"\tZCOMPACT Z3.D, P7, Z7.D\n" +
		"\tRET\n"
	requireARM64SVEGoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"svecompactforms": {Name: "svecompactforms", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				"\"target-features\"=\"+sve,+sve2p2\"",
				"@llvm.aarch64.sve.compact.nxv16i8",
				"@llvm.aarch64.sve.compact.nxv8i16",
				"@llvm.aarch64.sve.compact.nxv4i32",
				"@llvm.aarch64.sve.compact.nxv2i64",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE COMPACT lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-compact.ll", "arm64-sve-compact.o", ll)
		})
	}
}

func TestTranslateARM64SVECompactRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZCOMPACT Z0.B, P0, Z1.H",
		"ZCOMPACT Z0.H, P0, Z1.B",
		"ZCOMPACT Z0.S, P8, Z1.S",
		"ZCOMPACT Z0.D, P0.M, Z1.D",
		"ZCOMPACT Z0.Q, P0, Z1.Q",
		"ZCOMPACT.Z Z0.D, P0, Z1.D",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsvecompact(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvecompact": {Name: "badsvecompact", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's SVE COMPACT forms", instruction)
			}
		})
	}
}
