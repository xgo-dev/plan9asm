package plan9asm

import (
	"strings"
	"testing"
)

func TestTranslateARM64SVEHistogramCompleteGo127Family(t *testing.T) {
	source := `
TEXT svehistogram(SB),$0-0
	ZHISTCNT Z1.S, Z2.S, P0.Z, Z3.S
	ZHISTCNT Z4.D, Z5.D, P7.Z, Z6.D
	ZHISTSEG Z7.B, Z8.B, Z9.B
	RET
`
	requireARM64SVEGoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"svehistogram": {Name: "svehistogram", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`"target-features"="+sve,+sve2"`,
				"@llvm.aarch64.sve.histcnt.nxv4i32",
				"@llvm.aarch64.sve.histcnt.nxv2i64",
				"@llvm.aarch64.sve.histseg.nxv16i8",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE histogram lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-histogram.ll", "arm64-sve-histogram.o", ll)
		})
	}
}

func TestTranslateARM64SVEHistogramRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZHISTCNT Z1.B, Z2.B, P0.Z, Z3.B",
		"ZHISTCNT Z1.H, Z2.H, P0.Z, Z3.H",
		"ZHISTCNT Z1.S, Z2.D, P0.Z, Z3.S",
		"ZHISTCNT Z1.S, Z2.S, P8.Z, Z3.S",
		"ZHISTCNT Z1.S, Z2.S, P0.M, Z3.S",
		"ZHISTSEG Z1.H, Z2.H, Z3.H",
		"ZHISTSEG Z1.B, Z2.B, Z3.H",
		"ZHISTSEG.Z Z1.B, Z2.B, Z3.B",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_", ",", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsvehistogram(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvehistogram": {Name: "badsvehistogram", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's histogram forms", instruction)
			}
		})
	}
}
