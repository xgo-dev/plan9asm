package plan9asm

import (
	"strings"
	"testing"
)

func TestTranslateARM64SVECDOTCompleteGo127Family(t *testing.T) {
	const source = `TEXT svecdot(SB),$0-0
	ZCDOT $0, Z8.B, Z9.B, Z10.S
	ZCDOT $90, Z11.H, Z12.H, Z13.D
	ZCDOT $180, Z14.B, Z15.B, Z16.S
	ZCDOT $270, Z17.H, Z18.H, Z19.D
	ZCDOT $0, Z0.B[0], Z20.B, Z21.S
	ZCDOT $270, Z7.B[3], Z22.B, Z23.S
	ZCDOT $90, Z0.H[0], Z24.H, Z25.D
	ZCDOT $180, Z15.H[1], Z26.H, Z27.D
	RET
`
	requireARM64SVEGoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"svecdot": {Name: "svecdot", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`"target-features"="+sve,+sve2"`,
				"@llvm.aarch64.sve.cdot.nxv4i32",
				"@llvm.aarch64.sve.cdot.nxv2i64",
				"@llvm.aarch64.sve.cdot.lane.nxv4i32",
				"@llvm.aarch64.sve.cdot.lane.nxv2i64",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s ZCDOT lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-cdot.ll", "arm64-sve-cdot.o", ll)
		})
	}
}

func TestTranslateARM64SVECDOTRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZCDOT $1, Z1.B, Z2.B, Z3.S",
		"ZCDOT $90, Z1.B, Z2.H, Z3.S",
		"ZCDOT $90, Z1.H, Z2.H, Z3.S",
		"ZCDOT $90, Z8.B[0], Z2.B, Z3.S",
		"ZCDOT $90, Z7.B[4], Z2.B, Z3.S",
		"ZCDOT $90, Z16.H[0], Z2.H, Z3.D",
		"ZCDOT $90, Z15.H[2], Z2.H, Z3.D",
		"ZCDOT.Z $270, Z1.H, Z2.H, Z3.D",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_", ",", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsvecdot(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvecdot": {Name: "badsvecdot", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's ZCDOT forms", instruction)
			}
		})
	}
}
