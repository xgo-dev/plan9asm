package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateARM64SVEMADMSBCompleteGo127Family(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT svemadmsbforms(SB),$0-0\n")
	for _, op := range []string{"ZMAD", "ZMSB"} {
		for index, width := range []string{"B", "H", "S", "D"} {
			fmt.Fprintf(&source, "\t%s Z1.%s, Z2.%s, P%d.M, Z3.%s\n", op, width, width, index, width)
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
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"svemadmsbforms": {Name: "svemadmsbforms", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				"\"target-features\"=\"+sve\"",
				"@llvm.aarch64.sve.mad.nxv16i8",
				"@llvm.aarch64.sve.mad.nxv2i64",
				"@llvm.aarch64.sve.msb.nxv16i8",
				"@llvm.aarch64.sve.msb.nxv2i64",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE MAD/MSB lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-mad-msb.ll", "arm64-sve-mad-msb.o", ll)
		})
	}
}

func TestTranslateARM64SVEMADMSBRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZMAD Z1.B, Z2.H, P0.M, Z3.H",
		"ZMSB Z1.S, Z2.S, P0, Z3.S",
		"ZMAD Z1.D, Z2.D, P8.M, Z3.D",
		"ZMSB Z1.S, Z2.S, P0.Z, Z3.S",
		"ZMAD Z1.S, Z2.S, P0.M",
		"ZMSB.Z Z1.S, Z2.S, P0.M, Z3.S",
		"ZMAD Z7.H[0], Z2.H, Z3.H",
		"ZMSB Z15.D[1], Z2.D, Z3.D",
		"ZMAD Z1.D, Z2.D, Z3.D",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsvemadmsb(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvemadmsb": {Name: "badsvemadmsb", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's SVE MAD/MSB forms", instruction)
			}
		})
	}
}
