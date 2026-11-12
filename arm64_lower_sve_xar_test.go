package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateARM64SVEXARCompleteGo127Family(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT svexar(SB),$0-0\n")
	for widthIndex, width := range []struct {
		suffix string
		bits   int
	}{{"B", 8}, {"H", 16}, {"S", 32}, {"D", 64}} {
		for boundaryIndex, shift := range []int{1, width.bits - 1} {
			destination := widthIndex*2 + boundaryIndex
			fmt.Fprintf(&source, "\tZXAR $%d, Z%d.%s, Z%d.%s, Z%d.%s\n", shift, destination+1, width.suffix, destination, width.suffix, destination, width.suffix)
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
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"svexar": {Name: "svexar", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`"target-features"="+sve,+sve2"`,
				"@llvm.aarch64.sve.xar.nxv16i8",
				"@llvm.aarch64.sve.xar.nxv8i16",
				"@llvm.aarch64.sve.xar.nxv4i32",
				"@llvm.aarch64.sve.xar.nxv2i64",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE XAR lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-xar.ll", "arm64-sve-xar.o", ll)
		})
	}
}

func TestTranslateARM64SVEXARRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZXAR $0, Z1.B, Z2.B, Z2.B",
		"ZXAR $8, Z1.B, Z2.B, Z2.B",
		"ZXAR $16, Z1.H, Z2.H, Z2.H",
		"ZXAR $32, Z1.S, Z2.S, Z2.S",
		"ZXAR $64, Z1.D, Z2.D, Z2.D",
		"ZXAR $1, Z1.H, Z2.S, Z2.S",
		"ZXAR $1, Z1.D, Z2.D, Z3.D",
		"ZXAR.Z $1, Z1.B, Z2.B, Z2.B",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_", ",", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsvexar(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvexar": {Name: "badsvexar", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's XAR forms", instruction)
			}
		})
	}
}
