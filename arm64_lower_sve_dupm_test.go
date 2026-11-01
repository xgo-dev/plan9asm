package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateARM64SVEDupMCompleteGo127Family(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT svedupm(SB),$0-0\n")
	for index, form := range []struct {
		width     string
		immediate string
	}{{"B", "0x55"}, {"H", "0xff00"}, {"S", "0xffff0000"}, {"D", "-4294967296"}} {
		fmt.Fprintf(&source, "\tZDUPM $%s, Z%d.%s\n", form.immediate, index+16, form.width)
	}
	source.WriteString("\tRET\n")
	requireARM64SVEGoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"svedupm": {Name: "svedupm", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`"target-features"="+sve"`,
				"<vscale x 16 x i8>",
				"<vscale x 8 x i16>",
				"<vscale x 4 x i32>",
				"<vscale x 2 x i64>",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s ZDUPM lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-dupm.ll", "arm64-sve-dupm.o", ll)
		})
	}
}

func TestTranslateARM64SVEDupMRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZDUPM $0, Z1.B",
		"ZDUPM $255, Z1.B",
		"ZDUPM $5, Z1.B",
		"ZDUPM $65535, Z1.H",
		"ZDUPM $1, Z1.Q",
		"ZDUPM Z1.D, Z2.D",
		"ZDUPM.Z $7, Z2.D",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_", ",", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsvedupm(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvedupm": {Name: "badsvedupm", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's ZDUPM forms", instruction)
			}
		})
	}
}
