package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateARM64SVETableExtensionCompleteGo127Family(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT svetableextensionforms(SB),$0-0\n")
	for _, width := range []string{"B", "H", "S", "D"} {
		fmt.Fprintf(&source, "\tZTBLQ Z1.%s, [Z2.%s], Z3.%s\n", width, width, width)
		fmt.Fprintf(&source, "\tZTBX Z1.%s, Z2.%s, Z3.%s\n", width, width, width)
		fmt.Fprintf(&source, "\tZTBXQ Z1.%s, Z2.%s, Z3.%s\n", width, width, width)
	}
	source.WriteString("\tRET\n")
	requireARM64SVEGoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"svetableextensionforms": {Name: "svetableextensionforms", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{`"target-features"="+sve,+sve2,+sve2p1"`, "@llvm.aarch64.sve.tblq.nxv16i8", "@llvm.aarch64.sve.tbx.nxv4i32", "@llvm.aarch64.sve.tbxq.nxv2i64"} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE table extension lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-table-extension.ll", "arm64-sve-table-extension.o", ll)
		})
	}
}

func TestTranslateARM64SVETableExtensionRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZTBLQ Z1.B, [Z2.B, Z3.B], Z4.B",
		"ZTBLQ Z1.B, [Z2.H], Z3.B",
		"ZTBX Z1.B, Z2.H, Z3.B",
		"ZTBXQ Z1.Q, Z2.Q, Z3.Q",
		"ZTBXQ.Z Z1.D, Z2.D, Z3.D",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_", ",", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsvetableextension(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvetableextension": {Name: "badsvetableextension", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's SVE table extension forms", instruction)
			}
		})
	}
}
