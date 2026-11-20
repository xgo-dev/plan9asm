package plan9asm

import (
	"strings"
	"testing"
)

func arm64SVEAbsoluteDifferenceCompleteForms() string {
	var source strings.Builder
	source.WriteString("TEXT sveabsdiffforms(SB),$0-0\n")
	for _, op := range []string{"ZSABA", "ZUABA"} {
		for _, width := range []string{"B", "H", "S", "D"} {
			source.WriteString("\t" + op + " Z1." + width + ", Z2." + width + ", Z3." + width + "\n")
		}
	}
	for _, op := range []string{"ZSABD", "ZUABD"} {
		for predicate, width := range []string{"B", "H", "S", "D"} {
			source.WriteString("\t" + op + " Z4." + width + ", Z5." + width + ", P" + string(rune('0'+predicate)) + ".M, Z5." + width + "\n")
		}
	}
	for _, op := range []string{"ZSABALB", "ZSABALT", "ZUABALB", "ZUABALT", "ZSABDLB", "ZSABDLT", "ZUABDLB", "ZUABDLT"} {
		for _, narrowWidth := range []string{"B", "H", "S"} {
			wideWidth := map[string]string{"B": "H", "H": "S", "S": "D"}[narrowWidth]
			source.WriteString("\t" + op + " Z6." + narrowWidth + ", Z7." + narrowWidth + ", Z8." + wideWidth + "\n")
		}
	}
	for _, op := range []string{"ZSADALP", "ZUADALP"} {
		for predicate, narrowWidth := range []string{"B", "H", "S"} {
			wideWidth := map[string]string{"B": "H", "H": "S", "S": "D"}[narrowWidth]
			source.WriteString("\t" + op + " Z9." + narrowWidth + ", P" + string(rune('4'+predicate)) + ".M, Z10." + wideWidth + "\n")
		}
	}
	source.WriteString("\tRET\n")
	return source.String()
}

func TestTranslateARM64SVEAbsoluteDifferenceCompleteGo127Family(t *testing.T) {
	source := arm64SVEAbsoluteDifferenceCompleteForms()
	requireARM64SVEGoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"sveabsdiffforms": {Name: "sveabsdiffforms", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`"target-features"="+sve,+sve2"`,
				"@llvm.aarch64.sve.saba.nxv16i8",
				"@llvm.aarch64.sve.uaba.nxv2i64",
				"@llvm.aarch64.sve.sabd.nxv8i16",
				"@llvm.aarch64.sve.uabd.nxv4i32",
				"@llvm.aarch64.sve.sabalb.nxv8i16",
				"@llvm.aarch64.sve.uabalt.nxv2i64",
				"@llvm.aarch64.sve.sabdlt.nxv4i32",
				"@llvm.aarch64.sve.uabdlb.nxv8i16",
				"@llvm.aarch64.sve.sadalp.nxv8i16",
				"@llvm.aarch64.sve.uadalp.nxv2i64",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE absolute-difference lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-absolute-difference.ll", "arm64-sve-absolute-difference.o", ll)
		})
	}
}

func TestTranslateARM64SVEAbsoluteDifferenceRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZSABA Z1.B, Z2.H, Z3.B",
		"ZUABA Z1.S, Z2.S, Z3.D",
		"ZSABD Z1.B, Z2.B, P0, Z2.B",
		"ZUABD Z1.H, Z2.H, P8.M, Z2.H",
		"ZSABD Z1.S, Z2.S, P0.M, Z3.S",
		"ZSABALB Z1.B, Z2.H, Z3.H",
		"ZUABALT Z1.S, Z2.S, Z3.S",
		"ZSABDLB Z1.D, Z2.D, Z3.D",
		"ZUABDLT Z1.H, Z2.H, Z3.H",
		"ZSADALP Z1.B, P0, Z2.H",
		"ZUADALP Z1.H, P0.M, Z2.H",
		"ZSABA.Z Z1.B, Z2.B, Z3.B",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_", ",", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsveabsdiff(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsveabsdiff": {Name: "badsveabsdiff", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's SVE absolute-difference forms", instruction)
			}
		})
	}
}
