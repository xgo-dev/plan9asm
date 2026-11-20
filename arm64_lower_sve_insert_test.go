package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func arm64SVEInsertCompleteForms() string {
	var source strings.Builder
	source.WriteString("TEXT sveinsertforms(SB),$0-0\n")
	for _, spec := range []struct {
		op     string
		source string
	}{
		{op: "ZINSR", source: "ZR"},
		{op: "ZINSRW", source: "R25"},
		{op: "ZINSRB", source: "V25"},
		{op: "ZINSRH", source: "V7"},
		{op: "ZINSRS", source: "V14"},
		{op: "ZINSRD", source: "V2"},
	} {
		for vector, width := range []string{"B", "H", "S", "D"} {
			fmt.Fprintf(&source, "\t%s %s, Z%d.%s\n", spec.op, spec.source, vector+1, width)
		}
	}
	source.WriteString("\tRET\n")
	return source.String()
}

func TestTranslateARM64SVEInsertCompleteGo127Family(t *testing.T) {
	source := arm64SVEInsertCompleteForms()
	requireARM64SVEGoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"sveinsertforms": {Name: "sveinsertforms", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				"\"target-features\"=\"+sve\"",
				"@llvm.aarch64.sve.insr.nxv16i8",
				"@llvm.aarch64.sve.insr.nxv8i16",
				"@llvm.aarch64.sve.insr.nxv4i32",
				"@llvm.aarch64.sve.insr.nxv2i64",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE INSR lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-insert.ll", "arm64-sve-insert.o", ll)
		})
	}
}

func TestTranslateARM64SVEInsertRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZINSR V0, Z0.D",
		"ZINSRW V0, Z0.S",
		"ZINSRB R0, Z0.B",
		"ZINSRH R0, Z0.H",
		"ZINSRS R0, Z0.S",
		"ZINSRD R0, Z0.D",
		"ZINSR RSP, Z0.D",
		"ZINSR R0, Z0",
		"ZINSRB V0, Z0.Q",
		"ZINSR.Z R0, Z0.D",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsveinsert(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsveinsert": {Name: "badsveinsert", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's SVE INSR forms", instruction)
			}
		})
	}
}
