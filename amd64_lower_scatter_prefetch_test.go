package plan9asm

import (
	"fmt"
	"sort"
	"strings"
	"testing"
)

func TestAMD64VSIBPrefetchGrammarIsComplete(t *testing.T) {
	got := make([]string, 0, len(amd64VSIBPrefetchSpecs))
	for op := range amd64VSIBPrefetchSpecs {
		got = append(got, string(op))
	}
	sort.Strings(got)
	want := []string{
		"VGATHERPF0DPD", "VGATHERPF0DPS", "VGATHERPF0QPD", "VGATHERPF0QPS",
		"VGATHERPF1DPD", "VGATHERPF1DPS", "VGATHERPF1QPD", "VGATHERPF1QPS",
		"VSCATTERPF0DPD", "VSCATTERPF0DPS", "VSCATTERPF0QPD", "VSCATTERPF0QPS",
		"VSCATTERPF1DPD", "VSCATTERPF1DPS", "VSCATTERPF1QPD", "VSCATTERPF1QPS",
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("VSIB-prefetch grammar opcodes = %v, want %v", got, want)
	}
	for op, spec := range amd64VSIBPrefetchSpecs {
		name := string(op)
		wantDirection := amd64VSIBPrefetchGather
		if strings.HasPrefix(name, "VSCATTER") {
			wantDirection = amd64VSIBPrefetchScatter
		}
		wantHint := 0
		if strings.Contains(name, "PF1") {
			wantHint = 1
		}
		shape := name[strings.Index(name, "PF")+3:]
		wantIndexBits := 32
		if shape[0] == 'Q' {
			wantIndexBits = 64
		}
		wantElemBits := 32
		if shape[2] == 'D' {
			wantElemBits = 64
		}
		wantIndexBytes := 64
		if shape == "DPD" {
			wantIndexBytes = 32
		}
		if spec.direction != wantDirection || spec.hint != wantHint || spec.indexBits != wantIndexBits ||
			spec.elemBits != wantElemBits || spec.indexBytes != wantIndexBytes {
			t.Errorf("VSIB-prefetch grammar %s = %+v, want direction=%d hint=%d elem=%d index=%d vector=%d",
				op, spec, wantDirection, wantHint, wantElemBits, wantIndexBits, wantIndexBytes)
		}
	}
}

func TestTranslateX86ScatterPrefetchCompleteGoAssemblerForms(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range []struct {
		name   string
		goarch string
		triple string
	}{
		{name: "darwin-amd64", goarch: "amd64", triple: "x86_64-apple-darwin"},
		{name: "linux-amd64", goarch: "amd64", triple: "x86_64-unknown-linux-gnu"},
		{name: "windows-amd64", goarch: "amd64", triple: "x86_64-pc-windows-msvc"},
		{name: "linux-386", goarch: "386", triple: "i386-unknown-linux-gnu"},
		{name: "windows-386", goarch: "386", triple: "i686-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			var source strings.Builder
			source.WriteString("TEXT scatterprefetchforms(SB),$0-0\n")
			for _, op := range []string{"VSCATTERPF0DPD", "VSCATTERPF1DPD"} {
				fmt.Fprintf(&source, "\t%s K1, 8(SP)(Y2*8)\n", op)
				if target.goarch == "amd64" {
					fmt.Fprintf(&source, "\t%s K7, 16(R11)(Y20*4)\n", op)
				}
			}
			for _, op := range []string{
				"VSCATTERPF0DPS", "VSCATTERPF0QPD", "VSCATTERPF0QPS",
				"VSCATTERPF1DPS", "VSCATTERPF1QPD", "VSCATTERPF1QPS",
			} {
				fmt.Fprintf(&source, "\t%s K2, 24(BX)(Z3*4)\n", op)
				if target.goarch == "amd64" {
					fmt.Fprintf(&source, "\t%s K6, 32(SP)(Z20*8)\n", op)
				}
			}
			source.WriteString("\tRET\n")
			requireX86GoAssemblerResult(t, target.goarch, source.String(), true)
			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				Goarch: target.goarch, TargetTriple: target.triple,
				Sigs: map[string]FuncSig{"scatterprefetchforms": {Name: "scatterprefetchforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "scatter-prefetch-"+target.name+".ll", "scatter-prefetch-"+target.name+".o", ir)
		})
	}
}

func TestTranslateX86ScatterPrefetchRejectsFormsOutsideGoTables(t *testing.T) {
	for _, test := range []struct {
		goarch      string
		instruction string
	}{
		{goarch: "amd64", instruction: "VSCATTERPF0DPD K0, (AX)(Y2*8)"},
		{goarch: "amd64", instruction: "VSCATTERPF1DPD K1, (AX)(Z2*8)"},
		{goarch: "amd64", instruction: "VSCATTERPF0DPS K1, (AX)(Y2*4)"},
		{goarch: "amd64", instruction: "VSCATTERPF0QPD K1, (AX)"},
		{goarch: "amd64", instruction: "VSCATTERPF0QPS (AX)(Z2*4), K1"},
		{goarch: "amd64", instruction: "VSCATTERPF1DPS.Z K1, (AX)(Z2*4)"},
		{goarch: "amd64", instruction: "VSCATTERPF1QPD K1, (AX)(Z2*4), Z3"},
		{goarch: "amd64", instruction: "VSCATTERPF1QPS X1, (AX)(Z2*4)"},
		{goarch: "386", instruction: "VSCATTERPF0DPD K1, (R8)(Y2*8)"},
		{goarch: "386", instruction: "VSCATTERPF1DPS K1, (AX)(Z8*4)"},
	} {
		t.Run(test.goarch+"_"+strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(test.instruction), func(t *testing.T) {
			source := "TEXT bad(SB),$0-0\n\t" + test.instruction + "\n\tRET\n"
			requireX86GoAssemblerResult(t, test.goarch, source, false)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				return
			}
			triple := "x86_64-unknown-linux-gnu"
			if test.goarch == "386" {
				triple = "i386-unknown-linux-gnu"
			}
			if _, err := Translate(file, Options{
				Goarch: test.goarch, TargetTriple: triple,
				Sigs: map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's scatter-prefetch tables", test.instruction)
			}
		})
	}
}
