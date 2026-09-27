package plan9asm

import (
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestTranslateARM64WideningShiftCompleteGoAssemblerForms(t *testing.T) {
	type form struct {
		source      string
		destination string
		maxShift    int
	}
	low := []form{{"B8", "H8", 7}, {"H4", "S4", 15}, {"S2", "D2", 31}}
	high := []form{{"B16", "H8", 7}, {"H8", "S4", 15}, {"S4", "D2", 31}}
	var src strings.Builder
	src.WriteString("TEXT ·wideningforms(SB), $0-0\n")
	for _, signed := range []bool{false, true} {
		prefix := "VU"
		if signed {
			prefix = "VS"
		}
		for _, variant := range []struct {
			suffix string
			forms  []form
		}{{"", low}, {"2", high}} {
			for _, form := range variant.forms {
				for _, shift := range []int{0, form.maxShift} {
					fmt.Fprintf(&src, "\t%sSHLL%s $%d, V0.%s, V1.%s\n", prefix, variant.suffix, shift, form.source, form.destination)
				}
				fmt.Fprintf(&src, "\t%sXTL%s V0.%s, V1.%s\n", prefix, variant.suffix, form.source, form.destination)
			}
		}
	}
	src.WriteString("\tRET\n")
	if currentGoMinorAtLeast(27) {
		requireARM64GoAssemblerResult(t, src.String(), true)
	}

	for _, triple := range []string{
		"aarch64-apple-darwin",
		"aarch64-unknown-linux-gnu",
		"aarch64-pc-windows-msvc",
	} {
		file, err := Parse(ArchARM64, src.String())
		if err != nil {
			t.Fatal(err)
		}
		ll, err := Translate(file, Options{
			TargetTriple: triple,
			Goarch:       "arm64",
			ResolveSym:   func(sym string) string { return strings.TrimPrefix(sym, "·") },
			Sigs: map[string]FuncSig{
				"wideningforms": {Name: "wideningforms", Ret: Void},
			},
		})
		if err != nil {
			t.Fatalf("%s: %v", triple, err)
		}
		for operation, want := range map[string]int{"zext <": 18, "sext <": 18, "shl <": 24} {
			if got := strings.Count(ll, operation); got != want {
				t.Fatalf("%s emitted %d %q operations, want %d:\n%s", triple, got, operation, want, ll)
			}
		}
		llc := findLLVM22Tool("llc")
		if llc == "" {
			t.Fatal("LLVM 22 llc not found")
		}
		compileLLVMToObject(t, llc, triple, "arm64-widening-shift.ll", "arm64-widening-shift.o", ll)
	}
}

func TestTranslateARM64WideningShiftRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{
		"VUSHLL $8, V0.B8, V1.H8",
		"VSSHLL $-1, V0.H4, V1.S4",
		"VUSHLL2 $0, V0.B8, V1.H8",
		"VSSHLL2 $0, V0.B16, V1.S4",
		"VUXTL V0.B16, V1.H8",
		"VSXTL2 V0.H4, V1.S4",
		"VUXTL $0, V0.B8, V1.H8",
		"VSSHLL.P $0, V0.B8, V1.H8",
	} {
		t.Run(strings.Fields(instruction)[0]+"-"+strings.ReplaceAll(instruction, " ", "_"), func(t *testing.T) {
			src := "TEXT ·badwidening(SB), $0-0\n\t" + instruction + "\n\tRET\n"
			if currentGoMinorAtLeast(27) {
				requireARM64GoAssemblerResult(t, src, false)
			}
			file, err := Parse(ArchARM64, src)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Translate(file, Options{
				TargetTriple: "aarch64-unknown-linux-gnu",
				Goarch:       "arm64",
				ResolveSym:   func(sym string) string { return strings.TrimPrefix(sym, "·") },
				Sigs: map[string]FuncSig{
					"badwidening": {Name: "badwidening", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's widening optab", instruction)
			}
		})
	}
}

func currentGoMinorAtLeast(want int) bool {
	version := runtime.Version()
	start := strings.Index(version, "go1.")
	if start < 0 {
		return false
	}
	minor := version[start+len("go1."):]
	if end := strings.IndexFunc(minor, func(r rune) bool { return r < '0' || r > '9' }); end >= 0 {
		minor = minor[:end]
	}
	got, err := strconv.Atoi(minor)
	return err == nil && got >= want
}
