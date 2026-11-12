package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateX86CounterZeroBranchCompleteGoAssemblerForms(t *testing.T) {
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
			source := "TEXT counterzerobranchforms(SB),NOSPLIT,$0-0\n" +
				"\tJCXZW width16\n" +
				"width16:\n" +
				"\tJCXZL width32\n" +
				"width32:\n" +
				"\tJCXZQ width64\n" +
				"width64:\n" +
				"\tRET\n"
			// Preserve the exact original source as a Go-format and missing-CX
			// control; a bare register read does not establish its input bytes.
			x86UnboundVoidFormatSources(t, source, target.goarch, target.triple)
			move := "MOVQ"
			if target.goarch == "386" {
				move = "MOVL"
			}
			initialized := strings.Replace(source, "\tJCXZW", "\t"+move+" $1,CX\n\tJCXZW", 1)
			x86LEAActualTargetGoObject(t, target.goarch, target.triple, "#include \"textflag.h\"\n"+initialized)
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			for _, api := range []string{"text", "module", "Go"} {
				ll, err := x86ScalarFPBitViewAPI(t, initialized, "func counterzerobranchforms()", target.goarch, target.triple, api)
				if err != nil {
					t.Fatal("same original branches with actual numerical CX", api, err)
				}
				for _, level := range []string{"-O0", "-O2"} {
					x86PackedStringCompileObject(t, llc, target.triple, ll, level)
				}
			}
		})
	}
}

func TestTranslateX86CounterZeroBranchMatchesGoAssemblerAddressWidths(t *testing.T) {
	for _, target := range []struct {
		name   string
		goarch string
		triple string
		widths map[string]string
	}{
		{
			name: "amd64", goarch: "amd64", triple: "x86_64-unknown-linux-gnu",
			widths: map[string]string{"JCXZW": "i64", "JCXZL": "i32", "JCXZQ": "i64"},
		},
		{
			name: "386", goarch: "386", triple: "i386-unknown-linux-gnu",
			widths: map[string]string{"JCXZW": "i32", "JCXZL": "i16", "JCXZQ": "i32"},
		},
	} {
		for op, width := range target.widths {
			t.Run(target.name+"_"+op, func(t *testing.T) {
				source := fmt.Sprintf("TEXT counterzero(SB),NOSPLIT,$0-0\n\t%s zero\n\tRET\nzero:\n\tRET\n", op)
				x86UnboundVoidFormatSources(t, source, target.goarch, target.triple)
				move := "MOVQ"
				if target.goarch == "386" {
					move = "MOVL"
				}
				initialized := strings.Replace(source, "\t"+op, "\t"+move+" $1,CX\n\t"+op, 1)
				for _, api := range []string{"text", "module", "Go"} {
					ll, err := x86ScalarFPBitViewAPI(t, initialized, "func counterzero()", target.goarch, target.triple, api)
					if err != nil {
						t.Fatal("same original branch with actual numerical CX", api, err)
					}
					if !strings.Contains(ll, "icmp eq "+width) {
						t.Fatalf("%s/%s/%s did not test Go's %s counter width:\n%s", target.goarch, op, api, width, ll)
					}
				}
			})
		}
	}
}

func TestTranslateX86CounterZeroBranchRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{
		"JCXZW",
		"JCXZL $1, done",
		"JCXZQ done, other",
		"JCXZQ AX",
		"JCXZQ.Z done",
	} {
		t.Run(strings.NewReplacer(" ", "_", ",", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT bad(SB),NOSPLIT,$0-0\n\t" + instruction + "\ndone:\nother:\n\tRET\n"
			file, err := Parse(ArchAMD64, source)
			if err == nil {
				_, err = Translate(file, Options{
					TargetTriple: "x86_64-unknown-linux-gnu",
					Goarch:       "amd64",
					Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
				})
			}
			if err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's yloop table", instruction)
			}
		})
	}
}
