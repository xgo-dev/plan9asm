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
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				TargetTriple: target.triple,
				Goarch:       target.goarch,
				Sigs: map[string]FuncSig{
					"counterzerobranchforms": {Name: "counterzerobranchforms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "counter-zero-branch-"+target.name+".ll", "counter-zero-branch-"+target.name+".o", ll)
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
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				ll, err := Translate(file, Options{
					TargetTriple: target.triple,
					Goarch:       target.goarch,
					Sigs:         map[string]FuncSig{"counterzero": {Name: "counterzero", Ret: Void}},
				})
				if err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(ll, "icmp eq "+width) {
					t.Fatalf("%s/%s did not test the Go assembler's %s counter width:\n%s", target.goarch, op, width, ll)
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
