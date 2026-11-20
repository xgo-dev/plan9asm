package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateX86SegmentRegisterCompleteGoAssemblerForms(t *testing.T) {
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
			source.WriteString("TEXT segmentregisterforms(SB),$0-0\n")
			for _, segment := range []string{"ES", "CS", "SS", "DS", "FS", "GS"} {
				fmt.Fprintf(&source, "\tMOVW AX, %s\n", segment)
				fmt.Fprintf(&source, "\tMOVW %s, AX\n", segment)
				fmt.Fprintf(&source, "\tMOVW 8(BX), %s\n", segment)
				fmt.Fprintf(&source, "\tMOVW %s, 16(BX)\n", segment)
			}
			for _, suffix := range []string{
				"Z", "SAE", "SAE.Z",
				"RN_SAE", "RZ_SAE", "RD_SAE", "RU_SAE",
				"RN_SAE.Z", "RZ_SAE.Z", "RD_SAE.Z", "RU_SAE.Z",
				"BCST", "BCST.Z",
			} {
				fmt.Fprintf(&source, "\tMOVW.%s AX, DS\n", suffix)
			}
			source.WriteString("\tRET\n")
			requireX86GoAssemblerResult(t, target.goarch, source.String(), true)
			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				TargetTriple: target.triple,
				Goarch:       target.goarch,
				Sigs: map[string]FuncSig{
					"segmentregisterforms": {Name: "segmentregisterforms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "segment-register-"+target.name+".ll", "segment-register-"+target.name+".o", ll)
		})
	}
}

func TestTranslateX86SegmentRegisterRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{
		"MOVL AX, DS",
		"MOVQ AX, DS",
		"MOVW AL, DS",
		"MOVW X0, DS",
		"MOVW DS, X0",
		"MOVW DS, FS",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			for _, goarch := range []string{"386", "amd64"} {
				requireX86GoAssemblerResult(t, goarch, "TEXT bad(SB),$0-0\n\t"+instruction+"\n\tRET\n", false)
				triple := "i386-unknown-linux-gnu"
				if goarch == "amd64" {
					triple = "x86_64-unknown-linux-gnu"
				}
				assertX86SegmentRegisterRejected(t, goarch, triple, instruction)
			}
		})
	}
}

func assertX86SegmentRegisterRejected(t *testing.T, goarch, triple, instruction string) {
	t.Helper()
	file, err := Parse(ArchAMD64, "TEXT bad(SB),$0-0\n\t"+instruction+"\n\tRET\n")
	if err == nil {
		_, err = Translate(file, Options{
			TargetTriple: triple,
			Goarch:       goarch,
			Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
		})
	}
	if err == nil {
		t.Fatalf("Translate accepted %q outside Go 1.27's segment-register MOVW table for %s", instruction, goarch)
	}
}

func TestX86SegmentRegistersDoNotShadowARM64Conditions(t *testing.T) {
	file, err := Parse(ArchARM64, "TEXT select(SB),$0-0\n\tCSEL CS, R11, R3, R3\n\tRET\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(file.Funcs) != 1 || len(file.Funcs[0].Instrs) < 2 || len(file.Funcs[0].Instrs[1].Args) != 4 {
		t.Fatalf("unexpected ARM64 parse: %+v", file)
	}
	condition := file.Funcs[0].Instrs[1].Args[0]
	if condition.Kind == OpReg {
		t.Fatalf("ARM64 CS condition was parsed as an x86 segment register: %+v", condition)
	}
}
