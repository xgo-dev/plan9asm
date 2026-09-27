package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateX86ScatterCompleteGoAssemblerForms(t *testing.T) {
	// Go 1.27 exposes eight integer/floating spellings over three exact
	// data/index width tables. Every form is data, K1-K7, VSIB memory.
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
			lastZ := 20
			if target.goarch == "386" {
				lastZ = 7
			}
			var source strings.Builder
			source.WriteString("TEXT scatterforms(SB),NOSPLIT,$0-0\n")
			for _, op := range []string{"VPSCATTERDD", "VPSCATTERQQ", "VSCATTERDPS", "VSCATTERQPD"} {
				fmt.Fprintf(&source, "\t%s X20, K1, (AX)(X2*1)\n", op)
				fmt.Fprintf(&source, "\t%s Y20, K2, 8(BX)(Y3*2)\n", op)
				fmt.Fprintf(&source, "\t%s Z%d, K3, 16(CX)(Z4*4)\n", op, lastZ)
			}
			for _, op := range []string{"VPSCATTERDQ", "VSCATTERDPD"} {
				fmt.Fprintf(&source, "\t%s X20, K4, 24(DX)(X5*8)\n", op)
				fmt.Fprintf(&source, "\t%s Y20, K5, 32(SI)(X6*1)\n", op)
				fmt.Fprintf(&source, "\t%s Z%d, K6, 40(DI)(Y7*2)\n", op, lastZ)
			}
			for _, op := range []string{"VPSCATTERQD", "VSCATTERQPS"} {
				fmt.Fprintf(&source, "\t%s X20, K7, 48(AX)(X2*4)\n", op)
				fmt.Fprintf(&source, "\t%s X20, K1, 56(BX)(Y3*8)\n", op)
				fmt.Fprintf(&source, "\t%s Y20, K2, 64(CX)(Z4*1)\n", op)
			}
			source.WriteString("\tRET\n")

			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				TargetTriple: target.triple,
				Goarch:       target.goarch,
				Sigs:         map[string]FuncSig{"scatterforms": {Name: "scatterforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "scatter-"+target.name+".ll", "scatter-"+target.name+".o", ll)
		})
	}
}

func TestTranslateX86ScatterRejectsFormsOutsideGoAssemblerTables(t *testing.T) {
	for _, instruction := range []string{
		"VPSCATTERDD X1, (AX)(X2*1)",
		"VPSCATTERDD X1, K0, (AX)(X2*1)",
		"VPSCATTERDD X1, K1, (AX)",
		"VPSCATTERDD Y1, K1, (AX)(X2*1)",
		"VPSCATTERDQ X1, K1, (AX)(Y2*1)",
		"VPSCATTERQD Y1, K1, (AX)(Y2*1)",
		"VPSCATTERDD X1, K1, (AX)(X2*3)",
		"VPSCATTERDD.Z X1, K1, (AX)(X2*1)",
		"VPSCATTERDD X1, K1, X2",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			assertX86ScatterRejected(t, "amd64", "x86_64-unknown-linux-gnu", instruction)
		})
	}
	assertX86ScatterRejected(t, "386", "i386-unknown-linux-gnu", "VPSCATTERDD X1, K1, (R8)(X2*1)")
	assertX86ScatterRejected(t, "386", "i386-unknown-linux-gnu", "VPSCATTERDD X1, K1, (AX)(X8*1)")
	assertX86ScatterRejected(t, "386", "i386-unknown-linux-gnu", "VPSCATTERDD Z8, K1, (AX)(Z7*1)")
}

func assertX86ScatterRejected(t *testing.T, goarch, triple, instruction string) {
	t.Helper()
	file, err := Parse(ArchAMD64, "TEXT bad(SB),NOSPLIT,$0-0\n\t"+instruction+"\n\tRET\n")
	if err != nil {
		return
	}
	if _, err := Translate(file, Options{
		TargetTriple: triple,
		Goarch:       goarch,
		Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
	}); err == nil {
		t.Fatalf("Translate accepted %q outside Go 1.27's scatter forms", instruction)
	}
}
