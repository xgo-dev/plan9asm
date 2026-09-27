package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

type approximateMathTestSpec struct {
	op       string
	laneBits int
	scalar   bool
	mode     amd64ApproximateMathMode
}

func go127ApproximateMathSpecs() []approximateMathTestSpec {
	return []approximateMathTestSpec{
		{op: "VEXP2PS", laneBits: 32, mode: amd64ApproximateExp2},
		{op: "VEXP2PD", laneBits: 64, mode: amd64ApproximateExp2},
		{op: "VRCP28PS", laneBits: 32, mode: amd64ApproximateReciprocal28},
		{op: "VRCP28PD", laneBits: 64, mode: amd64ApproximateReciprocal28},
		{op: "VRCP28SS", laneBits: 32, scalar: true, mode: amd64ApproximateReciprocal28},
		{op: "VRCP28SD", laneBits: 64, scalar: true, mode: amd64ApproximateReciprocal28},
		{op: "VRSQRT28PS", laneBits: 32, mode: amd64ApproximateReciprocalSqrt28},
		{op: "VRSQRT28PD", laneBits: 64, mode: amd64ApproximateReciprocalSqrt28},
		{op: "VRSQRT28SS", laneBits: 32, scalar: true, mode: amd64ApproximateReciprocalSqrt28},
		{op: "VRSQRT28SD", laneBits: 64, scalar: true, mode: amd64ApproximateReciprocalSqrt28},
	}
}

func TestAMD64ApproximateMathGrammarCoversCompleteGoFamily(t *testing.T) {
	expected := go127ApproximateMathSpecs()
	if len(amd64ApproximateMathSpecs) != len(expected) {
		t.Fatalf("approximate-math grammar has %d entries, want %d", len(amd64ApproximateMathSpecs), len(expected))
	}
	for _, want := range expected {
		got, ok := amd64ApproximateMathSpecs[Op(want.op)]
		if !ok {
			t.Errorf("approximate-math grammar omitted %s", want.op)
			continue
		}
		if got.laneBits != want.laneBits || got.scalar != want.scalar || got.mode != want.mode {
			t.Errorf("approximate-math grammar %s = %+v, want laneBits=%d scalar=%v mode=%d", want.op, got, want.laneBits, want.scalar, want.mode)
		}
	}
}

func TestTranslateX86ApproximateMathCompleteGoAssemblerForms(t *testing.T) {
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
			vectorDestination := 23
			if target.goarch == "386" {
				vectorDestination = 7
			}
			var source strings.Builder
			source.WriteString("TEXT approximatemathforms(SB),$0-0\n")
			for index, spec := range go127ApproximateMathSpecs() {
				if spec.scalar {
					fmt.Fprintf(&source, "\t%s X1, X2, X23\n", spec.op)
					fmt.Fprintf(&source, "\t%s %d(AX), X2, X23\n", spec.op, index*8)
					fmt.Fprintf(&source, "\t%s.SAE X1, X2, X23\n", spec.op)
					if target.goarch == "amd64" {
						fmt.Fprintf(&source, "\t%s X1, X2, K1, X23\n", spec.op)
						fmt.Fprintf(&source, "\t%s.Z %d(AX), X2, K2, X23\n", spec.op, index*8)
						fmt.Fprintf(&source, "\t%s.SAE.Z X1, X2, K3, X23\n", spec.op)
					}
					continue
				}
				fmt.Fprintf(&source, "\t%s Z1, Z%d\n", spec.op, vectorDestination)
				fmt.Fprintf(&source, "\t%s %d(AX), Z%d\n", spec.op, index*8, vectorDestination)
				fmt.Fprintf(&source, "\t%s Z1, K1, Z%d\n", spec.op, vectorDestination)
				fmt.Fprintf(&source, "\t%s.Z %d(AX), K2, Z%d\n", spec.op, index*8, vectorDestination)
				fmt.Fprintf(&source, "\t%s.BCST %d(AX), Z%d\n", spec.op, index*8, vectorDestination)
				fmt.Fprintf(&source, "\t%s.BCST.Z %d(AX), K3, Z%d\n", spec.op, index*8, vectorDestination)
				fmt.Fprintf(&source, "\t%s.SAE Z1, Z%d\n", spec.op, vectorDestination)
				fmt.Fprintf(&source, "\t%s.SAE.Z Z1, K4, Z%d\n", spec.op, vectorDestination)
			}
			source.WriteString("\tRET\n")

			requireX86GoAssemblerResult(t, target.goarch, source.String(), true)
			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				Goarch: target.goarch, TargetTriple: target.triple,
				Sigs: map[string]FuncSig{"approximatemathforms": {Name: "approximatemathforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, mnemonic := range []string{"vexp2ps", "vexp2pd", "vrcp28ps", "vrcp28pd", "vrcp28ss", "vrcp28sd", "vrsqrt28ps", "vrsqrt28pd", "vrsqrt28ss", "vrsqrt28sd"} {
				if !strings.Contains(ir, mnemonic) {
					t.Fatalf("translation omitted inline %s:\n%s", mnemonic, ir)
				}
			}
			for _, fragment := range []string{"kmovw", "{%k1}", "{sae}", `"target-features"="+avx512f"`} {
				if !strings.Contains(ir, fragment) {
					t.Fatalf("translation omitted %q:\n%s", fragment, ir)
				}
			}
			compileLLVMToObject(t, llc, target.triple, "approximate-math-"+target.name+".ll", "approximate-math-"+target.name+".o", ir)
		})
	}
}

func TestTranslateX86ApproximateMathRejectsFormsOutsideGoTables(t *testing.T) {
	for _, test := range []struct {
		goarch      string
		instruction string
	}{
		{goarch: "amd64", instruction: "VEXP2PS X0, X1"},
		{goarch: "amd64", instruction: "VEXP2PD Y0, Y1"},
		{goarch: "amd64", instruction: "VRCP28PS Z0, K0, Z1"},
		{goarch: "amd64", instruction: "VRSQRT28PD.Z Z0, Z1"},
		{goarch: "amd64", instruction: "VEXP2PS.BCST Z0, Z1"},
		{goarch: "amd64", instruction: "VRCP28PD.SAE 0(AX), Z1"},
		{goarch: "amd64", instruction: "VRCP28SS X0, X1"},
		{goarch: "amd64", instruction: "VRSQRT28SD Y0, X1, X2"},
		{goarch: "amd64", instruction: "VRCP28SS.BCST 0(AX), X1, X2"},
		{goarch: "amd64", instruction: "VRSQRT28SD.SAE 0(AX), X1, X2"},
		{goarch: "amd64", instruction: "VEXP2PS.RN_SAE Z0, Z1"},
		{goarch: "386", instruction: "VEXP2PS Z0, Z8"},
		{goarch: "386", instruction: "VRCP28SS X0, X1, K1, X2"},
	} {
		t.Run(test.goarch+"_"+strings.NewReplacer(" ", "_", ",", "", "(", "_", ")", "_").Replace(test.instruction), func(t *testing.T) {
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
				t.Fatalf("Translate accepted %q outside Go 1.27's approximate-math tables", test.instruction)
			}
		})
	}
}
