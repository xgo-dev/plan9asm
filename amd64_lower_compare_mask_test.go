package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateX86ImmediatePackedCompareCompleteGoAssemblerForms(t *testing.T) {
	// Go 1.27 gives VPCMP{B,W,D,Q,UB,UW,UD,UQ} the same _yvpcmpb
	// table: unsigned-byte immediate, X/Y/Z r/m first source, matching vector
	// second source, optional K1-K7 write mask, and K destination. D/Q forms
	// additionally enable scalar-memory broadcast.
	for _, target := range []struct {
		name   string
		triple string
	}{
		{name: "darwin-amd64", triple: "x86_64-apple-darwin"},
		{name: "linux-amd64", triple: "x86_64-unknown-linux-gnu"},
		{name: "windows-amd64", triple: "x86_64-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			var source strings.Builder
			source.WriteString("TEXT immediatepackedcompareforms(SB),NOSPLIT,$0-0\n")
			for _, op := range []string{
				"VPCMPB", "VPCMPW", "VPCMPD", "VPCMPQ",
				"VPCMPUB", "VPCMPUW", "VPCMPUD", "VPCMPUQ",
			} {
				fmt.Fprintf(&source, "\t%s $0, X1, X20, K0\n", op)
				fmt.Fprintf(&source, "\t%s $1, 8(AX), X20, K1, K2\n", op)
				fmt.Fprintf(&source, "\t%s $2, Y1, Y20, K3\n", op)
				fmt.Fprintf(&source, "\t%s $3, 40(AX), Y20, K4, K5\n", op)
				fmt.Fprintf(&source, "\t%s $7, Z1, Z20, K6\n", op)
				fmt.Fprintf(&source, "\t%s $255, 104(AX), Z20, K7, K0\n", op)
				if strings.HasSuffix(op, "D") || strings.HasSuffix(op, "Q") {
					fmt.Fprintf(&source, "\t%s.BCST $4, 168(AX), X20, K1\n", op)
					fmt.Fprintf(&source, "\t%s.BCST $5, 176(AX), Y20, K2, K3\n", op)
					fmt.Fprintf(&source, "\t%s.BCST $6, 184(AX), Z20, K4\n", op)
				}
			}
			source.WriteString("\tRET\n")

			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				TargetTriple: target.triple,
				Goarch:       "amd64",
				Sigs: map[string]FuncSig{
					"immediatepackedcompareforms": {Name: "immediatepackedcompareforms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "immediate-packed-compare-"+target.name+".ll", "immediate-packed-compare-"+target.name+".o", ll)
		})
	}
}

func TestTranslateX86ImmediatePackedCompareRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{
		"VPCMPUD X0, X1, K1",
		"VPCMPUD $256, X0, X1, K1",
		"VPCMPUD $1, X0, Y1, K1",
		"VPCMPUD $1, X0, (AX), K1",
		"VPCMPUD $1, X0, X1, K0, K1",
		"VPCMPUD $1, X0, X1, AX",
		"VPCMPUD.Z $1, X0, X1, K1",
		"VPCMPUB.BCST $1, (AX), X1, K1",
		"VPCMPUW.BCST $1, (AX), X1, K1",
		"VPCMPUD.BCST $1, X0, X1, K1",
		"VPCMPUQ $1, X32, X1, K1",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			assertX86ImmediatePackedCompareRejected(t, "amd64", "x86_64-unknown-linux-gnu", instruction)
		})
	}
	// cmd/asm's 386 frontend rejects this table's four- and five-operand
	// spellings before its shared x86 optab is reached.
	assertX86ImmediatePackedCompareRejected(t, "386", "i386-unknown-linux-gnu", "VPCMPUD $1, Y2, Y0, K2")
}

func assertX86ImmediatePackedCompareRejected(t *testing.T, goarch, triple, instruction string) {
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
		t.Fatalf("Translate accepted %q outside Go 1.27's immediate packed compare forms", instruction)
	}
}
