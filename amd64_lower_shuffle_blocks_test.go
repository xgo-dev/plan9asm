package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestTranslateX86Shuffle128BitBlocksCompleteGoAssemblerForms(t *testing.T) {
	// Go 1.27 shares _yvshuff32x4 across the floating and integer D/Q
	// spellings. It has Y/Z rows, an unsigned-byte immediate, optional K
	// masking/.Z, and scalar broadcast from the first Plan 9 memory source.
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
			source.WriteString("TEXT shuffle128bitblockforms(SB),NOSPLIT,$0-0\n")
			for _, op := range []string{"VSHUFF32X4", "VSHUFF64X2", "VSHUFI32X4", "VSHUFI64X2"} {
				fmt.Fprintf(&source, "\t%s $0, Y1, Y20, Y21\n", op)
				fmt.Fprintf(&source, "\t%s $2, 8(AX), Y20, Y21\n", op)
				fmt.Fprintf(&source, "\t%s $255, Z1, Z2, Z%d\n", op, lastZ)
				fmt.Fprintf(&source, "\t%s.BCST $3, 40(AX), Z2, Z%d\n", op, lastZ)
				if target.goarch == "amd64" {
					fmt.Fprintf(&source, "\t%s $4, Y1, Y20, K1, Y21\n", op)
					fmt.Fprintf(&source, "\t%s.Z $5, Z1, Z20, K2, Z21\n", op)
					fmt.Fprintf(&source, "\t%s.BCST.Z $6, 104(AX), Z20, K3, Z21\n", op)
				}
			}
			source.WriteString("\tRET\n")

			if target.goarch == "386" {
				// Go's mode32 frontend rejects every original four-operand
				// spelling here. Keep those source observations; they are
				// neither numerical Context nor physical LLVM object passes.
				goAssemblerOracleOutput(t, "386", "#include \"textflag.h\"\n"+source.String(), "", false)
				file, err := Parse(ArchAMD64, source.String())
				if err != nil {
					t.Fatal(err)
				}
				count := 0
				for _, instruction := range file.Funcs[0].Instrs {
					if instruction.Op == OpTEXT || instruction.Op == OpRET {
						continue
					}
					t.Run(fmt.Sprint("GoFrontendRejects/", count), func(t *testing.T) {
						goAssemblerOracleOutput(t, "386", "TEXT ·rejected(SB),4,$0-0\n"+instruction.Raw+"\nRET\n", "", false)
						_, known, err := x86Shuffle128BitBlocksProperties(instruction.Op, instruction, "386")
						if !known || err == nil || errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("Go-refused frontend arity became an input Context or accepted form", instruction.Raw, err)
						}
					})
					count++
				}
				if count != 16 {
					t.Fatal("original mode32 source directory changed", count)
				}
				return
			}
			ll := x86ElementPermuteUnboundFormatObject(t, source.String(), target.goarch, target.triple, 28, 0)
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "shuffle-128-bit-blocks-"+target.name+".ll", "shuffle-128-bit-blocks-"+target.name+".o", ll)
		})
	}
}

func TestTranslateX86Shuffle128BitBlocksRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{
		"VSHUFF64X2 $1, X0, X1, X2",
		"VSHUFF64X2 $1, Y0, Z1, Z2",
		"VSHUFF64X2 $1, Y0, (AX), Y2",
		"VSHUFF64X2 $1, Y0, Y1, K0, Y2",
		"VSHUFF64X2 $1, Y0, Y1, AX",
		"VSHUFF64X2.Z $1, Y0, Y1, Y2",
		"VSHUFF64X2.BCST $1, Y0, Y1, Y2",
		"VSHUFF64X2.Z.BCST $1, (AX), Y1, K1, Y2",
		"VSHUFF64X2 $256, Y0, Y1, Y2",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			assertX86Shuffle128BitBlocksRejected(t, "amd64", "x86_64-unknown-linux-gnu", instruction)
		})
	}
	assertX86Shuffle128BitBlocksRejected(t, "386", "i386-unknown-linux-gnu", "VSHUFF64X2 $1, Y0, Y1, K1, Y2")
	assertX86Shuffle128BitBlocksRejected(t, "386", "i386-unknown-linux-gnu", "VSHUFF64X2 $1, Z0, Z1, Z8")
}

func assertX86Shuffle128BitBlocksRejected(t *testing.T, goarch, triple, instruction string) {
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
		t.Fatalf("Translate accepted %q outside Go 1.27's VSHUFF/VSHUFI forms", instruction)
	}
}
