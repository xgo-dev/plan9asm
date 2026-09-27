package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateX86PerLaneVariableShiftCompleteGoAssemblerForms(t *testing.T) {
	// Go 1.27 exposes the W/D/Q per-lane left, logical-right, and
	// arithmetic-right shifts. Every opcode has X/Y/Z rows and optional K
	// masking/.Z; D/Q additionally enable scalar count broadcast.
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
			source.WriteString("TEXT perlanevariableshiftforms(SB),NOSPLIT,$0-0\n")
			for _, op := range []string{
				"VPSLLVW", "VPSLLVD", "VPSLLVQ",
				"VPSRLVW", "VPSRLVD", "VPSRLVQ",
				"VPSRAVW", "VPSRAVD", "VPSRAVQ",
			} {
				fmt.Fprintf(&source, "\t%s X1, X20, X21\n", op)
				fmt.Fprintf(&source, "\t%s 8(AX), Y20, Y21\n", op)
				fmt.Fprintf(&source, "\t%s Z1, Z2, Z%d\n", op, lastZ)
				if target.goarch == "amd64" {
					fmt.Fprintf(&source, "\t%s X1, X20, K1, X21\n", op)
					fmt.Fprintf(&source, "\t%s.Z Y1, Y20, K2, Y21\n", op)
					fmt.Fprintf(&source, "\t%s.Z 40(AX), Z20, K3, Z21\n", op)
				}
				if strings.HasSuffix(op, "D") || strings.HasSuffix(op, "Q") {
					fmt.Fprintf(&source, "\t%s.BCST 104(AX), X20, X21\n", op)
					fmt.Fprintf(&source, "\t%s.BCST 112(AX), Y20, Y21\n", op)
					fmt.Fprintf(&source, "\t%s.BCST 120(AX), Z2, Z%d\n", op, lastZ)
					if target.goarch == "amd64" {
						fmt.Fprintf(&source, "\t%s.BCST.Z 128(AX), Z20, K4, Z21\n", op)
					}
				}
			}
			source.WriteString("\tRET\n")
			assembleX87ControlBytes(t, target.goarch, strings.ReplaceAll(source.String(), "NOSPLIT", "4"))

			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				TargetTriple: target.triple,
				Goarch:       target.goarch,
				Sigs: map[string]FuncSig{
					"perlanevariableshiftforms": {Name: "perlanevariableshiftforms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "per-lane-variable-shift-"+target.name+".ll", "per-lane-variable-shift-"+target.name+".o", ll)
		})
	}
}

func TestTranslateX86PerLaneVariableShiftRejectsFormsOutsideGoAssemblerTables(t *testing.T) {
	for _, instruction := range []string{
		"VPSLLVQ X0, X1",
		"VPSLLVQ $1, X1, X2",
		"VPSLLVQ X0, Y1, Y2",
		"VPSLLVQ X0, (AX), X2",
		"VPSLLVQ X0, X1, K0, X2",
		"VPSLLVQ X0, X1, AX",
		"VPSLLVQ.Z X0, X1, X2",
		"VPSLLVQ.BCST X0, X1, X2",
		"VPSLLVW.BCST (AX), X1, X2",
		"VPSLLVQ.Z.BCST (AX), X1, K1, X2",
		"VPSLLVQ.RN_SAE X0, X1, X2",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			assertX86PerLaneVariableShiftRejected(t, "amd64", "x86_64-unknown-linux-gnu", instruction)
		})
	}
	assertX86PerLaneVariableShiftRejected(t, "386", "i386-unknown-linux-gnu", "VPSLLVQ X0, X1, K1, X2")
	assertX86PerLaneVariableShiftRejected(t, "386", "i386-unknown-linux-gnu", "VPSLLVQ Z0, Z1, Z8")
}

func assertX86PerLaneVariableShiftRejected(t *testing.T, goarch, triple, instruction string) {
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
		t.Fatalf("Translate accepted %q outside Go 1.27's per-lane variable shift forms", instruction)
	}
}
