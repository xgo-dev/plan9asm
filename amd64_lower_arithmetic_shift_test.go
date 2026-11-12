package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestTranslateX86PackedArithmeticRightShiftCompleteGoAssemblerForms(t *testing.T) {
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
			legacyLast, zLast := 15, 22
			if target.goarch == "386" {
				legacyLast, zLast = 7, 7
			}
			var source strings.Builder
			source.WriteString("TEXT packedarithmeticrightshiftforms(SB),NOSPLIT,$0-0\n")
			for _, op := range []string{"PSRAW", "PSRAL"} {
				// Go's Py3 MMX rows are named-source mode64 only. Their
				// complete mode32 rejection controls are independently
				// exercised by TestX86YMMMode32LegacyShiftActualGoRows.
				if target.goarch == "amd64" {
					fmt.Fprintf(&source, "\t%s $3, M1\n", op)
					fmt.Fprintf(&source, "\t%s M0, M1\n", op)
					fmt.Fprintf(&source, "\t%s 8(AX), M1\n", op)
				}
				fmt.Fprintf(&source, "\t%s $-1, X%d\n", op, legacyLast)
				fmt.Fprintf(&source, "\t%s X0, X%d\n", op, legacyLast)
				fmt.Fprintf(&source, "\t%s 8(AX), X%d\n", op, legacyLast)
			}
			for _, op := range []string{"VPSRAW", "VPSRAD", "VPSRAQ"} {
				for _, width := range []string{"X", "Y"} {
					fmt.Fprintf(&source, "\t%s $3, %s20, %s21\n", op, width, width)
					fmt.Fprintf(&source, "\t%s $3, 8(AX), %s21\n", op, width)
					fmt.Fprintf(&source, "\t%s X0, %s20, %s21\n", op, width, width)
					fmt.Fprintf(&source, "\t%s 8(AX), %s20, %s21\n", op, width, width)
					if target.goarch == "amd64" {
						fmt.Fprintf(&source, "\t%s $3, %s20, K1, %s22\n", op, width, width)
						fmt.Fprintf(&source, "\t%s.Z X0, %s20, K7, %s22\n", op, width, width)
					}
				}
				fmt.Fprintf(&source, "\t%s $3, Z6, Z%d\n", op, zLast)
				fmt.Fprintf(&source, "\t%s $3, 8(AX), Z%d\n", op, zLast)
				fmt.Fprintf(&source, "\t%s X0, Z6, Z%d\n", op, zLast)
				fmt.Fprintf(&source, "\t%s 8(AX), Z6, Z%d\n", op, zLast)
				if target.goarch == "amd64" {
					fmt.Fprintf(&source, "\t%s $3, Z20, K2, Z22\n", op)
					fmt.Fprintf(&source, "\t%s.Z 8(AX), Z20, K6, Z22\n", op)
				}
				if op != "VPSRAW" {
					fmt.Fprintf(&source, "\t%s.BCST $3, 8(AX), X21\n", op)
					fmt.Fprintf(&source, "\t%s.BCST $3, 8(AX), Y21\n", op)
					fmt.Fprintf(&source, "\t%s.BCST $3, 8(AX), Z%d\n", op, zLast)
					if target.goarch == "amd64" {
						fmt.Fprintf(&source, "\t%s.BCST.Z $3, 8(AX), K5, Z22\n", op)
					}
				}
			}
			source.WriteString("\tRET\n")

			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			options := Options{
				TargetTriple: target.triple,
				Goarch:       target.goarch,
				Sigs: map[string]FuncSig{
					"packedarithmeticrightshiftforms": {Name: "packedarithmeticrightshiftforms", Ret: Void},
				},
			}
			goAssemblerOracleOutput(t, target.goarch, strings.ReplaceAll(source.String(), "NOSPLIT", "4"), "", true)
			for _, api := range []string{"text", "module", "Go"} {
				original := strings.Replace(source.String(), "packedarithmeticrightshiftforms(SB)", "·view(SB)", 1)
				if ir, err := x86ScalarFPBitViewAPI(t, original, "func view()", target.goarch, target.triple, api); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("uninitialized original formats acquired MMX/numerical/native inputs", api, err)
				}
			}
			if target.goarch == "386" {
				// Go emits high-bank EVEX spellings in mode32, but those
				// physical registers do not exist. Retain the original Go
				// objects/Context above; LLVM format objects use this explicit
				// low-bank counterpart, not an invented high-bank permission.
				counterpart := strings.NewReplacer("X20", "X5", "X21", "X6", "Y20", "Y5", "Y21", "Y6").Replace(source.String())
				goAssemblerOracleOutput(t, target.goarch, strings.ReplaceAll(counterpart, "NOSPLIT", "4"), "", true)
				file, err = Parse(ArchAMD64, counterpart)
				if err != nil {
					t.Fatal(err)
				}
			}
			ll := x86InstructionFormatObjectUnit(t, file, options.Sigs, target.goarch, target.triple, 0,
				func(c *amd64Ctx, ins Instr) (bool, bool, error) {
					return c.lowerPackedArithmeticRightShift(ins.Op, ins)
				})
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "packed-arithmetic-right-shift-"+target.name+".ll", "packed-arithmetic-right-shift-"+target.name+".o", ll)
		})
	}
}

func TestTranslateX86PackedArithmeticRightShiftRejectsFormsOutsideGoAssemblerTables(t *testing.T) {
	for _, instruction := range []string{
		"PSRAW.Z $3, X0",
		"PSRAL $3",
		"PSRAW M0, X1",
		"PSRAL X0, M1",
		"PSRAQ $3, X0",
		"PSRAW $3, Y0",
		"VPSRAW R8, X1, X2",
		"VPSRAD Y0, X1, X2",
		"VPSRAQ X0, 8(AX), X2",
		"VPSRAW.BCST $3, 8(AX), X2",
		"VPSRAD.BCST X0, X1, X2",
		"VPSRAQ.BCST $3, X1, X2",
		"VPSRAW.Z $3, X1, X2",
		"VPSRAD $3, X1, K0, X2",
		"VPSRAQ $3, X1, K1, Y2",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			assertX86PackedArithmeticRightShiftRejected(t, "amd64", "x86_64-unknown-linux-gnu", instruction)
		})
	}
	for _, instruction := range []string{
		"PSRAW X8, X0",
		"PSRAL X0, X8",
		"VPSRAW $3, Z8, Z1",
		"VPSRAD X0, Z1, Z8",
		"VPSRAQ $3, X1, K1, X2",
		"VPSRAW.Z X0, X1, K1, X2",
	} {
		t.Run("386_"+strings.NewReplacer(" ", "_").Replace(instruction), func(t *testing.T) {
			assertX86PackedArithmeticRightShiftRejected(t, "386", "i386-unknown-linux-gnu", instruction)
		})
	}
}

func assertX86PackedArithmeticRightShiftRejected(t *testing.T, goarch, triple, instruction string) {
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
		t.Fatalf("Translate accepted %q outside Go 1.27's packed arithmetic-right-shift forms for %s", instruction, goarch)
	}
}
