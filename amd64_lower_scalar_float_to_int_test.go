package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateX86ScalarFloatToIntegerCompleteGoAssemblerForms(t *testing.T) {
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
			source.WriteString("TEXT scalarfloattointforms(SB),NOSPLIT,$0-0\n")
			for _, precision := range []string{"SS", "SD"} {
				for _, truncating := range []bool{false, true} {
					prefix := "CVT"
					if truncating {
						prefix = "CVTT"
					}
					for _, width := range []string{"L", "Q"} {
						if target.goarch == "386" && width == "Q" {
							continue
						}
						op := prefix + precision + "2S" + width
						fmt.Fprintf(&source, "\t%s X0, AX\n", op)
						fmt.Fprintf(&source, "\t%s 8(BX), DI\n", op)
						vop := "V" + prefix + precision + "2SI"
						if width == "Q" {
							vop += "Q"
						}
						fmt.Fprintf(&source, "\t%s X0, AX\n", vop)
						fmt.Fprintf(&source, "\t%s 16(BX), DI\n", vop)
						if truncating {
							fmt.Fprintf(&source, "\t%s.SAE X16, AX\n", vop)
						} else {
							for _, rounding := range []string{"RN_SAE", "RD_SAE", "RU_SAE", "RZ_SAE"} {
								fmt.Fprintf(&source, "\t%s.%s X16, AX\n", vop, rounding)
							}
						}
					}
				}
				for _, truncating := range []bool{false, true} {
					prefix := "VCVT"
					if truncating {
						prefix = "VCVTT"
					}
					for _, width := range []string{"L", "Q"} {
						if target.goarch == "386" && width == "Q" {
							continue
						}
						op := prefix + precision + "2USI" + width
						fmt.Fprintf(&source, "\t%s X16, AX\n", op)
						fmt.Fprintf(&source, "\t%s 24(BX), DI\n", op)
						if truncating {
							fmt.Fprintf(&source, "\t%s.SAE X16, AX\n", op)
						} else {
							for _, rounding := range []string{"RN_SAE", "RD_SAE", "RU_SAE", "RZ_SAE"} {
								fmt.Fprintf(&source, "\t%s.%s X16, AX\n", op, rounding)
							}
						}
					}
				}
			}
			source.WriteString("\tRET\n")
			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				TargetTriple: target.triple,
				Goarch:       target.goarch,
				Sigs:         map[string]FuncSig{"scalarfloattointforms": {Name: "scalarfloattointforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "scalar-float-to-int-"+target.name+".ll", "scalar-float-to-int-"+target.name+".o", ll)
		})
	}
}

func TestTranslateX86ScalarFloatToIntegerRejectsFormsOutsideGoAssemblerTables(t *testing.T) {
	for _, instruction := range []string{
		"CVTSS2SL Y0, AX",
		"CVTTSD2SQ X16, AX",
		"CVTSS2SL X0, X1",
		"CVTSS2SL.Z X0, AX",
		"VCVTSS2SI Y0, AX",
		"VCVTSS2SI X0, X1",
		"VCVTSS2SI.SAE X0, AX",
		"VCVTTSS2SI.RN_SAE X0, AX",
		"VCVTSD2SI.RD_SAE 8(BX), AX",
		"VCVTTSD2SI.SAE 8(BX), AX",
		"VCVTSS2USIL X0, X1",
		"VCVTSS2USIL.Z X0, AX",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			assertX86ScalarFloatToIntegerRejected(t, "amd64", "x86_64-unknown-linux-gnu", instruction)
		})
	}
	for _, instruction := range []string{
		"CVTSS2SQ X0, AX",
		"CVTTSD2SQ 8(BX), AX",
		"VCVTSS2SIQ X0, AX",
		"VCVTTSD2SIQ.SAE X16, AX",
		"VCVTSS2USIQ X16, AX",
		"VCVTTSD2USIQ.SAE X16, AX",
		"CVTSS2SL X8, AX",
	} {
		t.Run("386_"+strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			assertX86ScalarFloatToIntegerRejected(t, "386", "i386-unknown-linux-gnu", instruction)
		})
	}
}

func assertX86ScalarFloatToIntegerRejected(t *testing.T, goarch, triple, instruction string) {
	t.Helper()
	file, err := Parse(ArchAMD64, "TEXT bad(SB),NOSPLIT,$0-0\n\t"+instruction+"\n\tRET\n")
	if err == nil {
		_, err = Translate(file, Options{
			TargetTriple: triple,
			Goarch:       goarch,
			Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
		})
	}
	if err == nil {
		t.Fatalf("Translate accepted %q outside Go 1.27's scalar float-to-integer tables for %s", instruction, goarch)
	}
}
