package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateX86PackedSignedGreaterThanCompleteGoAssemblerForms(t *testing.T) {
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
			source.WriteString("TEXT packedsignedgreaterthanforms(SB),NOSPLIT,$0-0\n")
			for _, op := range []string{"PCMPGTB", "PCMPGTW", "PCMPGTL"} {
				fmt.Fprintf(&source, "\t%s M0, M1\n", op)
				fmt.Fprintf(&source, "\t%s 8(AX), M2\n", op)
				fmt.Fprintf(&source, "\t%s X0, X%d\n", op, legacyLast)
				fmt.Fprintf(&source, "\t%s 8(AX), X%d\n", op, legacyLast)
			}
			fmt.Fprintf(&source, "\tPCMPGTQ X0, X%d\n", legacyLast)
			fmt.Fprintf(&source, "\tPCMPGTQ 8(AX), X%d\n", legacyLast)
			for _, op := range []string{"VPCMPGTB", "VPCMPGTW", "VPCMPGTD", "VPCMPGTQ"} {
				for _, width := range []string{"X", "Y"} {
					fmt.Fprintf(&source, "\t%s %s0, %s1, %s2\n", op, width, width, width)
					fmt.Fprintf(&source, "\t%s 8(AX), %s1, %s2\n", op, width, width)
					fmt.Fprintf(&source, "\t%s %s20, %s21, K3\n", op, width, width)
					if target.goarch == "amd64" {
						fmt.Fprintf(&source, "\t%s %s20, %s21, K1, K3\n", op, width, width)
					}
				}
				fmt.Fprintf(&source, "\t%s Z0, Z6, K3\n", op)
				fmt.Fprintf(&source, "\t%s 8(AX), Z6, K0\n", op)
				if target.goarch == "amd64" {
					fmt.Fprintf(&source, "\t%s Z20, Z21, K2, K3\n", op)
				} else {
					fmt.Fprintf(&source, "\t%s Z0, Z6, K%d\n", op, zLast)
				}
				if strings.HasSuffix(op, "D") || strings.HasSuffix(op, "Q") {
					for _, width := range []string{"X", "Y", "Z"} {
						reg := "21"
						if width == "Z" && target.goarch == "386" {
							reg = "6"
						}
						fmt.Fprintf(&source, "\t%s.BCST 8(AX), %s%s, K3\n", op, width, reg)
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
				Sigs: map[string]FuncSig{
					"packedsignedgreaterthanforms": {Name: "packedsignedgreaterthanforms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "packed-signed-greater-than-"+target.name+".ll", "packed-signed-greater-than-"+target.name+".o", ll)
		})
	}
}

func TestTranslateX86PackedSignedGreaterThanRejectsFormsOutsideGoAssemblerTables(t *testing.T) {
	for _, instruction := range []string{
		"PCMPGTB.Z X0, X1",
		"PCMPGTW X0",
		"PCMPGTL M0, X1",
		"PCMPGTQ M0, M1",
		"PCMPGTB Y0, Y1",
		"PCMPGTW X0, (AX)",
		"VPCMPGTB X0, X1",
		"VPCMPGTW X0, Y1, Y2",
		"VPCMPGTD Z0, Z1, Z2",
		"VPCMPGTQ X0, X1, K0, K2",
		"VPCMPGTB.Z X0, X1, K2",
		"VPCMPGTW.BCST 8(AX), X1, K2",
		"VPCMPGTD.BCST X0, X1, K2",
		"VPCMPGTQ.BCST 8(AX), X1, X2",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			assertX86PackedSignedGreaterThanRejected(t, "amd64", "x86_64-unknown-linux-gnu", instruction)
		})
	}
	for _, instruction := range []string{
		"PCMPGTW X8, X0",
		"PCMPGTL X0, X8",
		"VPCMPGTB X16, X1, X2",
		"VPCMPGTW X0, X1, X16",
		"VPCMPGTD Z8, Z1, K2",
		"VPCMPGTQ Z0, Z1, K1, K2",
	} {
		t.Run("386_"+strings.NewReplacer(" ", "_").Replace(instruction), func(t *testing.T) {
			assertX86PackedSignedGreaterThanRejected(t, "386", "i386-unknown-linux-gnu", instruction)
		})
	}
}

func assertX86PackedSignedGreaterThanRejected(t *testing.T, goarch, triple, instruction string) {
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
		t.Fatalf("Translate accepted %q outside Go 1.27's packed signed greater-than forms for %s", instruction, goarch)
	}
}
