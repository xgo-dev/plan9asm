package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateX86PackedByteShuffleCompleteGoAssemblerForms(t *testing.T) {
	// Go 1.27 uses ymshufb for PSHUFB and _yvandnpd for VPSHUFB.
	// The legacy instruction accepts X/m128, X. The vector instruction has
	// VEX X/Y forms and EVEX X/Y/Z forms, including K1-K7 merge/zero masks.
	// In 386 mode the Go frontend still exposes EVEX X/Y0-31 and Z0-7, but
	// cannot express the four-operand mask rows.
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
			legacyLast := 15
			zLast := 21
			if target.goarch == "386" {
				legacyLast = 7
				zLast = 7
			}
			var src strings.Builder
			src.WriteString("TEXT packedbyteshuffleforms(SB),NOSPLIT,$0-0\n")
			fmt.Fprintf(&src, "\tPSHUFB X0, X%d\n", legacyLast)
			fmt.Fprintf(&src, "\tPSHUFB (AX), X%d\n", legacyLast)
			for _, width := range []string{"X", "Y"} {
				fmt.Fprintf(&src, "\tVPSHUFB %s0, %s1, %s2\n", width, width, width)
				fmt.Fprintf(&src, "\tVPSHUFB (AX), %s20, %s21\n", width, width)
			}
			fmt.Fprintf(&src, "\tVPSHUFB Z0, Z1, Z%d\n", zLast)
			fmt.Fprintf(&src, "\tVPSHUFB (AX), Z6, Z%d\n", zLast)
			if target.goarch == "amd64" {
				for _, width := range []string{"X", "Y", "Z"} {
					fmt.Fprintf(&src, "\tVPSHUFB %s20, %s21, K1, %s22\n", width, width, width)
					fmt.Fprintf(&src, "\tVPSHUFB.Z (AX), %s21, K2, %s22\n", width, width)
				}
			}
			src.WriteString("\tRET\n")

			file, err := Parse(ArchAMD64, src.String())
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				TargetTriple: target.triple,
				Goarch:       target.goarch,
				Sigs: map[string]FuncSig{
					"packedbyteshuffleforms": {Name: "packedbyteshuffleforms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "packed-byte-shuffle-"+target.name+".ll", "packed-byte-shuffle-"+target.name+".o", ll)
		})
	}
}

func TestTranslateX86PackedByteShuffleRejectsFormsOutsideGoAssemblerTables(t *testing.T) {
	for _, instruction := range []string{
		"PSHUFB.Z X0, X1",
		"PSHUFB X0",
		"PSHUFB Y0, Y1",
		"PSHUFB X0, (AX)",
		"VPSHUFB X0, X1",
		"VPSHUFB X0, Y1, Y2",
		"VPSHUFB X0, X1, (AX)",
		"VPSHUFB.BCST (AX), X1, X2",
		"VPSHUFB.SAE X0, X1, X2",
		"VPSHUFB.Z X0, X1, X2",
		"VPSHUFB X0, X1, K0, X2",
		"VPSHUFB X0, X1, K1, Y2",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			assertX86PackedByteShuffleRejected(t, "amd64", "x86_64-unknown-linux-gnu", instruction)
		})
	}

	for _, instruction := range []string{
		"PSHUFB X8, X0",
		"PSHUFB X0, X8",
		"VPSHUFB Z8, Z0, Z1",
		"VPSHUFB Z0, Z1, Z8",
		"VPSHUFB X0, X1, K1, X2",
		"VPSHUFB.Z X0, X1, K1, X2",
	} {
		t.Run("386_"+strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			assertX86PackedByteShuffleRejected(t, "386", "i386-unknown-linux-gnu", instruction)
		})
	}
}

func assertX86PackedByteShuffleRejected(t *testing.T, goarch, triple, instruction string) {
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
		t.Fatalf("Translate accepted %q outside Go 1.27's ymshufb/_yvandnpd forms for %s", instruction, goarch)
	}
}
