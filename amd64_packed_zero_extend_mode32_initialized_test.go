package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// Retain the original six ratios, three banks, register/native source and
// merging/zeroing directory in the same order. These rows alone supply no
// numerical bytes, pointer, old destination or mask.
func x86ZeroExtendLowMaskedMode32Rows(t *testing.T) []string {
	t.Helper()
	var rows []string
	for _, ratio := range x86ZeroExtendTestRatios {
		for _, bank := range []string{"X", "Y", "Z"} {
			source := "X0"
			if bank == "Z" && ratio.output == 2*ratio.input {
				source = "Y0"
			}
			for _, input := range []string{source, "(AX)"} {
				for _, suffix := range []string{"", ".Z"} {
					rows = append(rows, fmt.Sprintf("VPMOVZX%s%s %s,K7,%s7", ratio.suffix, suffix, input, bank))
				}
			}
		}
	}
	if len(rows) != 72 {
		t.Fatal("complete original low-bank K7 format directory changed", len(rows))
	}
	return rows
}

func x86ZeroExtendLowMaskedInitialized(row, name string) (string, string) {
	var source strings.Builder
	fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-12\nMOVL p+0(FP),AX\nVMOVUPS (AX),Z7\n", name)
	if !strings.Contains(row, "(AX)") {
		source.WriteString("VMOVUPS (AX),Y0\n")
	}
	source.WriteString("KMOVD mask+4(FP),K7\n" + row + "\nPEXTRD $0,X7,AX\nMOVL AX,ret+8(FP)\nRET\n")
	return source.String(), fmt.Sprintf("func %s(p *[64]byte,mask uint32) uint32\n", name)
}

func TestX86PackedZeroExtendLowMaskedMode32InitializedThreeAPIObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	rows := x86ZeroExtendLowMaskedMode32Rows(t)
	for _, triple := range []string{"i386-unknown-linux-gnu", "i686-pc-windows-msvc"} {
		for batch := 0; batch < 2; batch++ {
			t.Run(fmt.Sprintf("%s/batch%d", triple, batch), func(t *testing.T) {
				var source, declarations strings.Builder
				for index, row := range rows[batch*36 : (batch+1)*36] {
					program, declaration := x86ZeroExtendLowMaskedInitialized(row, fmt.Sprint("LowMasked", index))
					source.WriteString(program)
					declarations.WriteString(declaration)
				}
				x86LEAActualTargetGoObject(t, "386", triple, source.String())
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(api, func(t *testing.T) {
						ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), "386", triple, api)
						if err != nil || ir == "" {
							t.Fatal("actual initialized low-bank K7 program lost public translation", err)
						}
						for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
							for _, level := range []string{"-O0", "-O2"} {
								x86PackedStringCompileObject(t, llc, triple, text, level)
							}
						}
					})
				}
			})
		}
	}
}

func TestX86PackedZeroExtendLowMaskedMode32RetainsActualInputs(t *testing.T) {
	for _, row := range x86ZeroExtendLowMaskedMode32Rows(t) {
		t.Run(row, func(t *testing.T) {
			source, declaration := x86ZeroExtendLowMaskedInitialized(row, "LowMasked")
			mutations := map[string]string{
				"missing-address": "MOVL p+0(FP),AX\n",
				"missing-mask":    "KMOVD mask+4(FP),K7\n",
			}
			if !strings.Contains(row, "(AX)") {
				mutations["missing-register-source"] = "VMOVUPS (AX),Y0\n"
			}
			if !strings.Contains(row, ".Z ") {
				mutations["missing-merge-bytes"] = "VMOVUPS (AX),Z7\n"
			}
			for _, api := range []string{"text", "module", "Go"} {
				if ir, err := x86ScalarFPBitViewAPI(t, source, declaration, "386", "i386-unknown-linux-gnu", api); err != nil || ir == "" {
					t.Fatal("initialized control failed before input mutations", api, err)
				}
				for name, removed := range mutations {
					changed := strings.Replace(source, removed, "", 1)
					if changed == source {
						t.Fatal("input mutation did not apply", name)
					}
					if ir, err := x86ScalarFPBitViewAPI(t, changed, declaration, "386", "i386-unknown-linux-gnu", api); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("complete widening borrowed a missing input", api, name, err)
					}
				}
				if strings.Contains(row, ".Z ") {
					withoutOld := strings.Replace(source, "VMOVUPS (AX),Z7\n", "", 1)
					if ir, err := x86ScalarFPBitViewAPI(t, withoutOld, declaration, "386", "i386-unknown-linux-gnu", api); err != nil || ir == "" {
						t.Fatal("zeroing register widening incorrectly requires old merge bytes", api, err)
					}
				}
			}
		})
	}
}
