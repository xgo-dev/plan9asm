package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func fourSourceDataBPFixture(row x86FourSourceOracleRow, name string) (string, string) {
	source, declaration := x86FourSourceInitializedSource(row, "amd64", name, false)
	source = strings.Replace(source, ",4,$0-", ",4,$8-", 1)
	source = strings.Replace(source, "MOVQ memory+24(FP),BX", "MOVQ memory+24(FP),BP\nMOVQ $5,DX", 1)
	source = strings.Replace(source, "(BX)", "-17(BP)(DX*4)", 1)
	return source, strings.Replace(declaration, "memory *[16]byte", "memory *[32]byte", 1)
}

func TestX86FourSourceDataBPObjects(t *testing.T) {
	llc, objdump := findLLVM22Tool("llc"), findLLVM22Tool("llvm-objdump")
	if llc == "" || objdump == "" {
		t.Fatal("data BP objects require LLVM 22 llc and llvm-objdump")
	}
	var source, declarations strings.Builder
	for index, member := range x86FourSourceOracle {
		for _, mode := range []string{"plain", "merge", "zero"} {
			row := x86FourSourceOracleRow{op: member.op, scalar: member.scalar, first: 2, dest: 6, mode: mode}
			body, declaration := fourSourceDataBPFixture(row, fmt.Sprintf("DataBP%d_%s", index, mode))
			source.WriteString(body)
			declarations.WriteString(declaration)
		}
	}
	for _, target := range x86RawReturnTargets {
		if target.arch != "amd64" {
			continue // The mode32 BP is already an ordinary GP input.
		}
		t.Run(target.triple, func(t *testing.T) {
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
					if err != nil {
						t.Fatal(err)
					}
					for _, level := range []string{"-O0", "-O2"} {
						listing := x86FourSourceNativeObjectListing(t, llc, objdump, target.triple, level, ir)
						for _, member := range x86FourSourceOracle {
							if count := strings.Count(listing, "\t"+strings.ToLower(member.op)+"\t"); count != 3 {
								t.Errorf("%s %s count = %d, want 3", level, member.op, count)
							}
						}
					}
				})
			}
		})
	}
}

func TestX86FourSourceDataBPNeedsReachingPointerAndIndex(t *testing.T) {
	row := x86FourSourceOracleRow{op: "V4FMADDPS", first: 2, dest: 6, mode: "zero"}
	source, declaration := fourSourceDataBPFixture(row, "Value")
	for _, test := range []struct{ name, replace, with string }{
		{"entry-bp", "MOVQ memory+24(FP),BP\n", ""},
		{"numeric-bp", "MOVQ memory+24(FP),BP", "MOVQ $17,BP"},
		{"missing-index", "MOVQ $5,DX\n", ""},
		{"bp-as-index", "-17(BP)(DX*4)", "-17(DX)(BP*4)"},
		{"frameless", ",4,$8-", ",4,$0-"},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := strings.Replace(source, test.replace, test.with, 1)
			goAssemblerOracleOutput(t, "amd64", body, "", true)
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, body, declaration, "amd64", "x86_64-unknown-linux-gnu", api)
				if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
					t.Errorf("%s allowed an unproved data BP address: %v", api, err)
				}
			}
		})
	}
}
