package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

// Independent named memory inventory from Go's legacy and AVX encoder rows.
// This address-role witness does not borrow the production spec or assert that
// a Context form was translated; the separate complete family matrix retains
// all widths, masks, rounding and raw encodings.
func x86PackedNativeAddressRows() []struct{ name, destination string } {
	var rows []struct{ name, destination string }
	for _, name := range []string{
		"CVTPS2PL", "CVTTPS2PL", "CVTPD2PL", "CVTTPD2PL",
		"VCVTPS2DQ", "VCVTTPS2DQ", "VCVTPD2DQX", "VCVTPD2DQY", "VCVTTPD2DQX", "VCVTTPD2DQY",
		"VCVTPD2QQ", "VCVTPD2UQQ", "VCVTTPD2QQ", "VCVTTPD2UQQ",
		"VCVTPS2UDQ", "VCVTTPS2UDQ", "VCVTUDQ2PS", "VCVTQQ2PD", "VCVTUQQ2PD",
		"VCVTPS2QQ", "VCVTPS2UQQ", "VCVTTPS2QQ", "VCVTTPS2UQQ", "VCVTUDQ2PD",
		"VCVTPD2UDQX", "VCVTPD2UDQY", "VCVTTPD2UDQX", "VCVTTPD2UDQY",
		"VCVTQQ2PSX", "VCVTQQ2PSY", "VCVTUQQ2PSX", "VCVTUQQ2PSY",
	} {
		rows = append(rows, struct{ name, destination string }{name, "X1"})
	}
	for _, name := range []string{"VCVTPD2DQ", "VCVTTPD2DQ", "VCVTPD2UDQ", "VCVTTPD2UDQ", "VCVTQQ2PS", "VCVTUQQ2PS"} {
		rows = append(rows, struct{ name, destination string }{name, "Y1"})
	}
	return rows
}

func TestX86PackedConversionOriginalNativeAddressRequired(t *testing.T) {
	rows := x86PackedNativeAddressRows()
	if len(rows) != 38 {
		t.Fatal("complete native conversion memory-name inventory changed", len(rows))
	}
	for _, arch := range []string{"386", "amd64"} {
		var original strings.Builder
		for index, row := range rows {
			for _, address := range []string{"(SP)", "32(SP)", "(BP)", "-17(BP)", "32(SP)(CX*2)", "32(AX)(BP*2)"} {
				name := fmt.Sprintf("original%d_%d", index, original.Len())
				original.WriteString(x86OrdinaryBPNativeSource(arch, name, row.name+" "+address+","+row.destination, address, 128))
			}
		}
		goAssemblerOracleOutput(t, arch, original.String(), "", true)
	}
	for _, target := range x86RawReturnTargets {
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(target.triple+"/"+api, func(t *testing.T) {
				for _, row := range rows {
					for _, address := range []string{"(SP)", "32(SP)", "(BP)", "-17(BP)", "32(SP)(CX*2)", "32(AX)(BP*2)"} {
						source := x86OrdinaryBPNativeSource(target.arch, "view", row.name+" "+address+","+row.destination, address, 128)
						ir, err := x86ScalarFPBitViewAPI(t, source, "func view(p *byte)", target.arch, target.triple, api)
						x86RequireOrdinaryBPNativeOutcome(t, target.arch, address, ir, err)
					}
				}
			})
		}
	}
}

func TestX86PackedConversionOrdinaryNativeAddressControls(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			move, frame := "MOVQ", 8
			if target.arch == "386" {
				move, frame = "MOVL", 4
			}
			var source, declarations strings.Builder
			for index, row := range x86PackedNativeAddressRows() {
				for variant, address := range []string{"(AX)", "16(AX)(CX*2)"} {
					name := fmt.Sprintf("control%d_%d", index, variant)
					fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n%s p+0(FP),AX\nMOVL $0,CX\n%s %s,%s\nRET\n", name, frame, move, row.name, address, row.destination)
					fmt.Fprintf(&declarations, "func %s(p *[128]byte)\n", name)
				}
			}
			goAssemblerOracleOutput(t, target.arch, source.String(), "", true)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
					if err != nil {
						t.Fatal("ordinary GP source control failed", err)
					}
					if strings.Count(ir, "asm sideeffect") != 76 {
						t.Fatal("dead conversions lost whole native effects")
					}
					compileLLVMToObject(t, llc, target.triple, "native-address.ll", "native-address.o", x86MulDivRoundOptimize(t, ir))
				})
			}
		})
	}
}
