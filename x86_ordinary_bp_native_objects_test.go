package plan9asm

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestX86OrdinaryBPNativeMemoryCompleteFamiliesGoAndLLVMObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	type row struct{ name, destination string }
	var scalar []row
	for _, names := range [][]string{
		x86LegacyFloatMemoryOpcodes(), x86LegacyLogicalMemoryNames,
		{"PMADDWL"}, x86WordMultiplyNames[:4], {"PMULLD", "PSHUFB", "CVTPL2PS", "CVTPL2PD", "VCVTDQ2PS", "VCVTDQ2PD"},
	} {
		for _, name := range names {
			scalar = append(scalar, row{name, "X0"})
		}
	}
	var conversions []row
	for _, form := range x86PackedNativeAddressRows() {
		conversions = append(conversions, row{form.name, form.destination})
	}
	// Literal inventory independent of the production family specifications.
	want := strings.Fields(`ADDPS ADDPD SUBPS SUBPD MULPS MULPD DIVPS DIVPD
ANDPS ANDPD ANDNPS ANDNPD ORPS ORPD XORPS XORPD PAND PANDN POR PXOR
PMADDWL PMULLW PMULHW PMULHUW PMULHRSW PMULLD PSHUFB CVTPL2PS CVTPL2PD VCVTDQ2PS VCVTDQ2PD
CVTPS2PL CVTTPS2PL CVTPD2PL CVTTPD2PL
VCVTPS2DQ VCVTTPS2DQ VCVTPD2DQX VCVTPD2DQY VCVTTPD2DQX VCVTTPD2DQY
VCVTPD2QQ VCVTPD2UQQ VCVTTPD2QQ VCVTTPD2UQQ VCVTPS2UDQ VCVTTPS2UDQ
VCVTUDQ2PS VCVTQQ2PD VCVTUQQ2PD VCVTPS2QQ VCVTPS2UQQ VCVTTPS2QQ
VCVTTPS2UQQ VCVTUDQ2PD VCVTPD2UDQX VCVTPD2UDQY VCVTTPD2UDQX
VCVTTPD2UDQY VCVTQQ2PSX VCVTQQ2PSY VCVTUQQ2PSX VCVTUQQ2PSY
VCVTPD2DQ VCVTTPD2DQ VCVTPD2UDQ VCVTTPD2UDQ VCVTQQ2PS VCVTUQQ2PS`)
	var got []string
	for _, form := range append(append([]row(nil), scalar...), conversions...) {
		got = append(got, form.name)
	}
	sort.Strings(got)
	sort.Strings(want)
	if len(got) != 69 || !reflect.DeepEqual(got, want) {
		t.Fatal("complete eight-family native BP opcode inventory changed", got)
	}
	for i := 1; i < len(got); i++ {
		if got[i] == got[i-1] {
			t.Fatal("duplicate family owner", got[i])
		}
	}
	batches := []struct {
		name  string
		frame int
		rows  []row
	}{
		{"scalar-zero", 0, scalar}, {"scalar-frame", 64, scalar},
		{"conversion-zero", 0, conversions}, {"conversion-frame", 128, conversions},
	}
	seen := make(map[string]bool)
	targets, objects, originals := 0, 0, 0
	for _, target := range x86RawReturnTargets {
		if target.arch != "386" {
			continue // BP has no ordinary native role on the three AMD64 targets.
		}
		targets++
		t.Run(target.triple, func(t *testing.T) {
			for _, batch := range batches {
				t.Run(batch.name, func(t *testing.T) {
					var source, declarations strings.Builder
					count := 0
					for index, form := range batch.rows {
						for variant, address := range []string{"-32(BP)", "(AX)(BP*1)"} {
							key := fmt.Sprintf("%s/%s/%d/%s", target.triple, form.name, batch.frame, address)
							if seen[key] {
								t.Fatal("native family/frame/address has multiple owners", key)
							}
							seen[key] = true
							name := fmt.Sprintf("nativeBP%d_%d", index, variant)
							source.WriteString(x86OrdinaryBPNativeSource(target.arch, name, form.name+" "+address+","+form.destination, address, batch.frame))
							fmt.Fprintf(&declarations, "func %s(p *byte)\n", name)
							count++
						}
					}
					if count > 76 || count != 2*len(batch.rows) {
						t.Fatal("bounded complete native batch changed", count)
					}
					x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
					originals++
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(api, func(t *testing.T) {
							ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
							if err != nil {
								t.Fatal("complete ordinary BP source failed", err)
							}
							for _, optimized := range []bool{false, true} {
								t.Run(fmt.Sprintf("optimized=%t", optimized), func(t *testing.T) {
									input := ir
									if optimized {
										input = x86MulDivRoundOptimize(t, input)
									}
									if strings.Count(input, "asm sideeffect") != count {
										t.Fatal("dead native outputs lost original memory/exception effects")
									}
									compileLLVMToObject(t, llc, target.triple, "native-bp.ll", "native-bp.o", input)
									objects++
								})
							}
						})
					}
				})
			}
		})
	}
	if targets != 2 || len(seen) != 552 || originals != 8 || objects != 48 {
		t.Fatal("complete source/target/frame/three-API/IR-axis union changed", targets, len(seen), originals, objects)
	}
	t.Log("complete69 opcodes,552 disjoint source functions,8 original Go objects,48 LLVM22 objects; compile-only, not native execution")
}
