package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

type x86LogicalPackedStoreCase struct {
	op, bank string
	masked   bool
}

func x86LogicalPackedStoreCases() []x86LogicalPackedStoreCase {
	var rows []x86LogicalPackedStoreCase
	for _, op := range []string{"MOVOU", "MOVUPS", "MOVUPD"} {
		rows = append(rows, x86LogicalPackedStoreCase{op: op, bank: "X"})
	}
	for _, op := range []string{"VMOVDQU", "VMOVUPS", "VMOVUPD", "VMOVDQU8", "VMOVDQU16", "VMOVDQU32", "VMOVDQU64"} {
		for _, bank := range []string{"X", "Y", "Z"} {
			if op == "VMOVDQU" && bank == "Z" {
				continue
			}
			rows = append(rows, x86LogicalPackedStoreCase{op: op, bank: bank})
			if op != "VMOVDQU" {
				rows = append(rows, x86LogicalPackedStoreCase{op: op, bank: bank, masked: true})
			}
		}
	}
	return rows
}

func x86LogicalPackedStoreSource(name string, row x86LogicalPackedStoreCase, result bool) (string, string) {
	var names []string
	for index := 0; index < 16; index++ {
		names = append(names, fmt.Sprintf("a%d", index))
	}
	declaration := "func " + name + "(" + strings.Join(names, ",") + " uint32)"
	extent, tail := 64, ""
	if result {
		declaration += " uint32"
		extent, tail = 68, "MOVL a0+0(FP),AX\nMOVL AX,ret+64(FP)\n"
	}
	mask := ""
	if row.masked {
		mask = ",K1"
	}
	return fmt.Sprintf("TEXT %s(SB),4,$0-%d\nMOVL $0x5555,AX\nKMOVW AX,K1\n"+
		"VPXORD Z0,Z0,Z0\n%s %s0%s,a0+0(FP)\n%sRET\n", name, extent, row.op, row.bank, mask, tail), declaration
}

// Keep the Windows VMOVDQU counterexample's private-parameter write distinct
// from native output storage. Batch complete shapes, rather than rebuilding an
// LLVM module for every operation/width/mask/return combination.
func TestX86PackedLogicalParameterCopiesCompleteThreeAPIsFiveTargets(t *testing.T) {
	rows := x86LogicalPackedStoreCases()
	if len(rows) != 41 {
		t.Fatal("incomplete whole-vector unaligned store family", len(rows))
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			var source, declarations strings.Builder
			for index, row := range rows {
				for _, result := range []bool{false, true} {
					body, declaration := x86LogicalPackedStoreSource(fmt.Sprintf("Copy%d_%t", index, result), row, result)
					source.WriteString(body)
					declarations.WriteString(declaration + "\n")
				}
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
				if err != nil {
					t.Error("initialized private parameter copies lost their logical stores", api, err)
					continue
				}
				if strings.Count(ir, "define void @") != len(rows) || strings.Count(ir, "define i32 @") != len(rows) {
					t.Fatal("translation omitted an original Void or integer-result program", api)
				}
				for _, text := range []string{ir, x86MulDivRoundOptimize(t, ir)} {
					for _, level := range []string{"-O0", "-O2"} {
						x86PackedStringCompileObject(t, llc, target.triple, text, level)
					}
				}
			}
		})
	}
}

func TestX86PackedLogicalParameterStoresKeepTypedAndPhysicalBoundaries(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, result := range []bool{false, true} {
			original, declaration := x86LogicalPackedStoreSource("Value", x86LogicalPackedStoreCase{op: "VMOVDQU32", bank: "X", masked: true}, result)
			for _, mutation := range []struct{ name, before, after string }{
				{"unknown-source", "VPXORD Z0,Z0,Z0\n", ""},
				{"bare-unknown-source", "MOVL $0x5555,AX\nKMOVW AX,K1\nVPXORD Z0,Z0,Z0\nVMOVDQU32 X0,K1,", "VMOVDQU X0,"},
				{"unknown-mask", "KMOVW AX,K1\n", ""},
				{"outside-fields", "X0,K1,a0+0(FP)", "X0,K1,a0+60(FP)"},
				{"native-SP", "X0,K1,a0+0(FP)", "X0,K1,0(SP)"},
				{"alignment", "VMOVDQU32", "VMOVDQA32"},
			} {
				t.Run(fmt.Sprintf("%s/result-%t/%s", target.triple, result, mutation.name), func(t *testing.T) {
					source := strings.Replace(original, mutation.before, mutation.after, 1)
					if source == original {
						t.Fatal("negative source mutation was not applied")
					}
					x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
					for _, api := range []string{"text", "module", "Go"} {
						ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, api)
						if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Error("private copies supplied unknown data or native storage", api, err)
						}
					}
				})
			}
		}
	}
}

func TestX86PackedLogicalParameterStoresExcludePointersBoolsAndHoles(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, result := range []bool{false, true} {
			source, _ := x86LogicalPackedStoreSource("Value", x86LogicalPackedStoreCase{op: "VMOVDQU", bank: "X"}, result)
			for _, fields := range []string{
				fmt.Sprintf("P *byte; Tail [%d]byte", 64-goWordSize(target.arch)),
				"B bool; Tail [63]byte",
				"B byte; W uint32; Tail [56]byte",
			} {
				t.Run(fmt.Sprintf("%s/result-%t/%s", target.triple, result, fields), func(t *testing.T) {
					declaration := "func Value(a0 struct{" + fields + "})"
					if result {
						declaration += " uint32"
					}
					x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
					for _, api := range []string{"text", "module", "Go"} {
						ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, api)
						if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Error("packed logical store overwrote nonnumeric or unowned bytes", api, err)
						}
					}
				})
			}
		}
	}
}
