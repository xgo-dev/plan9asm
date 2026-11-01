package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func x86LogicalFloatingFieldCopy(arch, kind string, extent int) (string, string) {
	lea, result := "LEAQ", 8
	if arch == "386" {
		lea = "LEAL"
		if kind == "float32" {
			result = 4
		}
	}
	move := "MOVSS"
	if kind == "float64" {
		move = "MOVSD"
	}
	return fmt.Sprintf("TEXT Value(SB),4,$0-%d\n%s x+0(FP),AX\n%s (AX),X0\n"+
			"%s ret+%d(FP),BX\n%s X0,(BX)\nRET\n", extent, lea, move, lea, result, move),
		fmt.Sprintf("func Value(x %s) %s", kind, kind)
}

// Isolate logical storage from SQRT's arithmetic effect in the unchanged
// SqrtByAddress reproducer. One field is not a contiguous incoming ABI0 frame.
func TestX86LogicalFloatingFieldAddressCopyThreeAPIsFiveTargets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		for _, kind := range []string{"float32", "float64"} {
			extents := []int{16}
			if kind == "float32" {
				if target.arch == "386" {
					extents = []int{8}
				} else {
					extents = []int{12, 16} // Logical end and rounded native allocation.
				}
			}
			for _, extent := range extents {
				t.Run(fmt.Sprintf("%s/%s/extent-%d", target.triple, kind, extent), func(t *testing.T) {
					source, declaration := x86LogicalFloatingFieldCopy(target.arch, kind, extent)
					x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
					for _, api := range []string{"text", "module", "Go"} {
						ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, api)
						if err != nil {
							t.Error("exact typed floating fields lost their private logical storage", api, err)
							continue
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
	}
}

func TestX86LogicalFloatingFieldAddressKeepsIndependentBoundaries(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, kind := range []string{"float32", "float64"} {
			move, wordMove, lea, width, result, extent := "MOVSS", "MOVQ", "LEAQ", 4, 8, 16
			if kind == "float64" {
				move, width = "MOVSD", 8
			}
			if target.arch == "386" {
				wordMove, lea = "MOVL", "LEAL"
				if kind == "float32" {
					result, extent = 4, 8
				}
			}
			source, declaration := x86LogicalFloatingFieldCopy(target.arch, kind, extent)
			resultAddress := fmt.Sprintf("ret+%d(FP)", result)
			for _, mutation := range []struct{ name, before, after string }{
				{"parameter-one-past", "x+0(FP),AX", fmt.Sprintf("x+%d(FP),AX", width)},
				{"result-one-past", resultAddress + ",BX", fmt.Sprintf("ret+%d(FP),BX", result+width)},
				{"uninitialized-result", "x+0(FP),AX", resultAddress + ",AX"},
				{"cross-field-read", move + " (AX),X0", "MOVUPS (AX),X0"},
				{"address-as-data", move + " X0,(BX)", wordMove + " AX,X0\n" + move + " X0,(BX)"},
				{"physical-SP", lea + " x+0(FP),AX\n" + move + " (AX),X0", lea + " x+0(FP),SP\n" + move + " (SP),X0"},
				{"unknown-store", move + " X0,(BX)", move + " X1,(BX)"},
				{"indexed-address", move + " (AX),X0", "MOVL $0,CX\n" + move + " (AX)(CX*1),X0"},
			} {
				t.Run(target.triple+"/"+kind+"/"+mutation.name, func(t *testing.T) {
					changed := strings.Replace(source, mutation.before, mutation.after, 1)
					if changed == source {
						t.Fatal("negative source mutation was not applied")
					}
					x86LEAActualTargetGoObject(t, target.arch, target.triple, changed)
					for _, api := range []string{"text", "module", "Go"} {
						ir, err := x86ScalarFPBitViewAPI(t, changed, declaration, target.arch, target.triple, api)
						if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Error("floating field acquired padding, unknown data or native state authority", api, err)
						}
					}
				})
			}
		}
	}
}

// Parameter fields already have mutable private logical copies, not incoming
// caller backing. A store confined to that copy is valid, unlike an address
// escape or a write into padding. Keep the same contract for floating bytes.
func TestX86LogicalFloatingFieldAddressPrivateParameterCopy(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, kind := range []string{"float32", "float64"} {
			t.Run(target.triple+"/"+kind, func(t *testing.T) {
				extent := 16
				if target.arch == "386" && kind == "float32" {
					extent = 8
				}
				source, declaration := x86LogicalFloatingFieldCopy(target.arch, kind, extent)
				move := "MOVSS"
				if kind == "float64" {
					move = "MOVSD"
				}
				source = strings.Replace(source, move+" (AX),X0", "PXOR X1,X1\n"+move+" X1,(AX)\n"+move+" (AX),X0", 1)
				x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, api)
					if err != nil {
						t.Error("private logical parameter-copy store failed", api, err)
						continue
					}
					for _, level := range []string{"-O0", "-O2"} {
						x86PackedStringCompileObject(t, findLLVM22Tool("llc"), target.triple, ir, level)
					}
				}
			})
		}
	}
}
