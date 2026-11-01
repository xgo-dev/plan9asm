package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

type x86ShiftLiteralKernel struct {
	name        string
	shift, mode int
	mask        byte
}

// Keep every form in one complete source, with distinct function and DATA
// identities. The legacy subset is the same source used by the native oracle.
func x86ShiftLiteralMaskProgram(legacyOnly bool) (string, string, []x86ShiftLiteralKernel) {
	var source, declarations strings.Builder
	var kernels []x86ShiftLiteralKernel
	for _, row := range x86ShiftLiteralMaskCases() {
		if legacyOnly && row.vector {
			continue
		}
		for _, shift := range []int{0, 1, 4, 7} {
			for mode, logical := range []string{"PAND", "PANDN", "POR"} {
				name := fmt.Sprint("shiftMask", len(kernels))
				mask := byte(255 >> uint(shift))
				if mode == 2 {
					mask = ^mask
				}
				assembly := x86ShiftLiteralMaskSource(row, logical, shift, mask, 0)
				assembly = strings.ReplaceAll(assembly, "mask<>", name+"Mask<>")
				assembly = strings.ReplaceAll(assembly, "·view", "·"+name)
				source.WriteString(assembly)
				fmt.Fprintf(&declarations, "func %s(input *byte) uint32\n", name)
				kernels = append(kernels, x86ShiftLiteralKernel{name, shift, mode, mask})
			}
		}
	}
	return source.String(), declarations.String(), kernels
}

func TestX86PackedShiftLiteralMaskCompleteThreeAPIObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	source, declarations, kernels := x86ShiftLiteralMaskProgram(false)
	if len(kernels) != 144 {
		t.Fatal("incomplete W/D/Q × legacy/VEX/EVEX × shift × logical union", len(kernels))
	}
	for _, triple := range []string{"x86_64-unknown-linux-gnu", "x86_64-apple-darwin", "x86_64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			x86LEAActualTargetGoObject(t, "amd64", triple, source)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, declarations, "amd64", triple, api)
					if err != nil {
						t.Fatal(err)
					}
					compileLLVMToObject(t, llc, triple, "shift-mask.ll", "shift-mask.o", ir)
				})
			}
		})
	}
	t.Log("144 complete functions × 3 APIs × Linux/Darwin/Windows LLVM22 objects; no physical AVX512 execution claim")
}
