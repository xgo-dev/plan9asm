package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func x86StaticDiscardedSBAddressRows(arch string) []string {
	widths := []string{"W", "L"}
	if arch == "amd64" {
		widths = append(widths, "Q")
	}
	var rows []string
	for _, width := range widths {
		for _, address := range []string{"pool<>(SB)", "pool<>+4(SB)"} {
			rows = append(rows, "LEA"+width+" "+address+",DX")
		}
		if arch == "386" {
			rows = append(rows, "LEA"+width+" pool<>(SB)(CX*2),DX",
				"LEA"+width+" pool<>(SB)(SI)(CX*2),DX")
		}
	}
	return rows
}

func x86StaticDiscardedSBAddressSource(row string) string {
	return "DATA pool<>+0(SB)/8,$7\nGLOBL pool<>(SB),16,$32\n" +
		"TEXT ·view(SB),4,$0-4\nMOVL $1,CX\n" + row +
		"\nMOVL pool<>(SB),AX\nMOVL AX,ret+0(FP)\nRET\n"
}

func TestX86StaticIntegerResultDiscardedSBAddresses(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("discarded static addresses require LLVM22 llc")
	}
	for _, target := range x86RawReturnTargets {
		for _, row := range x86StaticDiscardedSBAddressRows(target.arch) {
			t.Run(target.triple+"/"+row, func(t *testing.T) {
				source := x86StaticDiscardedSBAddressSource(row)
				x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(api, func(t *testing.T) {
						ir, err := x86ScalarFPBitViewAPI(t, source, "func view() uint32\n", target.arch, target.triple, api)
						// This is a routing/definedness regression, not a new
						// volatility requirement for the existing private global.
						if err != nil || ir == "" {
							t.Fatal("discarded unknown address blocked its independent numerical read/result", err)
						}
						for _, backend := range []string{"-O0", "-O2"} {
							x86PackedStringCompileObject(t, llc, target.triple, ir, backend)
						}
					})
				}
			})
		}
	}
}

func TestX86StaticIntegerSBAddressesDoNotAcquireNumericalOrStackRoles(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, row := range x86StaticDiscardedSBAddressRows(target.arch) {
			original := x86StaticDiscardedSBAddressSource(row)
			mutations := map[string]string{
				"address-result": strings.Replace(original, "MOVL AX,ret+0(FP)", "MOVL DX,ret+0(FP)", 1),
				"address-store":  strings.Replace(original, "MOVL pool<>(SB),AX", "MOVL DX,pool<>(SB)\nMOVL pool<>(SB),AX", 1),
				"physical-SP":    strings.Replace(original, row, strings.TrimSuffix(row, "DX")+"SP", 1),
			}
			if strings.Contains(row, "CX*") {
				mutations["unknown-index"] = strings.Replace(original, "MOVL $1,CX\n", "", 1)
			}
			for name, source := range mutations {
				t.Run(target.triple+"/"+row+"/"+name, func(t *testing.T) {
					if source == original {
						t.Fatal("negative address fixture did not change its source")
					}
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(api, func(t *testing.T) {
							ir, err := x86ScalarFPBitViewAPI(t, source, "func view() uint32\n", target.arch, target.triple, api)
							if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
								t.Fatal(fmt.Sprintf("%s acquired numerical address bytes or a native stack role", name), err)
							}
						})
					}
				})
			}
		}
	}
}
