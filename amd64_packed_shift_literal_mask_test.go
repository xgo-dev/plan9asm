package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

type x86ShiftLiteralMaskCase struct {
	shift, bank string
	width       int
	vector      bool
}

// Independent of the production shift registry: all W/D/Q logical-right
// families, with legacy X and VEX/EVEX X/Y/Z carriers.
func x86ShiftLiteralMaskCases() []x86ShiftLiteralMaskCase {
	var rows []x86ShiftLiteralMaskCase
	for _, pair := range [][2]string{{"PSRLW", "VPSRLW"}, {"PSRLL", "VPSRLD"}, {"PSRLQ", "VPSRLQ"}} {
		rows = append(rows, x86ShiftLiteralMaskCase{shift: pair[0], bank: "X", width: 16})
		for _, bank := range []struct {
			name  string
			width int
		}{{"X", 16}, {"Y", 32}, {"Z", 64}} {
			rows = append(rows, x86ShiftLiteralMaskCase{shift: pair[1], bank: bank.name, width: bank.width, vector: true})
		}
	}
	return rows
}

func x86ShiftLiteralMaskSource(row x86ShiftLiteralMaskCase, logical string, shift int, mask byte, extract int) string {
	var source strings.Builder
	value := uint64(mask) * 0x0101010101010101
	for at := 0; at < row.width; at += 8 {
		fmt.Fprintf(&source, "DATA mask<>+%d(SB)/8,$%#x\n", at, value)
	}
	fmt.Fprintf(&source, "GLOBL mask<>(SB),8,$%d\n", row.width)
	source.WriteString("TEXT ·view(SB),4,$0-12\nMOVQ input+0(FP),SI\nPINSRB $0,(SI),X0\n")
	// Deliberately leave every other byte of X0/Y0/Z0 unknown. Initializing
	// the whole bank would hide the missing bit-to-byte dependency.
	destination := "X0"
	if row.vector {
		destination = "X1"
		fmt.Fprintf(&source, "%s $%d,%s0,%s1\n", row.shift, shift, row.bank, row.bank)
		logical = "V" + logical
		if row.bank == "Z" {
			logical += "D"
		}
		fmt.Fprintf(&source, "%s mask<>(SB),%s1,%s1\n", logical, row.bank, row.bank)
	} else {
		fmt.Fprintf(&source, "%s $%d,X0\n%s mask<>(SB),X0\n", row.shift, shift, logical)
	}
	fmt.Fprintf(&source, "PEXTRB $%d,%s,AX\nMOVL AX,ret+8(FP)\nRET\n", extract, destination)
	return source.String()
}

func TestX86PackedLogicalRightShiftLiteralMaskDefinedBits(t *testing.T) {
	for _, row := range x86ShiftLiteralMaskCases() {
		for _, shift := range []int{0, 1, 4, 7} {
			for _, logical := range []string{"PAND", "PANDN", "POR"} {
				mask := byte(255 >> uint(shift))
				if logical == "POR" {
					mask = ^mask // OR's known ones remove the same unknown bits.
				}
				source := x86ShiftLiteralMaskSource(row, logical, shift, mask, 0)
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(fmt.Sprintf("%s/%s/%s/%d/%s", row.shift, row.bank, logical, shift, api), func(t *testing.T) {
						ir, err := x86ScalarFPBitViewAPI(t, source, "func view(input *byte) uint32\n",
							"amd64", "x86_64-unknown-linux-gnu", api)
						if err != nil || ir == "" {
							t.Fatalf("defined selected bits lost after literal mask: output=%t err=%v", ir != "", err)
						}
					})
				}
			}
		}
	}
}

func TestX86PackedShiftLiteralMaskKeepsUnknownBits(t *testing.T) {
	for _, row := range x86ShiftLiteralMaskCases() {
		for _, mutation := range []struct {
			name, logical  string
			shift, extract int
			mask           byte
		}{
			{"one-unknown-bit", "PAND", 4, 0, 0x1f},
			{"unmasked-unknown-bits", "PAND", 4, 0, 0xff},
			{"shift-needs-next-byte", "PAND", 5, 0, 0x0f},
			{"unused-byte-stays-unknown", "PAND", 4, 1, 0x0f},
			{"xor-does-not-kill-dependencies", "PXOR", 4, 0, 0x0f},
			{"or-leaves-unknown-bit", "POR", 4, 0, 0xe0},
		} {
			source := x86ShiftLiteralMaskSource(row, mutation.logical, mutation.shift, mutation.mask, mutation.extract)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(row.shift+"/"+row.bank+"/"+mutation.name+"/"+api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, "func view(input *byte) uint32\n",
						"amd64", "x86_64-unknown-linux-gnu", api)
					if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatalf("unknown source bits became defined: output=%t err=%v", ir != "", err)
					}
				})
			}
		}
	}
}

func TestX86PackedShiftLiteralMaskKeepsSourceAndMemoryBoundaries(t *testing.T) {
	for _, row := range x86ShiftLiteralMaskCases() {
		source := x86ShiftLiteralMaskSource(row, "PAND", 4, 0x0f, 0)
		logical := "PAND"
		if row.vector {
			logical = "VPAND"
			if row.bank == "Z" {
				logical += "D"
			}
		}
		maskLine := logical + " mask<>(SB),"
		for _, mutation := range []struct{ name, source string }{
			{"unknown-native-base", strings.Replace(source, "MOVQ input+0(FP),SI\n", "", 1)},
			{"unknown-selected-byte", strings.Replace(source, "PINSRB $0,(SI),X0\n", "", 1)},
			{"unknown-index", strings.Replace(source, "(SI),X0", "(SI)(CX*1),X0", 1)},
			{"unknown-literal", strings.Replace(source, " mask<>(SB),", " external(SB),", 1)},
			{"mutable-mask", strings.Replace(source, "GLOBL mask<>(SB),8,", "GLOBL mask<>(SB),0,", 1)},
			{"short-literal", strings.Replace(source, maskLine, logical+" mask<>+1(SB),", 1)},
			{"intervening-nop", strings.Replace(source, maskLine, "NOP\n"+maskLine, 1)},
			{"intervening-other-register", strings.Replace(source, maskLine, "PINSRB $0,(SI),X2\n"+maskLine, 1)},
			{"intervening-branch", strings.Replace(source, maskLine, "JMP masked\nmasked:\n"+maskLine, 1)},
		} {
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(row.shift+"/"+row.bank+"/"+mutation.name+"/"+api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, mutation.source, "func view(input *byte) uint32\n",
						"amd64", "x86_64-unknown-linux-gnu", api)
					if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatalf("missing source/readonly/address role was manufactured: output=%t err=%v", ir != "", err)
					}
				})
			}
		}
	}
}
