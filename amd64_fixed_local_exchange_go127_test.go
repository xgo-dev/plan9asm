//go:build go1.27

package plan9asm

import (
	"fmt"
	"math/bits"
	"strings"
	"testing"
)

type fixedLocalExchangeCase struct {
	body string
	want func(uint64) uint64
}

func fixedLocalExchangeCases() []fixedLocalExchangeCase {
	const other = uint64(0x1122334455667788)
	var rows []fixedLocalExchangeCase
	for _, width := range []struct {
		suffix string
		bits   uint
	}{{"B", 8}, {"W", 16}, {"L", 32}, {"Q", 64}} {
		for _, location := range []string{"register", "memory first", "memory last"} {
			width, location := width, location
			memory := "8(SP)"
			if location == "memory first" && width.bits < 64 {
				// Exercise unaligned native exchange without crossing a cacheline
				// on machines that trap split locks. Keep qwords word-aligned.
				memory = "3(SP)"
			}
			body := "MOVQ $0x1122334455667788,CX\nMOVQ CX," + memory + "\n"
			switch location {
			case "register":
				body += "XCHG" + width.suffix + " AX,CX\n"
			case "memory first":
				body += "XCHG" + width.suffix + " " + memory + ",AX\nMOVQ " + memory + ",CX\n"
			case "memory last":
				body += "XCHG" + width.suffix + " AX,8(SP)\nMOVQ 8(SP),CX\n"
			}
			// Observe both outputs asymmetrically: XOR or addition alone would
			// hide an incorrect implementation that did not exchange anything.
			body += "RORQ $13,CX\nXORQ CX,AX"
			rows = append(rows, fixedLocalExchangeCase{body, func(input uint64) uint64 {
				mask := uint64(1)<<width.bits - 1
				first, last := input&^mask|other&mask, other&^mask|input&mask
				if width.bits == 32 {
					first = uint64(uint32(first))
					if location == "register" {
						last = uint64(uint32(last))
					}
				}
				return first ^ bits.RotateLeft64(last, -13)
			}})
		}
	}
	for _, operands := range []string{"AH,AL", "AL,AH"} {
		rows = append(rows, fixedLocalExchangeCase{"XCHGB " + operands, func(input uint64) uint64 {
			return input&^0xffff | (input&255)<<8 | input>>8&255
		}})
	}
	rows = append(rows,
		fixedLocalExchangeCase{
			"MOVQ AX,8(SP)\nMOVQ $0x1122334455667788,CX\nMOVQ CX,24(SP)\nLEAQ 8(SP),CX\nLEAQ 24(SP),DX\nXCHGQ CX,DX\nMOVQ (CX),AX",
			func(uint64) uint64 { return other },
		},
		fixedLocalExchangeCase{
			"LEAQ 8(SP),CX\nMOVQ AX,DX\nXCHGQ CX,DX\nMOVQ CX,(DX)\nMOVQ 8(SP),AX",
			func(input uint64) uint64 { return input },
		},
		fixedLocalExchangeCase{
			"MOVQ AX,8(SP)\nLEAQ 8(SP),CX\nXCHGQ CX,(CX)\nMOVQ 8(SP),DX\nMOVQ CX,(DX)\nMOVQ 8(SP),AX",
			func(input uint64) uint64 { return input },
		},
		fixedLocalExchangeCase{
			"MOVQ AX,8(SP)\nMOVQ $0x1122334455667788,CX\nMOVQ CX,24(SP)\nMOVQ $8,CX\nMOVQ $24,DX\nXCHGQ CX,DX\nMOVQ (SP)(CX*1),AX",
			func(uint64) uint64 { return other },
		},
		fixedLocalExchangeCase{"XCHGL AX,AX", func(input uint64) uint64 { return input }},
		fixedLocalExchangeCase{"MOVQ AX,BX\nXCHGL BX,BX\nMOVQ BX,AX", func(input uint64) uint64 { return uint64(uint32(input)) }},
		fixedLocalExchangeCase{"MOVQ $0x1122334455667788,CX\nSTC\nXCHGQ AX,CX\nADCQ $0,AX", func(uint64) uint64 { return other + 1 }},
	)
	return rows
}

func fixedLocalExchangeProgram(t *testing.T) (string, string, []fixedLocalExchangeCase) {
	t.Helper()
	rows := fixedLocalExchangeCases()
	if len(rows) != 21 {
		t.Fatal("exchange width, memory, alias and typed-value inventory changed", len(rows))
	}
	var assembly, declarations strings.Builder
	for index, row := range rows {
		_, _, source := fixedLocalGPFixture(t, row.body)
		name := fmt.Sprintf("Value%d", index)
		assembly.WriteString(strings.Replace(source, "·Value", "·"+name, 1))
		fmt.Fprintf(&declarations, "func %s(a uint64) uint64\n", name)
	}
	return assembly.String(), declarations.String(), rows
}

func TestGoAMD64FixedLocalExchangeObjects(t *testing.T) {
	assembly, declarations, rows := fixedLocalExchangeProgram(t)
	fixedLocalCompleteVectorObjects(t, assembly, declarations, len(rows))
}
