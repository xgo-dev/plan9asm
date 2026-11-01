package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

type x86NumericalLEARow struct {
	width, address, destination, effective string
}

// Independent effective-address axes, not inferred from the typed effect or
// generated LLVM. Destination aliases expose read-before-write and W/L writes.
func x86NumericalLEARows(arch string) []x86NumericalLEARow {
	var rows []x86NumericalLEARow
	addresses := []struct{ source, effective string }{
		{"(AX)", "a"}, {"-129(AX)", "a-129"}, {"127(AX)", "a+127"}, {"128(AX)", "a+128"},
		{"2147483647(AX)", "a+2147483647"}, {"-2147483648(AX)", "a-2147483648"},
		{"17(AX)(BX*1)", "a+b+17"}, {"17(AX)(BX*2)", "a+2*b+17"},
		{"17(AX)(BX*4)", "a+4*b+17"}, {"17(AX)(BX*8)", "a+8*b+17"},
		{"0(BX*1)", "b"}, {"-7(BX*2)", "2*b-7"}, {"128(BX*4)", "4*b+128"}, {"0(BX*8)", "8*b"},
		{"17", "UINT64_C(17)"}, {"-7", "UINT64_MAX-6"}, {"(1<<7)", "UINT64_C(128)"},
	}
	for _, width := range x86NumericalLEAWidths(arch) {
		for _, address := range addresses {
			for _, destination := range []string{"AX", "BX", "CX"} {
				rows = append(rows, x86NumericalLEARow{width, address.source, destination, address.effective})
			}
		}
		if width == "L" && arch == "amd64" {
			rows = append(rows, x86NumericalLEARow{width, "0x100000002(AX)(BX*8)", "AX", "a+8*b+2"})
		}
		if arch == "386" {
			rows = append(rows, x86NumericalLEARow{width, "0xffffffff(AX)", "AX", "a+UINT32_MAX"})
		}
	}
	return rows
}

func (row x86NumericalLEARow) body(arch string, numericalResult bool) string {
	move, seed := "MOVQ", "0x1122334455667788"
	if arch == "386" {
		move, seed = "MOVL", "0x55667788"
	}
	body := move + " $" + seed + ",CX\nCMP" + move[3:] + " AX,BX\nLEA" + row.width + " " + row.address + "," + row.destination + "\n"
	if numericalResult {
		// This scalar bit view makes both ABI0 and register result consumers
		// check the complete original typed NUM-only source, not a final move.
		return body + move + " " + row.destination + ",X0\n" + move + " X0,AX\n"
	}
	return body
}

func x86NumericalLEASources(arch string, rows []x86NumericalLEARow, register bool) (string, string) {
	var source, declarations strings.Builder
	word, move, typ := 8, "MOVQ", "uint64"
	if arch == "386" {
		word, move, typ = 4, "MOVL", "uint32"
	}
	for index, row := range rows {
		name := fmt.Sprintf("NumericalLEA%d", index)
		fmt.Fprintf(&declarations, "func %s(x,y %s) %s\n", name, typ, typ)
		if register {
			fmt.Fprintf(&source, "TEXT ·%s<ABIInternal>(SB),4,$0-0\n%sRET\n", name, row.body(arch, true))
		} else {
			fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n%s x+0(FP),AX\n%s y+%d(FP),BX\n%s%s AX,ret+%d(FP)\nRET\n",
				name, 3*word, move, move, word, row.body(arch, true), move, 2*word)
		}
	}
	return source.String(), declarations.String()
}

func TestX86ResultNumericalLEAThreeAPIFiveTargetOriginalAndLLVMObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		rows := x86NumericalLEARows(target.arch)
		for start := 0; start < len(rows); start += 64 {
			end := start + 64
			if end > len(rows) {
				end = len(rows)
			}
			t.Run(fmt.Sprintf("%s/%d-%d", target.triple, start, end), func(t *testing.T) {
				source, declarations := x86NumericalLEASources(target.arch, rows[start:end], false)
				x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, source, declarations, target.arch, target.triple, api)
					if err != nil {
						t.Fatal(target.triple, api, err)
					}
					for _, optimized := range []bool{false, true} {
						input := ir
						if optimized {
							input = x86MulDivRoundOptimize(t, input)
						}
						x86ResultInitializationObject(t, llc, target.triple, input, "numerical-lea")
					}
				}
			})
		}
	}
}
