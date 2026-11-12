package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

type x86CallerCompareRow struct {
	body, left, right, rawBase string
	bits, condition            int
}

func x86CallerCompareRows() []x86CallerCompareRow {
	var rows []x86CallerCompareRow
	for _, width := range []struct {
		name string
		bits int
	}{{"B", 8}, {"W", 16}, {"L", 32}, {"Q", 64}} {
		for condition, op := range amd64RegisterBoolConditions {
			rows = append(rows, x86CallerCompareRow{"CMP" + width.name + " AX,BX\n" + op + " AX", "a", "b", "a", width.bits, condition})
		}
		for _, immediate := range []string{"0", "1", "127", "128", "255", "256", "-128", "-129", "32768", "65535", "2147483647", "2147483648", "4294967295", "-2147483648"} {
			rows = append(rows, x86CallerCompareRow{"CMP" + width.name + " AX,$" + immediate + "\nSETCS AX", "a", immediate, "a", width.bits, 1})
		}
	}
	for _, alias := range []string{"MOVQ", "MOVD", "MOVDQ2Q"} {
		rows = append(rows, x86CallerCompareRow{alias + " AX,DX\nLEAQ 16(DX),AX\nCMPQ AX,BX\nSETHI AX", "a+16", "b", "a+16", 64, 5})
	}
	return append(rows,
		x86CallerCompareRow{"CMPB AH,BH\nSETCS AX", "a>>8", "b>>8", "a", 8, 1},
		x86CallerCompareRow{"MOVQ AX,DI\nMOVQ BX,R8\nCMPB BH,R8B\nSETEQ AX", "a", "b", "a", 8, 2},
		x86CallerCompareRow{"MOVQ AX,DX\nCMPQ DX,AX\nSETEQ AX", "a", "a", "a", 64, 2},
	)
}

func x86CallerCompareSources() (string, string) {
	var source, declarations strings.Builder
	for index, row := range x86CallerCompareRows() {
		name := fmt.Sprintf("Compare%d", index)
		source.WriteString(strings.ReplaceAll(x86CallerAddressRegisterSource(row.body), "·view", "·"+name))
		fmt.Fprintf(&declarations, "func %s(p,q *byte) bool\n", name)
	}
	return source.String(), declarations.String()
}

func TestX86CallerAddressCMPThreeTargetOriginalAndLLVMObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	source, declarations := x86CallerCompareSources()
	requireAMD64RegisterResultGoObject(t, source)
	for _, triple := range []string{"x86_64-unknown-linux-gnu", "x86_64-apple-darwin", "x86_64-pc-windows-msvc"} {
		for _, api := range []string{"text", "module", "Go"} {
			ir, err := x86ScalarFPBitViewAPI(t, source, declarations, "amd64", triple, api)
			if err != nil {
				t.Fatal(triple, api, err)
			}
			for _, optimized := range []bool{false, true} {
				input := ir
				if optimized {
					input = x86MulDivRoundOptimize(t, input)
				}
				x86ResultInitializationObject(t, llc, triple, input, "caller-address-compare")
			}
		}
	}
}
