package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

// Independent native FSQRT D9FA observations, with both original Go encoding
// listings bound to the ELF. These eight results were identical for all twelve
// PC/RC words. Full raw348 SHA: 542520683acf8928ed14211fc046ab7341450c214fa600558bd7c1244b99cd3e.
// Native SW exceptions were recorded independently and are not asserted here.
var x87PortableSquareRootNativeSpecials = []struct{ input, want x87PortableBits }{
	{x87PortableBits{0x8000000000000000, 0xbfff}, x87PortableBits{0xc000000000000000, 0xffff}},
	{x87PortableBits{1, 0x8000}, x87PortableBits{0xc000000000000000, 0xffff}},
	{x87PortableBits{0x8000000000000000, 0x7fff}, x87PortableBits{0x8000000000000000, 0x7fff}},
	{x87PortableBits{0x8000000000000000, 0xffff}, x87PortableBits{0xc000000000000000, 0xffff}},
	{x87PortableBits{0xc000000000000001, 0x7fff}, x87PortableBits{0xc000000000000001, 0x7fff}},
	{x87PortableBits{0xc000000000000001, 0xffff}, x87PortableBits{0xc000000000000001, 0xffff}},
	{x87PortableBits{0x8000000000000001, 0x7fff}, x87PortableBits{0xc000000000000001, 0x7fff}},
	{x87PortableBits{0x8000000000000001, 0xffff}, x87PortableBits{0xc000000000000001, 0xffff}},
}

func x87PortableSquareRootNativeProgram(t *testing.T) string {
	t.Helper()
	var rows strings.Builder
	add := func(input, want x87PortableBits, cw int) {
		fmt.Fprintf(&rows, "{UINT64_C(%d),%d,%d,UINT64_C(%d),%d},\n", input.significand, input.signExponent, cw, want.significand, want.signExponent)
	}
	for _, precision := range []int{24, 53, 64} {
		pc := map[int]int{24: 0, 53: 0x200, 64: 0x300}[precision]
		for rounding := 0; rounding < 4; rounding++ {
			cw := 0x7f | pc | rounding<<10
			// All252 representative finite wants were independently matched
			// to native raw80 observations by exact integer-square intervals.
			for _, input := range x87PortableSquareRootRepresentativeInputs() {
				value, valid := x87PortableRational(input)
				if !valid || value.Sign() < 0 {
					t.Fatal("noncanonical native finite input", input)
				}
				want := x87PortableSqrtSquareOracle(value, precision, rounding)
				if input.significand == 0 {
					want.signExponent = input.signExponent
				}
				add(input, want, cw)
			}
			for _, row := range x87PortableSquareRootNativeSpecials {
				add(row.input, row.want, cw)
			}
		}
	}
	return x87PortableSquareRootCheckProgram(rows.String(), 348)
}

func TestCrossLinuxRuntimeMatrixX87PortableSquareRootNativeAnchors(t *testing.T) {
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM22 llc/clang are required")
	}
	ir, oracle := x87PortableSquareRootModule(t), x87PortableSquareRootNativeProgram(t)
	for _, level := range []int{0, 2} {
		t.Run(fmt.Sprintf("backend%d", level), func(t *testing.T) {
			compileAndRunRuntimeTestWithCompiler(t, llc, []string{clang}, "portable-sqrt-native", testTargetTriple(runtime.GOOS, runtime.GOARCH), ir, oracle, nil, level)
		})
	}
}
