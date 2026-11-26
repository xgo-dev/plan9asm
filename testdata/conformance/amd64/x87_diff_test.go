//go:build amd64

package amd64conformance

import (
	"fmt"
	"math"
	"os"
	"strings"
	"testing"
)

func x87DiffBCDInputs() [][10]byte {
	return [][10]byte{
		{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // +0
		{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80}, // -0
		{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // +1
		{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80}, // -1
		{0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // +42
		{0x99, 0x99, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80}, // -99999
		{0x78, 0x56, 0x34, 0x12, 0x90, 0x78, 0x56, 0x34, 0x12, 0x00}, // +123456789012345678
		{0x32, 0x54, 0x76, 0x98, 0x10, 0x32, 0x54, 0x76, 0x98, 0x80}, // -987654321098765432
	}
}

func x87DiffArithPairs() [][2]float64 {
	return [][2]float64{
		{10.0, 3.0},
		{-7.5, 2.25},
		{1.0, 3.0},
	}
}

func x87DiffCmpPairs() [][2]float64 {
	return [][2]float64{
		{1.0, 2.0},
		{2.0, 2.0},
		{3.0, 2.0},
		{math.Copysign(0, -1), 0.0},
		{math.NaN(), 1.0},
		{1.0, math.NaN()},
	}
}

func runX87DiffOracleLines() []string {
	var lines []string

	var stackOut [16]uint64
	diffX87FmovdStackDepths(&stackOut)
	lines = append(lines, fmt.Sprintf("x87_stack=%s", formatU64Slice(stackOut[:])))

	var constF64 [7]uint64
	var constRaw80 [70]byte
	diffX87Constants(&constF64, &constRaw80)
	lines = append(lines, fmt.Sprintf("x87_consts=%s|%x", formatU64Slice(constF64[:]), constRaw80))

	for i, in := range x87DiffBCDInputs() {
		var outBCD [10]byte
		var outF64 uint64
		inCopy := in
		diffX87BCD(&inCopy, &outBCD, &outF64)
		lines = append(lines, fmt.Sprintf("x87_bcd[%d]=%x|%016x", i, outBCD, outF64))
	}

	for i, p := range x87DiffArithPairs() {
		var out [10]uint64
		diffX87Arith80(p[0], p[1], &out)
		lines = append(lines, fmt.Sprintf("x87_arith[%d]=%s", i, formatU64Slice(out[:])))
	}

	for i, p := range x87DiffCmpPairs() {
		var out [6]uint64
		diffX87FUCOMI(p[0], p[1], &out)
		lines = append(lines, fmt.Sprintf("x87_fucomi[%d]=%s", i, formatU64Slice(out[:])))
	}

	return lines
}

func TestAMD64X87NativeSanity(t *testing.T) {
	var stackOut [16]uint64
	diffX87FmovdStackDepths(&stackOut)
	wantStack := [16]float64{
		0, 1, 0, // FLDZ; FLD1; FMOVD F1, F0
		10, 30, 20, 10, // FMOVD F2, F0
		7, 7, 5, // FMOVD F0, F0
		9, 2, 9, // FMOVD F0, F2
		22, 33, // FMOVDP F0, F2
		55, // FMOVDP F0, F1
	}
	for i, want := range wantStack {
		got := math.Float64frombits(stackOut[i])
		if got != want {
			t.Fatalf("diffX87FmovdStackDepths[%d] = %g, want %g", i, got, want)
		}
	}

	var constF64 [7]uint64
	var constRaw80 [70]byte
	diffX87Constants(&constF64, &constRaw80)
	wantConsts := [7]float64{1.0, 0.0, math.Pi, math.Log2E, math.Log2(10), math.Log10(2), math.Ln2}
	for i, want := range wantConsts {
		if constF64[i] != math.Float64bits(want) {
			t.Fatalf("diffX87Constants[%d] = %016x (%g), want %016x (%g)",
				i, constF64[i], math.Float64frombits(constF64[i]), math.Float64bits(want), want)
		}
	}

	// Verify FUCOMI clears OF, SF, AF (bits 11, 7, 4 -> mask 0x890).
	var cmpOut [6]uint64
	diffX87FUCOMI(1.0, 2.0, &cmpOut)
	if cmpOut[0]&0x890 != 0 || cmpOut[0]&0x45 != 0x01 {
		t.Fatalf("diffX87FUCOMI(1, 2) flags = %#x, want CF=1, ZF=0, PF=0, OF=SF=AF=0", cmpOut[0])
	}
}

func TestAMD64X87DiffDumpOracle(t *testing.T) {
	outPath := os.Getenv("PLAN9ASM_X87_DIFF_ORACLE_OUT")
	if outPath == "" {
		return
	}
	lines := runX87DiffOracleLines()
	if err := os.WriteFile(outPath, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("write x87 oracle output %s: %v", outPath, err)
	}
}
