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

	var topOut [12]uint64
	diffX87TopStatus(&topOut)
	lines = append(lines, fmt.Sprintf("x87_top=%s", formatU64Slice(topOut[:])))

	var bin80Int [6]int64
	var bin80Raw [60]byte
	diffX87Binary80Precision(&bin80Int, &bin80Raw)
	bin80U64 := make([]uint64, len(bin80Int))
	for i, v := range bin80Int {
		bin80U64[i] = uint64(v)
	}
	lines = append(lines, fmt.Sprintf("x87_bin80=%s|%x", formatU64Slice(bin80U64), bin80Raw))

	var excOut [10]uint64
	diffX87Exceptions(&excOut)
	lines = append(lines, fmt.Sprintf("x87_exc=%s", formatU64Slice(excOut[:])))

	var constRCRaw [280]byte
	diffX87ConstRoundingModes(&constRCRaw)
	lines = append(lines, fmt.Sprintf("x87_const_rc=%x", constRCRaw))

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

	// Verify FSTSW tracks x87 stack TOP pointer across pushes, pops, FTST, FCOMD, FINCSTP, FDECSTP.
	var topOut [12]uint64
	diffX87TopStatus(&topOut)
	wantTop := [12]uint64{0x0000, 0x3800, 0x3000, 0x2800, 0x6800, 0x2900, 0x2800, 0x3000, 0x0000, 0x3800, 0x0000, 0x0000}
	for i, want := range wantTop {
		if topOut[i] != want {
			t.Fatalf("diffX87TopStatus[%d] = %#x, want %#x", i, topOut[i], want)
		}
	}

	// Verify 64-bit significand binary80 precision (2^53 + 1 == 9007199254740993).
	var bin80Int [6]int64
	var bin80Raw [60]byte
	diffX87Binary80Precision(&bin80Int, &bin80Raw)
	wantBin80 := [6]int64{
		9007199254740993,
		4611686018427387905,
		4611686018427387903,
		27021597764222979,
		384307168202282326,
		2147483648,
	}
	for i, want := range wantBin80 {
		if bin80Int[i] != want {
			t.Fatalf("diffX87Binary80Precision[%d] = %d, want %d", i, bin80Int[i], want)
		}
	}

	// Verify Round 12 P1 #1: sticky arithmetic exception flags + C1 + TOP in FSTSW.
	var excOut [10]uint64
	diffX87Exceptions(&excOut)
	wantExc := [10]uint64{0x3804, 0x3801, 0x3a20, 0x0004, 0x3800, 0x0001, 0x0020, 0x0228, 0x0230, 0x0022}
	for i, want := range wantExc {
		if excOut[i] != want {
			t.Fatalf("diffX87Exceptions[%d] = %#x, want %#x", i, excOut[i], want)
		}
	}

	// Verify Round 12 P1 #2: FLDPI/FLDL2E/FLDL2T/FLDLG2/FLDLN2 obey FLDCW rounding modes.
	var constRCRaw [280]byte
	diffX87ConstRoundingModes(&constRCRaw)
	// FLDPI is at offset +20 within each 70-byte rounding-mode block:
	// RN (0x037f) and RU (0x0b7f) -> ...c235 (low byte 0x35);
	// RD (0x077f) and RZ (0x0f7f) -> ...c234 (low byte 0x34).
	if constRCRaw[20] != 0x35 || constRCRaw[70+20] != 0x34 || constRCRaw[140+20] != 0x35 || constRCRaw[210+20] != 0x34 {
		t.Fatalf("diffX87ConstRoundingModes FLDPI low bytes = [%#x %#x %#x %#x], want [0x35 0x34 0x35 0x34]",
			constRCRaw[20], constRCRaw[70+20], constRCRaw[140+20], constRCRaw[210+20])
	}
	// FLDL2T is at offset +40 within each block: RN/RD/RZ -> 0xfe, RU -> 0xff.
	if constRCRaw[40] != 0xfe || constRCRaw[70+40] != 0xfe || constRCRaw[140+40] != 0xff || constRCRaw[210+40] != 0xfe {
		t.Fatalf("diffX87ConstRoundingModes FLDL2T low bytes = [%#x %#x %#x %#x], want [0xfe 0xfe 0xff 0xfe]",
			constRCRaw[40], constRCRaw[70+40], constRCRaw[140+40], constRCRaw[210+40])
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
