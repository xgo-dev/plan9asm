//go:build amd64

package amd64conformance

import (
	"encoding/binary"
	"fmt"
	"math"
	"os"
	"strings"
	"testing"
)

func x87Raw80(sig uint64, signExp uint16) [10]byte {
	var b [10]byte
	binary.LittleEndian.PutUint64(b[:8], sig)
	binary.LittleEndian.PutUint16(b[8:10], signExp)
	return b
}

func x87RCControlWords() []uint64 {
	return []uint64{0x037f, 0x077f, 0x0b7f, 0x0f7f}
}

func x87PCRCControlWords() []uint64 {
	return []uint64{
		0x007f, 0x047f, 0x087f, 0x0c7f, // PC=24 (RN, RD, RU, RZ)
		0x027f, 0x067f, 0x0a7f, 0x0e7f, // PC=53 (RN, RD, RU, RZ)
		0x037f, 0x077f, 0x0b7f, 0x0f7f, // PC=64 (RN, RD, RU, RZ)
	}
}

func x87BCDBoundaryRaw80() [][10]byte {
	return [][10]byte{
		x87Raw80(0xde0b6b3a763ffff0, 0x403a), // +999999999999999999 (max valid)
		x87Raw80(0xde0b6b3a763ffff0, 0xc03a), // -999999999999999999 (min valid)
		x87Raw80(0xde0b6b3a76400000, 0x403a), // +10^18 (exact +overflow)
		x87Raw80(0xde0b6b3a76400000, 0xc03a), // -10^18 (exact -overflow)
		x87Raw80(0xde0b6b3a763ffff8, 0x403a), // +999999999999999999.5 (rounds to 10^18 in RN/RU)
		x87Raw80(0xde0b6b3a763ffff8, 0xc03a), // -999999999999999999.5 (rounds to -10^18 in RN/RD)
		x87Raw80(0xde0b6b3a763ffff1, 0x403a), // +999999999999999999.0625 (overflows ONLY in RU)
		x87Raw80(0xde0b6b3a763ffff1, 0xc03a), // -999999999999999999.0625 (overflows ONLY in RD)
		x87Raw80(0x8000000000000000, 0x403b), // +2^60 (exp > 16442)
		x87Raw80(0x0000000000000000, 0x0000), // +0.0
		x87Raw80(0x0000000000000000, 0x8000), // -0.0
		x87Raw80(0x8000000000000000, 0x3ffd), // +0.25
		x87Raw80(0x8000000000000000, 0xbffd), // -0.25
		x87Raw80(0x8000000000000000, 0x3ffe), // +0.5
		x87Raw80(0x8000000000000000, 0xbffe), // -0.5
		x87Raw80(0xc000000000000000, 0x3fff), // +1.5
		x87Raw80(0xc000000000000000, 0xbfff), // -1.5
		x87Raw80(0x8000000000000000, 0x7fff), // +Inf
		x87Raw80(0x8000000000000000, 0xffff), // -Inf
		x87Raw80(0xc000000000000001, 0x7fff), // QNaN
		x87Raw80(0x8000000000000001, 0x7fff), // SNaN
	}
}

func x87IntBoundaryRaw80() [][10]byte {
	return [][10]byte{
		x87Raw80(0xfffe000000000000, 0x400d), // +32767
		x87Raw80(0xffff000000000000, 0x400d), // +32767.5
		x87Raw80(0x8000000000000000, 0x400e), // +32768
		x87Raw80(0x8000000000000000, 0xc00e), // -32768
		x87Raw80(0x8000800000000000, 0xc00e), // -32768.5
		x87Raw80(0x8001000000000000, 0xc00e), // -32769
		x87Raw80(0xfffffffe00000000, 0x401d), // +2147483647
		x87Raw80(0xffffffff00000000, 0x401d), // +2147483647.5
		x87Raw80(0x8000000000000000, 0x401e), // +2147483648
		x87Raw80(0x8000000000000000, 0xc01e), // -2147483648
		x87Raw80(0x8000000080000000, 0xc01e), // -2147483648.5
		x87Raw80(0x8000000100000000, 0xc01e), // -2147483649
		x87Raw80(0xfffffffffffffffe, 0x403d), // +2^63 - 1
		x87Raw80(0xffffffffffffffff, 0x403d), // +2^63 - 0.5 (exact in binary80)
		x87Raw80(0x8000000000000000, 0x403e), // +2^63
		x87Raw80(0x8000000000000000, 0xc03e), // -2^63
		x87Raw80(0xffffffffffffffff, 0xc03d), // -2^63 + 0.5
		x87Raw80(0x8000000000000001, 0xc03e), // -2^63 - 1
		x87Raw80(0x8000000000000000, 0xc03f), // -2^64
		x87Raw80(0x8000000000000000, 0xbffd), // -0.25
		x87Raw80(0x8000000000000000, 0x3ffe), // +0.5
		x87Raw80(0x8000000000000000, 0x7fff), // +Inf
		x87Raw80(0xc000000000000001, 0x7fff), // QNaN
		x87Raw80(0x8000000000000001, 0x7fff), // SNaN
	}
}

func x87FloatBoundaryRaw80() [][10]byte {
	return [][10]byte{
		x87Raw80(0x0000000000000000, 0x0000), // +0.0
		x87Raw80(0x0000000000000000, 0x8000), // -0.0
		x87Raw80(0x8000000000000000, 0x3ffd), // +0.25
		x87Raw80(0x8000000000000000, 0xbffd), // -0.25
		x87Raw80(0x8000000000000000, 0x3ffe), // +0.5
		x87Raw80(0x8000000000000000, 0xbffe), // -0.5
		x87Raw80(0xc000000000000000, 0x3fff), // +1.5
		x87Raw80(0xc000000000000000, 0xbfff), // -1.5
		x87Raw80(0x8000000000000400, 0x3fff), // 1 + 2^-53 (f64 tie-to-even)
		x87Raw80(0x8000000000000c00, 0x3fff), // 1 + 2^-52 + 2^-53 (f64 tie rounds up)
		x87Raw80(0x8000008000000000, 0x3fff), // 1 + 2^-24 (f32 tie-to-even)
		x87Raw80(0x8000018000000000, 0x3fff), // 1 + 2^-23 + 2^-24 (f32 tie rounds up)
		x87Raw80(0xffffffffffffffff, 0x403d), // 2^63 - 0.5
		x87Raw80(0x8000000000000000, 0x403e), // 2^63
		x87Raw80(0xfffffffffffffc00, 0x3c00), // f64 subnormal promotion boundary (2^-1022 - 2^-1076)
		x87Raw80(0xffffffc000000000, 0x3f80), // f32 subnormal promotion boundary (2^-126 - 2^-151)
		x87Raw80(0xffffffffffffffff, 0x7ffe), // maxFinite80
		x87Raw80(0x8000000000000000, 0x0001), // minNormal80
		x87Raw80(0x0000000000000001, 0x0000), // smallestSubnormal80
		x87Raw80(0x8000000000000000, 0x7fff), // +Inf
		x87Raw80(0x8000000000000001, 0x7fff), // SNaN
	}
}

func x87ArithPCPairsRaw80() [][2][10]byte {
	return [][2][10]byte{
		{x87Raw80(0x8000000000000000, 0x3fff), x87Raw80(0xc000000000000000, 0x4000)}, // 1, 3
		{x87Raw80(0x8000000000000000, 0x4000), x87Raw80(0xc000000000000000, 0x4000)}, // 2, 3
		{x87Raw80(0x8000000000000000, 0x4034), x87Raw80(0x8000000000000000, 0x3fff)}, // 2^53, 1
		{x87Raw80(0x8000000000000000, 0x4017), x87Raw80(0x8000000000000000, 0x3fff)}, // 2^24, 1
		{x87Raw80(0xffffffffffffffff, 0x7ffe), x87Raw80(0x8000000000000000, 0x4000)}, // maxFinite, 2
		{x87Raw80(0x8000000000000000, 0x0001), x87Raw80(0xc000000000000000, 0x4000)}, // minNormal, 3
		{x87Raw80(0x0000000000000001, 0x0000), x87Raw80(0x8000000000000000, 0x3fff)}, // smallestSubnormal, 1
		{x87Raw80(0x8000000000000000, 0x3fff), x87Raw80(0x0000000000000000, 0x0000)}, // 1, 0
		{x87Raw80(0x0000000000000000, 0x0000), x87Raw80(0x0000000000000000, 0x0000)}, // 0, 0
		{x87Raw80(0x8000000000000000, 0x7fff), x87Raw80(0x8000000000000000, 0x7fff)}, // +Inf, +Inf
		{x87Raw80(0x0000000000000000, 0x8000), x87Raw80(0x0000000000000000, 0x8000)}, // -0, -0
		{x87Raw80(0xc000000000000001, 0x7fff), x87Raw80(0x8000000000000000, 0x3fff)}, // QNaN, 1
		{x87Raw80(0x8000000000000001, 0x7fff), x87Raw80(0x8000000000000000, 0x3fff)}, // SNaN, 1
	}
}

func x87CmpPairsRaw80() [][2][10]byte {
	return [][2][10]byte{
		{x87Raw80(0x8000000000000000, 0x3fff), x87Raw80(0x8000000000000000, 0x4000)}, // 1, 2
		{x87Raw80(0x8000000000000000, 0x4000), x87Raw80(0x8000000000000000, 0x4000)}, // 2, 2
		{x87Raw80(0xc000000000000000, 0x4000), x87Raw80(0x8000000000000000, 0x4000)}, // 3, 2
		{x87Raw80(0x0000000000000000, 0x8000), x87Raw80(0x0000000000000000, 0x0000)}, // -0, +0
		{x87Raw80(0xc000000000000001, 0x7fff), x87Raw80(0x8000000000000000, 0x3fff)}, // QNaN, 1
		{x87Raw80(0x8000000000000001, 0x7fff), x87Raw80(0x8000000000000000, 0x3fff)}, // SNaN, 1
		{x87Raw80(0x0000000000000001, 0x0000), x87Raw80(0x8000000000000000, 0x3fff)}, // subnormal, 1
		{x87Raw80(0xc000000000000001, 0x7fff), x87Raw80(0x0000000000000001, 0x0000)}, // QNaN, subnormal
		{x87Raw80(0x8000000000000001, 0x7fff), x87Raw80(0x0000000000000001, 0x0000)}, // SNaN, subnormal
		{x87Raw80(0x8000000000000000, 0xffff), x87Raw80(0x8000000000000000, 0x7fff)}, // -Inf, +Inf
	}
}

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

	rcWords := x87RCControlWords()
	for r, cw := range rcWords {
		for i, in := range x87BCDBoundaryRaw80() {
			var outBCD [10]byte
			var outSW uint64
			inCopy := in
			diffX87BCDOne(cw, &inCopy, &outBCD, &outSW)
			lines = append(lines, fmt.Sprintf("x87_bcd_rc[%d][%d]=%x|%04x", r, i, outBCD, outSW))
		}
		for i, in := range x87IntBoundaryRaw80() {
			var outVals, outSW [3]uint64
			inCopy := in
			diffX87ConvInt(cw, &inCopy, &outVals, &outSW)
			lines = append(lines, fmt.Sprintf("x87_conv_int[%d][%d]=%s|%s", r, i, formatU64Slice(outVals[:]), formatU64Slice(outSW[:])))
		}
		for i, in := range x87FloatBoundaryRaw80() {
			var outF32 uint32
			var outF64 uint64
			var outRnd [10]byte
			var outSW [3]uint64
			inCopy := in
			diffX87ConvFloat(cw, &inCopy, &outF32, &outF64, &outRnd, &outSW)
			lines = append(lines, fmt.Sprintf("x87_conv_flt[%d][%d]=%08x|%016x|%x|%s", r, i, outF32, outF64, outRnd, formatU64Slice(outSW[:])))
		}
	}
	for m, cw := range x87PCRCControlWords() {
		for i, p := range x87ArithPCPairsRaw80() {
			var outRaw [50]byte
			var outSW [5]uint64
			aCopy, bCopy := p[0], p[1]
			diffX87ArithPC(cw, &aCopy, &bCopy, &outRaw, &outSW)
			lines = append(lines, fmt.Sprintf("x87_arith_pc[%d][%d]=%x|%s", m, i, outRaw, formatU64Slice(outSW[:])))
		}
	}
	for i, p := range x87CmpPairsRaw80() {
		var outCC, outExc [5]uint64
		aCopy, bCopy := p[0], p[1]
		diffX87Cmp(&aCopy, &bCopy, &outCC, &outExc)
		lines = append(lines, fmt.Sprintf("x87_cmp[%d]=%s|%s", i, formatU64Slice(outCC[:]), formatU64Slice(outExc[:])))
	}
	for x := uint64(0); x <= 1; x++ {
		var out [4]uint64
		diffX87DynamicStackBranch(x, &out)
		lines = append(lines, fmt.Sprintf("x87_dyn_branch[%d]=%s", x, formatU64Slice(out[:])))
	}
	for x := uint64(0); x <= 1; x++ {
		var out [8]uint64
		diffX87MMXAliasAndTop(x, &out)
		lines = append(lines, fmt.Sprintf("x87_mmx_alias[%d]=%s", x, formatU64Slice(out[:])))
	}
	for x := uint64(0); x <= 1; x++ {
		var out [6]uint64
		diffX87CallAndMergeAlias(x, &out)
		lines = append(lines, fmt.Sprintf("x87_call_merge[%d]=%s", x, formatU64Slice(out[:])))
	}
	for x := uint64(0); x <= 1; x++ {
		var out [4]uint64
		diffX87EntryTopAndCW(x, &out)
		lines = append(lines, fmt.Sprintf("x87_entry_top_cw[%d]=%s", x, formatU64Slice(out[:])))
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

	// Verify Round 13 P1: FMOVBP / FBSTP 18-digit BCD range & indefinite (FFFFC000000000000000H + IE=1).
	bcdInputs := x87BCDBoundaryRaw80()
	var bcdOut [10]byte
	var bcdSW uint64
	// [0] +999999999999999999 -> valid (IE=0, PE=0, C1=0, TOP=0), bytes 0..8 = 0x99, byte 9 = 0x00
	inMax := bcdInputs[0]
	diffX87BCDOne(0x037f, &inMax, &bcdOut, &bcdSW)
	wantMax := [10]byte{0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x00}
	if bcdOut != wantMax || bcdSW != 0x0000 {
		t.Fatalf("diffX87BCDOne(+10^18-1, RN) = (%x, %#x), want (%x, 0x0)", bcdOut, bcdSW, wantMax)
	}
	// [2] +10^18 -> invalid (IE=1, PE=0, C1=0), packed BCD indefinite 00000000000000c0ffff
	inOvf := bcdInputs[2]
	diffX87BCDOne(0x037f, &inOvf, &bcdOut, &bcdSW)
	wantIndef := [10]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xff, 0xff}
	if bcdOut != wantIndef || bcdSW != 0x0001 {
		t.Fatalf("diffX87BCDOne(+10^18, RN) = (%x, %#x), want (%x, 0x1)", bcdOut, bcdSW, wantIndef)
	}
	// [4] +999999999999999999.5 -> RN overflows to indefinite (IE=1), RD rounds to valid max (PE=0x20)
	inHalf := bcdInputs[4]
	diffX87BCDOne(0x037f, &inHalf, &bcdOut, &bcdSW)
	if bcdOut != wantIndef || bcdSW != 0x0001 {
		t.Fatalf("diffX87BCDOne(+10^18-0.5, RN) = (%x, %#x), want (%x, 0x1)", bcdOut, bcdSW, wantIndef)
	}
	diffX87BCDOne(0x077f, &inHalf, &bcdOut, &bcdSW)
	if bcdOut != wantMax || bcdSW != 0x0020 {
		t.Fatalf("diffX87BCDOne(+10^18-0.5, RD) = (%x, %#x), want (%x, 0x20)", bcdOut, bcdSW, wantMax)
	}

	// Verify Round 14 dynamic x87 branch-depth non-overflowing cases on native amd64.
	var dyn0, dyn1 [4]uint64
	diffX87DynamicStackBranch(0, &dyn0)
	diffX87DynamicStackBranch(1, &dyn1)
	if dyn0 != [4]uint64{0x0000, 0x0800, 0x0000, 0x0000} {
		t.Fatalf("diffX87DynamicStackBranch(0) = %#x, want [0x0 0x800 0x0 0x0]", dyn0)
	}
	if dyn1 != [4]uint64{0x0000, 0x0000, 0x0800, 0x0000} {
		t.Fatalf("diffX87DynamicStackBranch(1) = %#x, want [0x0 0x0 0x800 0x0]", dyn1)
	}

	// Verify Round 15 P1/P2 physical x87/MMX register aliasing and TOP reset on native amd64.
	var mmx0, mmx1 [8]uint64
	diffX87MMXAliasAndTop(0, &mmx0)
	diffX87MMXAliasAndTop(1, &mmx1)
	wantMMX0 := [8]uint64{0x8000000000000000, 123, 0x3800, 0x3800, 0xc90fdaa22168c235, 0x8000000000000000, 0x8000000000000000, 123}
	wantMMX1 := [8]uint64{0x8000000000000000, 123, 0x3800, 0x3800, 0xc90fdaa22168c235, 0x8000000000000000, 0x8000000000000000, 0xc90fdaa22168c235}
	if mmx0 != wantMMX0 {
		t.Fatalf("diffX87MMXAliasAndTop(0) = %#x, want %#x", mmx0, wantMMX0)
	}
	if mmx1 != wantMMX1 {
		t.Fatalf("diffX87MMXAliasAndTop(1) = %#x, want %#x", mmx1, wantMMX1)
	}

	// Verify Round 16 P1/P2 CALL+FINIT/EMMS re-sync and differing-TOP CFG join M7 aliasing.
	var cm0, cm1 [6]uint64
	diffX87CallAndMergeAlias(0, &cm0)
	diffX87CallAndMergeAlias(1, &cm1)
	wantCM0 := [6]uint64{0x8000000000000000, 0x8000000000000000, 0x8000000000000000, 0x8000000000000000, 0x8000000000000000, 0x3800}
	wantCM1 := [6]uint64{0x8000000000000000, 0x8000000000000000, 0x8000000000000000, 0x8000000000000000, 0xc90fdaa22168c235, 0x3800}
	if cm0 != wantCM0 {
		t.Fatalf("diffX87CallAndMergeAlias(0) = %#x, want %#x", cm0, wantCM0)
	}
	if cm1 != wantCM1 {
		t.Fatalf("diffX87CallAndMergeAlias(1) = %#x, want %#x", cm1, wantCM1)
	}

	// Verify Round 17 P1 entry-TOP and entry-CW invariance with explicit FINIT/MMX+EMMS/FLDCW.
	wantET := [4]uint64{0x8000000000000000, 0x8000000000000000, 0xc90fdaa22168c235, 0xc90fdaa22168c234}
	for x := uint64(0); x <= 1; x++ {
		var et [4]uint64
		diffX87EntryTopAndCW(x, &et)
		if et != wantET {
			t.Fatalf("diffX87EntryTopAndCW(%d) = %#x, want %#x", x, et, wantET)
		}
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
