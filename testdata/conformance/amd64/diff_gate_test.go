//go:build amd64

package amd64conformance

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"testing"
)

func cpuidFeatures() (hasSSE42, hasADX, hasSHA bool) {
	var r0, r1, r7 [4]uint32
	diffCPUID(0, 0, &r0)
	if r0[0] >= 1 {
		diffCPUID(1, 0, &r1)
		// SSSE3(bit 9), SSE4.1(bit 19), SSE4.2(bit 20)
		hasSSE42 = (r1[2] & (1 << 20)) != 0
	}
	if r0[0] >= 7 {
		diffCPUID(7, 0, &r7)
		hasADX = (r7[1] & (1 << 19)) != 0
		hasSHA = (r7[1]&(1<<29)) != 0 && (r1[2]&(1<<9)) != 0 && (r1[2]&(1<<19)) != 0
	}
	return
}

func formatU64Slice(vals []uint64) string {
	var b strings.Builder
	for i, v := range vals {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, "%016x", v)
	}
	return b.String()
}

func runDiffGateOracleLines() (lines []string, hwPending []string) {
	hasSSE42, hasADX, hasSHA := cpuidFeatures()

	arithPairs := [][2]uint64{
		{0, 0},
		{15, 1},
		{16, 1},
		{3, 0},
		{0x7f, 1},
		{0x80, 1},
		{0xff, 1},
		{0x7fff, 1},
		{0x8000, 1},
		{0xffff, 1},
		{0x7fffffff, 1},
		{0x80000000, 1},
		{0xffffffff, 1},
		{0x7fffffffffffffff, 1},
		{0x8000000000000000, 1},
		{0xffffffffffffffff, 1},
		{0x123456789abcdef0, 0x0fedcba987654321},
		{0x8000000000000000, 0x8000000000000000},
	}

	for i, p := range arithPairs {
		var out20 [20]uint64
		diffArith64(p[0], p[1], &out20)
		lines = append(lines, fmt.Sprintf("arith64[%d]=%s", i, formatU64Slice(out20[:])))

		var out24 [24]uint64
		diffArithWidths(p[0], p[1], &out24)
		lines = append(lines, fmt.Sprintf("arithw[%d]=%s", i, formatU64Slice(out24[:])))

		var out16 [16]uint64
		diffMulDiv(p[0], p[1], &out16)
		lines = append(lines, fmt.Sprintf("muldiv[%d]=%s", i, formatU64Slice(out16[:])))

		var flg [16]uint64
		diffFlagsSaveRestore(p[0], p[1], &flg)
		lines = append(lines, fmt.Sprintf("flags[%d]=%s", i, formatU64Slice(flg[:])))

		var bit [16]uint64
		diffBitCond(p[0], p[1], &bit)
		lines = append(lines, fmt.Sprintf("bit[%d]=%s", i, formatU64Slice(bit[:])))
	}

	shiftVals := []uint64{
		0,
		1,
		0x8000,
		0x4000000000000000,
		0x8000000000000000,
		0xffffffffffffffff,
		0x0123456789abcdef,
	}
	shiftCnts := []uint64{0, 1, 7, 8, 15, 16, 31, 32, 63, 64}
	idx := 0
	for _, v := range shiftVals {
		for _, c := range shiftCnts {
			var out24 [24]uint64
			diffShiftsRotates(v, c, &out24)
			lines = append(lines, fmt.Sprintf("shift[%d]=%s", idx, formatU64Slice(out24[:])))
			idx++
		}
	}

	dshiftPairs := [][2]uint64{
		{1, 42},
		{0x1234, 0xabcd},
		{0x8001, 0x7ffe},
		{0x0123456789abcdef, 0xfedcba9876543210},
	}
	dshift16Cnts := []uint64{0, 1, 7, 8, 15, 16}
	idx16 := 0
	for _, p := range dshiftPairs {
		for _, c := range dshift16Cnts {
			var out16 [16]uint64
			diffDoubleShift16(p[0], p[1], c, &out16)
			lines = append(lines, fmt.Sprintf("dshift16[%d]=%s", idx16, formatU64Slice(out16[:])))
			idx16++
		}
	}
	dshift3264Cnts := []uint64{0, 1, 7, 16, 31, 32, 63, 64}
	idx3264 := 0
	for _, p := range dshiftPairs {
		for _, c := range dshift3264Cnts {
			var out16 [16]uint64
			diffDoubleShift3264(p[0], p[1], c, &out16)
			lines = append(lines, fmt.Sprintf("dshift3264[%d]=%s", idx3264, formatU64Slice(out16[:])))
			idx3264++
		}
	}

	atomicVals := []uint64{0x1122334455667788, 0x0000000000000042, 0xffffffffffffffff}
	for i, v := range atomicVals {
		var buf [64]byte
		for j := range buf {
			buf[j] = byte(j*7 + 3)
		}
		var out16 [16]uint64
		diffAtomicAndString(&buf, v, &out16)
		lines = append(lines, fmt.Sprintf("atomstr[%d]=%s|%x", i, formatU64Slice(out16[:]), buf))
	}

	lines = append(lines, fmt.Sprintf("zeroarg=%016x", uint64(diffZeroArgCaller())))
	lines = append(lines, fmt.Sprintf("pushfq_raw_if=%016x", diffPushfqRawIF()))

	if hasADX {
		for i, p := range arithPairs {
			var out8 [8]uint64
			diffADX(p[0], p[1], &out8)
			lines = append(lines, fmt.Sprintf("adx[%d]=%s", i, formatU64Slice(out8[:])))
		}
	} else {
		hwPending = append(hwPending, "adx")
	}

	if hasSSE42 {
		pcmpCases := []struct {
			needle [16]byte
			hay    [16]byte
			nLen   uint64
			hLen   uint64
		}{
			{[16]byte{'a', 'b', 'c'}, [16]byte{'x', 'y', 'a', 'b', 'c', 'z'}, 3, 6},
			{[16]byte{'a', 'b', 'c'}, [16]byte{'a', 'b', 'c', 'd', 'e', 'f'}, 3, 6},
			{[16]byte{'a', 'b', 'c'}, [16]byte{'x', 'y', 'z', 'a', 'b', 'c'}, 3, 4},
			{[16]byte{'a', 'b', 'c'}, [16]byte{'x', 'y', 'z', 'w'}, 3, 4},
			{[16]byte{'a', 'b', 'c'}, [16]byte{'x', 'y', 'z', 'w'}, 0, 4},
			{[16]byte{'a', 'b', 'c'}, [16]byte{'x', 'y', 'a', 'b', 'c', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9'}, 3, 16},
			{[16]byte{'a', 'b', 'c'}, [16]byte{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'x', 'y', 'z', 'w', 'a', 'b'}, 3, 16},
		}
		for i, tc := range pcmpCases {
			var out8 [8]uint64
			diffPCMPESTRI0C(&tc.needle, &tc.hay, tc.nLen, tc.hLen, &out8)
			lines = append(lines, fmt.Sprintf("pcmpestri0c[%d]=%s", i, formatU64Slice(out8[:])))
		}
	} else {
		hwPending = append(hwPending, "sse4.2")
	}

	if hasSHA {
		shaMsgs := [][]byte{
			[]byte(""),
			[]byte("abc"),
			[]byte("0123456789abcdef0123456789abcdef0123456789abcdef"),
		}
		for i, msg := range shaMsgs {
			var block [64]byte
			copy(block[:], msg)
			block[len(msg)] = 0x80
			binary.BigEndian.PutUint64(block[56:], uint64(len(msg)*8))

			st256 := [8]uint32{
				0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
				0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
			}
			diffSHA256Block(&st256, &block)
			var d256 [32]byte
			for j, w := range st256 {
				binary.BigEndian.PutUint32(d256[4*j:], w)
			}
			lines = append(lines, fmt.Sprintf("sha256[%d]=%x", i, d256))

			st1 := [5]uint32{0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0}
			diffSHA1Block(&st1, &block)
			var d1 [20]byte
			for j, w := range st1 {
				binary.BigEndian.PutUint32(d1[4*j:], w)
			}
			lines = append(lines, fmt.Sprintf("sha1[%d]=%x", i, d1))
		}
	} else {
		hwPending = append(hwPending, "sha-ni")
	}

	return lines, hwPending
}

func TestAMD64DiffGateNativeSanity(t *testing.T) {
	// Verify key Round 4, Round 5, Round 6 invariants on native Go amd64 hardware.
	if got := diffZeroArgCaller(); got != 42 {
		t.Fatalf("diffZeroArgCaller() = %d, want 42", got)
	}
	var ds [16]uint64
	diffDoubleShift16(1, 42, 16, &ds)
	if ds[4] != 42 || ds[6] != 42 || ds[8] != 42 || ds[10] != 42 {
		t.Fatalf("diffDoubleShift16(1, 42, 16) = %v, want 42 at [4,6,8,10]", ds)
	}
	var fl [16]uint64
	diffFlagsSaveRestore(15, 1, &fl)
	if fl[0]&1 != 1 || fl[0]&0x200 != 0x200 || fl[1]&1 != 1 || fl[1]&0x200 != 0x200 || fl[2] != 1 || fl[3] != 0 || fl[8] != 16 {
		t.Fatalf("diffFlagsSaveRestore(15, 1) = %#x, unexpected CF/IF/AF", fl)
	}
	if got := diffPushfqRawIF(); got != 0x0000000002000200 {
		t.Fatalf("diffPushfqRawIF() = %#x, want 0x2000200 (IF=0x200 preserved)", got)
	}
	_, _, hasSHA := cpuidFeatures()
	if hasSHA {
		var block [64]byte
		copy(block[:], "abc")
		block[3] = 0x80
		binary.BigEndian.PutUint64(block[56:], 24)
		st256 := [8]uint32{
			0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
			0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
		}
		diffSHA256Block(&st256, &block)
		var got256 [32]byte
		for j, w := range st256 {
			binary.BigEndian.PutUint32(got256[4*j:], w)
		}
		if want := sha256.Sum256([]byte("abc")); got256 != want {
			t.Fatalf("native SHA-NI sha256(abc) = %x, want %x", got256, want)
		}
		st1 := [5]uint32{0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0}
		diffSHA1Block(&st1, &block)
		var got1 [20]byte
		for j, w := range st1 {
			binary.BigEndian.PutUint32(got1[4*j:], w)
		}
		if want := sha1.Sum([]byte("abc")); got1 != want {
			t.Fatalf("native SHA-NI sha1(abc) = %x, want %x", got1, want)
		}
	}
}

func TestAMD64DiffGateDumpOracle(t *testing.T) {
	outPath := os.Getenv("PLAN9ASM_DIFF_ORACLE_OUT")
	if outPath == "" {
		return
	}
	lines, hwPending := runDiffGateOracleLines()
	var b strings.Builder
	fmt.Fprintf(&b, "HW_PENDING=%s\n", strings.Join(hwPending, ","))
	for _, line := range lines {
		b.WriteString(line)
		b.WriteByte('\n')
	}
	if err := os.WriteFile(outPath, []byte(b.String()), 0o600); err != nil {
		t.Fatalf("write oracle output %s: %v", outPath, err)
	}
}
