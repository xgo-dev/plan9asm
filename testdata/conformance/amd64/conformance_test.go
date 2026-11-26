//go:build amd64

package amd64conformance

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestByteMemoryDestinations(t *testing.T) {
	got := [4]byte{0x10, 0xf0, 0x5a, 0xa0}
	byteMemory(&got, 0x0f)
	want := [4]byte{0x1f, 0xff, 0x0a, 0xaf}
	if got != want {
		t.Fatalf("byteMemory() = %#v, want %#v", got, want)
	}
}

func TestPUNPCKLQDQMemorySource(t *testing.T) {
	dst := [2]uint64{0x0123456789abcdef, 0xfedcba9876543210}
	src := [2]uint64{0x1122334455667788, 0x8877665544332211}
	unpackLowQWords(&dst, &src)
	want := [2]uint64{0x0123456789abcdef, 0x1122334455667788}
	if dst != want {
		t.Fatalf("unpackLowQWords() = %#x, want %#x", dst, want)
	}
}

func TestByteMemoryFlags(t *testing.T) {
	values := [4]byte{0xff, 0xff, 0x7f, 0}
	var got [8]byte
	byteFlags(&values, &got)
	wantValues := [4]byte{0, 0, 0, 0x80}
	wantFlags := [8]byte{1, 1, 0, 1, 0, 1, 0, 1}
	if values != wantValues {
		t.Fatalf("byteFlags values = %#v, want %#v", values, wantValues)
	}
	if got != wantFlags {
		t.Fatalf("byteFlags flags = %#v, want %#v", got, wantFlags)
	}
}

func TestPUNPCKLQDQRegisterSource(t *testing.T) {
	got := [2]uint64{0x0123456789abcdef, 0xfedcba9876543210}
	unpackDuplicateLowQWord(&got)
	want := [2]uint64{0x0123456789abcdef, 0x0123456789abcdef}
	if got != want {
		t.Fatalf("unpackDuplicateLowQWord() = %#x, want %#x", got, want)
	}
}

func TestLegacyThreeOperandShift(t *testing.T) {
	if got, want := shiftLegacyThreeOperand(0x12345678, 0x89abcdef, 5), uint32(0x3579bde2); got != want {
		t.Fatalf("shiftLegacyThreeOperand() = %#x, want %#x", got, want)
	}
}

func TestBTRQClearTopBit(t *testing.T) {
	for _, tc := range []struct {
		in   uint64
		want uint64
	}{
		{in: ^uint64(0), want: 0x7fffffffffffffff},
		{in: 0x0123456789abcdef, want: 0x0123456789abcdef},
	} {
		if got := clearTopBit(tc.in); got != tc.want {
			t.Fatalf("clearTopBit(%#x) = %#x, want %#x", tc.in, got, tc.want)
		}
	}
}

func TestDoubleShiftFamily(t *testing.T) {
	pairs32 := [][2]uint32{
		{0x12345678, 0x89abcdef},
		{0, ^uint32(0)},
		{^uint32(0), 0},
		{0x80000001, 0x7ffffffe},
	}
	for _, pair := range pairs32 {
		src, dst := pair[0], pair[1]
		for count := uint32(0); count < 128; count++ {
			var got [8]uint32
			doubleShift32(&got, src, dst, count)
			want := [8]uint32{
				shld32(src, dst, count), shld32(src, dst, 7),
				shld32(src, dst, count), shld32(src, dst, 7),
				shrd32(src, dst, count), shrd32(src, dst, 7),
				shrd32(src, dst, count), shrd32(src, dst, 7),
			}
			if got != want {
				t.Fatalf("doubleShift32(%#x, %#x, %d) = %#x, want %#x", src, dst, count, got, want)
			}
		}
	}

	pairs64 := [][2]uint64{
		{0x0123456789abcdef, 0xfedcba9876543210},
		{0, ^uint64(0)},
		{^uint64(0), 0},
		{0x8000000000000001, 0x7ffffffffffffffe},
	}
	for _, pair := range pairs64 {
		src, dst := pair[0], pair[1]
		for count := uint64(0); count < 256; count++ {
			var got [8]uint64
			doubleShift64(&got, src, dst, count)
			want := [8]uint64{
				shld64(src, dst, count), shld64(src, dst, 7),
				shld64(src, dst, count), shld64(src, dst, 7),
				shrd64(src, dst, count), shrd64(src, dst, 7),
				shrd64(src, dst, count), shrd64(src, dst, 7),
			}
			if got != want {
				t.Fatalf("doubleShift64(%#x, %#x, %d) = %#x, want %#x", src, dst, count, got, want)
			}
		}
	}
}

func TestGoHexInstructionFamilies(t *testing.T) {
	a := [16]byte{}
	b := [16]byte{}
	for i := range a {
		a[i] = byte(i*29 + 3)
		b[i] = byte(i*17 + 0x70)
	}
	var got [160]byte
	goHexVectorOps(&got, &a, &b)
	mask := [16]byte{0x80, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0xff, 0x00, 0x55, 0xaa, 0x0f, 0xf0, 0x33, 0xcc}
	var want [160]byte
	for i := 0; i < 16; i++ {
		want[i] = a[i] | mask[i]
		want[16+i] = a[i] | b[i]
		if int8(a[i]) > int8(b[i]) {
			want[32+i] = 0xff
			want[48+i] = 0xff
		}
		want[64+i] = a[i] - b[i]
		want[144+i] = a[i] & b[i]
	}
	for i := 0; i < 8; i++ {
		word := uint16(a[2*i]) | uint16(a[2*i+1])<<8
		left := word << 4
		right := word >> 4
		want[80+2*i] = byte(left)
		want[80+2*i+1] = byte(left >> 8)
		want[96+2*i] = byte(right)
		want[96+2*i+1] = byte(right >> 8)
		want[112+2*i] = a[8+i]
		want[112+2*i+1] = b[8+i]
		want[128+2*i] = a[8+i]
		want[128+2*i+1] = b[8+i]
	}
	if got != want {
		t.Fatalf("goHexVectorOps() = %#v, want %#v", got, want)
	}

	for _, tc := range []struct {
		value uint64
		count uint64
	}{
		{0x123456789abcdef0, 0},
		{0x123456789abcdef0, 4},
		{0xfedcba9876543210, 12},
	} {
		shifted := uint16(tc.value) >> (tc.count & 31)
		var first uint64
		for ((shifted >> first) & 1) == 0 {
			first++
		}
		want := tc.value&^0xffff | uint64(shifted) | first<<16
		if got := goHexWordOps(tc.value, tc.count); got != want {
			t.Fatalf("goHexWordOps(%#x, %d) = %#x, want %#x", tc.value, tc.count, got, want)
		}
	}
}

func TestPackedArithmeticShiftCountSaturation(t *testing.T) {
	src := [4]int32{0, 1, -1, -1 << 31}
	var got [8]int32
	packedArithmeticShift32(&got, &src)
	want := [8]int32{0, 0, -1, -1, 0, 0, -1, -1}
	if got != want {
		t.Fatalf("packedArithmeticShift32() = %#v, want %#v", got, want)
	}
}

func runConformanceOracleLines() []string {
	var lines []string

	bytes := [4]byte{0x10, 0xf0, 0x5a, 0xa0}
	byteMemory(&bytes, 0x0f)
	lines = append(lines, fmt.Sprintf("byte_memory[0]=%02x%02x%02x%02x", bytes[0], bytes[1], bytes[2], bytes[3]))

	flagValues := [4]byte{0xff, 0xff, 0x7f, 0}
	var flags [8]byte
	byteFlags(&flagValues, &flags)
	lines = append(lines, fmt.Sprintf("byte_flags[0]=%x|%x", flagValues, flags))

	dst := [2]uint64{0x0123456789abcdef, 0xfedcba9876543210}
	src := [2]uint64{0x1122334455667788, 0x8877665544332211}
	unpackLowQWords(&dst, &src)
	lines = append(lines, fmt.Sprintf("punpck_mem[0]=%016x,%016x", dst[0], dst[1]))

	dup := [2]uint64{0x0123456789abcdef, 0xfedcba9876543210}
	unpackDuplicateLowQWord(&dup)
	lines = append(lines, fmt.Sprintf("punpck_reg[0]=%016x,%016x", dup[0], dup[1]))

	lines = append(lines, fmt.Sprintf("legacy_shll[0]=%08x", shiftLegacyThreeOperand(0x12345678, 0x89abcdef, 5)))

	for i, in := range []uint64{^uint64(0), 0x0123456789abcdef} {
		lines = append(lines, fmt.Sprintf("btrq[%d]=%016x", i, clearTopBit(in)))
	}

	pairs32 := [][2]uint32{
		{0x12345678, 0x89abcdef},
		{0, ^uint32(0)},
		{^uint32(0), 0},
		{0x80000001, 0x7ffffffe},
	}
	idx32 := 0
	for _, pair := range pairs32 {
		for count := uint32(0); count < 128; count++ {
			var out [8]uint32
			doubleShift32(&out, pair[0], pair[1], count)
			lines = append(lines, fmt.Sprintf("dshift32[%d]=%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x",
				idx32, out[0], out[1], out[2], out[3], out[4], out[5], out[6], out[7]))
			idx32++
		}
	}

	pairs64 := [][2]uint64{
		{0x0123456789abcdef, 0xfedcba9876543210},
		{0, ^uint64(0)},
		{^uint64(0), 0},
		{0x8000000000000001, 0x7ffffffffffffffe},
	}
	idx64 := 0
	for _, pair := range pairs64 {
		for count := uint64(0); count < 256; count++ {
			var out [8]uint64
			doubleShift64(&out, pair[0], pair[1], count)
			lines = append(lines, fmt.Sprintf("dshift64[%d]=%016x,%016x,%016x,%016x,%016x,%016x,%016x,%016x",
				idx64, out[0], out[1], out[2], out[3], out[4], out[5], out[6], out[7]))
			idx64++
		}
	}

	var a, b [16]byte
	for i := range a {
		a[i] = byte(i*29 + 3)
		b[i] = byte(i*17 + 0x70)
	}
	var vecOut [160]byte
	goHexVectorOps(&vecOut, &a, &b)
	lines = append(lines, fmt.Sprintf("gohex_vec[0]=%x", vecOut))

	wordInputs := [][2]uint64{
		{0x123456789abcdef0, 0},
		{0x123456789abcdef0, 4},
		{0xfedcba9876543210, 12},
	}
	for i, tc := range wordInputs {
		lines = append(lines, fmt.Sprintf("gohex_word[%d]=%016x", i, goHexWordOps(tc[0], tc[1])))
	}

	psrc := [4]int32{0, 1, -1, -1 << 31}
	var pout [8]int32
	packedArithmeticShift32(&pout, &psrc)
	lines = append(lines, fmt.Sprintf("psral[0]=%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x",
		uint32(pout[0]), uint32(pout[1]), uint32(pout[2]), uint32(pout[3]),
		uint32(pout[4]), uint32(pout[5]), uint32(pout[6]), uint32(pout[7])))

	return lines
}

func TestAMD64ConformanceDumpOracle(t *testing.T) {
	outPath := os.Getenv("PLAN9ASM_CONFORMANCE_ORACLE_OUT")
	if outPath == "" {
		return
	}
	lines := runConformanceOracleLines()
	var b strings.Builder
	for _, line := range lines {
		b.WriteString(line)
		b.WriteByte('\n')
	}
	if err := os.WriteFile(outPath, []byte(b.String()), 0o600); err != nil {
		t.Fatalf("write conformance oracle output %s: %v", outPath, err)
	}
}

func shld32(src, dst, count uint32) uint32 {
	count &= 31
	if count == 0 {
		return dst
	}
	return dst<<count | src>>(32-count)
}

func shrd32(src, dst, count uint32) uint32 {
	count &= 31
	if count == 0 {
		return dst
	}
	return dst>>count | src<<(32-count)
}

func shld64(src, dst, count uint64) uint64 {
	count &= 63
	if count == 0 {
		return dst
	}
	return dst<<count | src>>(64-count)
}

func shrd64(src, dst, count uint64) uint64 {
	count &= 63
	if count == 0 {
		return dst
	}
	return dst>>count | src<<(64-count)
}
