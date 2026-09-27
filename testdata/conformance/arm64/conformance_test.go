//go:build arm64

package arm64conformance

import (
	"encoding/binary"
	"math"
	"math/bits"
	"testing"
	"unsafe"
)

func TestFamilies(t *testing.T) {
	data := [8]uint64{0x0123456789abcdef, 0xfedcba9876543210, 0x1122334455667788, 0x8877665544332211}
	var got [76]uint64
	families(&got, &data)
	want := familyOracle(data)
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("families()[%d] = %#x, want %#x", i, got[i], want[i])
		}
	}
}

func TestScalarFloatSquareRoots(t *testing.T) {
	var got [16]byte
	scalarFloatSquareRoots(&got)
	if value := math.Float32frombits(binary.LittleEndian.Uint32(got[0:4])); value != 2 {
		t.Fatalf("FSQRTS/FMOVS result = %v, want 2", value)
	}
	if value := math.Float32frombits(binary.LittleEndian.Uint32(got[4:8])); value != 2 {
		t.Fatalf("FMOVS F<->R result = %v, want 2", value)
	}
	if value := math.Float64frombits(binary.LittleEndian.Uint64(got[8:16])); value != 4 {
		t.Fatalf("FSQRTD/FMOVD result = %v, want 4", value)
	}
}

func TestFusedMultiplyAddSemantics(t *testing.T) {
	var got [48]byte
	fusedMultiplyAddSemantics(&got)
	want32 := [...]float32{11, -1, -11, 1}
	for i, want := range want32 {
		value := math.Float32frombits(binary.LittleEndian.Uint32(got[i*4 : i*4+4]))
		if value != want {
			t.Fatalf("fusedMultiplyAddSemantics() float32[%d] = %v, want %v", i, value, want)
		}
	}
	want64 := [...]float64{11, -1, -11, 1}
	for i, want := range want64 {
		value := math.Float64frombits(binary.LittleEndian.Uint64(got[16+i*8 : 24+i*8]))
		if value != want {
			t.Fatalf("fusedMultiplyAddSemantics() float64[%d] = %v, want %v", i, value, want)
		}
	}
}

func TestVectorPermuteSemantics(t *testing.T) {
	var n, m [16]byte
	for i := range n {
		n[i] = byte(i)
		m[i] = byte(0x80 + i)
	}
	var got [96]byte
	vectorPermuteSemantics(&got, &n, &m)
	want := vectorPermuteOracle(n, m)
	if got != want {
		t.Fatalf("vectorPermuteSemantics() = %#v, want %#v", got, want)
	}
}

func vectorPermuteOracle(n, m [16]byte) (out [96]byte) {
	for i := 0; i < 8; i++ {
		out[2*i], out[2*i+1] = n[i], m[i]
		out[16+2*i], out[16+2*i+1] = n[8+i], m[8+i]
		out[32+i], out[32+8+i] = n[2*i], m[2*i]
		out[48+i], out[48+8+i] = n[2*i+1], m[2*i+1]
		out[64+2*i], out[64+2*i+1] = n[2*i], m[2*i]
		out[80+2*i], out[80+2*i+1] = n[2*i+1], m[2*i+1]
	}
	return out
}

func TestVectorWideningShiftSemantics(t *testing.T) {
	source := [16]byte{0, 1, 0x7f, 0x80, 0xff, 2, 0x55, 0xaa, 3, 4, 0x40, 0xc0, 0xfe, 0x81, 0x11, 0xee}
	var got [128]byte
	vectorWideningShiftSemantics(&got, &source)
	want := vectorWideningShiftOracle(source)
	if got != want {
		t.Fatalf("vectorWideningShiftSemantics() = %#v, want %#v", got, want)
	}
}

func vectorWideningShiftOracle(source [16]byte) (out [128]byte) {
	for lane := 0; lane < 8; lane++ {
		low, high := uint16(source[lane]), uint16(source[8+lane])
		signedLow, signedHigh := uint16(int16(int8(source[lane]))), uint16(int16(int8(source[8+lane])))
		values := [...]uint16{
			low, high, signedLow, signedHigh,
			low << 7, high << 1, signedLow << 3, signedHigh << 2,
		}
		for group, value := range values {
			binary.LittleEndian.PutUint16(out[group*16+lane*2:], value)
		}
	}
	return out
}

func TestScalarExtendSemantics(t *testing.T) {
	value := uint64(0x88776655fedcba98)
	var got [10]uint64
	scalarExtendSemantics(&got, value)
	want := [10]uint64{
		uint64(int64(int8(value))),
		uint64(uint32(int32(int8(value)))),
		uint64(int64(int16(value))),
		uint64(uint32(int32(int16(value)))),
		uint64(int64(int32(value))),
		uint64(uint8(value)),
		uint64(uint32(uint8(value))),
		uint64(uint16(value)),
		uint64(uint32(uint16(value))),
		uint64(uint32(value)),
	}
	if got != want {
		t.Fatalf("scalarExtendSemantics() = %#v, want %#v", got, want)
	}
}

func TestVectorCountBitsSemantics(t *testing.T) {
	source := [16]byte{0, 1, 2, 3, 7, 15, 31, 63, 127, 128, 129, 0xaa, 0x55, 0xfe, 0xff, 0x81}
	var got, want [32]byte
	vectorCountBitsSemantics(&got, &source)
	for i, value := range source {
		want[16+i] = byte(bits.OnesCount8(value))
		if i < 8 {
			want[i] = want[16+i]
		}
	}
	if got != want {
		t.Fatalf("vectorCountBitsSemantics() = %#v, want %#v", got, want)
	}
}

func TestUnsignedWideningAddSemantics(t *testing.T) {
	narrow := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 0xf1, 0xe2, 0xd3, 0xc4, 0xb5, 0xa6, 0x97, 0x88}
	addend := [16]byte{0xff, 0x00, 0xfe, 0xff, 0x78, 0x56, 0x34, 0x12, 0xf0, 0xde, 0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12}
	var got, want [96]byte
	unsignedWideningAddSemantics(&got, &narrow, &addend)
	for group, narrowBytes := range []int{1, 2, 4, 1, 2, 4} {
		wideBytes := narrowBytes * 2
		lanes := 16 / wideBytes
		sourceOffset := 0
		if group >= 3 {
			sourceOffset = 8
		}
		for lane := 0; lane < lanes; lane++ {
			narrowValue := readLittleEndianWidth(narrow[sourceOffset+lane*narrowBytes:], narrowBytes)
			addendValue := readLittleEndianWidth(addend[lane*wideBytes:], wideBytes)
			writeLittleEndianWidth(want[group*16+lane*wideBytes:], wideBytes, addendValue+narrowValue)
		}
	}
	if got != want {
		t.Fatalf("unsignedWideningAddSemantics() = %#v, want %#v", got, want)
	}
}

func readLittleEndianWidth(data []byte, width int) uint64 {
	switch width {
	case 1:
		return uint64(data[0])
	case 2:
		return uint64(binary.LittleEndian.Uint16(data))
	case 4:
		return uint64(binary.LittleEndian.Uint32(data))
	case 8:
		return binary.LittleEndian.Uint64(data)
	default:
		panic("invalid integer width")
	}
}

func writeLittleEndianWidth(data []byte, width int, value uint64) {
	switch width {
	case 2:
		binary.LittleEndian.PutUint16(data, uint16(value))
	case 4:
		binary.LittleEndian.PutUint32(data, uint32(value))
	case 8:
		binary.LittleEndian.PutUint64(data, value)
	default:
		panic("invalid integer width")
	}
}

func TestPairedAtomicSemantics(t *testing.T) {
	var storage [11]uint64
	start := 0
	if uintptr(unsafe.Pointer(&storage[0]))%16 != 0 {
		start = 1
	}
	data := (*[9]uint64)(unsafe.Pointer(&storage[start]))
	*data = [9]uint64{
		0x11, 0x22,
		0x33, 0x44,
		0x0000002200000011,
		0x0000004400000033,
		0x55, 0x66,
		0x0000008800000077,
	}
	var got [23]uint64
	pairedAtomicSemantics(&got, data)
	want := [23]uint64{
		0x11, 0x22, 0xaa, 0xbb,
		0x33, 0x44, 0x33, 0x44,
		0x11, 0x22, 0x000000bb000000aa,
		0x33, 0x44, 0x0000004400000033,
		0x55, 0x66, 0, 0xcc, 0xdd,
		0x77, 0x88, 1, 0x000000aa00000099,
	}
	if got != want {
		t.Fatalf("pairedAtomicSemantics() = %#v, want %#v", got, want)
	}
}

func familyOracle(data [8]uint64) (out [76]uint64) {
	src, dst := data[0], data[1]
	out[0] = insert(dst, src, 8, 16, 0)
	out[1] = uint64(uint32(insert(uint64(uint32(dst)), uint64(uint32(src)), 4, 8, 0)))
	out[2] = insert(dst, src, 0, 20, 12)
	out[3] = uint64(uint32(insert(uint64(uint32(dst)), uint64(uint32(src)), 0, 12, 12)))
	out[4] = uint64(int64(int16(src)) << 8)
	out[5] = uint64(uint32(int32(signExtend(src&mask(12), 12)) << 4))
	out[6] = uint64(signExtend((src>>12)&mask(20), 20))
	out[7] = uint64(uint32(signExtend((src>>12)&mask(12), 12)))
	out[8] = (src & mask(16)) << 8
	out[9] = uint64(uint32((src & mask(12)) << 4))
	out[10] = (src >> 12) & mask(20)
	out[11] = (src >> 12) & mask(12)
	out[12], out[13], out[14], out[15] = 5, 5, 10, 10
	out[16], out[17], out[18], out[19] = ^uint64(9), uint64(^uint32(9)), ^uint64(8), uint64(^uint32(8))
	out[20], out[21], out[22], out[23] = 1, 1, ^uint64(0), uint64(^uint32(0))
	out[24], out[25], out[26], out[27] = 6, 6, ^uint64(5), uint64(^uint32(5))
	out[28], out[29] = ^uint64(4), uint64(^uint32(4))
	out[30] = bits.ReverseBytes64(src)
	out[31] = uint64(bits.ReverseBytes32(uint32(src)))
	out[32] = reverse16(src)
	out[33] = uint64(uint32(reverse16(uint64(uint32(src)))))
	out[34] = uint64(bits.ReverseBytes32(uint32(src>>32)))<<32 | uint64(bits.ReverseBytes32(uint32(src)))
	out[35] = uint64(int64(src) >> 8)
	out[36] = uint64(uint32(int32(src) >> 8))
	out[37] = src << 8
	out[38] = uint64(uint32(src) << 8)
	out[39] = src >> 8
	out[40] = uint64(uint32(src) >> 8)
	out[41] = bits.RotateLeft64(src, -8)
	out[42] = uint64(bits.RotateLeft32(uint32(src), -8))
	out[43] = uint64(int64(src) >> 12)
	out[44] = uint64(uint32(int32(src) >> 12))
	out[45] = src << 12
	out[46] = uint64(uint32(src) << 12)
	out[47] = src >> 12
	out[48] = uint64(uint32(src) >> 12)
	out[49] = bits.RotateLeft64(src, -12)
	out[50] = uint64(bits.RotateLeft32(uint32(src), -12))
	out[51] = src - 24
	out[52] = uint64(uint32(src) - 24)
	out[53] = bool64(src&(12<<4) == 0)
	out[54] = bool64(uint32(src)&uint32(int32(12)>>3) == 0)
	out[55] = uint64(int64(int16(src >> 16)))
	out[56] = uint64(uint16(src >> 16))
	out[57] = uint64(int64(int32(src >> 32)))
	out[58] = uint64(uint32(src >> 32))
	out[59] = uint64(int64(int8(src)))
	out[60] = uint64(uint8(src))
	out[61], out[62] = data[0], data[1]
	out[63], out[64] = data[0], data[1]
	out[65], out[66] = data[2], data[3]
	out[67] = 0xffffffff89abcdef
	out[68], out[69], out[70], out[71] = 1, 1, 1, 1
	out[72] = 0x0000000089abcdef
	out[73] = data[0]
	out[74], out[75] = 0x1234, 0
	return out
}

func mask(width uint) uint64 { return uint64(1)<<width - 1 }

func insert(dst, src uint64, dstLSB, width, srcLSB uint) uint64 {
	field := mask(width) << dstLSB
	return dst&^field | ((src>>srcLSB)&mask(width))<<dstLSB
}

func signExtend(value uint64, width uint) int64 {
	shift := 64 - width
	return int64(value<<shift) >> shift
}

func reverse16(value uint64) uint64 {
	return (value&0x00ff00ff00ff00ff)<<8 | (value&0xff00ff00ff00ff00)>>8
}

func bool64(value bool) uint64 {
	if value {
		return 1
	}
	return 0
}
