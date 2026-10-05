//go:build arm64

package arm64conformance

import (
	"math/bits"
	"testing"
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

func TestPairStores(t *testing.T) {
	data := [8]uint64{0x0123456789abcdef, 0xfedcba9876543210, 0x1122334455667788, 0x8877665544332211}
	var got, want [20]uint64
	for i := range got {
		got[i], want[i] = 0xdeadbeef, 0xdeadbeef
	}
	want[0], want[1], want[6] = 0, 32, ^uint64(31)
	copy(want[2:6], data[:4])
	copy(want[8:10], data[2:4])
	copy(want[10:12], data[:2])
	copy(want[16:20], data[:4])
	for i := range pairStoreData {
		pairStoreData[i] = 0xdeadbeef
	}
	pairStores(&got, &data)
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("pairStores()[%d] = %#x, want %#x", i, got[i], want[i])
		}
	}
}

func TestPairStoreSymbols(t *testing.T) {
	data := [8]uint64{0x0123456789abcdef, 0xfedcba9876543210, 0x1122334455667788, 0x8877665544332211}
	var out [20]uint64
	for i := range pairStoreData {
		pairStoreData[i] = 0xdeadbeef
	}
	pairStores(&out, &data)
	want := [10]uint64{data[0], data[1], data[2], data[3], 0xdeadbeef, data[2], data[3], data[0], data[1], 0xdeadbeef}
	if pairStoreData != want {
		t.Fatalf("pairStoreData = %#x, want %#x", pairStoreData, want)
	}
}
