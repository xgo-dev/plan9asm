//go:build amd64

package amd64conformance

import (
	"encoding/binary"
	"math"
	"os"
	"testing"
	"unsafe"
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

func rotateLeft(value uint64, bits uint, count uint64) uint64 {
	mask := uint64(1)<<bits - 1
	count %= uint64(bits)
	value &= mask
	if count == 0 {
		return value
	}
	return ((value << count) | (value >> (uint64(bits) - count))) & mask
}

func rotateRight(value uint64, bits uint, count uint64) uint64 {
	return rotateLeft(value, bits, uint64(bits)-count%uint64(bits))
}

func replaceLow(value, low uint64, bits uint) uint64 {
	mask := uint64(1)<<bits - 1
	return value&^mask | low&mask
}

func TestScalarShiftRotateSemantics(t *testing.T) {
	value := uint64(0x8123456789abcdef)
	wordDst := uint64(0xfedcba9876543210)
	for count := uint64(0); count < 16; count++ {
		var got [14]uint64
		scalarShiftRotateSemantics(&got, value, count)
		hardwareCount := count & 31
		byteLogical := uint64(0)
		byteArithmetic := uint64(0xff)
		if hardwareCount < 8 {
			byteLogical = uint64(byte(value)) >> hardwareCount
			byteArithmetic = uint64(byte(int8(value) >> hardwareCount))
		}
		wordCount := count & 15
		shldw := uint64(uint16(wordDst))
		shrdw := uint64(uint16(wordDst))
		if wordCount != 0 {
			shldw = uint64(uint16(wordDst)<<wordCount | uint16(value)>>(16-wordCount))
			shrdw = uint64(uint16(wordDst)>>wordCount | uint16(value)<<(16-wordCount))
		}
		want := [14]uint64{
			replaceLow(value, rotateLeft(value, 8, count), 8),
			replaceLow(value, rotateRight(value, 8, count), 8),
			replaceLow(value, byteArithmetic, 8),
			replaceLow(value, byteLogical, 8),
			replaceLow(value, rotateLeft(value, 16, count), 16),
			replaceLow(value, uint64(uint16(int16(value)>>hardwareCount)), 16),
			uint64(uint32(value) << hardwareCount),
			rotateRight(value, 64, count),
			replaceLow(value, byteLogical, 8),
			replaceLow(value, rotateLeft(value, 16, count), 16),
			replaceLow(wordDst, shldw, 16),
			replaceLow(wordDst, shrdw, 16),
			replaceLow(value, uint64(byte(value)<<3), 8),
			uint64(uint32(int32(value) >> 3)),
		}
		if got != want {
			t.Fatalf("scalarShiftRotateSemantics(%#x, %d) = %#x, want %#x", value, count, got, want)
		}
	}
}

func TestIncDecSemantics(t *testing.T) {
	for _, value := range []uint64{0, 1, 0x7f, 0xff, 0xffff, 0xffffffff, 0x8123456789abcdef} {
		var got [12]uint64
		incDecSemantics(&got, value)
		want := [12]uint64{
			replaceLow(value, uint64(byte(value)+1), 8),
			replaceLow(value, uint64(byte(value)-1), 8),
			replaceLow(value, uint64(uint16(value)+1), 16),
			replaceLow(value, uint64(uint16(value)-1), 16),
			uint64(uint32(value) + 1),
			uint64(uint32(value) - 1),
			value + 1,
			value - 1,
			replaceLow(value, uint64(byte(value)+1), 8),
			replaceLow(value, uint64(uint16(value)-1), 16),
			0x0000000000010101,
			0x0000000101000001,
		}
		if got != want {
			t.Fatalf("incDecSemantics(%#x) = %#x, want %#x", value, got, want)
		}
	}
}

func referenceScalarAddSub(add bool, bits uint, value, source uint64, registerDestination bool) (uint64, uint64) {
	mask := ^uint64(0)
	if bits != 64 {
		mask = uint64(1)<<bits - 1
	}
	destinationLow := value & mask
	sourceLow := source & mask
	var resultLow uint64
	var carry, overflow bool
	if add {
		resultLow = (destinationLow + sourceLow) & mask
		carry = resultLow < destinationLow
		overflow = (^(destinationLow ^ sourceLow) & (destinationLow ^ resultLow) & (uint64(1) << (bits - 1))) != 0
	} else {
		resultLow = (destinationLow - sourceLow) & mask
		carry = destinationLow < sourceLow
		overflow = ((destinationLow ^ sourceLow) & (destinationLow ^ resultLow) & (uint64(1) << (bits - 1))) != 0
	}
	result := resultLow
	if bits < 64 && !(registerDestination && bits == 32) {
		result = value&^mask | resultLow
	}
	parity := byte(1)
	for low := byte(resultLow); low != 0; low &= low - 1 {
		parity ^= 1
	}
	flag := func(value bool) uint64 {
		if value {
			return 1
		}
		return 0
	}
	flags := flag(carry) |
		flag(overflow)<<8 |
		flag(resultLow == 0)<<16 |
		flag(resultLow&(uint64(1)<<(bits-1)) != 0)<<24 |
		uint64(parity)<<32
	return result, flags
}

func TestScalarAddSubSemantics(t *testing.T) {
	for _, tc := range []struct {
		value  uint64
		source uint64
	}{
		{0, 0},
		{^uint64(0), 1},
		{0x7f, 1},
		{0x7fff, 1},
		{0x7fffffff, 1},
		{0x7fffffffffffffff, 1},
		{0x8123456789abcdef, 0xfedcba9876543210},
	} {
		var got, want [16]uint64
		scalarAddSubSemantics(&got, tc.value, tc.source)
		for widthIndex, bits := range []uint{8, 16, 32, 64} {
			want[widthIndex*4], want[widthIndex*4+1] = referenceScalarAddSub(true, bits, tc.value, tc.source, true)
			want[widthIndex*4+2], want[widthIndex*4+3] = referenceScalarAddSub(false, bits, tc.value, ^uint64(0), false)
		}
		if got != want {
			t.Fatalf("scalarAddSubSemantics(%#x, %#x) = %#x, want %#x", tc.value, tc.source, got, want)
		}
	}
}

func TestCompareExchangeScalarSemantics(t *testing.T) {
	const desired = uint64(0xfedcba9876543210)
	for _, expected := range []uint64{0, ^uint64(0), 0x7f, 0x7fff, 0x7fffffff, 0x7fffffffffffffff, 0x8123456789abcdef} {
		var memory [8]uint64
		for widthIndex, bits := range []uint{8, 16, 32, 64} {
			mask := ^uint64(0)
			if bits != 64 {
				mask = uint64(1)<<bits - 1
			}
			base := uint64(0xa5a5a5a5a5a5a5a5) &^ mask
			memory[widthIndex*2] = base | expected&mask
			memory[widthIndex*2+1] = base | (expected^(uint64(1)<<(bits-1)))&mask
		}
		initial := memory
		var got, want [24]uint64
		compareExchangeScalarSemantics(&got, &memory, expected, desired)
		for widthIndex, bits := range []uint{8, 16, 32, 64} {
			mask := ^uint64(0)
			if bits != 64 {
				mask = uint64(1)<<bits - 1
			}
			successInitial := initial[widthIndex*2]
			failureInitial := initial[widthIndex*2+1]
			outputIndex := widthIndex * 6
			want[outputIndex] = successInitial&^mask | desired&mask
			want[outputIndex+1] = expected
			_, want[outputIndex+2] = referenceScalarAddSub(false, bits, successInitial, expected, true)
			want[outputIndex+3] = failureInitial
			switch bits {
			case 8, 16:
				want[outputIndex+4] = expected&^mask | failureInitial&mask
			case 32:
				want[outputIndex+4] = uint64(uint32(failureInitial))
			case 64:
				want[outputIndex+4] = failureInitial
			}
			_, want[outputIndex+5] = referenceScalarAddSub(false, bits, expected, failureInitial, true)
		}
		if os.Getenv("PLAN9ASM_ROSETTA") == "1" {
			// Rosetta 2 does not preserve CMPXCHG's architecturally defined CF
			// and OF results, and clears RAX's high half after a successful
			// CMPXCHGL even though EAX is not written. Keep the native oracle for
			// every other result; the LLVM runtime oracle verifies these details.
			const rosettaUnreliableFlags = uint64(1) | uint64(1)<<8
			for widthIndex := 0; widthIndex < 4; widthIndex++ {
				got[widthIndex*6+2] &^= rosettaUnreliableFlags
				got[widthIndex*6+5] &^= rosettaUnreliableFlags
				want[widthIndex*6+2] &^= rosettaUnreliableFlags
				want[widthIndex*6+5] &^= rosettaUnreliableFlags
			}
			const cmpxchg32SuccessAccumulator = 2*6 + 1
			got[cmpxchg32SuccessAccumulator] = uint64(uint32(got[cmpxchg32SuccessAccumulator]))
			want[cmpxchg32SuccessAccumulator] = uint64(uint32(want[cmpxchg32SuccessAccumulator]))
		}
		if got != want {
			t.Fatalf("compareExchangeScalarSemantics(%#x, %#x) = %#x, want %#x", expected, desired, got, want)
		}
	}
}

func TestCompareExchangePairSemantics(t *testing.T) {
	const (
		expectedLow  = uint64(0xaaaaaaaa11223344)
		expectedHigh = uint64(0xbbbbbbbb55667788)
		desiredLow   = uint64(0x0123456789abcdef)
		desiredHigh  = uint64(0xfedcba9876543210)
	)
	for _, success := range []bool{true, false} {
		storage := new([6]uint64)
		base := uintptr(unsafe.Pointer(&storage[0]))
		aligned := (base + 15) &^ uintptr(15)
		memory := (*uint64)(unsafe.Pointer(aligned))
		view := unsafe.Slice(memory, 4)
		if success {
			view[0], view[1] = expectedLow, expectedHigh
			view[2] = expectedLow&0xffffffff | (expectedHigh&0xffffffff)<<32
		} else {
			view[0], view[1] = 0x1020304050607080, 0x90a0b0c0d0e0f001
			view[2] = 0x8877665544332211
		}
		old16Low, old16High, old8 := view[0], view[1], view[2]
		var got, want [9]uint64
		compareExchangePairSemantics(&got, memory, expectedLow, expectedHigh, desiredLow, desiredHigh)
		if success {
			want = [9]uint64{
				desiredLow&0xffffffff | (desiredHigh&0xffffffff)<<32,
				expectedLow, expectedHigh, 1,
				desiredLow, desiredHigh, expectedLow, expectedHigh, 1,
			}
		} else {
			want = [9]uint64{
				old8, uint64(uint32(old8)), uint64(uint32(old8 >> 32)), 0,
				old16Low, old16High, old16Low, old16High, 0,
			}
		}
		if got != want {
			t.Fatalf("compareExchangePairSemantics(success=%v) = %#x, want %#x", success, got, want)
		}
	}
}

func referencePDEP(mask, source uint64) uint64 {
	var result uint64
	for mask != 0 {
		lowest := mask & -mask
		if source&1 != 0 {
			result |= lowest
		}
		source >>= 1
		mask &= mask - 1
	}
	return result
}

func referencePEXT(mask, source uint64) uint64 {
	var result, outputBit uint64 = 0, 1
	for mask != 0 {
		lowest := mask & -mask
		if source&lowest != 0 {
			result |= outputBit
		}
		outputBit <<= 1
		mask &= mask - 1
	}
	return result
}

func TestParallelBitDepositExtractSemantics(t *testing.T) {
	for _, tc := range []struct {
		mask   uint64
		source uint64
	}{
		{0, 0x0123456789abcdef},
		{^uint64(0), 0x0123456789abcdef},
		{0xaaaaaaaaaaaaaaaa, 0x0123456789abcdef},
		{0x8040201008040201, 0xfedcba9876543210},
		{0x8000000100000081, ^uint64(0)},
	} {
		var got [8]uint64
		parallelBitSemantics(&got, tc.mask, tc.source)
		mask32, source32 := uint64(uint32(tc.mask)), uint64(uint32(tc.source))
		want := [8]uint64{
			referencePDEP(tc.mask, tc.source), referencePDEP(tc.mask, tc.source),
			referencePEXT(tc.mask, tc.source), referencePEXT(tc.mask, tc.source),
			referencePDEP(mask32, source32), referencePDEP(mask32, source32),
			referencePEXT(mask32, source32), referencePEXT(mask32, source32),
		}
		if got != want {
			t.Fatalf("parallelBitSemantics(%#x, %#x) = %#x, want %#x", tc.mask, tc.source, got, want)
		}
	}
}

func referenceBitTestRegister(stem string, bits int, value, index uint64) (result, carry uint64) {
	bit := index & uint64(bits-1)
	carry = (value >> bit) & 1
	if stem == "BT" {
		return value, carry
	}
	mask := uint64(1) << bit
	low := value
	switch stem {
	case "BTC":
		low ^= mask
	case "BTR":
		low &^= mask
	case "BTS":
		low |= mask
	}
	switch bits {
	case 16:
		return value&^uint64(0xffff) | low&0xffff, carry
	case 32:
		return uint64(uint32(low)), carry
	default:
		return low, carry
	}
}

func TestBitTestRegisterSemantics(t *testing.T) {
	const value = uint64(0xfedcba9876543210)
	const index = uint64(21)
	var got, want [24]uint64
	bitWidths := []int{16, 32, 64}
	stems := []string{"BT", "BTC", "BTR", "BTS"}
	for widthIndex, bits := range bitWidths {
		for stemIndex, stem := range stems {
			operandIndex := index
			switch stem {
			case "BT":
				operandIndex = uint64(bits - 1)
			case "BTR":
				operandIndex = 4
			}
			result, carry := referenceBitTestRegister(stem, bits, value, operandIndex)
			outIndex := 2 * (widthIndex*len(stems) + stemIndex)
			want[outIndex], want[outIndex+1] = result, carry
		}
	}
	bitTestRegisterSemantics(&got, value, index)
	if got != want {
		t.Fatalf("bitTestRegisterSemantics() = %#x, want %#x", got, want)
	}
}

func TestBitTestMemorySemantics(t *testing.T) {
	data := [9]uint64{
		^uint64(0), uint64(1) << 17, 0,
		^uint64(0), uint64(1) << 33, 0,
		^uint64(0), 0, uint64(1) << 1,
	}
	wantData := data
	wantData[0] &^= uint64(1) << 63
	wantData[1] = 1
	wantData[3] &^= uint64(1) << 63
	wantData[4] = 1
	wantData[6] &^= uint64(1) << 63
	wantData[7] = 1
	wantData[8] = 0
	var got [12]byte
	bitTestMemorySemantics(&got, &data)
	wantCarry := [12]byte{1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0}
	if got != wantCarry {
		t.Fatalf("bitTestMemorySemantics() carry = %#v, want %#v", got, wantCarry)
	}
	if data != wantData {
		t.Fatalf("bitTestMemorySemantics() data = %#x, want %#x", data, wantData)
	}
}

func referencePackedWordMultiplyAdd(a, b []int16) []int32 {
	result := make([]int32, len(a)/2)
	for i := range result {
		sum := int64(a[2*i])*int64(b[2*i]) + int64(a[2*i+1])*int64(b[2*i+1])
		result[i] = int32(uint32(sum))
	}
	return result
}

func TestPackedWordMultiplyAddSemantics(t *testing.T) {
	a := [16]int16{-32768, -32768, -30000, -1, 0, 1, 12345, 32767, 7, -11, 1000, -2000, 22222, -12345, 32767, 32767}
	b := [16]int16{-32768, -32768, -23456, 32767, -1, 32767, -2345, 32767, -9, 13, -3000, 4000, -11111, 23456, 32767, 32767}
	var got, want [18]int32
	first2 := referencePackedWordMultiplyAdd(a[:4], b[:4])
	first4 := referencePackedWordMultiplyAdd(a[:8], b[:8])
	first8 := referencePackedWordMultiplyAdd(a[:], b[:])
	copy(want[0:2], first2)
	copy(want[2:6], first4)
	copy(want[6:10], first4)
	copy(want[10:18], first8)
	packedWordMultiplyAddSemantics(&got, &a, &b)
	if got != want {
		t.Fatalf("packedWordMultiplyAddSemantics() = %v, want %v", got, want)
	}
}

func referencePackedUnsignedSignedByteMultiplyAdd(signed []int8, unsigned []uint8) []int16 {
	result := make([]int16, len(signed)/2)
	for i := range result {
		sum := int32(signed[2*i])*int32(unsigned[2*i]) + int32(signed[2*i+1])*int32(unsigned[2*i+1])
		if sum > 32767 {
			sum = 32767
		} else if sum < -32768 {
			sum = -32768
		}
		result[i] = int16(sum)
	}
	return result
}

func TestPackedUnsignedSignedByteMultiplyAddSemantics(t *testing.T) {
	signed := [32]int8{
		127, 127, -128, -128, 100, -100, 1, -1,
		64, -64, 11, 12, -13, 14, 15, -16,
		31, -32, 33, -34, 35, -36, 37, -38,
		39, -40, 41, -42, 43, -44, 45, -46,
	}
	unsigned := [32]uint8{
		255, 255, 255, 255, 200, 3, 255, 128,
		250, 249, 17, 19, 23, 29, 31, 37,
		41, 43, 47, 53, 59, 61, 67, 71,
		73, 79, 83, 89, 97, 101, 103, 107,
	}
	var got, want [32]int16
	first8 := referencePackedUnsignedSignedByteMultiplyAdd(signed[:16], unsigned[:16])
	first16 := referencePackedUnsignedSignedByteMultiplyAdd(signed[:], unsigned[:])
	copy(want[0:8], first8)
	copy(want[8:16], first8)
	copy(want[16:32], first16)
	packedUnsignedSignedByteMultiplyAddSemantics(&got, &signed, &unsigned)
	if got != want {
		t.Fatalf("packedUnsignedSignedByteMultiplyAddSemantics() = %v, want %v", got, want)
	}
}

func TestInLaneFloatingPermuteSemantics(t *testing.T) {
	dataWords := [8]uint32{0x100, 0x101, 0x102, 0x103, 0x104, 0x105, 0x106, 0x107}
	controlWords := [8]uint32{3, 2, 1, 0, 4, 5, 6, 7}
	var data, control [32]byte
	for i := range dataWords {
		binary.LittleEndian.PutUint32(data[4*i:], dataWords[i])
		binary.LittleEndian.PutUint32(control[4*i:], controlWords[i])
	}
	var got, want [144]byte
	write32 := func(offset int, value uint32) {
		binary.LittleEndian.PutUint32(want[offset:], value)
	}
	for lane := 0; lane < 4; lane++ {
		write32(4*lane, dataWords[3-lane])
	}
	for lane := 0; lane < 8; lane++ {
		write32(16+4*lane, dataWords[lane/4*4+3-lane%4])
		write32(48+4*lane, dataWords[lane/4*4+int(controlWords[lane]&3)])
	}
	dataQWords := [4]uint64{}
	controlQWords := [4]uint64{}
	for lane := 0; lane < 4; lane++ {
		dataQWords[lane] = binary.LittleEndian.Uint64(data[8*lane:])
		controlQWords[lane] = binary.LittleEndian.Uint64(control[8*lane:])
	}
	for lane := 0; lane < 4; lane++ {
		immediateSource := lane/2*2 + int(uint8(0x05)>>uint(lane)&1)
		variableSource := lane/2*2 + int(controlQWords[lane]>>1&1)
		binary.LittleEndian.PutUint64(want[80+8*lane:], dataQWords[immediateSource])
		binary.LittleEndian.PutUint64(want[112+8*lane:], dataQWords[variableSource])
	}
	inLaneFloatingPermuteSemantics(&got, &data, &control)
	if got != want {
		t.Fatalf("inLaneFloatingPermuteSemantics() = %x, want %x", got, want)
	}
}

func TestPackedWordMultiplySemantics(t *testing.T) {
	a := [8]int16{-32768, -32768, -30000, -1, 0, 1, 12345, 32767}
	b := [8]int16{-32768, 32767, -23456, 32767, -1, 32767, -2345, 32767}
	var got, want [64]uint16
	packedWordMultiplySemantics(&got, &a, &b)
	for i := range a {
		product := int32(a[i]) * int32(b[i])
		unsignedProduct := uint32(uint16(a[i])) * uint32(uint16(b[i]))
		rounded := (product + 0x4000) >> 15
		values := [4]uint16{
			uint16(product),
			uint16(product >> 16),
			uint16(unsignedProduct >> 16),
			uint16(rounded),
		}
		for mode, value := range values {
			want[mode*8+i] = value
			want[(mode+4)*8+i] = value
		}
	}
	if got != want {
		t.Fatalf("packedWordMultiplySemantics() = %#x, want %#x", got, want)
	}
}

func TestPackedFloatShuffleSemantics(t *testing.T) {
	var a, b [32]byte
	for i := 0; i < 8; i++ {
		binary.LittleEndian.PutUint32(a[4*i:], uint32(0xa0+i))
		binary.LittleEndian.PutUint32(b[4*i:], uint32(0xb0+i))
	}
	var got, want [96]byte
	packedFloatShuffleSemantics(&got, &a, &b)
	put32 := func(offset, value int) {
		binary.LittleEndian.PutUint32(want[offset:], uint32(value))
	}
	for i, value := range []int{0xb3, 0xb2, 0xa1, 0xa0} {
		put32(4*i, value)
	}
	for i, value := range []uint64{0x000000b1000000b0, 0x000000a3000000a2} {
		binary.LittleEndian.PutUint64(want[16+8*i:], value)
	}
	for group := 0; group < 2; group++ {
		base := group * 4
		for position, value := range []int{0xb3, 0xb2, 0xa1, 0xa0} {
			put32(32+4*(base+position), value+base)
		}
	}
	for i, value := range []uint64{0x000000b1000000b0, 0x000000a3000000a2, 0x000000b5000000b4, 0x000000a7000000a6} {
		binary.LittleEndian.PutUint64(want[64+8*i:], value)
	}
	if got != want {
		t.Fatalf("packedFloatShuffleSemantics() = %#x, want %#x", got, want)
	}
}

func TestImmediatePackedBlendSemantics(t *testing.T) {
	var a, b [32]byte
	for i := range a {
		a[i] = byte(0x20 + i)
		b[i] = byte(0xc0 + i)
	}
	var got, want [240]byte
	immediatePackedBlendSemantics(&got, &a, &b)
	blocks := []struct {
		offset, width, laneBytes int
	}{
		{0, 16, 2},   // PBLENDW
		{16, 16, 4},  // BLENDPS
		{32, 16, 8},  // BLENDPD
		{48, 16, 2},  // VPBLENDW X
		{64, 32, 2},  // VPBLENDW Y
		{96, 16, 4},  // VPBLENDD X
		{112, 32, 4}, // VPBLENDD Y
		{144, 16, 4}, // VBLENDPS X
		{160, 32, 4}, // VBLENDPS Y
		{192, 16, 8}, // VBLENDPD X
		{208, 32, 8}, // VBLENDPD Y
	}
	const mask = 0xa5
	for _, block := range blocks {
		for i := 0; i < block.width; i++ {
			source := b[i]
			if mask&(1<<uint((i/block.laneBytes)%8)) != 0 {
				source = a[i]
			}
			want[block.offset+i] = source
		}
	}
	if got != want {
		t.Fatalf("immediatePackedBlendSemantics() = %#x, want %#x", got, want)
	}
}

func TestPackedUnpackSemantics(t *testing.T) {
	var a, b [32]byte
	for i := range a {
		a[i] = byte(0x20 + i)
		b[i] = byte(0xc0 + i)
	}
	var got, want [384]byte
	packedUnpackSemantics(&got, &a, &b)
	type unpackBlock struct {
		offset, width, laneBytes int
		high                     bool
	}
	blocks := []unpackBlock{
		{0, 16, 1, false}, {16, 16, 1, true},
		{32, 16, 2, false}, {48, 16, 2, true},
		{64, 16, 4, false}, {80, 16, 4, true},
		{96, 16, 8, false}, {112, 16, 8, true},
		{128, 32, 1, false}, {160, 32, 1, true},
		{192, 32, 2, false}, {224, 32, 2, true},
		{256, 32, 4, false}, {288, 32, 4, true},
		{320, 32, 8, false}, {352, 32, 8, true},
	}
	for _, block := range blocks {
		output := block.offset
		for group := 0; group < block.width; group += 16 {
			lanesPerGroup := 16 / block.laneBytes
			start := 0
			if block.high {
				start = lanesPerGroup / 2
			}
			for lane := start; lane < start+lanesPerGroup/2; lane++ {
				input := group + lane*block.laneBytes
				copy(want[output:], b[input:input+block.laneBytes])
				output += block.laneBytes
				copy(want[output:], a[input:input+block.laneBytes])
				output += block.laneBytes
			}
		}
	}
	if got != want {
		t.Fatalf("packedUnpackSemantics() = %#x, want %#x", got, want)
	}
}

func TestQwordPermuteSemantics(t *testing.T) {
	data := [4]uint64{0x10, 0x21, 0x32, 0x43}
	var got [8]uint64
	qwordPermuteSemantics(&got, &data)
	immediate := [4]uint64{data[0], data[2], data[1], data[3]}
	var want [8]uint64
	copy(want[0:4], immediate[:])
	copy(want[4:8], immediate[:])
	if got != want {
		t.Fatalf("qwordPermuteSemantics() = %#x, want %#x", got, want)
	}
}

func TestPackedFloatMoveVEXSemantics(t *testing.T) {
	var src [32]byte
	for i := range src {
		src[i] = byte(3 + 17*i)
	}
	var got, want [128]byte
	packedFloatMoveVEXSemantics(&got, &src)
	for block := 0; block < 4; block++ {
		copy(want[block*32:], src[:])
	}
	if got != want {
		t.Fatalf("packedFloatMoveVEXSemantics() = %#x, want %#x", got, want)
	}
}

func TestPackedSignExtendMoveVEXSemantics(t *testing.T) {
	src := [32]byte{
		0x00, 0x01, 0x7f, 0x80, 0xff, 0x55, 0xaa, 0x40,
		0xc0, 0x11, 0xee, 0x33, 0xcc, 0x66, 0x99, 0x22,
		0xdd, 0x44, 0xbb, 0x77, 0x88, 0x10, 0xf0, 0x20,
		0xe0, 0x30, 0xd0, 0x50, 0xb0, 0x60, 0xa0, 0x70,
	}
	var got, want [288]byte
	packedSignExtendMoveVEXSemantics(&got, &src)
	type conversion struct{ inputBits, outputBits int }
	conversions := []conversion{{8, 16}, {8, 32}, {8, 64}, {16, 32}, {16, 64}, {32, 64}}
	readSigned := func(offset, bits int) int64 {
		switch bits {
		case 8:
			return int64(int8(src[offset]))
		case 16:
			return int64(int16(binary.LittleEndian.Uint16(src[offset:])))
		default:
			return int64(int32(binary.LittleEndian.Uint32(src[offset:])))
		}
	}
	write := func(dst []byte, bits int, value int64) {
		switch bits {
		case 16:
			binary.LittleEndian.PutUint16(dst, uint16(value))
		case 32:
			binary.LittleEndian.PutUint32(dst, uint32(value))
		default:
			binary.LittleEndian.PutUint64(dst, uint64(value))
		}
	}
	for index, conversion := range conversions {
		for _, block := range []struct{ offset, width int }{{index * 16, 16}, {96 + index*32, 32}} {
			lanes := block.width * 8 / conversion.outputBits
			for lane := 0; lane < lanes; lane++ {
				inputOffset := lane * conversion.inputBits / 8
				outputOffset := block.offset + lane*conversion.outputBits/8
				write(want[outputOffset:], conversion.outputBits, readSigned(inputOffset, conversion.inputBits))
			}
		}
	}
	if got != want {
		t.Fatalf("packedSignExtendMoveVEXSemantics() = %#x, want %#x", got, want)
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

func TestPackedSubtractSemantics(t *testing.T) {
	a := [16]byte{0x7f, 0x80, 0x64, 0x9c, 0x32, 0xce, 0x00, 0x01, 0xff, 0x00, 0x34, 0x12, 0x00, 0x80, 0xff, 0x7f}
	b := [16]byte{0xff, 0x01, 0x9c, 0x64, 0xce, 0x32, 0x01, 0x00, 0x01, 0xff, 0x78, 0x56, 0xff, 0x7f, 0x01, 0x80}
	var got, want [80]byte
	packedSubtractSemantics(&got, &a, &b)
	for i := 0; i < 16; i++ {
		signed := int(int8(a[i])) - int(int8(b[i]))
		if signed < -128 {
			signed = -128
		} else if signed > 127 {
			signed = 127
		}
		want[i] = byte(int8(signed))
		unsigned := int(a[i]) - int(b[i])
		if unsigned < 0 {
			unsigned = 0
		}
		want[32+i] = byte(unsigned)
	}
	for i := 0; i < 8; i++ {
		av, bv := binary.LittleEndian.Uint16(a[2*i:]), binary.LittleEndian.Uint16(b[2*i:])
		signed := int(int16(av)) - int(int16(bv))
		if signed < -32768 {
			signed = -32768
		} else if signed > 32767 {
			signed = 32767
		}
		binary.LittleEndian.PutUint16(want[16+2*i:], uint16(int16(signed)))
		unsigned := int(av) - int(bv)
		if unsigned < 0 {
			unsigned = 0
		}
		binary.LittleEndian.PutUint16(want[48+2*i:], uint16(unsigned))
	}
	for i := 0; i < 2; i++ {
		av, bv := binary.LittleEndian.Uint64(a[8*i:]), binary.LittleEndian.Uint64(b[8*i:])
		binary.LittleEndian.PutUint64(want[64+8*i:], av-bv)
	}
	if got != want {
		t.Fatalf("packedSubtractSemantics() = %#v, want %#v", got, want)
	}
}

func TestParityBranchSemantics(t *testing.T) {
	for _, tc := range []struct {
		value byte
		want  uint64
	}{
		{value: 0x00, want: 1},
		{value: 0x03, want: 1},
		{value: 0x01, want: 2},
		{value: 0x07, want: 2},
	} {
		if got := parityBranches(tc.value); got != tc.want {
			t.Fatalf("parityBranches(%#x) = %d, want %d", tc.value, got, tc.want)
		}
	}
	if got := unorderedBranch(1.25); got != 0 {
		t.Fatalf("unorderedBranch(finite) = %d, want 0", got)
	}
	if got := unorderedBranch(math.NaN()); got != 1 {
		t.Fatalf("unorderedBranch(NaN) = %d, want 1", got)
	}
}

func TestPackedFloatToDwordRoundingModes(t *testing.T) {
	src := [4]float32{1.5, -1.5, 2.75, -2.75}
	var got [20]int32
	packedFloatToDwordModes(&got, &src)
	want := [20]int32{
		2, -2, 3, -3,
		1, -2, 2, -3,
		2, -1, 3, -2,
		1, -1, 2, -2,
		1, -1, 2, -2,
	}
	if got != want {
		t.Fatalf("packedFloatToDwordModes() = %v, want %v", got, want)
	}
}

func TestPackedSingleToDoubleSemantics(t *testing.T) {
	src := [4]float32{1.5, -2.25, 3.125, -4.5}
	var got [4]float64
	packedSingleToDouble(&got, &src)
	want := [4]float64{1.5, -2.25, 3.125, -4.5}
	if got != want {
		t.Fatalf("packedSingleToDouble() = %v, want %v", got, want)
	}
}

func TestConditionalMoveConditionCodes(t *testing.T) {
	var src [16]uint64
	for i := range src {
		src[i] = uint64(101 + i)
	}
	var got [16]uint64
	conditionalMoveCodes(&got, &src)
	want := [16]uint64{
		src[0], ^uint64(0), ^uint64(0), src[3],
		src[4], src[5], ^uint64(0), ^uint64(0),
		^uint64(0), src[9], src[10], ^uint64(0),
		src[12], ^uint64(0), ^uint64(0), src[15],
	}
	if got != want {
		t.Fatalf("conditionalMoveCodes() = %#x, want %#x", got, want)
	}
}

func TestFMA3Semantics(t *testing.T) {
	a64 := [2]float64{2, -3}
	b64 := [2]float64{5, 7}
	c64 := [2]float64{11, -13}
	a32 := [4]float32{2, -3, 4, -5}
	b32 := [4]float32{5, 7, -11, -13}
	c32 := [4]float32{17, -19, 23, -29}
	var got [288]byte
	fma3Semantics(&got, &a64, &b64, &c64, &a32, &b32, &c32)

	read64 := func(block, lane int) float64 {
		return math.Float64frombits(binary.LittleEndian.Uint64(got[16*block+8*lane:]))
	}
	packed64 := [8][2]float64{}
	for lane := 0; lane < 2; lane++ {
		a, b, c := a64[lane], b64[lane], c64[lane]
		packed64[0][lane] = c*a + b
		packed64[1][lane] = b*c + a
		packed64[2][lane] = b*a + c
		packed64[3][lane] = c*a - b
		packed64[4][lane] = -(b * c) + a
		packed64[5][lane] = -(b * a) - c
		if lane%2 == 0 {
			packed64[6][lane] = c*a - b
			packed64[7][lane] = b*a + c
		} else {
			packed64[6][lane] = c*a + b
			packed64[7][lane] = b*a - c
		}
	}
	for block, want := range packed64 {
		for lane := range want {
			if value := read64(block, lane); value != want[lane] {
				t.Fatalf("packed f64 block %d lane %d = %v, want %v", block, lane, value, want[lane])
			}
		}
	}

	read32 := func(block, lane int) float32 {
		return math.Float32frombits(binary.LittleEndian.Uint32(got[16*block+4*lane:]))
	}
	packed32 := [6][4]float32{}
	for lane := 0; lane < 4; lane++ {
		a, b, c := a32[lane], b32[lane], c32[lane]
		packed32[0][lane] = c*a + b
		packed32[1][lane] = b*c - a
		packed32[2][lane] = -(b * a) + c
		packed32[3][lane] = -(c * a) - b
		if lane%2 == 0 {
			packed32[4][lane] = b*c - a
			packed32[5][lane] = b*a + c
		} else {
			packed32[4][lane] = b*c + a
			packed32[5][lane] = b*a - c
		}
	}
	for block, want := range packed32 {
		for lane := range want {
			if value := read32(8+block, lane); value != want[lane] {
				t.Fatalf("packed f32 block %d lane %d = %v, want %v", block, lane, value, want[lane])
			}
		}
	}

	wantScalar64 := [2][2]float64{
		{c64[0]*a64[0] + b64[0], c64[1]},
		{b64[0]*c64[0] - a64[0], c64[1]},
	}
	for block, want := range wantScalar64 {
		for lane := range want {
			if value := read64(14+block, lane); value != want[lane] {
				t.Fatalf("scalar f64 block %d lane %d = %v, want %v", block, lane, value, want[lane])
			}
		}
	}
	wantScalar32 := [2][4]float32{
		{-(b32[0] * a32[0]) + c32[0], c32[1], c32[2], c32[3]},
		{-(c32[0] * a32[0]) - b32[0], c32[1], c32[2], c32[3]},
	}
	for block, want := range wantScalar32 {
		for lane := range want {
			if value := read32(16+block, lane); value != want[lane] {
				t.Fatalf("scalar f32 block %d lane %d = %v, want %v", block, lane, value, want[lane])
			}
		}
	}
}

func TestBinaryFloatingSemantics(t *testing.T) {
	a64 := [2]float64{2, -3}
	b64 := [2]float64{20, 30}
	a32 := [4]float32{2, -3, 4, -5}
	b32 := [4]float32{20, 30, -40, -50}
	var got [384]byte
	binaryFloatingSemantics(&got, &a64, &b64, &a32, &b32)

	operation64 := func(operation, lane int) float64 {
		a, b := a64[lane], b64[lane]
		switch operation {
		case 0:
			return b + a
		case 1:
			return b - a
		case 2:
			return b * a
		case 3:
			return b / a
		case 4:
			if b > a {
				return b
			}
			return a
		default:
			if b < a {
				return b
			}
			return a
		}
	}
	operation32 := func(operation, lane int) float32 {
		a, b := a32[lane], b32[lane]
		switch operation {
		case 0:
			return b + a
		case 1:
			return b - a
		case 2:
			return b * a
		case 3:
			return b / a
		case 4:
			if b > a {
				return b
			}
			return a
		default:
			if b < a {
				return b
			}
			return a
		}
	}
	read64 := func(block, lane int) float64 {
		return math.Float64frombits(binary.LittleEndian.Uint64(got[16*block+8*lane:]))
	}
	read32 := func(block, lane int) float32 {
		return math.Float32frombits(binary.LittleEndian.Uint32(got[16*block+4*lane:]))
	}
	for operation := 0; operation < 6; operation++ {
		for lane := 0; lane < 2; lane++ {
			if value, want := read64(operation, lane), operation64(operation, lane); value != want {
				t.Fatalf("packed f64 operation %d lane %d = %v, want %v", operation, lane, value, want)
			}
		}
		for lane := 0; lane < 4; lane++ {
			if value, want := read32(6+operation, lane), operation32(operation, lane); value != want {
				t.Fatalf("packed f32 operation %d lane %d = %v, want %v", operation, lane, value, want)
			}
		}
		for lane := 0; lane < 2; lane++ {
			want := b64[lane]
			if lane == 0 {
				want = operation64(operation, 0)
			}
			if value := read64(12+operation, lane); value != want {
				t.Fatalf("scalar f64 operation %d lane %d = %v, want %v", operation, lane, value, want)
			}
		}
		for lane := 0; lane < 4; lane++ {
			want := b32[lane]
			if lane == 0 {
				want = operation32(operation, 0)
			}
			if value := read32(18+operation, lane); value != want {
				t.Fatalf("scalar f32 operation %d lane %d = %v, want %v", operation, lane, value, want)
			}
		}
	}
}

func TestHorizontalFloatingSemantics(t *testing.T) {
	a32 := [8]float32{1, 2, 3, 4, 5, 6, 7, 8}
	b32 := [8]float32{10, 20, 30, 40, 50, 60, 70, 80}
	a64 := [4]float64{1, 2, 3, 4}
	b64 := [4]float64{10, 20, 30, 40}
	var got [192]byte
	horizontalFloatingSemantics(&got, &a32, &b32, &a64, &b64)

	read32 := func(offset int) float32 {
		return math.Float32frombits(binary.LittleEndian.Uint32(got[offset:]))
	}
	read64 := func(offset int) float64 {
		return math.Float64frombits(binary.LittleEndian.Uint64(got[offset:]))
	}
	packed32 := [2][8]float32{
		{30, 70, 3, 7, 110, 150, 11, 15},
		{-10, -10, -1, -1, -10, -10, -1, -1},
	}
	for block, want := range packed32 {
		for lane := range want {
			if value := read32(32*block + 4*lane); value != want[lane] {
				t.Fatalf("vector f32 block %d lane %d = %v, want %v", block, lane, value, want[lane])
			}
		}
	}
	packed64 := [2][4]float64{{30, 3, 70, 7}, {-10, -1, -10, -1}}
	for block, want := range packed64 {
		for lane := range want {
			if value := read64(64 + 32*block + 8*lane); value != want[lane] {
				t.Fatalf("vector f64 block %d lane %d = %v, want %v", block, lane, value, want[lane])
			}
		}
	}
	legacy32 := [2][4]float32{{30, 70, 3, 7}, {-10, -10, -1, -1}}
	for block, want := range legacy32 {
		for lane := range want {
			if value := read32(128 + 16*block + 4*lane); value != want[lane] {
				t.Fatalf("legacy f32 block %d lane %d = %v, want %v", block, lane, value, want[lane])
			}
		}
	}
	legacy64 := [2][2]float64{{30, 3}, {-10, -1}}
	for block, want := range legacy64 {
		for lane := range want {
			if value := read64(160 + 16*block + 8*lane); value != want[lane] {
				t.Fatalf("legacy f64 block %d lane %d = %v, want %v", block, lane, value, want[lane])
			}
		}
	}
}

func TestExpandedEcosystemVectorSemantics(t *testing.T) {
	a := [16]byte{0x00, 0x7f, 0x80, 0xff, 0x34, 0x12, 0xfe, 0xff, 0x78, 0x56, 0x34, 0x12, 0x00, 0x00, 0x00, 0x80}
	b := [16]byte{0xff, 0x80, 0x7f, 0x00, 0x78, 0x56, 0x02, 0x00, 0xef, 0xcd, 0xab, 0x90, 0xff, 0xff, 0xff, 0x7f}
	var got, want [816]byte
	expandedEcosystemVectors(&got, &a, &b)

	for i := range a {
		minU, maxU := a[i], a[i]
		if b[i] < minU {
			minU = b[i]
		}
		if b[i] > maxU {
			maxU = b[i]
		}
		minS, maxS := int8(a[i]), int8(a[i])
		if int8(b[i]) < minS {
			minS = int8(b[i])
		}
		if int8(b[i]) > maxS {
			maxS = int8(b[i])
		}
		want[i], want[16+i] = minU, byte(minS)
		want[96+i], want[112+i] = maxU, byte(maxS)
	}
	for i := 0; i < 8; i++ {
		av := binary.LittleEndian.Uint16(a[2*i:])
		bv := binary.LittleEndian.Uint16(b[2*i:])
		minU, maxU := av, av
		if bv < minU {
			minU = bv
		}
		if bv > maxU {
			maxU = bv
		}
		minS, maxS := int16(av), int16(av)
		if int16(bv) < minS {
			minS = int16(bv)
		}
		if int16(bv) > maxS {
			maxS = int16(bv)
		}
		binary.LittleEndian.PutUint16(want[32+2*i:], minU)
		binary.LittleEndian.PutUint16(want[48+2*i:], uint16(minS))
		binary.LittleEndian.PutUint16(want[128+2*i:], maxU)
		binary.LittleEndian.PutUint16(want[144+2*i:], uint16(maxS))
	}
	for i := 0; i < 4; i++ {
		av := binary.LittleEndian.Uint32(a[4*i:])
		bv := binary.LittleEndian.Uint32(b[4*i:])
		minU, maxU := av, av
		if bv < minU {
			minU = bv
		}
		if bv > maxU {
			maxU = bv
		}
		minS, maxS := int32(av), int32(av)
		if int32(bv) < minS {
			minS = int32(bv)
		}
		if int32(bv) > maxS {
			maxS = int32(bv)
		}
		binary.LittleEndian.PutUint32(want[64+4*i:], minU)
		binary.LittleEndian.PutUint32(want[80+4*i:], uint32(minS))
		binary.LittleEndian.PutUint32(want[160+4*i:], maxU)
		binary.LittleEndian.PutUint32(want[176+4*i:], uint32(maxS))
	}
	for i := 0; i < 2; i++ {
		binary.LittleEndian.PutUint64(want[192+8*i:], binary.LittleEndian.Uint64(a[8*i:])<<13)
	}
	binary.LittleEndian.PutUint64(want[224:], 0x0123456789abcdef)
	binary.LittleEndian.PutUint64(want[232:], 0x0000000089abcdef)
	binary.LittleEndian.PutUint32(want[240:], 0x89abcdef)
	copy(want[256:264], a[:8])
	for i := range a {
		want[272+i] = byte((uint16(a[i]) + uint16(b[i]) + 1) >> 1)
	}
	for i := 0; i < 8; i++ {
		av := binary.LittleEndian.Uint16(a[2*i:])
		bv := binary.LittleEndian.Uint16(b[2*i:])
		binary.LittleEndian.PutUint16(want[288+2*i:], uint16((uint32(av)+uint32(bv)+1)>>1))
	}
	for i := range a {
		if int8(a[i]) > int8(b[i]) {
			want[304+i] = 0xff
		}
	}
	for i := 0; i < 8; i++ {
		if int16(binary.LittleEndian.Uint16(a[2*i:])) > int16(binary.LittleEndian.Uint16(b[2*i:])) {
			binary.LittleEndian.PutUint16(want[320+2*i:], 0xffff)
		}
	}
	for i := 0; i < 4; i++ {
		if int32(binary.LittleEndian.Uint32(a[4*i:])) > int32(binary.LittleEndian.Uint32(b[4*i:])) {
			binary.LittleEndian.PutUint32(want[336+4*i:], 0xffffffff)
		}
	}
	for i := 0; i < 2; i++ {
		if int64(binary.LittleEndian.Uint64(a[8*i:])) > int64(binary.LittleEndian.Uint64(b[8*i:])) {
			binary.LittleEndian.PutUint64(want[352+8*i:], ^uint64(0))
		}
	}
	for i := 0; i < 8; i++ {
		av := int16(binary.LittleEndian.Uint16(a[2*i:]))
		binary.LittleEndian.PutUint16(want[368+2*i:], uint16(av>>3))
		binary.LittleEndian.PutUint16(want[384+2*i:], uint16(av>>15))
	}
	for lane := 0; lane < 2; lane++ {
		copy(want[400+lane*8:], a[lane*4:lane*4+4])
		copy(want[404+lane*8:], b[lane*4:lane*4+4])
		copy(want[416+lane*8:], a[8+lane*4:12+lane*4])
		copy(want[420+lane*8:], b[8+lane*4:12+lane*4])
	}
	copy(want[432:440], a[0:8])
	copy(want[440:448], b[0:8])
	copy(want[448:456], a[8:16])
	copy(want[456:464], b[8:16])
	conversions := []struct{ inputBits, outputBits int }{{8, 16}, {8, 32}, {8, 64}, {16, 32}, {16, 64}, {32, 64}}
	for index, conversion := range conversions {
		lanes := 128 / conversion.outputBits
		for lane := 0; lane < lanes; lane++ {
			inputOffset := lane * conversion.inputBits / 8
			outputOffset := 464 + index*16 + lane*conversion.outputBits/8
			switch conversion.outputBits {
			case 16:
				binary.LittleEndian.PutUint16(want[outputOffset:], uint16(a[inputOffset]))
			case 32:
				value := uint32(a[inputOffset])
				if conversion.inputBits == 16 {
					value = uint32(binary.LittleEndian.Uint16(a[inputOffset:]))
				}
				binary.LittleEndian.PutUint32(want[outputOffset:], value)
			case 64:
				value := uint64(a[inputOffset])
				if conversion.inputBits == 16 {
					value = uint64(binary.LittleEndian.Uint16(a[inputOffset:]))
				} else if conversion.inputBits == 32 {
					value = uint64(binary.LittleEndian.Uint32(a[inputOffset:]))
				}
				binary.LittleEndian.PutUint64(want[outputOffset:], value)
			}
		}
	}
	clampWord := func(value int32) int16 {
		if value < -32768 {
			return -32768
		}
		if value > 32767 {
			return 32767
		}
		return int16(value)
	}
	for pair := 0; pair < 2; pair++ {
		a0 := binary.LittleEndian.Uint32(a[8*pair:])
		a1 := binary.LittleEndian.Uint32(a[8*pair+4:])
		b0 := binary.LittleEndian.Uint32(b[8*pair:])
		b1 := binary.LittleEndian.Uint32(b[8*pair+4:])
		binary.LittleEndian.PutUint32(want[560+4*pair:], a0+a1)
		binary.LittleEndian.PutUint32(want[568+4*pair:], b0+b1)
		binary.LittleEndian.PutUint32(want[608+4*pair:], a0-a1)
		binary.LittleEndian.PutUint32(want[616+4*pair:], b0-b1)
	}
	for pair := 0; pair < 4; pair++ {
		a0 := binary.LittleEndian.Uint16(a[4*pair:])
		a1 := binary.LittleEndian.Uint16(a[4*pair+2:])
		b0 := binary.LittleEndian.Uint16(b[4*pair:])
		b1 := binary.LittleEndian.Uint16(b[4*pair+2:])
		binary.LittleEndian.PutUint16(want[576+2*pair:], uint16(clampWord(int32(int16(a0))+int32(int16(a1)))))
		binary.LittleEndian.PutUint16(want[584+2*pair:], uint16(clampWord(int32(int16(b0))+int32(int16(b1)))))
		binary.LittleEndian.PutUint16(want[592+2*pair:], a0+a1)
		binary.LittleEndian.PutUint16(want[600+2*pair:], b0+b1)
		binary.LittleEndian.PutUint16(want[624+2*pair:], uint16(clampWord(int32(int16(a0))-int32(int16(a1)))))
		binary.LittleEndian.PutUint16(want[632+2*pair:], uint16(clampWord(int32(int16(b0))-int32(int16(b1)))))
		binary.LittleEndian.PutUint16(want[640+2*pair:], a0-a1)
		binary.LittleEndian.PutUint16(want[648+2*pair:], b0-b1)
	}
	minimum, minimumIndex := uint16(0xffff), uint16(0)
	for lane := 0; lane < 8; lane++ {
		value := binary.LittleEndian.Uint16(a[2*lane:])
		if value < minimum {
			minimum, minimumIndex = value, uint16(lane)
		}
	}
	binary.LittleEndian.PutUint16(want[656:], minimum)
	binary.LittleEndian.PutUint16(want[658:], minimumIndex)
	for block := 0; block < 2; block++ {
		for lane := range a {
			want[672+16*block+lane] = b[lane]
			if int8(b[lane]) < 0 {
				want[672+16*block+lane] = a[lane]
			}
		}
	}
	for lane := 0; lane < 8; lane++ {
		value := binary.LittleEndian.Uint16(a[2*lane:])
		binary.LittleEndian.PutUint16(want[704+2*lane:], value<<3)
		binary.LittleEndian.PutUint16(want[752+2*lane:], value>>3)
	}
	for lane := 0; lane < 4; lane++ {
		value := binary.LittleEndian.Uint32(a[4*lane:])
		binary.LittleEndian.PutUint32(want[720+4*lane:], value<<3)
		binary.LittleEndian.PutUint32(want[768+4*lane:], value>>3)
	}
	for lane := 0; lane < 2; lane++ {
		value := binary.LittleEndian.Uint64(a[8*lane:])
		binary.LittleEndian.PutUint64(want[736+8*lane:], value<<3)
		binary.LittleEndian.PutUint64(want[784+8*lane:], value>>3)
	}
	binary.LittleEndian.PutUint64(want[800:], 3)
	if got != want {
		t.Fatalf("expandedEcosystemVectors() = %#v, want %#v", got, want)
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
