//go:build !llgo

package plan9asm

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestAMD64ConformanceNativeGo(t *testing.T) {
	if runtime.GOARCH != "amd64" && !(runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()) {
		t.Skip("native Go assembler oracle requires an amd64 host")
	}
	cmd := exec.Command("go", "test", "./testdata/conformance/amd64")
	if runtime.GOARCH != "amd64" {
		cmd.Env = append(os.Environ(), "GOARCH=amd64")
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("native Go conformance failed: %v\n%s", err, out)
	}
}

func TestAMD64ConformanceLLVMRuntime(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution test only runs on amd64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Skip("llc/clang not found")
	}

	src, err := os.ReadFile(filepath.Join("testdata", "conformance", "amd64", "conformance_amd64.s"))
	if err != nil {
		t.Fatal(err)
	}
	file, err := Parse(ArchAMD64, string(src))
	if err != nil {
		t.Fatal(err)
	}
	resolve := func(sym string) string { return strings.TrimPrefix(sym, "·") }
	ptrParams := FrameLayout{Params: []FrameSlot{
		{Offset: 0, Type: Ptr, Index: 0, Field: -1},
		{Offset: 8, Type: Ptr, Index: 1, Field: -1},
	}}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	var runPrefix []string
	if crossRosetta {
		triple = "x86_64-apple-macosx"
		runPrefix = []string{"/usr/bin/arch", "-x86_64"}
	}
	ll, err := Translate(file, Options{
		TargetTriple: triple,
		ResolveSym:   resolve,
		Goarch:       "amd64",
		Sigs: map[string]FuncSig{
			"byteMemory": {
				Name: "byteMemory",
				Args: []LLVMType{Ptr, I8},
				Ret:  Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
					{Offset: 8, Type: I8, Index: 1, Field: -1},
				}},
			},
			"unpackLowQWords": {
				Name:  "unpackLowQWords",
				Args:  []LLVMType{Ptr, Ptr},
				Ret:   Void,
				Frame: ptrParams,
			},
			"byteFlags": {
				Name:  "byteFlags",
				Args:  []LLVMType{Ptr, Ptr},
				Ret:   Void,
				Frame: ptrParams,
			},
			"unpackDuplicateLowQWord": {
				Name: "unpackDuplicateLowQWord",
				Args: []LLVMType{Ptr},
				Ret:  Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
				}},
			},
			"shiftLegacyThreeOperand": {
				Name: "shiftLegacyThreeOperand",
				Args: []LLVMType{I32, I32, I32},
				Ret:  I32,
				Frame: FrameLayout{
					Params: []FrameSlot{
						{Offset: 0, Type: I32, Index: 0, Field: -1},
						{Offset: 4, Type: I32, Index: 1, Field: -1},
						{Offset: 8, Type: I32, Index: 2, Field: -1},
					},
					Results: []FrameSlot{
						{Offset: 16, Type: I32, Index: 0, Field: -1},
					},
				},
			},
			"clearTopBit": {
				Name: "clearTopBit",
				Args: []LLVMType{I64},
				Ret:  I64,
				Frame: FrameLayout{
					Params:  []FrameSlot{{Offset: 0, Type: I64, Index: 0, Field: -1}},
					Results: []FrameSlot{{Offset: 8, Type: I64, Index: 0, Field: -1}},
				},
			},
			"doubleShift32": {
				Name: "doubleShift32",
				Args: []LLVMType{Ptr, I32, I32, I32},
				Ret:  Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
					{Offset: 8, Type: I32, Index: 1, Field: -1},
					{Offset: 12, Type: I32, Index: 2, Field: -1},
					{Offset: 16, Type: I32, Index: 3, Field: -1},
				}},
			},
			"doubleShift64": {
				Name: "doubleShift64",
				Args: []LLVMType{Ptr, I64, I64, I64},
				Ret:  Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
					{Offset: 8, Type: I64, Index: 1, Field: -1},
					{Offset: 16, Type: I64, Index: 2, Field: -1},
					{Offset: 24, Type: I64, Index: 3, Field: -1},
				}},
			},
			"goHexVectorOps": {
				Name: "goHexVectorOps",
				Args: []LLVMType{Ptr, Ptr, Ptr},
				Ret:  Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
					{Offset: 8, Type: Ptr, Index: 1, Field: -1},
					{Offset: 16, Type: Ptr, Index: 2, Field: -1},
				}},
			},
			"goHexWordOps": {
				Name: "goHexWordOps",
				Args: []LLVMType{I64, I64},
				Ret:  I64,
				Frame: FrameLayout{
					Params: []FrameSlot{
						{Offset: 0, Type: I64, Index: 0, Field: -1},
						{Offset: 8, Type: I64, Index: 1, Field: -1},
					},
					Results: []FrameSlot{{Offset: 16, Type: I64, Index: 0, Field: -1}},
				},
			},
			"packedArithmeticShift32": {
				Name:  "packedArithmeticShift32",
				Args:  []LLVMType{Ptr, Ptr},
				Ret:   Void,
				Frame: ptrParams,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	mainC := `
#include <stdint.h>
extern void byteMemory(uint8_t *p, uint8_t value);
extern void byteFlags(uint8_t *p, uint8_t *flags);
extern void unpackLowQWords(uint64_t *dst, uint64_t *src);
extern void unpackDuplicateLowQWord(uint64_t *dst);
extern uint32_t shiftLegacyThreeOperand(uint32_t src, uint32_t dst, uint32_t amount);
extern uint64_t clearTopBit(uint64_t value);
extern void doubleShift32(uint32_t *out, uint32_t src, uint32_t dst, uint32_t amount);
extern void doubleShift64(uint64_t *out, uint64_t src, uint64_t dst, uint64_t amount);
extern void goHexVectorOps(uint8_t *out, uint8_t *a, uint8_t *b);
extern uint64_t goHexWordOps(uint64_t value, uint64_t count);
extern void packedArithmeticShift32(int32_t *out, int32_t *src);

static uint32_t shld32(uint32_t src, uint32_t dst, uint32_t count) {
	count &= 31;
	return count == 0 ? dst : (dst << count) | (src >> (32 - count));
}
static uint32_t shrd32(uint32_t src, uint32_t dst, uint32_t count) {
	count &= 31;
	return count == 0 ? dst : (dst >> count) | (src << (32 - count));
}
static uint64_t shld64(uint64_t src, uint64_t dst, uint64_t count) {
	count &= 63;
	return count == 0 ? dst : (dst << count) | (src >> (64 - count));
}
static uint64_t shrd64(uint64_t src, uint64_t dst, uint64_t count) {
	count &= 63;
	return count == 0 ? dst : (dst >> count) | (src << (64 - count));
}

int main(void) {
	uint8_t bytes[4] = {0x10, 0xf0, 0x5a, 0xa0};
	byteMemory(bytes, 0x0f);
	if (bytes[0] != 0x1f || bytes[1] != 0xff || bytes[2] != 0x0a || bytes[3] != 0xaf)
		return 11;
	uint8_t flag_values[4] = {0xff, 0xff, 0x7f, 0};
	uint8_t flags[8] = {0};
	byteFlags(flag_values, flags);
	uint8_t want_values[4] = {0, 0, 0, 0x80};
	uint8_t want_flags[8] = {1, 1, 0, 1, 0, 1, 0, 1};
	for (int i = 0; i < 4; i++)
		if (flag_values[i] != want_values[i])
			return 13 + i;
	for (int i = 0; i < 8; i++)
		if (flags[i] != want_flags[i])
			return 20 + i;
	uint64_t dst[2] = {0x0123456789abcdefULL, 0xfedcba9876543210ULL};
	uint64_t src[2] = {0x1122334455667788ULL, 0x8877665544332211ULL};
	unpackLowQWords(dst, src);
	if (dst[0] != 0x0123456789abcdefULL || dst[1] != 0x1122334455667788ULL)
		return 12;
	uint64_t duplicate[2] = {0x0123456789abcdefULL, 0xfedcba9876543210ULL};
	unpackDuplicateLowQWord(duplicate);
	if (duplicate[0] != 0x0123456789abcdefULL || duplicate[1] != 0x0123456789abcdefULL)
		return 30;
	if (shiftLegacyThreeOperand(0x12345678U, 0x89abcdefU, 5) != 0x3579bde2U)
		return 31;
	if (clearTopBit(UINT64_MAX) != 0x7fffffffffffffffULL ||
		clearTopBit(0x0123456789abcdefULL) != 0x0123456789abcdefULL)
		return 32;
	const uint32_t pairs32[][2] = {
		{0x12345678U, 0x89abcdefU}, {0, UINT32_MAX},
		{UINT32_MAX, 0}, {0x80000001U, 0x7ffffffeU},
	};
	for (unsigned p = 0; p < sizeof(pairs32) / sizeof(pairs32[0]); p++) {
		for (uint32_t count = 0; count < 128; count++) {
			uint32_t src = pairs32[p][0], dst_value = pairs32[p][1], out[8] = {0};
			doubleShift32(out, src, dst_value, count);
			uint32_t want[8] = {
				shld32(src, dst_value, count), shld32(src, dst_value, 7),
				shld32(src, dst_value, count), shld32(src, dst_value, 7),
				shrd32(src, dst_value, count), shrd32(src, dst_value, 7),
				shrd32(src, dst_value, count), shrd32(src, dst_value, 7),
			};
			for (int i = 0; i < 8; i++)
				if (out[i] != want[i])
					return 40 + i;
		}
	}
	const uint64_t pairs64[][2] = {
		{0x0123456789abcdefULL, 0xfedcba9876543210ULL}, {0, UINT64_MAX},
		{UINT64_MAX, 0}, {0x8000000000000001ULL, 0x7ffffffffffffffeULL},
	};
	for (unsigned p = 0; p < sizeof(pairs64) / sizeof(pairs64[0]); p++) {
		for (uint64_t count = 0; count < 256; count++) {
			uint64_t src = pairs64[p][0], dst_value = pairs64[p][1], out[8] = {0};
			doubleShift64(out, src, dst_value, count);
			uint64_t want[8] = {
				shld64(src, dst_value, count), shld64(src, dst_value, 7),
				shld64(src, dst_value, count), shld64(src, dst_value, 7),
				shrd64(src, dst_value, count), shrd64(src, dst_value, 7),
				shrd64(src, dst_value, count), shrd64(src, dst_value, 7),
			};
			for (int i = 0; i < 8; i++)
				if (out[i] != want[i])
					return 50 + i;
		}
	}
	uint8_t a[16], b[16], vector_out[160] = {0};
	const uint8_t or_mask[16] = {
		0x80, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
		0xff, 0x00, 0x55, 0xaa, 0x0f, 0xf0, 0x33, 0xcc,
	};
	for (int i = 0; i < 16; i++) {
		a[i] = (uint8_t)(i * 29 + 3);
		b[i] = (uint8_t)(i * 17 + 0x70);
	}
	goHexVectorOps(vector_out, a, b);
	for (int i = 0; i < 16; i++) {
		if (vector_out[i] != (uint8_t)(a[i] | or_mask[i])) return 70;
		if (vector_out[16+i] != (uint8_t)(a[i] | b[i])) return 71;
		uint8_t gt = (int8_t)a[i] > (int8_t)b[i] ? 0xff : 0;
		if (vector_out[32+i] != gt || vector_out[48+i] != gt) return 72;
		if (vector_out[64+i] != (uint8_t)(a[i] - b[i])) return 73;
		if (vector_out[144+i] != (uint8_t)(a[i] & b[i])) return 74;
	}
	for (int i = 0; i < 8; i++) {
		uint16_t word = (uint16_t)a[2*i] | (uint16_t)a[2*i+1] << 8;
		uint16_t left = (uint16_t)(word << 4), right = (uint16_t)(word >> 4);
		if (vector_out[80+2*i] != (uint8_t)left || vector_out[80+2*i+1] != (uint8_t)(left >> 8)) return 75;
		if (vector_out[96+2*i] != (uint8_t)right || vector_out[96+2*i+1] != (uint8_t)(right >> 8)) return 76;
		if (vector_out[112+2*i] != a[8+i] || vector_out[112+2*i+1] != b[8+i]) return 77;
		if (vector_out[128+2*i] != a[8+i] || vector_out[128+2*i+1] != b[8+i]) return 78;
	}
	const uint64_t word_values[][2] = {
		{0x123456789abcdef0ULL, 0},
		{0x123456789abcdef0ULL, 4},
		{0xfedcba9876543210ULL, 12},
	};
	for (unsigned i = 0; i < sizeof(word_values) / sizeof(word_values[0]); i++) {
		uint64_t value = word_values[i][0], count = word_values[i][1];
		uint16_t shifted = (uint16_t)value >> (count & 31);
		unsigned first = 0;
		while (((shifted >> first) & 1) == 0) first++;
		uint64_t want = (value & ~0xffffULL) | shifted | ((uint64_t)first << 16);
		if (goHexWordOps(value, count) != want) return 79;
	}
	int32_t packed_src[4] = {0, 1, -1, INT32_MIN};
	int32_t packed_out[8] = {0};
	const int32_t packed_want[8] = {0, 0, -1, -1, 0, 0, -1, -1};
	packedArithmeticShift32(packed_out, packed_src);
	for (int i = 0; i < 8; i++)
		if (packed_out[i] != packed_want[i]) return 80 + i;
	return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "amd64_conformance", triple, ll, mainC, runPrefix)
	recordAMD64ConformanceManifestCases(t, "amd64/conformance_amd64.s", runtime.GOARCH == "amd64" || crossRosetta)
}

func rosettaAvailable() bool {
	return exec.Command("/usr/bin/arch", "-x86_64", "/usr/bin/true").Run() == nil
}
