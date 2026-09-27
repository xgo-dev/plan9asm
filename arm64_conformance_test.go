package plan9asm

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestARM64ConformanceNativeGo(t *testing.T) {
	if !currentGoMinorAtLeast(27) {
		// The translated conformance test still runs on every supported Go
		// version. Only the native oracle needs the Go 1.27 assembler because
		// its source intentionally exercises Go 1.27-only aliases.
		return
	}
	crossLinux := runtime.GOOS == "linux" && runtime.GOARCH == "amd64" && os.Getenv("PLAN9ASM_CROSS_EXEC") == "1"
	if runtime.GOARCH != "arm64" && !crossLinux {
		t.Skip("native Go assembler oracle requires an arm64 host")
	}
	args := []string{"test", "./testdata/conformance/arm64"}
	if crossLinux {
		if _, err := exec.LookPath("qemu-aarch64"); err != nil {
			t.Fatal("qemu-aarch64 not found")
		}
		args = []string{"test", "-exec=qemu-aarch64", "./testdata/conformance/arm64"}
	}
	cmd := exec.Command("go", args...)
	if crossLinux {
		cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=arm64", "CGO_ENABLED=0")
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("native Go conformance failed: %v\n%s", err, out)
	}
}

func TestARM64ConformanceTranslate(t *testing.T) {
	translateARM64Conformance(t, "aarch64-unknown-linux-gnu")
}

func translateARM64Conformance(t *testing.T, triple string) string {
	t.Helper()
	src, err := os.ReadFile(filepath.Join("testdata", "conformance", "arm64", "conformance_arm64.s"))
	if err != nil {
		t.Fatal(err)
	}
	file, err := Parse(ArchARM64, string(src))
	if err != nil {
		t.Fatal(err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: triple,
		ResolveSym:   func(sym string) string { return strings.TrimPrefix(sym, "·") },
		Goarch:       "arm64",
		Sigs: map[string]FuncSig{
			"families": {
				Name: "families",
				Args: []LLVMType{Ptr, Ptr},
				Ret:  Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
					{Offset: 8, Type: Ptr, Index: 1, Field: -1},
				}},
			},
			"scalarFloatSquareRoots": {
				Name: "scalarFloatSquareRoots",
				Args: []LLVMType{Ptr},
				Ret:  Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
				}},
			},
			"fusedMultiplyAddSemantics": {
				Name: "fusedMultiplyAddSemantics",
				Args: []LLVMType{Ptr},
				Ret:  Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
				}},
			},
			"pairedAtomicSemantics": {
				Name: "pairedAtomicSemantics",
				Args: []LLVMType{Ptr, Ptr},
				Ret:  Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
					{Offset: 8, Type: Ptr, Index: 1, Field: -1},
				}},
			},
			"vectorPermuteSemantics": {
				Name: "vectorPermuteSemantics",
				Args: []LLVMType{Ptr, Ptr, Ptr},
				Ret:  Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
					{Offset: 8, Type: Ptr, Index: 1, Field: -1},
					{Offset: 16, Type: Ptr, Index: 2, Field: -1},
				}},
			},
			"vectorWideningShiftSemantics": {
				Name: "vectorWideningShiftSemantics",
				Args: []LLVMType{Ptr, Ptr},
				Ret:  Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
					{Offset: 8, Type: Ptr, Index: 1, Field: -1},
				}},
			},
			"scalarExtendSemantics": {
				Name: "scalarExtendSemantics",
				Args: []LLVMType{Ptr, I64},
				Ret:  Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
					{Offset: 8, Type: I64, Index: 1, Field: -1},
				}},
			},
			"vectorCountBitsSemantics": {
				Name: "vectorCountBitsSemantics",
				Args: []LLVMType{Ptr, Ptr},
				Ret:  Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
					{Offset: 8, Type: Ptr, Index: 1, Field: -1},
				}},
			},
			"unsignedWideningAddSemantics": {
				Name: "unsignedWideningAddSemantics",
				Args: []LLVMType{Ptr, Ptr, Ptr},
				Ret:  Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
					{Offset: 8, Type: Ptr, Index: 1, Field: -1},
					{Offset: 16, Type: Ptr, Index: 2, Field: -1},
				}},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return ll
}

func TestARM64ConformanceLLVMRuntime(t *testing.T) {
	crossLinux := runtime.GOOS == "linux" && runtime.GOARCH == "amd64" && os.Getenv("PLAN9ASM_CROSS_EXEC") == "1"
	if runtime.GOARCH != "arm64" && !crossLinux {
		t.Skip("runtime execution test only runs on an arm64 host")
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("llc not found")
	}
	compiler := []string{}
	runPrefix := []string(nil)
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	if crossLinux {
		compiler = []string{"aarch64-linux-gnu-gcc"}
		runPrefix = []string{"qemu-aarch64", "-L", "/usr/aarch64-linux-gnu"}
		triple = "aarch64-unknown-linux-gnu"
	} else {
		_, clang, ok := findLlcAndClang(t)
		if !ok {
			t.Fatal("clang not found")
		}
		compiler = []string{clang}
	}

	ll := translateARM64Conformance(t, triple)
	mainC := `
#include <stdint.h>
extern void families(uint64_t *out, uint64_t *data);
extern void scalarFloatSquareRoots(uint8_t *out);
extern void fusedMultiplyAddSemantics(uint8_t *out);
extern void pairedAtomicSemantics(uint64_t *out, uint64_t *data);
extern void vectorPermuteSemantics(uint8_t *out, uint8_t *n, uint8_t *m);
extern void vectorWideningShiftSemantics(uint8_t *out, uint8_t *source);
extern void scalarExtendSemantics(uint64_t *out, uint64_t value);
extern void vectorCountBitsSemantics(uint8_t *out, uint8_t *source);
extern void unsignedWideningAddSemantics(uint8_t *out, uint8_t *narrow, uint8_t *addend);
int main(void) {
    uint64_t data[8] = {0x0123456789abcdefULL, 0xfedcba9876543210ULL, 0x1122334455667788ULL, 0x8877665544332211ULL};
    uint64_t want[76] = {
        0xfedcba9876cdef10ULL, 0x0000000076543ef0ULL, 0xfedcba9876589abcULL, 0x0000000076543abcULL,
        0xffffffffffcdef00ULL, 0x00000000ffffdef0ULL, 0xfffffffffff89abcULL, 0x00000000fffffabcULL,
        0x0000000000cdef00ULL, 0x000000000000def0ULL, 0x0000000000089abcULL, 0x0000000000000abcULL,
        5, 5, 10, 10, 0xfffffffffffffff6ULL, 0x00000000fffffff6ULL, 0xfffffffffffffff7ULL, 0x00000000fffffff7ULL,
        1, 1, 0xffffffffffffffffULL, 0x00000000ffffffffULL, 6, 6, 0xfffffffffffffffaULL, 0x00000000fffffffaULL,
        0xfffffffffffffffbULL, 0x00000000fffffffbULL, 0xefcdab8967452301ULL, 0x00000000efcdab89ULL,
        0x23016745ab89efcdULL, 0x00000000ab89efcdULL, 0x67452301efcdab89ULL, 0x000123456789abcdULL,
        0x00000000ff89abcdULL, 0x23456789abcdef00ULL, 0x00000000abcdef00ULL, 0x000123456789abcdULL,
        0x000000000089abcdULL, 0xef0123456789abcdULL, 0x00000000ef89abcdULL, 0x0000123456789abcULL,
        0x00000000fff89abcULL, 0x3456789abcdef000ULL, 0x00000000bcdef000ULL, 0x0000123456789abcULL,
        0x0000000000089abcULL, 0xdef0123456789abcULL, 0x00000000def89abcULL, 0x0123456789abcdd7ULL,
        0x0000000089abcdd7ULL, 0, 0, 0xffffffffffff89abULL, 0x00000000000089abULL, 0x0000000001234567ULL,
        0x0000000001234567ULL, 0xffffffffffffffefULL, 0x00000000000000efULL, 0x0123456789abcdefULL,
        0xfedcba9876543210ULL, 0x0123456789abcdefULL, 0xfedcba9876543210ULL, 0x1122334455667788ULL,
        0x8877665544332211ULL, 0xffffffff89abcdefULL, 1, 1, 1, 1,
        0x0000000089abcdefULL, 0x0123456789abcdefULL, 0x1234, 0
    };
    uint64_t got[76] = {0};
    families(got, data);
    for (int i = 0; i < 76; i++)
        if (got[i] != want[i])
            return i + 1;
	union {
		uint8_t bytes[16];
		struct { float s0, s1; double d; } values;
	} scalar = {0};
	scalarFloatSquareRoots(scalar.bytes);
	if (scalar.values.s0 != 2.0f) return 80;
	if (scalar.values.s1 != 2.0f) return 81;
	if (scalar.values.d != 4.0) return 82;
	union {
		uint8_t bytes[48];
		struct { float s[4]; double d[4]; } values;
	} fma = {0};
	fusedMultiplyAddSemantics(fma.bytes);
	float fma_s_want[4] = {11.0f, -1.0f, -11.0f, 1.0f};
	double fma_d_want[4] = {11.0, -1.0, -11.0, 1.0};
	for (int i = 0; i < 4; i++) {
		if (fma.values.s[i] != fma_s_want[i]) return 83 + i;
		if (fma.values.d[i] != fma_d_want[i]) return 87 + i;
	}
	uint8_t permute_n[16], permute_m[16], permute_got[96] = {0};
	for (int i = 0; i < 16; i++) {
		permute_n[i] = (uint8_t)i;
		permute_m[i] = (uint8_t)(0x80 + i);
	}
	uint8_t widen_narrow[16] = {1, 2, 3, 4, 5, 6, 7, 8, 0xf1, 0xe2, 0xd3, 0xc4, 0xb5, 0xa6, 0x97, 0x88};
	uint8_t widen_addend[16] = {0xff, 0x00, 0xfe, 0xff, 0x78, 0x56, 0x34, 0x12, 0xf0, 0xde, 0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12};
	uint8_t widen_add_got[96] = {0};
	unsignedWideningAddSemantics(widen_add_got, widen_narrow, widen_addend);
	int narrow_widths[6] = {1, 2, 4, 1, 2, 4};
	for (int group = 0; group < 6; group++) {
		int narrow_bytes = narrow_widths[group], wide_bytes = 2*narrow_bytes, lanes = 16/wide_bytes;
		int source_offset = group >= 3 ? 8 : 0;
		for (int lane = 0; lane < lanes; lane++) {
			uint64_t narrow_value = 0, addend_value = 0, got = 0;
			for (int b = 0; b < narrow_bytes; b++) narrow_value |= (uint64_t)widen_narrow[source_offset+lane*narrow_bytes+b] << (8*b);
			for (int b = 0; b < wide_bytes; b++) {
				addend_value |= (uint64_t)widen_addend[lane*wide_bytes+b] << (8*b);
				got |= (uint64_t)widen_add_got[group*16+lane*wide_bytes+b] << (8*b);
			}
			uint64_t sum = addend_value + narrow_value;
			if (wide_bytes < 8) sum &= (1ULL << (8*wide_bytes)) - 1;
			if (got != sum) return 190 + group;
		}
	}
	vectorPermuteSemantics(permute_got, permute_n, permute_m);
	for (int i = 0; i < 8; i++) {
		if (permute_got[2*i] != permute_n[i] || permute_got[2*i+1] != permute_m[i]) return 100;
		if (permute_got[16+2*i] != permute_n[8+i] || permute_got[16+2*i+1] != permute_m[8+i]) return 101;
		if (permute_got[32+i] != permute_n[2*i] || permute_got[40+i] != permute_m[2*i]) return 102;
		if (permute_got[48+i] != permute_n[2*i+1] || permute_got[56+i] != permute_m[2*i+1]) return 103;
		if (permute_got[64+2*i] != permute_n[2*i] || permute_got[64+2*i+1] != permute_m[2*i]) return 104;
		if (permute_got[80+2*i] != permute_n[2*i+1] || permute_got[80+2*i+1] != permute_m[2*i+1]) return 105;
	}
	uint64_t scalar_extend_got[10] = {0};
	uint64_t scalar_extend_value = 0x88776655fedcba98ULL;
	uint64_t scalar_extend_want[10] = {
		(uint64_t)(int64_t)(int8_t)scalar_extend_value,
		(uint64_t)(uint32_t)(int32_t)(int8_t)scalar_extend_value,
		(uint64_t)(int64_t)(int16_t)scalar_extend_value,
		(uint64_t)(uint32_t)(int32_t)(int16_t)scalar_extend_value,
		(uint64_t)(int64_t)(int32_t)scalar_extend_value,
		(uint64_t)(uint8_t)scalar_extend_value,
		(uint64_t)(uint32_t)(uint8_t)scalar_extend_value,
		(uint64_t)(uint16_t)scalar_extend_value,
		(uint64_t)(uint32_t)(uint16_t)scalar_extend_value,
		(uint64_t)(uint32_t)scalar_extend_value,
	};
	scalarExtendSemantics(scalar_extend_got, scalar_extend_value);
	for (int i = 0; i < 10; i++)
		if (scalar_extend_got[i] != scalar_extend_want[i]) return 120 + i;
	uint8_t count_source[16] = {0, 1, 2, 3, 7, 15, 31, 63, 127, 128, 129, 0xaa, 0x55, 0xfe, 0xff, 0x81};
	uint8_t count_got[32] = {0};
	vectorCountBitsSemantics(count_got, count_source);
	for (int i = 0; i < 16; i++) {
		uint8_t value = count_source[i], count = 0;
		while (value) { count += value & 1; value >>= 1; }
		if (count_got[16+i] != count) return 140 + i;
		if (i < 8 && count_got[i] != count) return 160 + i;
		if (i >= 8 && count_got[i] != 0) return 170 + i;
	}
	uint8_t widening_source[16] = {0, 1, 0x7f, 0x80, 0xff, 2, 0x55, 0xaa, 3, 4, 0x40, 0xc0, 0xfe, 0x81, 0x11, 0xee};
	uint16_t widening_got[64] = {0};
	vectorWideningShiftSemantics((uint8_t *)widening_got, widening_source);
	for (int i = 0; i < 8; i++) {
		uint16_t low = widening_source[i], high = widening_source[8+i];
		uint16_t signed_low = (uint16_t)(int16_t)(int8_t)widening_source[i];
		uint16_t signed_high = (uint16_t)(int16_t)(int8_t)widening_source[8+i];
		uint16_t want_widening[8] = {low, high, signed_low, signed_high, (uint16_t)(low << 7), (uint16_t)(high << 1), (uint16_t)(signed_low << 3), (uint16_t)(signed_high << 2)};
		for (int group = 0; group < 8; group++)
			if (widening_got[group*8+i] != want_widening[group]) return 110 + group;
	}
	uint64_t atomic_data[9] __attribute__((aligned(16))) = {
		0x11, 0x22, 0x33, 0x44,
		0x0000002200000011ULL, 0x0000004400000033ULL,
		0x55, 0x66, 0x0000008800000077ULL
	};
	uint64_t atomic_want[23] = {
		0x11, 0x22, 0xaa, 0xbb,
		0x33, 0x44, 0x33, 0x44,
		0x11, 0x22, 0x000000bb000000aaULL,
		0x33, 0x44, 0x0000004400000033ULL,
		0x55, 0x66, 0, 0xcc, 0xdd,
		0x77, 0x88, 1, 0x000000aa00000099ULL
	};
	uint64_t atomic_got[23] = {0};
	pairedAtomicSemantics(atomic_got, atomic_data);
	for (int i = 0; i < 23; i++)
		if (atomic_got[i] != atomic_want[i])
			return 100 + i;
    return 0;
}
`
	compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "arm64_conformance", triple, ll, mainC, runPrefix)
}
