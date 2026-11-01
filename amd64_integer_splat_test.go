package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestLLVMIntegerSplatsPreserveExactText(t *testing.T) {
	for _, test := range []struct {
		name    string
		bits    int
		value   int64
		element string
	}{
		{"zero", 8, 0, "i8 0"},
		{"boolean", 1, 1, "i1 1"},
		{"negative-byte", 8, -128, "i8 -128"},
		{"negative-saturation", 32, -32768, "i32 -32768"},
		{"positive-saturation", 32, 32767, "i32 32767"},
		{"all-ones", 64, -1, "i64 -1"},
		{"minimum", 64, -1 << 63, "i64 -9223372036854775808"},
		{"maximum", 64, 1<<63 - 1, "i64 9223372036854775807"},
		{"wide-carrier", 128, -1 << 63, "i128 -9223372036854775808"},
	} {
		t.Run("signed/"+test.name, func(t *testing.T) {
			checkIntegerSplatText(t, test.element, func(lanes int) string {
				return llvmSplatSignedInteger(lanes, test.bits, test.value)
			})
		})
	}
	for _, test := range []struct {
		name    string
		bits    int
		value   uint64
		element string
	}{
		{"zero", 8, 0, "i8 0"},
		{"boolean", 1, 1, "i1 1"},
		{"byte-mask", 8, 255, "i8 255"},
		{"word-mask", 16, 65535, "i16 65535"},
		{"dword-mask", 32, 4294967295, "i32 4294967295"},
		{"high-bit", 64, 1 << 63, "i64 9223372036854775808"},
		{"maximum", 64, ^uint64(0), "i64 18446744073709551615"},
		{"wide-carrier", 128, ^uint64(0), "i128 18446744073709551615"},
	} {
		t.Run("unsigned/"+test.name, func(t *testing.T) {
			checkIntegerSplatText(t, test.element, func(lanes int) string {
				return llvmSplatInteger(lanes, test.bits, test.value)
			})
		})
	}
}

// The decimal spellings above are independent literal expectations. This
// oracle constructs a slice and joins it; it does not reuse the formatter or
// production builder, and includes the existing empty result for lanes <= 0.
func checkIntegerSplatText(t *testing.T, element string, splat func(int) string) {
	t.Helper()
	for _, lanes := range []int{-2, 0, 1, 2, 4, 16, 64, 256} {
		t.Run(fmt.Sprint(lanes), func(t *testing.T) {
			var elements []string
			for lane := 0; lane < lanes; lane++ {
				elements = append(elements, element)
			}
			want := "<" + strings.Join(elements, ", ") + ">"
			if got := splat(lanes); got != want {
				t.Fatalf("splat(%d): got %q, want %q", lanes, got, want)
			}
		})
	}
}

func TestLLVMIntegerSplatsHaveBoundedAllocationGrowth(t *testing.T) {
	for _, test := range integerSplatAllocationCases() {
		t.Run(test.name, func(t *testing.T) {
			var result string
			small := testing.AllocsPerRun(20, func() {
				result = test.splat(1)
			})
			large := testing.AllocsPerRun(20, func() {
				result = test.splat(256)
			})
			if strings.Count(result, ", ") != 255 {
				t.Fatal("allocation check did not produce all 256 lanes")
			}
			// Formatting and output storage may allocate a small constant
			// amount. Neither per-lane boxing nor repeated builder growth is
			// part of the contract; retain room for SDK formatting overhead.
			if large > small+1 || large > 8 {
				t.Fatalf("allocations grow with lane count: 1 lane=%g, 256 lanes=%g", small, large)
			}
		})
	}
}

func integerSplatAllocationCases() []struct {
	name  string
	splat func(int) string
} {
	return []struct {
		name  string
		splat func(int) string
	}{
		{"signed-min", func(lanes int) string { return llvmSplatSignedInteger(lanes, 64, -1<<63) }},
		{"signed-saturation", func(lanes int) string { return llvmSplatSignedInteger(lanes, 32, -32768) }},
		{"unsigned-max", func(lanes int) string { return llvmSplatInteger(lanes, 64, ^uint64(0)) }},
		{"unsigned-byte", func(lanes int) string { return llvmSplatInteger(lanes, 8, 255) }},
	}
}

var integerSplatBenchmarkSink string

func BenchmarkLLVMIntegerSplats(b *testing.B) {
	for _, test := range integerSplatAllocationCases() {
		b.Run(test.name, func(b *testing.B) {
			for _, lanes := range []int{1, 16, 64, 256} {
				b.Run(fmt.Sprint(lanes), func(b *testing.B) {
					b.SetBytes(int64(len(test.splat(lanes))))
					b.ReportAllocs()
					b.ResetTimer()
					for iteration := 0; iteration < b.N; iteration++ {
						integerSplatBenchmarkSink = test.splat(lanes)
					}
				})
			}
		})
	}
}
