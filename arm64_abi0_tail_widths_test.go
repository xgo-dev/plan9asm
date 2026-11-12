package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func arm64ABI0TailWidthsFixture(named bool, tail string) (string, string) {
	declaration := "func Slots(value uint64) (b uint8, h uint16, w uint32, d uint64)"
	if named {
		declaration = `type Small uint8
type Half int16
type Word uint32
type Long int64
func Slots(value uint64) (b Small, h Half, w Word, d Long)`
	}
	source := fmt.Sprintf(`TEXT ·Slots(SB),516,$0-24
MOVD value+0(FP),R0
MOVD $b+8(FP),R8
MOVD $h+10(FP),R9
MOVD $w+12(FP),R10
MOVD $d+16(FP),R11
%s resultbody<>(SB)
TEXT resultbody<>(SB),516,$0
ADD $7,R0,R12
MOVB R12,(R8)
ADD $3,R0,R13
MOVH R13,(R9)
ADD $5,R0,R14
MOVW R14,(R10)
ADD $9,R0,R15
MOVD R15,(R11)
RET
`, tail)
	return declaration, source
}

func TestARM64ABI0TailResultMixedWidthsObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc is required")
	}
	for _, named := range []bool{false, true} {
		for _, tail := range []string{"B", "JMP", "RET"} {
			declaration, source := arm64ABI0TailWidthsFixture(named, tail)
			requireARM64GoABIInternalObject(t, source)
			for _, target := range []string{
				"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-unknown-linux-musl",
				"aarch64-unknown-freebsd", "aarch64-pc-windows-msvc",
			} {
				for _, api := range []string{"text", "module", "GoModule"} {
					t.Run(fmt.Sprintf("named=%t/%s/%s/%s", named, tail, target, api), func(t *testing.T) {
						ir, err := arm64ABI0TailResultTranslate(t, source, declaration, target, api, nil)
						if err != nil {
							t.Fatal(err)
						}
						compileLLVMToObject(t, llc, target, "abi0-widths.ll", "abi0-widths.o", ir)
					})
				}
			}
		}
	}
}

func TestCrossLinuxRuntimeMatrixARM64ABI0TailResultMixedWidths(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	const bridge = `
define void @observe_tail_widths(ptr %out, i64 %value) {
  %results = call { i8, i16, i32, i64 } @Slots(i64 %value)
  %b = extractvalue { i8, i16, i32, i64 } %results, 0
  %h = extractvalue { i8, i16, i32, i64 } %results, 1
  %w = extractvalue { i8, i16, i32, i64 } %results, 2
  %d = extractvalue { i8, i16, i32, i64 } %results, 3
  %b64 = zext i8 %b to i64
  %h64 = zext i16 %h to i64
  %w64 = zext i32 %w to i64
  %hptr = getelementptr i64, ptr %out, i64 1
  %wptr = getelementptr i64, ptr %out, i64 2
  %dptr = getelementptr i64, ptr %out, i64 3
  store i64 %b64, ptr %out, align 8
  store i64 %h64, ptr %hptr, align 8
  store i64 %w64, ptr %wptr, align 8
  store i64 %d, ptr %dptr, align 8
  ret void
}
`
	const main = `#include <stdint.h>
#include <string.h>
extern void observe_tail_widths(uint64_t*, uint64_t);
int main(void) {
  uint64_t values[] = {0, 1, 255, 65535, UINT32_MAX, UINT64_C(1)<<63, UINT64_MAX};
  uint64_t original[7];
  memcpy(original, values, sizeof values);
  for (unsigned i = 0; i < 7; i++) {
    uint64_t value = values[i];
    uint64_t out[] = {0xabc, 0xbad, 0xbad, 0xbad, 0xbad, 0xdef};
    observe_tail_widths(out+1, value);
    if (out[1] != (uint8_t)(value+7) || out[2] != (uint16_t)(value+3) ||
        out[3] != (uint32_t)(value+5) || out[4] != value+9) return 11;
    if (out[0] != 0xabc || out[5] != 0xdef) return 12;
  }
  return memcmp(original, values, sizeof values) == 0 ? 0 : 13;
}
`
	for _, named := range []bool{false, true} {
		for _, tail := range []string{"B", "JMP", "RET"} {
			declaration, source := arm64ABI0TailWidthsFixture(named, tail)
			t.Run(fmt.Sprintf("original/named=%t/%s", named, tail), func(t *testing.T) {
				program := "package main\n" + declaration + `
func main() {
  values := [...]uint64{0,1,255,65535,1<<32-1,1<<63,^uint64(0)}
  original := values
  for _,value := range values {
    b,h,w,d := Slots(value)
    out := [6]uint64{0xabc, uint64(uint8(b)), uint64(uint16(h)), uint64(uint32(w)), uint64(d), 0xdef}
    want := [6]uint64{0xabc, uint64(uint8(value+7)), uint64(uint16(value+3)), uint64(uint32(value+5)), value+9, 0xdef}
    if out != want { panic("ABI0 mixed-width results/canaries") }
  }
  if values != original { panic("ABI0 mixed-width input changed") }
}
`
				runARM64LocalRegisterGoOracle(t, source, program, len(runner) != 0)
			})
			for _, api := range []string{"text", "module", "GoModule"} {
				t.Run(fmt.Sprintf("LLVM/named=%t/%s/%s", named, tail, api), func(t *testing.T) {
					ir, err := arm64ABI0TailResultTranslate(t, source, declaration, triple, api, nil)
					if err != nil {
						t.Fatal(err)
					}
					if !strings.Contains(ir, "{ i8, i16, i32, i64 }") {
						t.Fatal("mixed-width typed result tuple was not preserved")
					}
					// The observer uses the actual LLVM tuple convention instead of
					// guessing a C aggregate ABI. It does not produce expected values.
					compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "abi0_tail_widths", triple, ir+bridge, main, runner)
				})
			}
		}
	}
}
