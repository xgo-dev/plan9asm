package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func arm64RawPoolGuardIR(t *testing.T, triple string) string {
	t.Helper()
	lines := []string{
		"adr x9, #0",
		"cmp x1, #16", "b.hs #12", "ldrb w2, [x9, x1]", "str x2, [x0]",
		"cmp x1, #3", "b.hi #16", "add x12, x9, x1, lsl #2", "ldr w12, [x12]", "str x12, [x0, #8]",
		"cmp w1, #3", "b.hi #16", "add x12, x9, w1, uxtw #2", "ldr w12, [x12]", "str x12, [x0, #16]",
		"mov x9, xzr", "mov x12, xzr", "ret",
	}
	lines[0] = fmt.Sprintf("adr x9, #%d", len(lines)*4)
	var source strings.Builder
	source.WriteString("TEXT pool_guard(SB),$0-16\nMOVD out+0(FP),R0\nMOVD index+8(FP),R1\n")
	for _, word := range assembleARM64LLVMWords(t, lines, "") {
		fmt.Fprintf(&source, "WORD $%#08x\n", word)
	}
	for i := 0; i < 4; i++ {
		fmt.Fprintf(&source, "WORD $%#08x\n", uint32(0x17b4a140+i))
	}
	source.WriteString("RET\n")
	requireARM64GoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple,
		Sigs: map[string]FuncSig{"pool_guard": {
			Name: "pool_guard", Args: []LLVMType{Ptr, I64}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1},
				{Offset: 8, Type: I64, Index: 1, Field: -1},
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return ir
}

func TestARM64RawPoolGuardLLVM(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ir := arm64RawPoolGuardIR(t, triple)
			compileLLVMToObject(t, llc, triple, "pool_guard.ll", "pool_guard.o", ir)
			if runtime.GOARCH == "arm64" && runtime.GOOS == "darwin" && triple == "aarch64-apple-darwin" {
				clang := findLLVM22Tool("clang")
				if clang == "" {
					t.Fatal("LLVM 22 clang not found")
				}
				compileAndRunRuntimeTestForTarget(t, llc, clang, "pool_guard", triple, ir, arm64RawPoolGuardMain, nil)
			}
		})
	}
}

const arm64RawPoolGuardMain = `
#include <stdint.h>
#include <string.h>
extern void pool_guard(uint64_t *, uint64_t);
int main(void) {
  const uint32_t words[4] = {0x17b4a140, 0x17b4a141, 0x17b4a142, 0x17b4a143};
  uint8_t bytes[16];
  memcpy(bytes, words, sizeof(bytes));
  const uint64_t indexes[] = {0, 1, 3, 4, 15, 16, 255, 1ULL << 32, (1ULL << 32) + 3, UINT64_MAX};
  for (unsigned i = 0; i < sizeof(indexes) / sizeof(indexes[0]); i++) {
    uint64_t index = indexes[i];
    uint64_t result[5] = {0x1234, 0, 0, 0, 0x5678};
    pool_guard(result + 1, index);
    if (result[0] != 0x1234 || result[4] != 0x5678 ||
        result[1] != (index < 16 ? bytes[index] : 0) ||
        result[2] != (index <= 3 ? words[index] : 0) ||
        result[3] != ((uint32_t)index <= 3 ? words[(uint32_t)index] : 0)) return 1;
  }
  return 0;
}
`
