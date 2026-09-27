package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func arm64RawPoolLoopIR(t *testing.T, triple string) string {
	t.Helper()
	lines := []string{
		"adr x9, #0", "mov x4, xzr", "cmp x1, #7", "b.hi #0", "cbz x1, #0",
		"ldr x3, [x9, x1, lsl #3]", "add x4, x4, x3", "subs x1, x1, #1",
	}
	for i := 0; i < 12; i++ {
		lines = append(lines, "ext v0.16b, v1.16b, v2.16b, #8", "uxtl v3.4s, v4.4h",
			"cmhi v5.8b, v6.8b, v7.8b", "mul x2, xzr, xzr")
	}
	lines = append(lines, fmt.Sprintf("b.ne #%d", (5-len(lines))*4))
	lines[3] = fmt.Sprintf("b.hi #%d", (len(lines)-3)*4)
	lines[4] = fmt.Sprintf("cbz x1, #%d", (len(lines)-4)*4)
	lines = append(lines,
		"str x4, [x0]",

		"add x10, x9, #32", "mov x2, #-8",
		"ldp q0, q1, [x10], #-64", "add x2, x2, #8", "cbnz x2, #-8",
		"stp q0, q1, [x0, #16]",

		"mov x10, x9", "mov x2, #16",
		"ldp q2, q3, [x10, #16]!", "sub x2, x2, #16", "cbnz x2, #-8",
		"stp q2, q3, [x0, #48]",

		"add x10, x9, #24", "ldr x2, [x10], #8", "ldr x3, [x10, #8]!",
		"stp x2, x3, [x0, #80]",

		"mov x10, x9", "cbz x1, #8", "adr x10, #0",
		"sub x12, x10, x2", "add x12, x12, x2", "ldr x3, [x12]", "str x3, [x0, #96]",
	)
	output := 104
	for _, op := range []string{"orr", "eor"} {
		for _, source := range []struct {
			operand string
			value   int
		}{
			{"x4", 16}, {"x4, lsl #4", 1}, {"x4, lsr #1", 32},
			{"x4, asr #1", 32}, {"x4, ror #63", 8}, {"#16", 0},
		} {
			lines = append(lines, "and x2, x1, #1", fmt.Sprintf("mov x4, #%d", source.value),
				fmt.Sprintf("%s x3, x2, %s", op, source.operand),
				"ldrb w3, [x9, x3]", fmt.Sprintf("str x3, [x0, #%d]", output))
			output += 8
		}
	}
	for _, branch := range []struct{ up, down string }{
		{"lt", "gt"}, {"lo", "hi"}, {"le", "ge"}, {"ls", "hs"},
	} {
		for _, ascending := range []bool{true, false} {
			for _, reversed := range []bool{false, true} {
				initial, difference, update := 8, "sub x5, x3, x2", "add x2, x2, #1"
				condition, compare := branch.up, "cmp x2, x3"
				if !ascending {
					initial, difference, update = 24, "sub x5, x2, x3", "sub x2, x2, #1"
					condition = branch.down
				}
				if reversed {
					compare = "cmp x3, x2"
					condition = branch.down
					if !ascending {
						condition = branch.up
					}
				}
				lines = append(lines, "and x2, x1, #7", fmt.Sprintf("add x2, x2, #%d", initial),
					"mov x3, #16", "mov x4, xzr")
				head := len(lines)
				lines = append(lines, difference, "ldrb w5, [x9, x5]", "add x4, x4, x5",
					update, compare, "orr w6, w6, w7")
				lines = append(lines, fmt.Sprintf("b.%s #%d", condition, (head-len(lines))*4),
					fmt.Sprintf("str x4, [x0, #%d]", output))
				output += 8
			}
		}
	}
	lines = append(lines,
		"and x2, x1, #7", "add x2, x2, #8", "and x4, x2, #0xfffffffffffffff8",
		"sub x5, x2, x4", "cmp x2, x4", "mov x4, xzr", "b.eq #16",
		"sub x5, x5, #1", "ldrb w5, [x9, x5]", fmt.Sprintf("str x5, [x0, #%d]", output),

		"adds x2, x1, #1", "mov x5, x2", "mov x2, xzr", "b.ne #12",
		"ldrb w5, [x9, x5]", fmt.Sprintf("str x5, [x0, #%d]", output+8),

		"and x2, x1, #15", "mov x5, x2", "cmp x2, #7", "mov x2, xzr", "b.hi #12",
		"ldrb w5, [x9, x5]", fmt.Sprintf("str x5, [x0, #%d]", output+16),
	)
	output += 24
	for _, reverse := range []bool{true, false} {
		lines = append(lines, "and x3, x1, #7", "add x3, x3, #1", "mov x2, xzr", "mov x4, xzr")
		load := "ldr x5, [x10], #-8"
		if reverse {
			lines = append(lines, "add x10, x9, x3, lsl #3", "sub x10, x10, #8")
		} else {
			lines = append(lines, "add x10, x9, #64", "sub x10, x10, x3, lsl #3")
			load = "ldr x5, [x10], #8"
		}
		head := len(lines)
		lines = append(lines, load, "add x4, x4, x5", "add x2, x2, #1", "cmp x2, x3")
		lines = append(lines, fmt.Sprintf("b.lt #%d", (head-len(lines))*4),
			fmt.Sprintf("str x4, [x0, #%d]", output), "mov x10, xzr")
		output += 8
	}
	lines = append(lines,
		"and x2, x1, #7", "str x2, [sp, #8]", "mov x2, #99", "ldr x3, [sp, #8]",
		"ldr x3, [x9, x3, lsl #3]", fmt.Sprintf("str x3, [x0, #%d]", output),
		"and x2, x1, #3", "add x4, x2, #4", "stp x2, x4, [sp, #8]",
		"mov x2, #99", "mov x4, #99", "ldp x2, x4, [sp, #8]",
		"ldr x2, [x9, x2, lsl #3]", "ldr x4, [x9, x4, lsl #3]",
		fmt.Sprintf("str x2, [x0, #%d]", output+8), fmt.Sprintf("str x4, [x0, #%d]", output+16),
	)
	output += 24
	for _, division := range []struct {
		divisor, multiplier uint64
		pre, post           uint
	}{
		{3, 0xaaaaaaaaaaaaaaab, 0, 1}, {5, 0xcccccccccccccccd, 0, 2},
		{10, 0xcccccccccccccccd, 0, 3}, {100, 0x28f5c28f5c28f5c3, 2, 2},
		{8, 0x8000000000000000, 2, 0},
	} {
		lines = append(lines, arm64PoolMaterialize("x15", division.multiplier)...)
		lines = append(lines, fmt.Sprintf("mov x16, #%d", division.divisor), "mov x21, x1",
			fmt.Sprintf("lsr x7, x1, #%d", division.pre), "umulh x7, x7, x15",
			fmt.Sprintf("lsr x7, x7, #%d", division.post), "msub x22, x7, x16, x21",
			"ldrb w22, [x9, x22]", fmt.Sprintf("str x22, [x0, #%d]", output))
		output += 8
	}
	lines = append(lines, "mov x16, #7", "udiv x7, x1, x16", "msub x22, x7, x16, x1",
		"ldrb w22, [x9, x22]", fmt.Sprintf("str x22, [x0, #%d]", output))
	output += 8
	lines = append(lines, arm64PoolMaterialize("x15", 0x28f5c28f5c28f5c3)...)
	lines = append(lines, "and x2, x1, #16383", "mov x21, x2",
		"lsr x7, x2, #2", "umulh x7, x7, x15", "lsr x7, x7, #2",
		"lsr x21, x21, #4", "cmp x21, #624", "b.hi #12",
		"ldrb w7, [x9, x7]", fmt.Sprintf("str x7, [x0, #%d]", output),
		"mov x12, xzr", "mov x9, xzr", "mov x10, xzr", "ret")
	lines[0] = fmt.Sprintf("adr x9, #%d", len(lines)*4)
	for at, line := range lines {
		if line == "adr x10, #0" {
			lines[at] = fmt.Sprintf("adr x10, #%d", (len(lines)-at)*4+8)
		}
	}
	var source strings.Builder
	source.WriteString("TEXT pool_loop(SB),$32-16\nMOVD out+0(FP),R0\nMOVD count+8(FP),R1\n")
	for _, word := range assembleARM64LLVMWords(t, lines, "") {
		fmt.Fprintf(&source, "WORD $%#08x\n", word)
	}
	for i := 0; i < 32; i++ {
		fmt.Fprintf(&source, "WORD $%#08x\n", uint32(0x17b4a140+i))
	}
	source.WriteString("RET\n")
	requireARM64GoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple,
		Sigs: map[string]FuncSig{"pool_loop": {
			Name: "pool_loop", Args: []LLVMType{Ptr, I64}, Ret: Void,
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

func TestARM64RawPoolLoopLLVM(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ir := arm64RawPoolLoopIR(t, triple)
			compileLLVMToObject(t, llc, triple, "pool_loop.ll", "pool_loop.o", ir)
			if runtime.GOARCH == "arm64" && runtime.GOOS == "darwin" && triple == "aarch64-apple-darwin" {
				clang := findLLVM22Tool("clang")
				if clang == "" {
					t.Fatal("LLVM 22 clang not found")
				}
				compileAndRunRuntimeTestForTarget(t, llc, clang, "pool_loop", triple, ir, arm64RawPoolLoopMain, nil)
			}
		})
	}
}

const arm64RawPoolLoopMain = `
#include <stdint.h>
#include <stdio.h>
#include <string.h>
extern void pool_loop(uint64_t *, uint64_t);
int main(void) {
  uint32_t words[32];
  for (unsigned i = 0; i < 32; i++) words[i] = 0x17b4a140 + i;
  uint64_t values[16];
  memcpy(values, words, sizeof(values));
  const uint64_t counts[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 15, 16, 17, 19, 20, 23, 32, 255,
                             1234, 9999, 10000, 16383, 1ULL << 32, 1ULL << 63, UINT64_MAX};
  for (unsigned i = 0; i < sizeof(counts) / sizeof(counts[0]); i++) {
    uint64_t result[58] = {0}, expected[56] = {0};
    result[0] = 0x12345678;
    result[57] = 0x87654321;
    if (counts[i] <= 7) {
      for (uint64_t n = 1; n <= counts[i]; n++) expected[0] += values[n];
    }
    memcpy(expected + 2, values + 4, 32);
    memcpy(expected + 6, values + 2, 32);
    expected[10] = values[3];
    expected[11] = values[5];
    expected[12] = values[counts[i] > 7 ? 1 : 0];
    const uint8_t *bytes = (const uint8_t *)words;
    uint64_t remaining = counts[i] > 7 ? counts[i] : 0;
    for (unsigned j = 13; j < 25; j++) expected[j] = bytes[16 + (remaining & 1)];
    unsigned output = 25;
    for (unsigned kind = 0; kind < 4; kind++) {
      for (unsigned direction = 0; direction < 2; direction++) {
        for (unsigned reversed = 0; reversed < 2; reversed++) {
          unsigned distance = direction ? 8 + (remaining & 7) : 8 - (remaining & 7);
          for (unsigned n = kind < 2 ? 1 : 0; n <= distance; n++) expected[output] += bytes[n];
          output++;
        }
      }
    }
    if ((remaining & 7) != 0) expected[41] = bytes[(remaining & 7) - 1];
    if (remaining == UINT64_MAX) expected[42] = bytes[0];
    if ((remaining & 15) <= 7) expected[43] = bytes[remaining & 15];
    unsigned distance = (remaining & 7) + 1;
    for (unsigned n = 0; n < distance; n++) {
      expected[44] += values[n];
      expected[45] += values[7-n];
    }
    expected[46] = values[remaining & 7];
    expected[47] = values[remaining & 3];
    expected[48] = values[4 + (remaining & 3)];
    const unsigned divisors[] = {3, 5, 10, 100, 8, 7};
    for (unsigned j = 0; j < 6; j++) expected[49+j] = bytes[remaining % divisors[j]];
    if ((remaining & 16383) <= 9999) expected[55] = bytes[(remaining & 16383) / 100];
    pool_loop(result + 1, counts[i]);
    if (result[0] != 0x12345678 || result[57] != 0x87654321) {
      fprintf(stderr, "pool loop overwrote a canary for count %llu\n", (unsigned long long)counts[i]);
      return 1;
    }
    for (unsigned j = 0; j < sizeof(expected) / sizeof(expected[0]); j++) {
      if (result[j+1] != expected[j]) {
        fprintf(stderr, "pool loop count=%llu output=%u actual=%llx expected=%llx\n",
                (unsigned long long)counts[i], j,
                (unsigned long long)result[j+1], (unsigned long long)expected[j]);
        return 1;
      }
    }
  }
  return 0;
}
`
