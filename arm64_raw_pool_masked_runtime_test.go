package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func arm64RawPoolMaskedIR(t *testing.T, triple string) string {
	t.Helper()
	lines := []string{"adr x9,#0", "mov x2,#15", "mov x3,#-16", "mov x6,#16", "mov x7,#19"}
	forms := []string{"and x4,x1,x2", "and x4,x2,x1", "bic x4,x1,x3", "and x4,x1,#15"}
	for mode, limits := range [][2]string{{"#16", "#19"}, {"x6", "x7"}} {
		for index, form := range forms {
			lines = append(lines, "cmp x1,"+limits[0], "b.lo #32", "cmp x1,"+limits[1], "b.hi #24", form,
				"sub x5,x1,x4", "sub x5,x5,#16", "ldr x5,[x9,x5]", fmt.Sprintf("str x5,[x0,#%d]", (mode*len(forms)+index)*8))
		}
	}
	for index, compare := range []string{"cmp x11,x4", "cmp x4,x11"} {
		start := len(lines)
		lines = append(lines, "cmp x1,#16", "b.lo #0", "cmp x1,#19", "b.hi #0",
			"mov x10,x9", "mov x11,x1", "and x4,x1,x2")
		head := len(lines)
		// A second iteration would read beyond the twenty-four-byte pool. The
		// relational zero proof must establish that the backedge is impossible.
		lines = append(lines, "ldr x5,[x10],#24", "sub x11,x11,x6", compare)
		lines = append(lines, fmt.Sprintf("b.ne #%d", (head-len(lines))*4),
			fmt.Sprintf("str x5,[x0,#%d]", 64+index*8), "mov x10,xzr")
		lines[start+1] = fmt.Sprintf("b.lo #%d", (len(lines)-start-1)*4)
		lines[start+3] = fmt.Sprintf("b.hi #%d", (len(lines)-start-3)*4)
	}
	// The alternative load is genuinely out of bounds. Only the proved
	// incoming 16..19 interval makes its branch impossible.
	lines = append(lines, "and x12,x1,#3", "add x12,x12,#16", "mov x6,#32",
		"cmp x12,x6", "b.hs #12", "ldr x5,[x9]", "b #8", "ldr x5,[x9,#24]",
		"str x5,[x0,#80]")
	for index := 0; index < 4; index++ {
		ascending, carried := index&1 != 0, index&2 != 0
		lines = append(lines, "and x11,x1,#8", "add x11,x11,#8", "mov x12,#0")
		copy, update := "mov x10,x11", "sub x11,x11,#8"
		if ascending {
			lines = append(lines, "neg x11,x11")
			copy, update = "neg x10,x11", "add x11,x11,#8"
		}
		if carried {
			lines = append(lines, copy, "sub x10,x10,#8", "add x10,x9,x10")
		}
		head := len(lines)
		if carried {
			lines = append(lines, "ldr x5,[x10],#-8")
		} else {
			lines = append(lines, copy, "sub x10,x10,#8", "ldr x5,[x9,x10]")
		}
		lines = append(lines, "add x12,x12,x5", update)
		lines = append(lines, fmt.Sprintf("cbnz x11,#%d", (head-len(lines))*4),
			fmt.Sprintf("str x12,[x0,#%d]", 88+index*8), "mov x10,xzr")
	}
	lines = append(lines, "mov x6,#-25")
	for index, mask := range []string{"and x10,x11,#24", "ands x10,x11,#24", "bic x10,x11,x6", "bics x10,x11,x6"} {
		lines = append(lines, "and x11,x1,#15", "add x11,x11,#8", mask,
			"sub x10,x11,x10", "ldrb w5,[x9,x10]", fmt.Sprintf("str x5,[x0,#%d]", 120+index*8))
	}
	for index, ascending := range []bool{false, true} {
		lines = append(lines, "and x11,x1,#8", "add x11,x11,#8", "and x12,x1,#7",
			"add x10,x11,x12", "sub x10,x10,#4", "add x10,x9,x10", "mov x12,#0")
		update := "sub x11,x11,#8"
		if ascending {
			lines = append(lines, "neg x11,x11")
			update = "add x11,x11,#8"
		}
		head := len(lines)
		lines = append(lines, "ldrb w5,[x10],#-8", "add x12,x12,x5", update)
		lines = append(lines, fmt.Sprintf("cbnz x11,#%d", (head-len(lines))*4),
			fmt.Sprintf("str x12,[x0,#%d]", 152+index*8), "mov x10,xzr")
	}
	lines = append(lines, "and x11,x1,#15", "add x11,x11,#8", "and x10,x11,#24",
		"cmp x11,x10", "b.eq #20", "sub x10,x11,x10", "sub x10,x10,#1",
		"ldrb w5,[x9,x10]", "str x5,[x0,#168]")
	// The earlier loop preserves a relation expressed using different copies
	// of the length. Its guard excludes a zero remainder before the later
	// countdown indexes the pool. The input is also an arbitrary base offset,
	// including values for which base+length wraps at the machine width.
	lines = append(lines, "and x17,x1,#15", "add x17,x17,#8", "mov x16,x1",
		"add x14,x16,x17", "and x6,x17,#24", "neg x7,x6",
		"nop", "add x7,x7,#8", "cbnz x7,#-8", "cmp x17,x6",
		"b.eq #44", "sub x17,x14,x6", "add x6,x6,x16", "sub x16,x17,x16", "mov x12,#0",
		"sub x7,x16,#1", "ldrb w5,[x9,x7]", "add x12,x12,x5", "subs x16,x16,#1", "b.ne #-16",
		"str x12,[x0,#176]")
	for index, op := range []string{"orr", "eor"} {
		lines = append(lines, "and x11,x1,#15", "add x11,x11,#8", "and x10,x11,#24",
			"and x12,x1,#1", op+" x10,x10,x12", "sub x10,x10,x12", "sub x10,x11,x10",
			"ldrb w5,[x9,x10]", fmt.Sprintf("str x5,[x0,#%d]", 184+index*8))
	}
	lines = append(lines, "mov x9,xzr", "ret")
	lines[0] = fmt.Sprintf("adr x9,#%d", len(lines)*4)
	var source strings.Builder
	source.WriteString("TEXT pool_masked(SB),$0-16\nMOVD out+0(FP),R0\nMOVD input+8(FP),R1\n")
	for _, word := range assembleARM64LLVMWords(t, lines, "") {
		fmt.Fprintf(&source, "WORD $%#08x\n", word)
	}
	for index := 0; index < 6; index++ {
		fmt.Fprintf(&source, "WORD $%#x\n", 0x17b4a140+index)
	}
	source.WriteString("RET\n")
	requireARM64GoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple,
		Sigs: map[string]FuncSig{"pool_masked": {
			Name: "pool_masked", Args: []LLVMType{Ptr, I64}, Ret: Void,
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

func TestARM64RawPoolMaskedLLVM(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ir := arm64RawPoolMaskedIR(t, triple)
			compileLLVMToObject(t, llc, triple, "pool_masked.ll", "pool_masked.o", ir)
			if runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && triple == "aarch64-apple-darwin" {
				clang := findLLVM22Tool("clang")
				if clang == "" {
					t.Fatal("LLVM 22 clang not found")
				}
				compileAndRunRuntimeTestForTarget(t, llc, clang, "pool_masked", triple, ir, arm64RawPoolMaskedMain, nil)
			}
		})
	}
}

const arm64RawPoolMaskedMain = `
#include <stdint.h>
#include <string.h>
extern void pool_masked(uint64_t *, uint64_t);
int main(void) {
  const uint64_t inputs[] = {0, 1, 15, 16, 17, 18, 19, 20, 31, 255, UINT64_C(1)<<63, UINT64_MAX};
  const uint64_t poolWords[] = {UINT64_C(0x17b4a14117b4a140), UINT64_C(0x17b4a14317b4a142), UINT64_C(0x17b4a14517b4a144)};
  uint8_t poolBytes[24];
  memcpy(poolBytes, poolWords, sizeof(poolBytes));
  for (unsigned test = 0; test < 32 + sizeof(inputs)/sizeof(inputs[0]); test++) {
    uint64_t out[27] = {0x1234};
    out[26] = 0x5678;
    uint64_t n = test < 32 ? test : inputs[test - 32];
    pool_masked(out+1, n);
    if (out[0] != 0x1234 || out[26] != 0x5678) return 1;
    uint64_t expected = n >= 16 && n <= 19 ? UINT64_C(0x17b4a14117b4a140) : 0;
    for (unsigned form = 0; form < 10; form++) {
      if (out[form+1] != expected) return 2;
    }
    if (out[11] != UINT64_C(0x17b4a14117b4a140)) return 3;
    uint64_t sum = UINT64_C(0x17b4a14117b4a140);
    if (n & 8) sum += UINT64_C(0x17b4a14317b4a142);
    for (unsigned form = 12; form < 16; form++) {
      if (out[form] != sum) return 4;
    }
    uint64_t remainderByte = (UINT64_C(0x17b4a14117b4a140) >> ((n & 7) * 8)) & 255;
    for (unsigned form = 16; form < 20; form++) {
      if (out[form] != remainderByte) return 5;
    }
    uint64_t byteSum = 0;
    for (unsigned remaining = (n & 8) + 8; remaining; remaining -= 8) {
      byteSum += poolBytes[remaining + (n & 7) - 4];
    }
    if (out[20] != byteSum || out[21] != byteSum) return 6;
    if (out[22] != ((n & 7) ? poolBytes[(n & 7) - 1] : 0)) return 7;
    uint64_t tailSum = 0;
    for (unsigned index = 0; index < (n & 7); index++) tailSum += poolBytes[index];
    if (out[23] != tailSum) return 8;
    if (out[24] != poolBytes[n & 7] || out[25] != poolBytes[n & 7]) return 9;
  }
  return 0;
}
`
