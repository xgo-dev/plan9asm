package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/arch/arm64/arm64asm"
)

func TestARM64RawPoolAliases(t *testing.T) {
	// Go asm7.go's MOVD and ADD/SUB rows include immediate, shifted and
	// extended registers. Relocation must follow every surviving alias,
	// including aliases whose original register has already been overwritten.
	const loadedDifference = "ldr x1, [x0]\nldr x2, [x0, #8]\nsub x3, x2, x1\n"
	for _, test := range []struct {
		name, body string
		want       bool
	}{
		{"copy", "mov x12, x9\nldr x0, [x12]", true},
		{"immediate-add", "add x12, x9, #8\nldr x0, [x12]", true},
		{"immediate-sub", "sub x12, x9, #8\nldr x0, [x12]", true},
		{"alias-chain", "add x10, x9, #16\nsub x12, x10, #8\nldr x0, [x12]\nmov x10, xzr", true},
		{"transient-offset-cancelled", "sub x10, x9, x1, lsl #3\nadd x12, x10, x1, lsl #3\nldr x0, [x12]\nmov x10, xzr", true},
		{"transient-add-cancelled", "add x10, x9, x1, lsl #3\nsub x12, x10, x1, lsl #3\nldr x0, [x12]\nmov x10, xzr", true},
		{
			"transient-guarded-difference",
			loadedDifference + "cmp x3, #5\nb.hi #16\n" +
				"sub x10, x9, x1, lsl #3\nadd x12, x10, x2, lsl #3\n" +
				"ldr x0, [x12]\nmov x10, xzr",
			true,
		},
		{
			"transient-guarded-overrun",
			loadedDifference + "cmp x3, #6\nb.hi #16\n" +
				"sub x10, x9, x1, lsl #3\nadd x12, x10, x2, lsl #3\n" +
				"ldr x0, [x12]\nmov x10, xzr",
			false,
		},
		{
			"transient-guarded-negative-displacement",
			loadedDifference + "cmp x3, #8\nb.lo #28\ncmp x3, #13\nb.hi #20\n" +
				"sub x10, x9, x1, lsl #3\nadd x12, x10, x2, lsl #3\n" +
				"sub x12, x12, #64\nldr x0, [x12]\nmov x10, xzr",
			true,
		},
		{
			"transient-guarded-negative-underrun",
			loadedDifference + "cmp x3, #5\nb.lo #28\ncmp x3, #13\nb.hi #20\n" +
				"sub x10, x9, x1, lsl #3\nadd x12, x10, x2, lsl #3\n" +
				"sub x12, x12, #64\nldr x0, [x12]\nmov x10, xzr",
			false,
		},
		{"transient-offset-not-cancelled", "sub x10, x9, x1, lsl #3\nadd x12, x10, x2, lsl #3\nldr x0, [x12]\nmov x10, xzr", false},
		{"transient-index-clobbered", "sub x10, x9, x1\nmov x1, x2\nadd x12, x10, x1\nldr x0, [x12]\nmov x10, xzr", false},
		{"transient-flags-observed", "sub x10, x9, x1\ncmp x10, #0\nadd x12, x10, x1\nldr x0, [x12]\nmov x10, xzr", false},
		{"transient-offset-escapes", "sub x10, x9, x1, lsl #3\nstr x10, [x0]\nadd x12, x10, x1, lsl #3\nldr x0, [x12]\nmov x10, xzr", false},
		{"transient-offset-writes", "sub x10, x9, x1, lsl #3\nadd x12, x10, x1, lsl #3\nstr x0, [x12]\nmov x10, xzr", false},
		{"original-killed", "mov x12, x9\nmov x9, xzr\nldr x0, [x12]", true},
		{"load-kills-alias", "mov x12, x9\nldr x12, [x12]", true},
		{"shifted-add", "and x1, x0, #3\nadd x12, x9, x1, lsl #3\nldr x0, [x12]", true},
		{"shifted-sub", "and x1, x0, #1\nsub x12, x9, x1, lsl #3\nldr x0, [x12]", true},
		{"commuted-add", "and x1, x0, #15\nadd x12, x1, x9\nldr x0, [x12]", true},
		{"masked-numeric-difference", "and x1, x0, #15\nadd x1, x1, #8\nand x2, x1, #24\nsub x3, x1, x2\nadd x12, x9, x3\nldrb w0, [x12]", true},
		{"masked-address-not-relocated", "and x1, x9, #-8\nsub x12, x9, x1\nldrb w0, [x12]", false},
		{"masked-address-not-an-index", "and x1, x9, #-8\nsub x2, x9, x1\nadd x12, x9, x2\nldrb w0, [x12]", false},
		{"uxtw", "and w1, w0, #3\nadd x12, x9, w1, uxtw #3\nldr x0, [x12]", true},
		{"sxtw-nonnegative", "and w1, w0, #3\nadd x12, x9, w1, sxtw #3\nldr x0, [x12]", true},
		{"unchanging-loop", "mov x12, x9\nldr x0, [x12]\ncbnz x1, #-4", true},
		{"escaping-copy", "mov x12, x9\nstr x12, [x0]\nldr x0, [x9]", false},
		{"escaping-after-kill", "mov x12, x9\nmov x9, xzr\nstr x12, [x0]\nldr x0, [x12]", false},
		{"second-alias-escapes", "mov x10, x9\nmov x12, x10\nmov x10, xzr\nldr x0, [x9]\nstr x12, [x1]", false},
		{"return-alias", "mov x0, x9\nldr x1, [x9]", false},
		{"truncated-copy", "mov w12, w9\nldr x0, [x12]", false},
		{"truncated-add", "add w12, w9, #8\nldr x0, [x12]", false},
		{"flags-observe-address", "adds x12, x9, #8\nldr x0, [x12]", false},
		{"unknown-index", "add x12, x9, x1\nldr x0, [x12]", false},
		{"shifted-address", "mov x1, #1\nadd x12, x1, x9, lsl #1\nldr x0, [x12]", false},
		{"two-addresses", "add x12, x9, x9\nldr x0, [x12]", false},
		{"two-address-aliases", "mov x10, x9\nadd x12, x9, x10\nldr x0, [x12]\nmov x10, xzr", false},
		{"two-address-aliases-shifted", "mov x10, x9\nadd x12, x9, x10, lsl #1\nldr x0, [x12]\nmov x10, xzr", false},
		{"reverse-subtraction", "mov x1, #1\nsub x12, x1, x9\nldr x0, [x12]", false},
		{"negative-sxtw", "mov w1, #-1\nadd x12, x9, w1, sxtw\nldr x0, [x12]", false},
		{"shift-overflow", "mov x1, #2\nadd x12, x9, x1, lsl #63\nldr x0, [x12]", false},
		{"out-of-bounds", "add x12, x9, #48\nldr x0, [x12]", false},
		{"negative-footprint", "sub x12, x9, #16\nldur x0, [x12, #-1]", false},
		{"alias-join", "mov x12, x9\ncbz x1, #8\nadd x12, x12, #8\nldr x0, [x12]", true},
		{"alias-join-overrun", "mov x12, x9\ncbz x1, #8\nadd x12, x12, #48\nldr x0, [x12]", false},
		{"alias-changing-loop", "mov x12, x9\nldr x0, [x12]\nadd x12, x12, #8\ncbnz x1, #-8", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			lines := append([]string{"adr x9, #0"}, strings.Split(test.body, "\n")...)
			lines = append(lines, "mov x9, xzr", "mov x12, xzr", "ret")
			lines[0] = fmt.Sprintf("adr x9, #%d", len(lines)*4+16)
			var instructions []Instr
			for _, word := range assembleARM64LLVMWords(t, lines, "") {
				instructions = append(instructions, Instr{Op: OpWORD, Args: []Operand{{Kind: OpImm, Imm: int64(word)}}})
			}
			for i := 0; i < 16; i++ {
				instructions = append(instructions, Instr{Op: OpWORD, Args: []Operand{{Kind: OpImm, Imm: 0x17b4a14d}}})
			}
			points := make([]arm64RawLayoutPoint, len(instructions))
			for i := range points {
				points[i].offset = int64(i * 4)
			}
			data, _, _ := identifyARM64UnlabelledPool(Func{Instrs: instructions}, points, map[string]bool{}, 0)
			if got := len(data) == 16; got != test.want {
				t.Fatalf("pool alias proof=%v, want %v", got, test.want)
			}
		})
	}
}

func TestARM64RawPoolAliasArithmeticForms(t *testing.T) {
	// Exercise the independent encoding axes, including all eight extension
	// modes. Signed modes require a nonnegative bound; unknown signed values
	// are covered by the rejection cases above.
	for _, op := range []string{"add", "sub"} {
		for _, modifier := range []string{"lsl", "lsr", "asr", "uxtb", "uxth", "uxtw", "uxtx", "sxtb", "sxth", "sxtw", "sxtx"} {
			for _, shift := range []int{0, 1, 4} {
				index := "x1"
				reg := arm64asm.X1
				if strings.HasSuffix(modifier, "b") || strings.HasSuffix(modifier, "h") || strings.HasSuffix(modifier, "w") {
					index, reg = "w1", arm64asm.W1
				}
				line := fmt.Sprintf("%s x12, x9, %s, %s #%d", op, index, modifier, shift)
				t.Run(line, func(t *testing.T) {
					word := assembleARM64LLVMWords(t, []string{line}, "")[0]
					values := &arm64RawPoolValues{cache: map[arm64RawPoolValue]uint64{{0, reg}: 7}}
					bounds := &arm64RawPoolBounds{size: 512, values: values}
					dest, got, ok := arm64RawPoolAlias(word, 0, 9, arm64RawPoolRange{128, 128}, bounds)
					delta := int64(7 << uint(shift))
					if modifier == "lsr" || modifier == "asr" {
						delta = 7 >> uint(shift)
					}
					want := arm64RawPoolRange{128, 128 + delta}
					if op == "sub" {
						want = arm64RawPoolRange{128 - delta, 128}
					}
					if !ok || dest != 12 || got != want {
						t.Fatalf("alias=(%d, %+v, %v), want (12, %+v, true)", dest, got, ok, want)
					}
				})
			}
		}
	}
}

func arm64RawPoolAliasesIR(t *testing.T, triple string) string {
	t.Helper()
	lines := []string{
		"adr x9, #0", "mov x10, x9", "add x12, x10, #16", "mov x9, xzr",
		"and x3, x1, #3", "add x11, x12, x3, lsl #3", "ldr x4, [x11]", "str x4, [x0]",
		"sub x11, x12, x3, lsl #2", "ldr w4, [x11]", "str x4, [x0, #8]",
		"and w3, w1, #7", "add x11, x10, w3, uxtw #2", "ldr w11, [x11]", "str x11, [x0, #16]",
		"add x11, x10, #48", "ldur x4, [x11, #-8]", "str x4, [x0, #24]",
		"mov x10, xzr", "mov x11, xzr", "mov x12, xzr", "ret",
	}
	lines[0] = fmt.Sprintf("adr x9, #%d", len(lines)*4)
	var source strings.Builder
	source.WriteString("TEXT pool_alias(SB),$0-16\nMOVD out+0(FP),R0\nMOVD index+8(FP),R1\n")
	for _, word := range assembleARM64LLVMWords(t, lines, "") {
		fmt.Fprintf(&source, "WORD $%#08x\n", word)
	}
	for i := 0; i < 12; i++ {
		fmt.Fprintf(&source, "WORD $%#08x\n", uint32(0x17b4a140+i))
	}
	source.WriteString("RET\n")
	requireARM64GoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple,
		Sigs: map[string]FuncSig{"pool_alias": {
			Name: "pool_alias", Args: []LLVMType{Ptr, I64}, Ret: Void,
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

func TestARM64RawPoolAliasesLLVM(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ir := arm64RawPoolAliasesIR(t, triple)
			compileLLVMToObject(t, llc, triple, "pool_alias.ll", "pool_alias.o", ir)
			// Linux execution is also required by the cross-runtime matrix.
			if runtime.GOARCH == "arm64" && runtime.GOOS == "darwin" && triple == "aarch64-apple-darwin" {
				clang := findLLVM22Tool("clang")
				if clang == "" {
					t.Fatal("LLVM 22 clang not found")
				}
				compileAndRunRuntimeTestForTarget(t, llc, clang, "pool_alias", triple, ir, arm64RawPoolAliasesMain, nil)
			}
		})
	}
}

const arm64RawPoolAliasesMain = `
#include <stdint.h>
#include <string.h>
extern void pool_alias(uint64_t *, uint64_t);
int main(void) {
  uint32_t words[12];
  for (unsigned i = 0; i < 12; i++) words[i] = 0x17b4a140 + i;
  const uint64_t indexes[] = {0, 1, 2, 3, 4, 7, 8, 255, UINT64_MAX};
  for (unsigned i = 0; i < sizeof(indexes) / sizeof(indexes[0]); i++) {
    uint64_t result[6] = {0x1234, 0, 0, 0, 0, 0x5678};
    uint64_t pair, last;
    memcpy(&pair, words + 4 + (indexes[i] & 3) * 2, sizeof(pair));
    memcpy(&last, words + 10, sizeof(last));
    pool_alias(result + 1, indexes[i]);
    if (result[0] != 0x1234 || result[5] != 0x5678 ||
        result[1] != pair || result[2] != words[4 - (indexes[i] & 3)] ||
        result[3] != words[indexes[i] & 7] || result[4] != last) return 1;
  }
  return 0;
}
`
