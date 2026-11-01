package plan9asm

import (
	"encoding/binary"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/arch/arm64/arm64asm"
)

func TestARM64RawPoolBoundedIndexes(t *testing.T) {
	for _, test := range []struct {
		name, body string
		want       bool
	}{
		{"constant", "mov x1, #15\nldr b0, [x9, x1]", true},
		{"mask", "and x1, x0, #15\nldr b0, [x9, x1]", true},
		{"byte-explicit-zero-shift", "and x1, x0, #15\nldrb w2, [x9, x1, lsl #0]", true},
		{"shifted-double", "and x1, x0, #1\nldr d0, [x9, x1, lsl #3]", true},
		{"uxtw", "and w1, w0, #15\nldrb w2, [x9, w1, uxtw]", true},
		{"sxtw-positive", "and w1, w0, #15\nldrb w2, [x9, w1, sxtw]", true},
		{"sxtx-positive", "and x1, x0, #15\nldrb w2, [x9, x1, sxtx]", true},
		{"byte-high-nibble", "ldrb w1, [x0]\nlsr x1, x1, #4\nldrb w2, [x9, x1]", true},
		{"select", "mov w2, #8\ncsel x1, x2, xzr, ge\nldr d0, [x9, x1]", true},
		{"select-loop", "mov w2, #8\ncsel x1, x2, xzr, ge\nldr d0, [x9, x1]\ncbnz x0, #-8", true},
		{"mask-after-loop", "add x1, x1, #1\ncbnz x0, #-4\nand x1, x1, #15\nldrb w2, [x9, x1]", true},
		{"dead-unbounded-predecessor", "b #8\nmov x1, x0\nand x1, x0, #15\nldrb w2, [x9, x1]", true},
		{"join-bounded", "cbz x0, #12\nmov x1, #8\nb #8\nmov x1, #4\nldr d0, [x9, x1]", true},
		{"definition-before-adr", "and x1, x0, #15\n@ADR@\nldrb w2, [x9, x1]", true},
		{"zero-index", "ldr q0, [x9, xzr]", true},
		{"guard-lo", "cmp x1, #16\nb.hs #8\nldrb w2, [x9, x1]", true},
		{"guard-ls", "cmp x1, #15\nb.hi #8\nldrb w2, [x9, x1]", true},
		{"guard-taken", "cmp x1, #15\nb.ls #8\nb #8\nldrb w2, [x9, x1]", true},
		{"guard-equal", "cmp x1, #15\nb.ne #8\nldrb w2, [x9, x1]", true},
		{"guard-word-index", "cmp w1, #15\nb.hi #8\nldrb w2, [x9, w1, uxtw]", true},
		{"guard-zero-fallthrough", "cbnz x1, #8\nldr q0, [x9, x1]", true},
		{"guard-zero-taken", "cbz x1, #8\nb #8\nldr q0, [x9, x1]", true},
		{"guard-preserved-flags", "cmp x1, #16\norr x3, x3, x3\nb.hs #8\nldrb w2, [x9, x1]", true},
		{"guard-register-equality", "cmp x1, x2\nnop\nb.ne #12\nsub x3, x1, x2\nldr q0, [x9, x3]", true},
		{"guard-register-zero-sum", "cmn x1, x2\nnop\nb.ne #12\nadd x3, x1, x2\nldr q0, [x9, x3]", true},
		{"guard-preserved-flags-changed-input", "cmp x1, #16\nmov x1, #16\nb.hs #8\nldrb w2, [x9, x1]", false},
		{"guard-register-equality-changed-input", "mov x2, #15\ncmp x1, x2\nmov x1, x0\nb.ne #8\nldrb w2, [x9, x1]", false},
		{"guard-preserved-flags-bypassed-compare", "cbz x0, #8\ncmp x1, #16\norr x3, x3, x3\nb.hs #8\nldrb w2, [x9, x1]", false},
		{"guard-float-clobbered-flags", "cmp x1, #16\nfcmp d0, d1\nb.hs #8\nldrb w2, [x9, x1]", false},
		{"guard-conditional-clobbered-flags", "cmp x1, #16\nccmp x0, #0, #0, eq\nb.hs #8\nldrb w2, [x9, x1]", false},
		{"guard-system-clobbered-flags", "cmp x1, #16\nmsr nzcv, x0\nb.hs #8\nldrb w2, [x9, x1]", false},
		{"guard-memory-preserved-flags", "cmp x1, #16\nldr x2, [x0], #8\nb.hs #8\nldrb w2, [x9, x1]", true},
		{"guard-memory-clobbered-input", "cmp x1, #16\nldr x2, [x1], #1\nb.hs #8\nldrb w2, [x9, x1]", false},
		{"guard-cmn-wrap", "sub x2, x1, #16\ncmn x2, #15\nb.lo #8\nldrb w2, [x9, x1]", true},
		{"guard-cmn-taken", "sub x2, x1, #16\ncmn x2, #15\nb.hs #8\nb #8\nldrb w2, [x9, x1]", true},
		{"guard-affine-difference", "sub x2, x3, x4\nsub x5, x2, #16\ncmn x5, #15\nb.lo #12\nsub x1, x3, x4\nldrb w2, [x9, x1]", true},
		{"guard-affine-scaled", "sub x2, x3, x4\ncmp x2, #3\nb.hi #16\nlsl x1, x3, #2\nsub x1, x1, x4, lsl #2\nldr w2, [x9, x1]", true},
		{"guard-mask-exact", "cmp x1, #8\nb.lo #24\ncmp x1, #15\nb.hi #16\nand x2, x1, #24\nsub x2, x2, #8\nldr q0, [x9, x2]", true},
		{"guard-mask-overrun", "cmp x1, #8\nb.lo #24\ncmp x1, #16\nb.hi #16\nand x2, x1, #24\nsub x2, x2, #8\nldr q0, [x9, x2]", false},
		{"guard-bit-infeasible-nonzero", "cmp x1, #15\nb.ls #20\ncmp x1, #19\nb.hi #16\ntbnz w1, #3, #8\nb #8\nldrb w2, [x9, x1]", true},
		{"guard-bit-infeasible-zero", "cmp x1, #15\nb.ls #20\ncmp x1, #19\nb.hi #16\ntbz x1, #4, #8\nb #8\nldrb w2, [x9, x1]", true},
		{"guard-bit-feasible-overrun", "cmp x1, #15\nb.ls #20\ncmp x1, #19\nb.hi #16\ntbnz x1, #4, #8\nb #8\nldrb w2, [x9, x1]", false},
		{"guard-bit-redefined-index", "cmp x1, #15\nb.ls #24\ncmp x1, #19\nb.hi #20\ntbnz w1, #3, #12\nmov x1, #16\nb #4\nldrb w2, [x9, x1]", false},
		{"guard-cmn-wrong-edge", "sub x2, x1, #16\ncmn x2, #15\nb.hs #8\nldrb w2, [x9, x1]", false},
		{"guard-cmn-bypassed", "sub x2, x1, #16\ncbz x0, #8\ncmn x2, #15\nb.lo #8\nldrb w2, [x9, x1]", false},
		{"guard-cmn-word-not-whole-register", "sub w2, w1, #16\ncmn w2, #15\nb.lo #8\nldrb w2, [x9, x1]", false},
		{"guard-affine-changed-source", "sub x2, x3, x4\ncmp x2, #15\nb.hi #16\nadd x3, x3, #1\nsub x1, x3, x4\nldrb w2, [x9, x1]", false},
		{"guard-changing-flags", "cmp x1, #16\nadds x2, x2, #1\nb.hs #8\nldrb w2, [x9, x1]", false},
		{"guard-bypassed-compare", "cbz x0, #8\ncmp x1, #16\nb.hs #8\nldrb w2, [x9, x1]", false},
		{"guard-bypassed-bound", "cmp x1, #16\nb.lo #8\nnop\nldrb w2, [x9, x1]", false},
		{"guard-word-not-whole-register", "cmp w1, #16\nb.hs #8\nldrb w2, [x9, x1]", false},
		{"guard-signed-negative", "cmp x1, #16\nb.ge #8\nldrb w2, [x9, x1]", false},
		{"guard-redefined-index", "cmp x1, #16\nb.hs #12\nmov x1, x0\nldrb w2, [x9, x1]", false},
		{"guard-converged-edges", "cmp x1, #16\nb.hs #4\nldrb w2, [x9, x1]", false},
		{"unbounded", "ldr b0, [x9, x1]", false},
		{"mask-bypassed", "cbz x0, #8\nand x1, x1, #15\nldrb w2, [x9, x1]", false},
		{"join-too-large", "cbz x0, #12\nmov x1, #16\nb #8\nmov x1, #4\nldrb w2, [x9, x1]", false},
		{"loop-changing", "mov x1, #0\nldrb w2, [x9, x1]\nadd x1, x1, #1\ncbnz x0, #-8", false},
		{"select-unbounded", "csel x1, x0, xzr, ge\nldrb w2, [x9, x1]", false},
		{"load-overrun", "mov x1, #15\nldr h0, [x9, x1]", false},
		{"shift-overrun", "mov x1, #2\nldr d0, [x9, x1, lsl #3]", false},
		{"signed-negative", "mov w1, #-1\nldrb w2, [x9, w1, sxtw]", false},
		{"unsigned-large", "mov w1, #-1\nldrb w2, [x9, w1, uxtw]", false},
		{"writeback-clobber", "mov x1, #0\nldr w2, [x1], #32\nldrb w2, [x9, x1]", false},
		{"pair-second-clobber", "mov x1, #0\nldp x2, x1, [x0]\nldrb w2, [x9, x1]", false},
		{"gp-from-vector-clobber", "mov x1, #0\nfmov x1, d0\nldrb w2, [x9, x1]", false},
		{"move-keep-clobber", "mov x1, #0\nmovk x1, #1, lsl #48\nldrb w2, [x9, x1]", false},
		{"system-clobber-before-adr", "mov x1, #0\nmrs x1, tpidr_el0\n@ADR@\nldrb w2, [x9, x1]", false},
		{"unknown-before-adr", "mov x1, #0\nnop\n@ADR@\nldrb w2, [x9, x1]", false},
		{"unknown-word-clobber", "mov x1, #0\nnop\nldrb w2, [x9, x1]", false},
		{"address-as-index", "and x1, x0, #15\nldrb w2, [x1, x9]", false},
		{"indexed-store", "mov x1, #0\nstrb w2, [x9, x1]", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := test.body
			if !strings.Contains(body, "@ADR@") {
				body = "@ADR@\n" + body
			}
			lines := strings.Split(body, "\n")
			for i, line := range lines {
				if line == "@ADR@" {
					lines[i] = fmt.Sprintf("adr x9, #%d", (len(lines)+2-i)*4)
				}
			}
			lines = append(lines, "mov x9, xzr", "ret")
			var instructions []Instr
			for _, word := range assembleARM64LLVMWords(t, lines, "") {
				if strings.HasPrefix(test.name, "unknown-") && word == 0xd503201f {
					word = 0xffffffff
				}
				instructions = append(instructions, Instr{Op: OpWORD, Args: []Operand{{Kind: OpImm, Imm: int64(word)}}})
			}
			for i := 0; i < 4; i++ {
				instructions = append(instructions, Instr{Op: OpWORD, Args: []Operand{{Kind: OpImm, Imm: 0x17b4a14d}}})
			}
			points := make([]arm64RawLayoutPoint, len(instructions))
			for i := range points {
				points[i].offset = int64(i * 4)
			}
			data, _, _ := identifyARM64UnlabelledPool(Func{Instrs: instructions}, points, map[string]bool{}, 0)
			if got := len(data) == 4; got != test.want {
				for _, ins := range instructions[:len(lines)] {
					var code [4]byte
					word := uint32(ins.Args[0].Imm)
					binary.LittleEndian.PutUint32(code[:], word)
					decoded, _ := arm64asm.Decode(code[:])
					writes, known := arm64RawPoolGPWrites(word)
					t.Logf("%s args=%#v writes=%x known=%v", decoded, decoded.Args, writes, known)
				}
				t.Fatalf("pool proof=%v, want %v", got, test.want)
			}
		})
	}
}

func TestARM64RawPoolIndexedMemoryForms(t *testing.T) {
	// Go's C_ROFF load rows cover integer signed/unsigned widths and scalar
	// floating/vector destinations. Exercise each encoding with every index
	// extension and its optional natural-size shift, including byte LSL #0.
	for _, load := range []struct {
		op, reg string
		shift   int
	}{
		{"ldrb", "w0", 0}, {"ldrh", "w0", 1},
		{"ldrsb", "w0", 0}, {"ldrsb", "x0", 0},
		{"ldrsh", "w0", 1}, {"ldrsh", "x0", 1}, {"ldrsw", "x0", 2},
		{"ldr", "w0", 2}, {"ldr", "x0", 3},
		{"ldr", "b0", 0}, {"ldr", "h0", 1}, {"ldr", "s0", 2},
		{"ldr", "d0", 3}, {"ldr", "q0", 4},
	} {
		for _, index := range []string{"x1", "x1, lsl", "w1, uxtw", "w1, sxtw", "x1, sxtx"} {
			for _, shifted := range []bool{false, true} {
				if shifted && index == "x1" {
					continue
				}
				address := index
				if shifted {
					address += fmt.Sprintf(" #%d", load.shift)
				} else if index == "x1, lsl" {
					continue // LSL requires the amount; plain X1 is the omitted form.
				}
				line := fmt.Sprintf("%s %s, [x9, %s]", load.op, load.reg, address)
				t.Run(line, func(t *testing.T) {
					word := assembleARM64LLVMWords(t, []string{line}, "")[0]
					var code [4]byte
					binary.LittleEndian.PutUint32(code[:], word)
					ins, err := arm64asm.Decode(code[:])
					if err != nil {
						t.Fatal(err)
					}
					memory := ins.Args[1].(arm64asm.MemExtend)
					flow := &arm64RawPoolValues{cache: map[arm64RawPoolValue]uint64{{0, memory.Index}: 1}}
					width := int64(1) << uint(load.shift)
					displacement := int64(1)
					if shifted {
						displacement = width
					}
					bounds := &arm64RawPoolBounds{size: displacement + width, values: flow}
					if !arm64RawPoolIndexedLoadInBounds(ins, word, memory, 0, 0, bounds) {
						t.Fatal("exact ending footprint rejected")
					}
					bounds.size--
					if arm64RawPoolIndexedLoadInBounds(ins, word, memory, 0, 0, bounds) {
						t.Fatal("one-byte overrun accepted")
					}
				})
			}
		}
	}
}

func arm64RawPoolIndexedIR(t *testing.T, triple string) string {
	t.Helper()
	lines := []string{
		"adr x9, #0", "and x3, x1, #15", "ldrb w4, [x9, x3, lsl #0]", "str x4, [x0]",
		"mov w5, #8", "cmp x2, #0", "csel x3, x5, xzr, ge", "ldr d0, [x9, x3]", "str d0, [x0, #8]",
		"and w3, w1, #15", "ldrb w4, [x9, w3, sxtw]", "str x4, [x0, #16]",
		"and w3, w1, #7", "ldrh w4, [x9, w3, uxtw #1]", "str x4, [x0, #24]",
		"mov x9, xzr", "ret",
	}
	lines[0] = fmt.Sprintf("adr x9, #%d", len(lines)*4)
	var source strings.Builder
	source.WriteString("TEXT pool_index(SB),$0-24\nMOVD out+0(FP),R0\nMOVD index+8(FP),R1\nMOVD choose+16(FP),R2\n")
	for _, word := range assembleARM64LLVMWords(t, lines, "") {
		fmt.Fprintf(&source, "WORD $%#08x\n", word)
	}
	for _, word := range []uint32{0x17b4a14d, 0x03020100, 0x07060504, 0x0b0a0908} {
		fmt.Fprintf(&source, "WORD $%#08x\n", word)
	}
	source.WriteString("RET\n")
	requireARM64GoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple,
		Sigs: map[string]FuncSig{"pool_index": {
			Name: "pool_index", Args: []LLVMType{Ptr, I64, I64}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1},
				{Offset: 8, Type: I64, Index: 1, Field: -1},
				{Offset: 16, Type: I64, Index: 2, Field: -1},
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return ir
}

func TestARM64RawPoolIndexedLLVM(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			compileLLVMToObject(t, llc, triple, "pool_index.ll", "pool_index.o", arm64RawPoolIndexedIR(t, triple))
		})
	}
}

const arm64RawPoolIndexedMain = `
#include <stdint.h>
#include <string.h>
extern void pool_index(uint64_t *, uint64_t, int64_t);
int main(void) {
  const uint8_t bytes[16] = {0x4d, 0xa1, 0xb4, 0x17, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};
  const uint64_t indexes[] = {0, 1, 15, 16, 255, UINT64_MAX};
  for (unsigned i = 0; i < sizeof(indexes) / sizeof(indexes[0]); i++) {
    for (int choice = -1; choice <= 1; choice++) {
      uint64_t result[6] = {0x1234, 0, 0, 0, 0, 0x5678};
      uint64_t expected;
      uint16_t half;
      memcpy(&expected, bytes + (choice >= 0 ? 8 : 0), sizeof(expected));
      memcpy(&half, bytes + (indexes[i] & 7) * 2, sizeof(half));
      pool_index(result + 1, indexes[i], choice);
      if (result[0] != 0x1234 || result[5] != 0x5678 ||
          result[1] != bytes[indexes[i] & 15] || result[2] != expected ||
          result[3] != bytes[indexes[i] & 15] || result[4] != half) return 1;
    }
  }
  return 0;
}
`
