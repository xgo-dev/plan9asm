package plan9asm

import (
	"encoding/binary"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/arch/arm64/arm64asm"
)

func TestARM64RawPoolBoundedOffsets(t *testing.T) {
	for _, test := range []struct {
		name, body string
		want       bool
	}{
		{"add", "add x9, x9, #16\nldr q0, [x9]", true},
		{"subtract", "sub x9, x9, #16\nldr q0, [x9]", true},
		{"negative-load-offset", "add x9, x9, #16\nldur x0, [x9, #-32]", true},
		{"pair-end", "add x9, x9, #32\nldp x0, x1, [x9]", true},
		{"scalar-post-index", "ldr x0, [x9], #8\nldr x1, [x9]", true},
		{"scalar-pre-index", "ldr x0, [x9, #-16]!\nldr x1, [x9]", true},
		{"pair-post-index", "ldp q0, q1, [x9], #16\nldp q2, q3, [x9]", true},
		{"pair-pre-index", "ldp q0, q1, [x9, #16]!", true},
		{"post-index-transient-before-pool", "ldr x0, [x9], #-32\nadd x9, x9, #32\nldr x1, [x9]", true},
		{"post-index-underrun", "ldr x0, [x9], #-32\nldr x1, [x9]", false},
		{"post-index-overrun", "ldr x0, [x9], #48\nldr x1, [x9]", false},
		{"pre-index-overrun", "ldp q0, q1, [x9, #32]!", false},
		{"countdown-index", "mov x1, #5\nldr x0, [x9, x1, lsl #3]\nsubs x1, x1, #1\nb.ne #-8", true},
		{"countdown-index-overrun", "mov x1, #6\nldr x0, [x9, x1, lsl #3]\nsubs x1, x1, #1\nb.ne #-8", false},
		{"single-vector-iteration", "mov x1, #16\nldp q0, q1, [x9], #64\nsub x1, x1, #16\ncbnz x1, #-8", true},
		{"second-vector-iteration-overrun", "mov x1, #32\nldp q0, q1, [x9], #64\nsub x1, x1, #16\ncbnz x1, #-8", false},
		{"replicate-scalar", "add x9, x9, #40\nld1rd {z0.d}, p0/z, [x9]", true},
		{"replicate-block", "add x9, x9, #16\nld1rqd {z0.d}, p0/z, [x9]", true},
		{"past-end", "add x9, x9, #48\nldr b0, [x9]", false},
		{"before-start", "sub x9, x9, #17\nldr b0, [x9]", false},
		{"load-overrun", "add x9, x9, #40\nldr q0, [x9]", false},
		{"pair-overrun", "add x9, x9, #40\nldp x0, x1, [x9]", false},
		{"replicate-overrun", "add x9, x9, #44\nld1rd {z0.d}, p0/z, [x9]", false},
		{"replicate-block-overrun", "add x9, x9, #40\nld1rqd {z0.d}, p0/z, [x9]", false},
		{"negative-load-underrun", "sub x9, x9, #16\nldur x0, [x9, #-1]", false},
		{"shifted-overrun", "add x9, x9, #1, lsl #12\nldr x0, [x9]", false},
		{"truncating", "add w9, w9, #16\nldr x0, [x9]", false},
		{"address-flags", "adds x9, x9, #16\nldr x0, [x9]", false},
		{"escaping", "add x9, x9, #16\nstr x9, [x0]", false},
		{"index-unknown", "add x9, x9, #16\nldr x0, [x9, x1]", false},
		{"offset-loop", "add x9, x9, #8\nldr x0, [x9]\ncbnz x1, #-8", false},
		{"same-offset-join", "cbz x1, #8\nadd x9, x9, #0\nldr x0, [x9]", true},
		{"different-offset-join", "cbz x1, #8\nadd x9, x9, #8\nldr x0, [x9]", true},
		{"different-offset-join-overrun", "cbz x1, #8\nadd x9, x9, #48\nldr x0, [x9]", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := strings.Split(test.body, "\n")
			lines := []string{fmt.Sprintf("adr x9, #%d", (len(body)+3)*4+16)}
			lines = append(lines, body...)
			lines = append(lines, "mov x9, xzr", "ret")
			var instructions []Instr
			for _, word := range assembleARM64LLVMWords(t, lines, "+sve") {
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
				t.Fatalf("pool proof=%v, want %v", got, test.want)
			}
		})
	}
}

func TestARM64RawPoolLoadFootprints(t *testing.T) {
	type footprint struct {
		line  string
		bytes int64
	}
	var cases []footprint
	for _, load := range []struct {
		op, reg string
		bytes   int64
	}{
		{"ldr", "b0", 1}, {"ldr", "h0", 2}, {"ldr", "s0", 4},
		{"ldr", "d0", 8}, {"ldr", "q0", 16}, {"ldr", "w0", 4}, {"ldr", "x0", 8},
		{"ldrb", "w0", 1}, {"ldrh", "w0", 2},
		{"ldrsb", "w0", 1}, {"ldrsb", "x0", 1},
		{"ldrsh", "w0", 2}, {"ldrsh", "x0", 2}, {"ldrsw", "x0", 4},
		{"ldur", "b0", 1}, {"ldur", "h0", 2}, {"ldur", "s0", 4},
		{"ldur", "d0", 8}, {"ldur", "q0", 16}, {"ldur", "w0", 4}, {"ldur", "x0", 8},
		{"ldurb", "w0", 1}, {"ldurh", "w0", 2},
		{"ldursb", "w0", 1}, {"ldursb", "x0", 1},
		{"ldursh", "w0", 2}, {"ldursh", "x0", 2}, {"ldursw", "x0", 4},
		{"ldtr", "w0", 4}, {"ldtr", "x0", 8}, {"ldtrb", "w0", 1}, {"ldtrh", "w0", 2},
		{"ldtrsb", "w0", 1}, {"ldtrsb", "x0", 1}, {"ldtrsh", "w0", 2}, {"ldtrsh", "x0", 2}, {"ldtrsw", "x0", 4},
		{"ldar", "w0", 4}, {"ldar", "x0", 8}, {"ldarb", "w0", 1}, {"ldarh", "w0", 2},
	} {
		cases = append(cases, footprint{load.op + " " + load.reg + ", [x9]", load.bytes})
	}
	for _, op := range []string{"ldp", "ldnp"} {
		for _, reg := range []struct {
			name  string
			bytes int64
		}{{"w", 4}, {"x", 8}, {"s", 4}, {"d", 8}, {"q", 16}} {
			cases = append(cases, footprint{fmt.Sprintf("%s %s0, %s1, [x9]", op, reg.name, reg.name), reg.bytes * 2})
		}
	}
	cases = append(cases, footprint{"ldpsw x0, x1, [x9]", 8})
	for count := 1; count <= 4; count++ {
		for _, width := range []struct {
			name  string
			bytes int64
		}{{"b", 1}, {"h", 2}, {"s", 4}, {"d", 8}} {
			var lanes, vectors, replicas []string
			for reg := 0; reg < count; reg++ {
				lanes = append(lanes, fmt.Sprintf("v%d.%s", reg, width.name))
				vectors = append(vectors, fmt.Sprintf("v%d.%d%s", reg, 16/width.bytes, width.name))
				replicas = append(replicas, fmt.Sprintf("v%d.%d%s", reg, 8/width.bytes, width.name))
			}
			cases = append(cases,
				footprint{fmt.Sprintf("ld%d {%s}[0], [x9]", count, strings.Join(lanes, ", ")), int64(count) * width.bytes},
				footprint{fmt.Sprintf("ld%d {%s}, [x9]", count, strings.Join(vectors, ", ")), int64(count) * 16},
				footprint{fmt.Sprintf("ld%dr {%s}, [x9]", count, strings.Join(replicas, ", ")), int64(count) * width.bytes},
			)
		}
	}
	var lines []string
	for _, test := range cases {
		lines = append(lines, test.line)
	}
	words := assembleARM64LLVMWords(t, lines, "")
	for i, test := range cases {
		var code [4]byte
		binary.LittleEndian.PutUint32(code[:], words[i])
		ins, err := arm64asm.Decode(code[:])
		if err != nil {
			t.Fatalf("decode %s: %v", test.line, err)
		}
		if got := arm64RawPoolLoadBytes(ins, words[i]); got != test.bytes {
			t.Errorf("%s reads %d bytes, want %d", test.line, got, test.bytes)
		}
	}
}

func arm64RawPoolOffsetIR(t *testing.T, triple string) string {
	t.Helper()
	lines := []string{
		"adr x19, #68", "add x19, x19, #8", "ldr w2, [x19]", "str x2, [x0]",
		"sub x19, x19, #16", "mov x3, #1", "whilelo p0.d, xzr, x3",
		"ld1rd {z0.d}, p0/z, [x19]", "fneg z0.d, p0/m, z0.d",
		"add x1, x0, #8", "st1d {z0.d}, p0, [x1]",
		"mov x19, xzr", "ret",
	}
	// ADR reaches byte 16 of this 32-byte pool; ADD and SUB then select
	// offsets 24 and 8. The constant that resembles B must remain data.
	var source strings.Builder
	source.WriteString("TEXT pool_offset(SB),$0-8\nMOVD out+0(FP),R0\n")
	for _, word := range assembleARM64LLVMWords(t, lines, "+sve") {
		fmt.Fprintf(&source, "WORD $%#08x\n", word)
	}
	for _, word := range []uint32{0, 0, 0x11223344, 0x55667788, 0, 0, 0x17b4a14d, 0} {
		fmt.Fprintf(&source, "WORD $%#08x\n", word)
	}
	source.WriteString("RET\n")
	requireARM64GoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple,
		Sigs: map[string]FuncSig{"pool_offset": {
			Name: "pool_offset", Args: []LLVMType{Ptr}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return ir
}

func TestARM64RawPoolOffsetLLVM(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			compileLLVMToObject(t, llc, triple, "pool_offset.ll", "pool_offset.o", arm64RawPoolOffsetIR(t, triple))
		})
	}
}

const arm64RawPoolOffsetMain = `
#include <stdint.h>
extern void pool_offset(uint64_t *);
int main(void) {
  uint64_t result[4] = {1, 0, 0, 2};
  pool_offset(result + 1);
  return result[0] != 1 || result[1] != 0x17b4a14d ||
         result[2] != 0xd566778811223344ULL || result[3] != 2;
}
`
