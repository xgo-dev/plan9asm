package plan9asm

import (
	"fmt"
	"testing"
)

func TestARM64RawPoolRepeatedOrigins(t *testing.T) {
	for _, test := range []struct {
		name    string
		lines   []string
		origins map[int]int
		want    bool
	}{
		{"reacquire-at-join", []string{
			"adr x9, #0", "cbz x0, #8", "adr x9, #0",
			"sub x12, x9, x2", "add x12, x12, x2", "ldr x1, [x12]",
			"mov x12, xzr", "mov x9, xzr", "ret",
		}, map[int]int{0: 0, 2: 8}, true},
		{"independent-registers", []string{
			"adr x9, #0", "adr x10, #0", "ldr x1, [x9]", "ldr x2, [x10]",
			"mov x9, xzr", "mov x10, xzr", "ret",
		}, map[int]int{0: 0, 1: 8}, true},
		{"copied-or-reacquired", []string{
			"adr x9, #0", "cbz x0, #12", "adr x10, #0", "b #8", "mov x10, x9",
			"sub x12, x10, x2", "add x12, x12, x2", "ldr x1, [x12]",
			"mov x12, xzr", "mov x9, xzr", "mov x10, xzr", "ret",
		}, map[int]int{0: 0, 2: 8}, true},
		{"sum-of-origins", []string{
			"adr x9, #0", "adr x10, #0", "add x12, x9, x10", "ldr x1, [x12]",
			"mov x9, xzr", "mov x10, xzr", "mov x12, xzr", "ret",
		}, map[int]int{0: 0, 1: 8}, false},
		{"shifted-sum-of-origins", []string{
			"adr x9, #0", "adr x10, #0", "add x12, x9, x10, lsl #1", "ldr x1, [x12]",
			"mov x9, xzr", "mov x10, xzr", "mov x12, xzr", "ret",
		}, map[int]int{0: 0, 1: 4}, false},
		{"reacquired-overrun", []string{
			"adr x9, #0", "cbz x0, #8", "adr x9, #0", "ldr x1, [x9]", "mov x9, xzr", "ret",
		}, map[int]int{0: 0, 2: 12}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			for at, offset := range test.origins {
				register := 9
				if test.lines[at] == "adr x10, #0" {
					register = 10
				}
				test.lines[at] = fmt.Sprintf("adr x%d, #%d", register, (len(test.lines)-at)*4+offset)
			}
			var instructions []Instr
			for _, word := range assembleARM64LLVMWords(t, test.lines, "") {
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
				t.Fatalf("repeated-origin proof=%v, want %v", got, test.want)
			}
		})
	}
}
