package plan9asm

import (
	"fmt"
	"testing"
)

// Enumerate operations and orthogonal width/index modes independently of the
// decoder. LLVM 22 supplies the encodings, including the flag-writing siblings.
func arm64PoolSVEFlagPreservingForms() []string {
	var lines []string
	for _, op := range []string{"sunpklo", "sunpkhi", "uunpklo", "uunpkhi"} {
		for _, widths := range [][2]string{{"h", "b"}, {"s", "h"}, {"d", "s"}} {
			lines = append(lines, fmt.Sprintf("%s z9.%s,z31.%s", op, widths[0], widths[1]))
		}
	}
	for _, op := range []string{"mla", "mls", "mad", "msb"} {
		for size := 0; size < 4; size++ {
			lines = append(lines, arm64RawSVEMultiplyAccumulateAssembly(op, size, 31, 30, 29, 7, -1))
			if size == 0 || op == "mad" || op == "msb" {
				continue
			}
			for lane := 0; lane < 16>>size; lane++ {
				lines = append(lines, arm64RawSVEMultiplyAccumulateAssembly(op, size, 31, 30, 7, 0, lane))
			}
		}
	}
	for _, width := range "bhsd" {
		for _, immediate := range []int{-128, -1, 0, 1, 127} {
			lines = append(lines, fmt.Sprintf("dup z9.%c,#%d", width, immediate))
			if width != 'b' {
				lines = append(lines, fmt.Sprintf("dup z9.%c,#%d,lsl #8", width, immediate))
			}
		}
		general := "w1"
		if width == 'd' {
			general = "x1"
		}
		lines = append(lines, fmt.Sprintf("dup z9.%c,%s", width, general))
		for _, op := range []string{"and", "bic", "eor", "orr"} {
			lines = append(lines, fmt.Sprintf("%s z9.%c,p7/m,z9.%c,z31.%c", op, width, width, width))
			if op != "bic" {
				lines = append(lines, fmt.Sprintf("%s z9.%c,z9.%c,#1", op, width, width))
			}
		}
		for _, op := range []string{"andv", "eorv", "orv"} {
			lines = append(lines, fmt.Sprintf("%s %c9,p7,z31.%c", op, width, width))
		}
		lines = append(lines, fmt.Sprintf("uaddv d9,p7,z31.%c", width))
		if width != 'd' {
			lines = append(lines, fmt.Sprintf("saddv d9,p7,z31.%c", width))
		}
	}
	for size, width := range "bhsdq" {
		for lane := 0; lane < 64>>size; lane++ {
			lines = append(lines, fmt.Sprintf("dup z9.%c,z31.%c[%d]", width, width, lane))
		}
	}
	for _, op := range []string{"and", "bic", "eor", "orr"} {
		lines = append(lines, fmt.Sprintf("%s z9.d,z30.d,z31.d", op))
	}
	for _, op := range []string{"addqv", "andqv", "eorqv", "orqv"} {
		for size := 0; size < 4; size++ {
			lines = append(lines, arm64RawSVEIntegerReductionAssembly(op, size, 9, 31, 7))
		}
	}
	for _, op := range []string{"and", "bic", "eor", "nand", "nor", "orn", "orr"} {
		lines = append(lines, op+" p9.b,p15/z,p9.b,p14.b")
	}
	lines = append(lines, "sel p9.b,p15,p9.b,p14.b")
	return append(lines, arm64RawSVECopyForms()...)
}

func TestARM64RawPoolSVEFlagProvenance(t *testing.T) {
	lines := arm64PoolSVEFlagPreservingForms()
	wants := make([]bool, len(lines))
	for index := range wants {
		wants[index] = true
	}
	for _, op := range []string{"ands", "bics", "eors", "nands", "nors", "orns", "orrs"} {
		lines = append(lines, op+" p9.b,p15/z,p9.b,p14.b")
	}
	lines = append(lines,
		"ptest p7,p9.b", "whilelo p7.b,x1,x2", "cmpeq p7.b,p7/z,z9.b,z31.b",
		"fcmgt p7.s,p7/z,z9.s,z31.s", "msr nzcv,x1", "smstart sm", "udf #0",
	)
	for len(wants) < len(lines) {
		wants = append(wants, false)
	}
	for index, word := range assembleARM64LLVMWords(t, lines, "+sve2p1,+sme") {
		// CMP X1,#7, followed by exactly this instruction. A no-GP-write
		// classification alone must not license carrying CMP's NZCV through it.
		flow := &arm64RawPoolValues{words: []uint32{0xf1001c3f, word, 0xd503201f},
			before: [][]int{{-1}, {0}, {1}}}
		compare, clobbered, after, ok := flow.affineFlagSourceBefore(2)
		if ok != wants[index] || ok && (compare != flow.words[0] || clobbered != 0 || after != 1) {
			t.Errorf("%s: flags=(%#x,%#x,%d,%v), want preserved=%v", lines[index], compare, clobbered, after, ok, wants[index])
		}
	}
}

func TestARM64RawPoolSVEFlagsRespectControlFlow(t *testing.T) {
	for _, test := range []struct {
		name string
		body []string
		want bool
	}{
		{"preserved", []string{"uunpklo z9.h,z31.b", "mla z31.d,p7/m,z30.d,z29.d"}, true},
		{"predicate-flags", []string{"uunpklo z9.h,z31.b", "ands p9.b,p15/z,p9.b,p14.b"}, false},
		{"scalar-flags", []string{"uunpklo z9.h,z31.b", "tst x2,x3"}, false},
		{"bypassed-compare", []string{"uunpklo z9.h,z31.b", "mla z31.d,p7/m,z30.d,z29.d"}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			lines := []string{"mov x1,#7", "nop", "subs x1,x1,#1"}
			lines = append(lines, test.body...)
			lines = append(lines, fmt.Sprintf("b.ne #%d", (1-len(lines))*4), "ret")
			if test.name == "bypassed-compare" {
				lines[1] = "cbz x2,#8"
			}
			words := assembleARM64LLVMWords(t, lines, "+sve2")
			instructions := make([]Instr, len(words))
			reachable := make(map[int]bool)
			for at, word := range words {
				instructions[at] = Instr{Op: OpWORD, Args: []Operand{{Kind: OpImm, Imm: int64(word)}}}
				reachable[at] = true
			}
			flow := newARM64RawPoolValues(instructions, 0, len(words), reachable)
			want := arm64PoolUnknownInterval
			if test.want {
				want = arm64PoolInterval{1, 7}
			}
			if got := flow.affineInterval(1, arm64PoolRegisterExpression(1)); got != want {
				t.Fatalf("counter interval=%+v, want %+v", got, want)
			}
		})
	}
}

func TestARM64RawPoolSVECopyGeneralEffects(t *testing.T) {
	for _, width := range "bhsd" {
		for _, source := range []int{0, 9, 30, 31} {
			register := fmt.Sprintf("w%d", source)
			if width == 'd' {
				register = fmt.Sprintf("x%d", source)
			}
			if source == 31 {
				register = "wsp"
				if width == 'd' {
					register = "sp"
				}
			}
			line := fmt.Sprintf("cpy z9.%c,p7/m,%s", width, register)
			word := assembleARM64LLVMWords(t, []string{line}, "+sve")[0]
			if writes, known := arm64RawPoolGPWrites(word); !known || writes != 0 {
				t.Errorf("%s: GP writes=%#x, known=%v", line, writes, known)
			}
			for address := 0; address < 32; address++ {
				if ignored := arm64RawPoolSVEIgnoresAddress(word, address); ignored != (address != source) {
					t.Errorf("%s: ignored address R%d=%v", line, address, ignored)
				}
			}
		}
	}
}
