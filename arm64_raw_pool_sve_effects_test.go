package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestARM64RawPoolSVETypedEffects(t *testing.T) {
	type effect struct {
		line string
		want bool
	}
	var cases []effect
	for _, extract := range []struct {
		op, destination, lane string
		lanes                 int
	}{
		{"umov", "w9", "b", 16}, {"umov", "w9", "h", 8},
		{"umov", "w9", "s", 4}, {"umov", "x9", "d", 2},
		{"smov", "w9", "b", 16}, {"smov", "w9", "h", 8},
		{"smov", "x9", "b", 16}, {"smov", "x9", "h", 8}, {"smov", "x9", "s", 4},
	} {
		for lane := 0; lane < extract.lanes; lane++ {
			cases = append(cases, effect{fmt.Sprintf("%s %s, v31.%s[%d]", extract.op, extract.destination, extract.lane, lane), true})
		}
	}
	for _, op := range []string{"and", "ands", "bic", "bics", "eor", "eors", "nand", "nands", "nor", "nors", "orn", "orns", "orr", "orrs"} {
		cases = append(cases, effect{op + " p9.b, p15/z, p9.b, p14.b", true})
	}
	cases = append(cases, effect{"sel p9.b, p15, p9.b, p14.b", true})
	for _, reg := range []string{"z31", "p15"} {
		for _, op := range []string{"ldr", "str"} {
			cases = append(cases,
				effect{fmt.Sprintf("%s %s, [x30, #255, mul vl]", op, reg), true},
				effect{fmt.Sprintf("%s %s, [sp, #-256, mul vl]", op, reg), true},
				effect{fmt.Sprintf("%s %s, [x9]", op, reg), false},
			)
		}
	}
	for _, op := range []string{"addvl", "addpl"} {
		for _, immediate := range []int{-32, 0, 31} {
			cases = append(cases,
				effect{fmt.Sprintf("%s x9, x30, #%d", op, immediate), true},
				effect{fmt.Sprintf("%s x30, sp, #%d", op, immediate), true},
				effect{fmt.Sprintf("%s x30, x9, #%d", op, immediate), false},
				effect{fmt.Sprintf("%s x9, x9, #%d", op, immediate), false},
			)
		}
	}
	cases = append(cases, effect{"rdvl x9, #1", true}, effect{"rdvl x30, #-32", true})
	cases = append(cases, effect{"dupm z9.d, #0x3ff0000000000000", true})
	cases = append(cases, effect{"movprfx z9, z31\nadd z9.d, p0/m, z9.d, z30.d", true})
	for _, op := range []string{"cntb", "cnth", "cntw", "cntd", "incb", "inch", "incw", "incd", "decb", "dech", "decw", "decd"} {
		cases = append(cases, effect{op + " x30, all, mul #16", true})
		cases = append(cases, effect{op + " x9, all, mul #16", strings.HasPrefix(op, "cnt")})
	}
	for _, width := range []string{"b", "h", "s", "d"} {
		for _, immediate := range []int{-128, -1, 0, 1, 127} {
			cases = append(cases, effect{fmt.Sprintf("dup z9.%s, #%d", width, immediate), true})
			if width != "b" {
				cases = append(cases, effect{fmt.Sprintf("dup z9.%s, #%d, lsl #8", width, immediate), true})
			}
		}
		cases = append(cases,
			effect{fmt.Sprintf("movprfx z9.%s, p7/m, z31.%s\nadd z9.%s, p7/m, z9.%s, z30.%s", width, width, width, width, width), true},
			effect{fmt.Sprintf("movprfx z9.%s, p7/z, z31.%s\nadd z9.%s, p7/m, z9.%s, z30.%s", width, width, width, width, width), true},
			effect{fmt.Sprintf("asrd z9.%s, p7/m, z9.%s, #1", width, width), true},
			effect{fmt.Sprintf("mov z9.%s, p15/m, #7", width), true},
			effect{fmt.Sprintf("mov z9.%s, p15/z, #-7", width), true},
			effect{fmt.Sprintf("mov z9.%s, p7/m, %s9", width, width), true},
			effect{fmt.Sprintf("sel z9.%s, p15, z30.%s, z31.%s", width, width, width), true},
			effect{fmt.Sprintf("dup z9.%s, z31.%s[0]", width, width), true},
		)
		for _, op := range []string{"sub", "sqadd", "uqadd", "sqsub", "uqsub"} {
			cases = append(cases, effect{fmt.Sprintf("%s z9.%s, z30.%s, z31.%s", op, width, width, width), true})
		}
		for _, op := range []string{"lsl", "lsr", "asr"} {
			cases = append(cases, effect{fmt.Sprintf("%s z9.%s, z31.%s, #1", op, width, width), true})
		}
	}
	for _, op := range []string{"zip1", "zip2", "uzp1", "uzp2", "trn1", "trn2"} {
		for _, width := range []string{"b", "h", "s", "d"} {
			cases = append(cases, effect{fmt.Sprintf("%s z9.%s, z9.%s, z31.%s", op, width, width, width), true})
		}
	}
	for _, width := range []string{"h", "s", "d"} {
		for _, op := range []string{"frecps", "frsqrts"} {
			cases = append(cases, effect{
				fmt.Sprintf("%s z9.%s, z30.%s, z31.%s", op, width, width, width), true,
			})
		}
		for _, op := range []string{"fadd", "fsub", "fmul", "fdiv", "fdivr", "fscale", "fmax", "fmin"} {
			cases = append(cases, effect{fmt.Sprintf("%s z9.%s, p7/m, z9.%s, z31.%s", op, width, width, width), true})
		}
		for _, op := range []string{"fabs", "fneg", "fsqrt"} {
			cases = append(cases, effect{fmt.Sprintf("%s z9.%s, p7/m, z31.%s", op, width, width), true})
		}
		cases = append(cases,
			effect{fmt.Sprintf("fmov z9.%s, #1.0", width), true},
			effect{fmt.Sprintf("fcmgt p7.%s, p7/z, z9.%s, z31.%s", width, width, width), true},
			effect{fmt.Sprintf("fmla z9.%s, p7/m, z9.%s, z31.%s", width, width, width), true},
			effect{fmt.Sprintf("scvtf z9.%s, p7/m, z31.%s", width, width), true},
		)
	}
	for _, width := range []string{"b", "h", "s", "d"} {
		gp := "w"
		if width == "d" {
			gp = "x"
		}
		cases = append(cases,
			effect{fmt.Sprintf("cntp x30, p15, p14.%s", width), true},
			effect{fmt.Sprintf("cntp x9, p15, p14.%s", width), true},
			effect{fmt.Sprintf("cntp x30, pn15.%s, vlx2", width), true},
			effect{fmt.Sprintf("cntp x9, pn15.%s, vlx4", width), true},
			effect{fmt.Sprintf("dup z31.%s, %s30", width, gp), true},
			effect{fmt.Sprintf("dup z31.%s, %s9", width, gp), false},
			effect{fmt.Sprintf("compact z31.%s, p7, z30.%s", width, width), true},
			effect{fmt.Sprintf("cnt z31.%s, p7/m, z30.%s", width, width), true},
			effect{fmt.Sprintf("cnt z31.%s, p7/z, z30.%s", width, width), true},
		)
		for _, condition := range []string{"ge", "gt", "hi", "hs", "le", "lo", "ls", "lt"} {
			for _, inputs := range []struct {
				first, second string
				want          bool
			}{
				{"xzr", "x30", true}, {"x9", "x30", false},
				{"x30", "x9", false}, {"x9", "x9", false},
			} {
				cases = append(cases, effect{
					fmt.Sprintf("while%s p15.%s, %s, %s", condition, width, inputs.first, inputs.second), inputs.want,
				})
			}
		}
	}
	for _, memory := range []struct {
		suffix, width string
		shift         int
	}{
		{"b", "b", 0}, {"b", "h", 0}, {"b", "s", 0}, {"b", "d", 0},
		{"h", "h", 1}, {"h", "s", 1}, {"h", "d", 1},
		{"w", "s", 2}, {"d", "d", 3},
	} {
		for _, load := range []bool{false, true} {
			op, mode := "st1", ""
			if load {
				op, mode = "ld1", "/z"
			}
			for _, address := range []struct {
				text string
				want bool
			}{
				{"[x30]", true}, {"[sp, #-8, mul vl]", true},
				{"[x9]", false}, {"[x9, #7, mul vl]", false},
				{fmt.Sprintf("[x30, x29, lsl #%d]", memory.shift), true},
				{fmt.Sprintf("[x30, x9, lsl #%d]", memory.shift), false},
				{fmt.Sprintf("[x9, x30, lsl #%d]", memory.shift), false},
			} {
				cases = append(cases, effect{
					fmt.Sprintf("%s%s {z31.%s}, p7%s, %s", op, memory.suffix, memory.width, mode, address.text), address.want,
				})
			}
		}
	}
	// A GP source cannot be mistaken for a vector register sharing its number.
	cases = append(cases, effect{"dup z31.d, x9", false})
	var lines []string
	starts := []int{0}
	for _, test := range cases {
		lines = append(lines, "adr x9, #64", "ldr w1, [x9]")
		lines = append(lines, strings.Split(test.line, "\n")...)
		lines = append(lines, "mov x9, xzr", "ret")
		starts = append(starts, len(lines))
	}
	words := assembleARM64LLVMWords(t, lines, "+sve2p2")
	for i, test := range cases {
		t.Run(test.line, func(t *testing.T) {
			var instructions []Instr
			for _, word := range words[starts[i]:starts[i+1]] {
				instructions = append(instructions, Instr{Op: OpWORD, Args: []Operand{{Kind: OpImm, Imm: int64(word)}}})
			}
			if got := arm64RawAddressOnlyLoaded(instructions, 0, len(instructions)); got != test.want {
				t.Fatalf("load-only proof=%v, want %v for %s", got, test.want, test.line)
			}
		})
	}
	if decoded, ok := decodeARM64RawSVEWhile(0x25ae1ff3); !ok || decoded.Op != "PWHILELS" {
		t.Fatalf("previously unmodeled WHILELS word did not enter the typed family: %+v", decoded)
	}
	if !arm64RawPoolSVEIgnoresAddress(0x25ae1ff3, 9) {
		t.Fatal("WHILELS reading XZR and X14 unexpectedly depends on the pool address in X9")
	}
	for _, word := range []uint32{0, 0x6ea0f16c, 0x6ebee0e4} {
		if arm64RawPoolSVEIgnoresAddress(word, 9) {
			t.Fatalf("unknown or unmodeled encoding %#08x acquired a safe effect", word)
		}
	}
}

func TestARM64RawPoolFlagArithmeticKills(t *testing.T) {
	for _, width := range []string{"w", "x"} {
		for _, op := range []string{"add", "adds", "adc", "adcs", "sub", "subs", "sbc", "sbcs", "neg", "negs", "ngc", "ngcs"} {
			for _, source := range []int{0, 9} {
				line := fmt.Sprintf("%s %s9, %s%d", op, width, width, source)
				if !strings.HasPrefix(op, "n") {
					line += fmt.Sprintf(", %s1", width)
				}
				t.Run(line, func(t *testing.T) {
					var instructions []Instr
					for _, word := range assembleARM64LLVMWords(t, []string{"adr x9, #64", "ldr w2, [x9]", line, "ret"}, "") {
						instructions = append(instructions, Instr{Op: OpWORD, Args: []Operand{{Kind: OpImm, Imm: int64(word)}}})
					}
					if got := arm64RawAddressOnlyLoaded(instructions, 0, len(instructions)); got != (source != 9) {
						t.Fatalf("load-only proof=%v for %s", got, line)
					}
				})
			}
		}
	}
}
