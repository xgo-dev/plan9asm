package plan9asm

import (
	"fmt"
	"math/bits"
	"strings"
	"testing"
)

// Keep the oracle independent of the proof's pattern decoder.
func arm64PoolExpectedPattern(elements int64, pattern int) int64 {
	counts := [32]int64{0, 1, 2, 3, 4, 5, 6, 7, 8, 16, 32, 64, 128, 256}
	counts[0] = 1 << (bits.Len64(uint64(elements)) - 1)
	counts[29] = elements &^ 3
	counts[30] = elements - elements%3
	counts[31] = elements
	if counts[pattern] > elements {
		return 0
	}
	return counts[pattern]
}

func TestARM64RawPoolScalableCountGrammar(t *testing.T) {
	var assembly []string
	for _, op := range []string{"cnt", "inc", "dec"} {
		for _, width := range "bhwd" {
			for pattern := 0; pattern < 32; pattern++ {
				for multiplier := 1; multiplier <= 16; multiplier++ {
					assembly = append(assembly, fmt.Sprintf("%s%c x10,#%d,mul #%d", op, width, pattern, multiplier))
				}
			}
		}
	}
	words := assembleARM64LLVMWords(t, assembly, "+sve")
	for index, word := range words {
		requireARM64PoolScalableFlags(t, assembly[index], word, 1<<10)
		op, width := index/(4*32*16), index/(32*16)%4
		pattern, multiplier := index/16%32, index%16+1
		for vectorBytes := int64(16); vectorBytes <= 256; vectorBytes += 16 {
			flow := &arm64RawPoolValues{vectorBytes: vectorBytes}
			destination, got, ok := flow.affineDefinition(word)
			count := arm64PoolExpectedPattern(vectorBytes>>uint(width), pattern) * int64(multiplier)
			want := arm64PoolAffine{constant: uint64(count)}
			if op != 0 {
				want.coefficient[10] = 1
			}
			if op == 2 {
				want.constant = -want.constant
			}
			if !ok || destination != 10 || got != want {
				t.Fatalf("%s VL=%d: got r%d %+v/%v, want %+v", assembly[index], vectorBytes, destination, got, ok, want)
			}
		}
	}
}

func TestARM64RawPoolScalableAddressGrammar(t *testing.T) {
	var assembly []string
	for _, op := range []string{"rdvl", "addvl", "addpl"} {
		for immediate := -32; immediate <= 31; immediate++ {
			operands := "x10,x9"
			if op == "rdvl" {
				operands = "x10"
			}
			assembly = append(assembly, fmt.Sprintf("%s %s,#%d", op, operands, immediate))
		}
	}
	for index, word := range assembleARM64LLVMWords(t, assembly, "+sve") {
		requireARM64PoolScalableFlags(t, assembly[index], word, 1<<10)
		for vectorBytes := int64(16); vectorBytes <= 256; vectorBytes += 16 {
			unit := vectorBytes
			if index >= 128 {
				unit /= 8
			}
			want := arm64PoolAffine{constant: uint64(int64(index%64-32) * unit)}
			if index >= 64 {
				want.coefficient[9] = 1
			}
			flow := &arm64RawPoolValues{vectorBytes: vectorBytes}
			destination, got, ok := flow.affineDefinition(word)
			if !ok || destination != 10 || got != want {
				t.Fatalf("%s VL=%d: got r%d %+v/%v, want %+v", assembly[index], vectorBytes, destination, got, ok, want)
			}
		}
	}
}

func requireARM64PoolScalableFlags(t *testing.T, line string, word, wantWrites uint32) {
	t.Helper()
	flow := &arm64RawPoolValues{
		words: []uint32{0xf1001c3f, word, 0xd503201f}, before: [][]int{{-1}, {0}, {1}},
	}
	compare, writes, after, ok := flow.affineFlagSourceBefore(2)
	if !ok || compare != flow.words[0] || writes != wantWrites || after != 1 {
		t.Fatalf("%s: flags=(%#x,%#x,%d,%v), want preserved with writes=%#x", line, compare, writes, after, ok, wantWrites)
	}
}

func arm64PoolScalableProof(t *testing.T, body string, poolWords int) bool {
	t.Helper()
	lines := append([]string{"adr x9,#0"}, strings.Split(body, "\n")...)
	lines = append(lines, "ldr x0,[x9]", "mov x9,xzr", "ret")
	lines[0] = fmt.Sprintf("adr x9,#%d", len(lines)*4)
	var instructions []Instr
	for _, word := range assembleARM64LLVMWords(t, lines, "+sve,+sme") {
		instructions = append(instructions, Instr{Op: OpWORD, Args: []Operand{{Kind: OpImm, Imm: int64(word)}}})
	}
	for i := 0; i < poolWords; i++ {
		instructions = append(instructions, Instr{Op: OpWORD, Args: []Operand{{Kind: OpImm, Imm: 0x17b4a14d}}})
	}
	points := make([]arm64RawLayoutPoint, len(instructions))
	for i := range points {
		points[i].offset = int64(i * 4)
	}
	data, _, _ := identifyARM64UnlabelledPool(Func{Instrs: instructions}, points, map[string]bool{}, 0)
	return len(data) == poolWords
}

func TestARM64RawPoolScalableValueCorrelations(t *testing.T) {
	for _, test := range []struct {
		name, body string
		want       bool
	}{
		{"addvl-cancellation", "addvl x9,x9,#-31\naddvl x9,x9,#31", true},
		{"addpl-cancellation", "addpl x9,x9,#-32\nrdvl x10,#4\nadd x9,x9,x10", true},
		{"rdvl-cancellation", "addvl x9,x9,#-8\nrdvl x10,#8\nadd x9,x9,x10", true},
		{"negative-rdvl", "addvl x9,x9,#-1\nrdvl x10,#-1\nsub x9,x9,x10", true},
		{"count-bytes", "addvl x9,x9,#-16\ncntb x10,all,mul #16\nadd x9,x9,x10", true},
		{"count-halfwords", "addpl x9,x9,#-4\ncnth x10\nadd x9,x9,x10", true},
		{"count-words", "addpl x9,x9,#-2\ncntw x10\nadd x9,x9,x10", true},
		{"count-doublewords", "addpl x9,x9,#-1\ncntd x10\nadd x9,x9,x10", true},
		{"increment", "addvl x9,x9,#-1\nmov x10,#0\nincb x10\nadd x9,x9,x10", true},
		{"decrement", "addvl x9,x9,#-1\nmov x10,#0\ndecb x10\nsub x9,x9,x10", true},
		{"maximum-vl-overrun", "rdvl x10,#1\nadd x9,x9,x10", false},
		{"mismatched-units", "addvl x9,x9,#-1\ncnth x10\nadd x9,x9,x10", false},
		{"changed-vector-length", "rdvl x10,#1\nsmstart sm\naddvl x9,x9,#-1\nadd x9,x9,x10", false},
		{"unknown-input", "addvl x9,x9,#-1\nadd x9,x9,x10", false},
		{"truncated-count", "addvl x9,x9,#-1\nrdvl x10,#1\nadd w9,w9,w10", false},
		{"read-before-cancellation", "addvl x9,x9,#-1\nldr x0,[x9]\naddvl x9,x9,#1", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := arm64PoolScalableProof(t, test.body, 8); got != test.want {
				t.Fatalf("scalable pool proof=%v, want %v", got, test.want)
			}
		})
	}
}
