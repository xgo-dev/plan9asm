package plan9asm

import (
	"fmt"
	"testing"
)

func TestARM64RawPoolContiguousScalableLoads(t *testing.T) {
	for _, signed := range []bool{false, true} {
		for memory := 0; memory < 4; memory++ {
			for element := memory; element < 4; element++ {
				if signed && element == memory {
					continue
				}
				form := arm64RawSVELoadCase{memorySize: memory, elementSize: element}
				width := 256 >> uint(element-memory)
				for _, kind := range []string{"immediate", "register"} {
					form.kind = kind
					load := form.loadAssembly(signed, 31, 7, 9, 10, 0)
					for _, short := range []bool{false, true} {
						words := width / 4
						if short {
							words--
						}
						t.Run(fmt.Sprintf("%s/short=%v", load, short), func(t *testing.T) {
							body := "mov x10,#0\n" + load
							if got := arm64PoolScalableProof(t, body, words); got == short {
								t.Fatalf("pool proof=%v, want %v", got, !short)
							}
						})
					}
				}
			}
		}
	}
}

func TestARM64RawPoolContiguousScalableIndexGuards(t *testing.T) {
	for _, test := range []struct {
		name, body string
		want       bool
	}{
		{"bounded-doubleword", "and x10,x10,#7\nld1d {z31.d},p7/z,[x9,x10,lsl #3]", true},
		{"byte-address-in-index", "and x10,x10,#7\nld1b {z31.b},p7/z,[x10,x9]", true},
		{"correlated-displacement", "addvl x9,x9,#-1\ncntd x10\nld1d {z31.d},p7/z,[x9,x10,lsl #3]\naddvl x9,x9,#1", true},
		{"unknown-index", "ld1d {z31.d},p7/z,[x9,x10,lsl #3]", false},
		{"out-of-range-index", "mov x10,#9\nld1d {z31.d},p7/z,[x9,x10,lsl #3]", false},
		{"scaled-relocated-index", "mov x10,#0\nld1d {z31.d},p7/z,[x10,x9,lsl #3]", false},
		{"double-relocation", "ld1b {z31.b},p7/z,[x9,x9]", false},
		{"store-is-not-read", "mov x10,#0\nst1d {z31.d},p7,[x9,x10,lsl #3]", false},
		{"first-fault-not-ordinary", "ldff1d {z31.d},p7/z,[x9]", false},
		{"vector-index-unproved", "ld1d {z31.d},p7/z,[x9,z30.d,lsl #3]", false},
		{"masked-off-still-unproved", "pfalse p7.b\nld1d {z31.d},p7/z,[x9,x10,lsl #3]", false},
		{"vector-length-mode-change", "smstart sm\nld1d {z31.d},p7/z,[x9]", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := arm64PoolScalableProof(t, test.body, 80); got != test.want {
				t.Fatalf("indexed pool proof=%v, want %v", got, test.want)
			}
		})
	}
}

func TestARM64RawPoolContiguousScalableImmediateGrammar(t *testing.T) {
	var lines []string
	var widths []int64
	for _, signed := range []bool{false, true} {
		for memory := 0; memory < 4; memory++ {
			for element := memory; element < 4; element++ {
				if signed && element == memory {
					continue
				}
				form := arm64RawSVELoadCase{memorySize: memory, elementSize: element, kind: "immediate"}
				for immediate := -8; immediate < 8; immediate++ {
					lines = append(lines, form.loadAssembly(signed, 31, 7, 9, 10, immediate))
					widths = append(widths, 1<<uint(element-memory))
				}
			}
		}
	}
	for index, word := range assembleARM64LLVMWords(t, lines, "+sve") {
		row, ok := arm64RawPoolContiguousLoad(word)
		if !ok {
			t.Fatalf("missing typed contiguous load: %s", lines[index])
		}
		if _, ok := arm64RawPoolContiguousLoad(word | (1 << 20)); ok {
			t.Fatalf("%s: reserved immediate high bit accepted", lines[index])
		}
		for vectorBytes := int64(16); vectorBytes <= 256; vectorBytes += 16 {
			flow := &arm64RawPoolValues{
				words: []uint32{0x10000009, word}, before: [][]int{{-1}, {0}}, vectorBytes: vectorBytes,
			}
			bounds := (&arm64RawPoolBounds{size: 1024, offset: 512, values: flow}).withSymbolicOrigin(0)
			width := vectorBytes / widths[index]
			offset := 512 + int64(index%16-8)*width
			want := offset >= 0 && offset+width <= 1024
			if got := bounds.contiguousScalableLoadInBounds(1, word, row); got != want {
				t.Fatalf("%s VL=%d: footprint proof=%v, want %v", lines[index], vectorBytes, got, want)
			}
		}
	}
}
