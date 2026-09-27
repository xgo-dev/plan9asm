package plan9asm

import (
	"fmt"
	"testing"
)

func TestARM64RawPoolWholeScalableImmediateGrammar(t *testing.T) {
	var lines []string
	for _, register := range []string{"z31", "p15"} {
		for immediate := -256; immediate <= 255; immediate++ {
			lines = append(lines, fmt.Sprintf("ldr %s,[x9,#%d,mul vl]", register, immediate))
		}
	}
	for index, word := range assembleARM64LLVMWords(t, lines, "+sve") {
		form, ok := decodeARM64RawSVELoadStore(word)
		if !ok {
			t.Fatalf("missing typed whole-register memory form: %s", lines[index])
		}
		for vectorBytes := int64(16); vectorBytes <= 256; vectorBytes += 16 {
			flow := &arm64RawPoolValues{
				words: []uint32{0x10000009, word}, before: [][]int{{-1}, {0}},
				vectorBytes: vectorBytes,
			}
			bounds := (&arm64RawPoolBounds{
				size: 1024, offset: 512, values: flow,
			}).withSymbolicOrigin(0)
			width := vectorBytes
			if index >= 512 {
				width /= 8
			}
			offset := 512 + int64(index%512-256)*width
			want := offset >= 0 && offset+width <= 1024
			if got := bounds.wholeScalableLoadInBounds(1, form); got != want {
				t.Fatalf("%s VL=%d: proof=%v, want %v", lines[index], vectorBytes, got, want)
			}
		}
	}
}

func TestARM64RawPoolWholeScalableLoadBounds(t *testing.T) {
	for _, test := range []struct {
		name, body string
		words      int
		want       bool
	}{
		{"vector", "ldr z31,[x9]", 64, true},
		{"predicate", "ldr p15,[x9]", 8, true},
		{"vector-short", "ldr z31,[x9]", 63, false},
		{"predicate-short", "ldr p15,[x9]", 7, false},
		{"vector-immediate", "ldr z31,[x9,#1,mul vl]", 128, true},
		{"predicate-immediate", "ldr p15,[x9,#1,mul vl]", 16, true},
		{"vector-negative", "addvl x9,x9,#1\nldr z31,[x9,#-1,mul vl]\naddvl x9,x9,#-1", 64, true},
		{"predicate-negative", "addpl x9,x9,#1\nldr p15,[x9,#-1,mul vl]\naddpl x9,x9,#-1", 8, true},
		{"vector-before-pool", "ldr z31,[x9,#-1,mul vl]", 64, false},
		{"predicate-before-pool", "ldr p15,[x9,#-1,mul vl]", 8, false},
		{"vector-write", "str z31,[x9]", 64, false},
		{"predicate-write", "str p15,[x9]", 8, false},
		{"unrelated-vector-write", "str z31,[x0]\nldr p15,[x9]", 8, true},
		{"predicate-overrun", "ldr p15,[x9,#1,mul vl]", 15, false},
		{"vector-overrun", "ldr z31,[x9,#1,mul vl]", 127, false},
		{"vector-length-mode-change", "smstart sm\nldr z31,[x9]", 64, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := arm64PoolScalableProof(t, test.body, test.words); got != test.want {
				t.Fatalf("whole scalable load proof=%v, want %v", got, test.want)
			}
		})
	}
}
