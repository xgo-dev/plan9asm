package plan9asm

import (
	"encoding/binary"
	"fmt"
	"testing"

	"golang.org/x/arch/arm64/arm64asm"
)

func TestARM64RawPoolWritebackFootprints(t *testing.T) {
	// Go asm7.go MOV[BHWD], FMOV[SDQ] and LDP[W/SW]/FLDP[SDQ] have
	// independent offset/pre/post rows. Check every load width and sign view;
	// store, exclusive and atomic operations are never read-only pool uses.
	type form struct {
		line         string
		bytes, delta int64
		pre          bool
	}
	var cases []form
	for _, load := range []struct {
		operands string
		bytes    int64
	}{
		{"ldr b0", 1}, {"ldr h0", 2}, {"ldr s0", 4}, {"ldr d0", 8}, {"ldr q0", 16},
		{"ldr w0", 4}, {"ldr x0", 8}, {"ldr xzr", 8}, {"ldrb w0", 1}, {"ldrh w0", 2},
		{"ldrsb w0", 1}, {"ldrsb x0", 1}, {"ldrsh w0", 2}, {"ldrsh x0", 2}, {"ldrsw x0", 4},
		{"ldp w0, w1", 8}, {"ldp x0, x1", 16}, {"ldpsw x0, x1", 8},
		{"ldp s0, s1", 8}, {"ldp d0, d1", 16}, {"ldp q0, q1", 32},
	} {
		for _, delta := range []int64{-16, 0, 16} {
			for _, pre := range []bool{false, true} {
				memory := fmt.Sprintf("[x9], #%d", delta)
				if pre {
					memory = fmt.Sprintf("[x9, #%d]!", delta)
				}
				cases = append(cases, form{load.operands + ", " + memory, load.bytes, delta, pre})
			}
		}
	}
	lines := make([]string, len(cases))
	for i, test := range cases {
		lines[i] = test.line
	}
	words := assembleARM64LLVMWords(t, lines, "")
	for i, test := range cases {
		t.Run(test.line, func(t *testing.T) {
			var code [4]byte
			binary.LittleEndian.PutUint32(code[:], words[i])
			ins, err := arm64asm.Decode(code[:])
			if err != nil {
				t.Fatal(err)
			}
			var memory arm64asm.MemImmediate
			for _, arg := range ins.Args {
				if value, ok := arg.(arm64asm.MemImmediate); ok {
					memory = value
				}
			}
			start := int64(64)
			if test.pre {
				start += test.delta
			}
			if !arm64RawPoolLoadInBounds(ins, words[i], memory, 64, start+test.bytes) {
				t.Fatal("exact footprint rejected")
			}
			if arm64RawPoolLoadInBounds(ins, words[i], memory, 64, start+test.bytes-1) {
				t.Fatal("one-byte overrun accepted")
			}
			base, delta, valid := arm64PoolLoadWriteback(ins, words[i])
			if !valid || base != 9 || delta != test.delta {
				t.Fatalf("writeback=(%d, %d, %v), want (9, %d, true)", base, delta, valid, test.delta)
			}
			_, value, affine := arm64PoolAffineDefinition(words[i])
			expected := arm64PoolRegisterExpression(9)
			expected.constant = uint64(test.delta)
			if !affine || value != expected {
				t.Fatalf("wrong affine base update: %+v, %v", value, affine)
			}
		})
	}
}

func TestARM64RawPoolWritebackRejectsOverlaps(t *testing.T) {
	for _, line := range []string{"ldr x0, [x9], #8", "ldr w0, [x9, #-8]!", "ldp x0, x1, [x9], #16"} {
		word := assembleARM64LLVMWords(t, []string{line}, "")[0]
		for _, shift := range []uint{0, 10} {
			if shift == 10 && word&0x3a000000 != 0x28000000 {
				continue
			}
			overlap := word&^(31<<shift) | 9<<shift
			var code [4]byte
			binary.LittleEndian.PutUint32(code[:], overlap)
			if ins, err := arm64asm.Decode(code[:]); err == nil {
				if _, _, valid := arm64PoolLoadWriteback(ins, overlap); valid {
					t.Fatalf("accepted destination/base overlap: %s (%#x)", line, overlap)
				}
			}
			if _, _, valid := arm64PoolAffineDefinition(overlap); valid {
				t.Fatalf("overlap invented an affine definition: %s (%#x)", line, overlap)
			}
		}
	}
}
