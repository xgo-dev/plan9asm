//go:build go1.27
// +build go1.27

package plan9asm

import (
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
)

func TestARM64RawPrefetchAddressingMatchesLLVM22(t *testing.T) {
	type sample struct {
		assembly  string
		base      int
		index     int
		registers uint32
	}
	var samples []sample
	for hint := 0; hint < 32; hint++ {
		for _, base := range []struct {
			name string
			reg  int
		}{{"x9", 9}, {"sp", 31}} {
			for _, offset := range []int{0, 8, 32760} {
				assembly := fmt.Sprintf("prfm #%d, [%s, #%d]", hint, base.name, offset)
				samples = append(samples, sample{assembly, base.reg, 31, 31 << 5})
			}
			for _, offset := range []int{-256, -1, 0, 255} {
				assembly := fmt.Sprintf("prfum #%d, [%s, #%d]", hint, base.name, offset)
				samples = append(samples, sample{assembly, base.reg, 31, 31 << 5})
			}
		}
		if hint >= 24 {
			continue // This part of the register opcode space encodes RPRFM.
		}
		for _, extend := range []struct{ name, register, zero string }{
			{"uxtw", "w7", "wzr"}, {"lsl", "x7", "xzr"},
			{"sxtw", "w7", "wzr"}, {"sxtx", "x7", "xzr"},
		} {
			for _, shift := range []int{0, 3} {
				assembly := fmt.Sprintf("prfm #%d, [x9, %s, %s #%d]", hint, extend.register, extend.name, shift)
				samples = append(samples, sample{assembly, 9, 7, 31<<5 | 31<<16})
				assembly = fmt.Sprintf("prfm #%d, [sp, %s, %s #%d]", hint, extend.zero, extend.name, shift)
				samples = append(samples, sample{assembly, 31, 31, 31 << 5})
			}
		}
	}
	for hint := 0; hint < 64; hint++ {
		assembly := fmt.Sprintf("rprfm #%d, x7, [x9]", hint)
		samples = append(samples, sample{assembly, 9, 7, 31<<5 | 31<<16})
		assembly = fmt.Sprintf("rprfm #%d, xzr, [sp]", hint)
		samples = append(samples, sample{assembly, 31, 31, 31 << 5})
	}
	lines := make([]string, len(samples))
	for i, sample := range samples {
		lines[i] = sample.assembly
	}
	words := assembleARM64LLVMWords(t, lines, "")
	var source strings.Builder
	source.WriteString("TEXT rawPrefetch(SB),516,$0-0\nMOVD $7,R7\nMOVD $9,R9\n")
	for i, word := range words {
		sample := samples[i]
		fmt.Fprintf(&source, "WORD $%#08x\n", word)
		want := arm64RawContinuationEffects{readsSP: sample.base == 31}
		if sample.base != 31 {
			want.gpReads |= 1 << sample.base
		}
		if sample.index != 31 {
			want.gpReads |= 1 << sample.index
		}
		if effect, ok := arm64RawContinuationEffectsForWord(word); !ok || effect != want {
			t.Errorf("%s: effects %+v, recognized %t, want %+v", sample.assembly, effect, ok, want)
		}
	}
	source.WriteString("RET\n")
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{arm64LinuxGNUTriple, "aarch64-apple-darwin", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple,
				Sigs: map[string]FuncSig{"rawPrefetch": {Name: "rawPrefetch", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			object := compileLLVMToObject(t, llc, triple, "prefetch.ll", "prefetch.o", ir)
			text := arm64BarrierObjectText(t, object, triple)
			var emitted []uint32
			for at := 0; at+4 <= len(text); at += 4 {
				word := binary.LittleEndian.Uint32(text[at:])
				if word&0xffc00000 == 0xf9800000 || word&0xffe00c00 == 0xf8800000 || word&0xffe00c00 == 0xf8a00800 {
					emitted = append(emitted, word)
				}
			}
			if len(emitted) != len(words) {
				t.Fatalf("emitted %d prefetch encodings, want %d", len(emitted), len(words))
			}
			for i, word := range words {
				mask := ^samples[i].registers // LLVM can allocate the ordinary GP operands.
				if emitted[i]&mask != word&mask {
					t.Errorf("%s: emitted %#08x, want %#08x with mask %#08x", samples[i].assembly, emitted[i], word, mask)
				}
			}
		})
	}
}
