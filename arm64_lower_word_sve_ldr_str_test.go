package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func encodeARM64RawSVELoadStore(load bool, immediate, base, vector int) uint32 {
	word := uint32(0xe5804000)
	if load {
		word = 0x85804000
	}
	imm9 := uint32(immediate) & 0x1ff
	return word | (imm9>>3)<<16 | (imm9&7)<<10 | uint32(base)<<5 | uint32(vector)
}

func TestTranslateARM64RawSVELoadStoreCompleteFormat(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT sveLoadStoreRaw(SB), $0-0\n")
	for _, form := range []struct {
		load                    bool
		immediate, base, vector int
	}{{true, -256, 0, 0}, {true, 255, 31, 31}, {false, -256, 0, 0}, {false, 255, 31, 31}} {
		fmt.Fprintf(&source, "\tWORD $%#08x\n", encodeARM64RawSVELoadStore(form.load, form.immediate, form.base, form.vector))
	}
	source.WriteString("\tRET\n")
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		ir, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"sveLoadStoreRaw": {Name: "sveLoadStoreRaw", Ret: Void}}})
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"load <vscale x 16 x i8>", "store <vscale x 16 x i8>", "call i64 @llvm.vscale.i64()", `"target-features"="+sve"`} {
			if !strings.Contains(ir, want) {
				t.Fatalf("%s SVE LDR/STR IR omitted %q:\n%s", triple, want, ir)
			}
		}
		llc := findLLVM22Tool("llc")
		if llc == "" {
			t.Fatal("LLVM 22 llc not found")
		}
		compileLLVMToObject(t, llc, triple, "arm64-sve-ldr-str.ll", "arm64-sve-ldr-str.o", ir)
	}
}

func TestARM64RawSVELoadStoreDecoderCoversEveryEncodingField(t *testing.T) {
	count := 0
	for _, load := range []bool{false, true} {
		for immediate := -256; immediate <= 255; immediate++ {
			for base := 0; base < 32; base++ {
				for vector := 0; vector < 32; vector++ {
					word := encodeARM64RawSVELoadStore(load, immediate, base, vector)
					got, ok := decodeARM64RawSVELoadStore(word)
					if !ok || got.load != load || got.immediate != immediate || got.base != base || got.vector != vector {
						t.Fatalf("decoded SVE LDR/STR %#08x as %+v, ok=%v", word, got, ok)
					}
					count++
				}
			}
		}
	}
	if count != 2*512*32*32 {
		t.Fatalf("covered %d SVE LDR/STR encodings", count)
	}
}

func TestARM64RawSVELoadStoreDecoderRejectsAdjacentEncodings(t *testing.T) {
	for _, word := range []uint32{0x85404000, 0xe5404000, 0x85806000} {
		if _, ok := decodeARM64RawSVELoadStore(word); ok {
			t.Fatalf("SVE LDR/STR decoder accepted adjacent encoding %#08x", word)
		}
	}
}
