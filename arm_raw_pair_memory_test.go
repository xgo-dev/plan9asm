package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// These encodings use R4 as the base, R0:R1 as the value pair and R6 as
// the register offset. EQ makes both the taken and untaken paths observable.
func armRawPairMemoryFixture() (string, []string) {
	var source strings.Builder
	var names []string
	for _, direction := range []uint32{0x000000d0, 0x000000f0} {
		for _, addressing := range []uint32{1 << 24, 1<<24 | 1<<21, 0} {
			for _, offset := range []uint32{1<<22 | 1<<8 | 8, 6} {
				for _, sign := range []uint32{0, 1 << 23} {
					word := direction | addressing | offset | sign | 4<<16
					name := fmt.Sprintf("Pair%d", len(names))
					names = append(names, name)
					fmt.Fprintf(&source, `TEXT ·%s(SB),4,$0-24
 MOVW p+0(FP),R4
 MOVW R4,R7
 MOVW offset+4(FP),R6
 MOVW check+8(FP),R3
 MOVW low+12(FP),R0
 MOVW high+16(FP),R1
 CMP $0,R3
 WORD $%#08x
 MOVW out+20(FP),R5
 MOVW R0,(R5)
 MOVW R1,4(R5)
 SUB R7,R4,R4
 MOVW R4,8(R5)
 RET
`, name, word)
				}
			}
		}
	}
	return source.String(), names
}

func armRawPairMemorySignatures(names []string) map[string]FuncSig {
	types := []LLVMType{Ptr, I32, I32, I32, I32, Ptr}
	params := make([]FrameSlot, len(types))
	for i, typ := range types {
		params[i] = FrameSlot{Offset: int64(i * 4), Index: i, Field: -1, Type: typ}
	}
	sigs := make(map[string]FuncSig, len(names))
	for _, name := range names {
		sigs[name] = FuncSig{Name: name, Args: types, Ret: Void, Frame: FrameLayout{Params: params}}
	}
	return sigs
}

func TestARMRawPairMemoryCompleteAddressForms(t *testing.T) {
	source, names := armRawPairMemoryFixture()
	requireARMGoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM, source)
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{
		"armv5te-unknown-linux-gnueabi",
		"armv7-unknown-linux-gnueabihf",
		"thumbv7-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{
				Goarch: "arm", TargetTriple: triple, Sigs: armRawPairMemorySignatures(names),
				ResolveSym: func(name string) string { return strings.TrimPrefix(name, "·") },
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, instruction := range []string{"ldrd", "strd"} {
				if count := strings.Count(ir, "asm sideeffect \""+instruction+" "); count != 12 {
					t.Fatalf("translated %d %s address forms, want 12", count, instruction)
				}
			}
			compileLLVMToObject(t, llc, triple, "pair.ll", "pair.o", ir)
		})
	}
}

func TestARMRawPairMemoryChecksSourceContext(t *testing.T) {
	for _, test := range []struct {
		name    string
		word    uint32
		context bool
	}{
		{"predicate without NZCV", 0x014400d8, true},
		{"literal needs PC layout", 0xe1cf00d8, true},
		{"register offset reserved bits", 0xe00404d2, false},
		{"writeback overlaps pair", 0xe0c000d8, false},
		{"load offset overlaps pair", 0xe18400d1, false},
		{"PC as offset register", 0xe18400df, false},
		{"odd start register", 0xe1c410d8, false},
		{"unallocated post-index bit", 0xe0e400d8, false},
		{"official data payload", 0x000004d2, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			source := fmt.Sprintf("TEXT pair(SB),4,$0-0\nWORD $%#08x\nRET\n", test.word)
			file, err := Parse(ArchARM, source)
			if err != nil {
				t.Fatal(err)
			}
			_, err = Translate(file, Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf",
				Sigs: map[string]FuncSig{"pair": {Name: "pair", Ret: Void}}})
			if err == nil || errors.Is(err, ErrProbeNeedsContext) != test.context {
				t.Fatalf("raw pair context=%v, got %v", test.context, err)
			}
		})
	}
}
