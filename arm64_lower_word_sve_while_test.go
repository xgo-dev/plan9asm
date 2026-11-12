package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateARM64RawSVEWhileLTDiscoveryWord(t *testing.T) {
	const source = `TEXT whileltword(SB),$0-0
	WORD $0x25a217e1 // whilelt p1.s, xzr, x2
	RET
`
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: "aarch64-unknown-linux-gnu",
		Goarch:       "arm64",
		Sigs:         map[string]FuncSig{"whileltword": {Name: "whileltword", Ret: Void}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ll, "@llvm.aarch64.sve.whilelt.nxv4i1.i64") {
		t.Fatalf("raw WHILELT did not use the typed predicate lowering:\n%s", ll)
	}
}

func TestTranslateARM64RawSVEWhileCompleteGo127Family(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT rawpredicatewhileforms(SB),$0-0\n")
	for _, spec := range arm64RawSVEWhileSpecs {
		for size := uint32(0); size < 4; size++ {
			operands := uint32(2<<16 | 9<<5)
			for _, word := range []uint32{
				spec.scalarX | size<<22 | operands | 1,
				spec.scalarW | size<<22 | operands | 1,
				spec.pair | size<<22 | operands | 10,
				spec.counter | size<<22 | operands | 7,
				spec.counter | size<<22 | operands | 1<<13 | 7,
			} {
				decoded, ok := decodeARM64RawSVEWhile(word)
				if !ok || !strings.HasPrefix(string(decoded.Op), "PWHILE"+spec.condition) {
					t.Fatalf("WORD %#08x did not decode as WHILE%s: %+v", word, spec.condition, decoded)
				}
				fmt.Fprintf(&source, "\tWORD $%#08x\n", word)
			}
		}
	}
	source.WriteString("\tRET\n")
	requireARM64GoAssemblerResult(t, source.String(), true)

	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{
		"aarch64-apple-darwin",
		"aarch64-unknown-linux-gnu",
		"aarch64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{
				TargetTriple: triple,
				Goarch:       "arm64",
				Sigs: map[string]FuncSig{
					"rawpredicatewhileforms": {Name: "rawpredicatewhileforms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, spec := range arm64RawSVEWhileSpecs {
				calls := 0
				for _, line := range strings.Split(ll, "\n") {
					if strings.Contains(line, " = call ") &&
						strings.Contains(line, "@llvm.aarch64.sve.while"+strings.ToLower(spec.condition)+".") {
						calls++
					}
				}
				if calls != 20 {
					t.Fatalf("WHILE%s emitted %d calls, want 20", spec.condition, calls)
				}
			}
			for _, want := range []string{
				"+sve2p1",
				"@llvm.aarch64.sve.whilelt.nxv2i1.i32",
				"@llvm.aarch64.sve.whilelt.x2.nxv4i1",
				"@llvm.aarch64.sve.whilelt.c64",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("raw predicate family omitted %q", want)
				}
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-sve-while.ll", "arm64-raw-sve-while.o", ll)
		})
	}
}

func TestDecodeARM64RawSVEWhileRejectsOtherEncodings(t *testing.T) {
	for _, word := range []uint32{
		0x25203010,         // WHILERW is a separate pointer comparison family.
		0x25203410,         // WHILEWR is a separate pointer comparison family.
		0x25201420 | 1<<15, // Reserved bit in the single-predicate form.
		0x25205410 | 1<<15, // Reserved bit in the pair form.
	} {
		if decoded, ok := decodeARM64RawSVEWhile(word); ok {
			t.Fatalf("reserved or foreign WORD %#08x decoded as %+v", word, decoded)
		}
	}
}
