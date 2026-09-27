package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateARM64RawTableLookupCompleteAdvancedSIMDFormats(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT rawtablelookupforms(SB),$0-0\n")
	for _, extension := range []bool{false, true} {
		for _, lanes := range []int{8, 16} {
			for tableCount := 1; tableCount <= 4; tableCount++ {
				word := uint32(0x0e000000 | ((tableCount - 1) << 13) | (3 << 16) | (2 << 5) | 1)
				if extension {
					word |= 1 << 12
				}
				if lanes == 16 {
					word |= 1 << 30
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
					"rawtablelookupforms": {Name: "rawtablelookupforms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"<8 x i8>", "<16 x i8>", "<64 x i8>", "icmp ult i32"} {
				if !strings.Contains(ll, want) {
					t.Fatalf("ARM64 raw table lookup lowering for %s omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-table-lookup.ll", "arm64-raw-table-lookup.o", ll)
		})
	}
}

func TestARM64RawTableLookupDecoderCoversAllRegisterFields(t *testing.T) {
	for _, extension := range []bool{false, true} {
		for _, lanes := range []int{8, 16} {
			for tableCount := 1; tableCount <= 4; tableCount++ {
				for index := 0; index < 32; index++ {
					for firstTable := 0; firstTable < 32; firstTable++ {
						for destination := 0; destination < 32; destination++ {
							word := uint32(0x0e000000 | ((tableCount - 1) << 13) | (index << 16) | (firstTable << 5) | destination)
							if extension {
								word |= 1 << 12
							}
							if lanes == 16 {
								word |= 1 << 30
							}
							form, ok := decodeARM64RawTableLookup(word)
							if !ok || form.extension != extension || form.lanes != lanes || form.tableCount != tableCount || form.index != index || form.firstTable != firstTable || form.destination != destination {
								t.Fatalf("decode %#08x = %#v, %v", word, form, ok)
							}
						}
					}
				}
			}
		}
	}
}

func TestARM64RawTableLookupDecoderRejectsAdjacentEncodings(t *testing.T) {
	for _, word := range []uint32{
		0x2e030042,
		0x0e038042,
		0x0e030442,
		0x0e030c42,
	} {
		if form, ok := decodeARM64RawTableLookup(word); ok {
			t.Fatalf("table lookup decoder accepted adjacent encoding %#08x as %#v", word, form)
		}
	}
}
