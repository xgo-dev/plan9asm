package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateARM64SVECharacterMatchCompleteGo127Family(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT svecharactermatch(SB),$0-0\n")
	for opIndex, op := range []string{"ZMATCH", "ZNMATCH"} {
		for widthIndex, width := range []string{"B", "H"} {
			fmt.Fprintf(&source, "\t%s Z%d.%s, Z%d.%s, P%d.Z, P%d.%s\n", op, opIndex*2+widthIndex, width, opIndex*2+widthIndex+1, width, opIndex+widthIndex, opIndex*2+widthIndex+8, width)
		}
	}
	source.WriteString("\tRET\n")
	requireARM64SVEGoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"svecharactermatch": {Name: "svecharactermatch", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`"target-features"="+sve,+sve2"`,
				"@llvm.aarch64.sve.match.nxv16i8",
				"@llvm.aarch64.sve.match.nxv8i16",
				"@llvm.aarch64.sve.nmatch.nxv16i8",
				"@llvm.aarch64.sve.nmatch.nxv8i16",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE character-match lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-character-match.ll", "arm64-sve-character-match.o", ll)
		})
	}
}

func TestTranslateARM64RawSVECharacterMatchCompleteFamily(t *testing.T) {
	// Go 1.27's ZMATCH/ZNMATCH rows permit B/H elements, P0..P7 as the
	// governing predicate, and all P destinations. The first encoding is
	// independently checked against LLVM MC and occurs in lightning.
	const observedMatch = uint32(0x45218402)
	var source strings.Builder
	source.WriteString("TEXT rawSVECharacterMatch(SB),$0-0\n")
	fmt.Fprintf(&source, "\tWORD $%#08x\n", observedMatch)
	for _, notMatch := range []bool{false, true} {
		for _, halfword := range []bool{false, true} {
			word := uint32(0x45208000) | 30<<16 | 31<<5 | 7<<10 | 15
			if notMatch {
				word |= 1 << 4
			}
			if halfword {
				word |= 1 << 22
			}
			fmt.Fprintf(&source, "\tWORD $%#08x\n", word)
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
					"rawSVECharacterMatch": {Name: "rawSVECharacterMatch", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`"target-features"="+sve,+sve2"`,
				"@llvm.aarch64.sve.match.nxv16i8",
				"@llvm.aarch64.sve.match.nxv8i16",
				"@llvm.aarch64.sve.nmatch.nxv16i8",
				"@llvm.aarch64.sve.nmatch.nxv8i16",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s raw SVE character-match IR omitted %q", triple, want)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-sve-character-match.ll", "arm64-raw-sve-character-match.o", ll)
		})
	}
}

func TestDecodeARM64RawSVECharacterMatchBoundaries(t *testing.T) {
	for _, test := range []struct {
		name string
		word uint32
		op   Op
		args []Reg
	}{
		{
			name: "lightning-match-byte",
			word: 0x45218402,
			op:   "ZMATCH",
			args: []Reg{"Z1.B", "Z0.B", "P1.Z", "P2.B"},
		},
		{
			name: "nmatch-halfword-high-registers",
			word: 0x457e9fff,
			op:   "ZNMATCH",
			args: []Reg{"Z30.H", "Z31.H", "P7.Z", "P15.H"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			ins, ok := decodeARM64RawSVECharacterMatch(test.word)
			if !ok || ins.Op != test.op || len(ins.Args) != len(test.args) {
				t.Fatalf("decode %#08x = %+v, %v", test.word, ins, ok)
			}
			for index, want := range test.args {
				if ins.Args[index].Kind != OpReg || ins.Args[index].Reg != want {
					t.Errorf("operand %d = %+v, want %s", index, ins.Args[index], want)
				}
			}
		})
	}
	for _, word := range []uint32{
		0x45208000 ^ (1 << 15), // fixed one bit
		0x45208000 | (1 << 13), // reserved bit
		0x45208000 | (1 << 23), // adjacent instruction class
	} {
		if ins, ok := decodeARM64RawSVECharacterMatch(word); ok {
			t.Errorf("decoded reserved encoding %#08x as %+v", word, ins)
		}
	}
}

func TestTranslateARM64SVECharacterMatchRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZMATCH Z1.S, Z2.S, P0.Z, P1.S",
		"ZNMATCH Z1.D, Z2.D, P0.Z, P1.D",
		"ZMATCH Z1.B, Z2.H, P0.Z, P1.B",
		"ZNMATCH Z1.H, Z2.H, P8.Z, P1.H",
		"ZMATCH Z1.B, Z2.B, P0.M, P1.B",
		"ZNMATCH Z1.H, Z2.H, P0.Z, P1.B",
		"ZMATCH.Z Z1.B, Z2.B, P0.Z, P1.B",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_", ",", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsvecharactermatch(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvecharactermatch": {Name: "badsvecharactermatch", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's character-match forms", instruction)
			}
		})
	}
}
