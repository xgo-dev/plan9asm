package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

type armNEONConversionFixture struct {
	word           uint32
	source, target int // Physical D number; a Q occupies an even pair.
	quad, toFloat  bool
	unsigned, dead bool
}

// Arm DDI0406C.c A8.8.305, independent of the production decoder. These
// operations use StandardFPSCRValue, unlike the neighboring scalar VCVT.
func armNEONConversionFixtureWord(toFloat, unsigned, quad bool, source, target int) uint32 {
	word := uint32(0xf3bb0600)
	if !toFloat {
		word |= 1 << 8
	}
	if unsigned {
		word |= 1 << 7
	}
	if quad {
		word |= 1 << 6
	}
	return word | uint32(target%16)<<12 | uint32(target/16)<<22 | uint32(source%16) | uint32(source/16)<<5
}

func armNEONConversionStatusFixtures() []armNEONConversionFixture {
	var fixtures []armNEONConversionFixture
	for _, toFloat := range []bool{false, true} {
		for _, unsigned := range []bool{false, true} {
			for _, quad := range []bool{false, true} {
				for _, dead := range []bool{false, true} {
					fixtures = append(fixtures, armNEONConversionFixture{
						word:   armNEONConversionFixtureWord(toFloat, unsigned, quad, 0, 2),
						source: 0, target: 2, quad: quad, toFloat: toFloat, unsigned: unsigned, dead: dead,
					})
				}
			}
		}
	}
	return fixtures
}

func armNEONConversionEndpointFixtures() []armNEONConversionFixture {
	var fixtures []armNEONConversionFixture
	for _, toFloat := range []bool{false, true} {
		for _, unsigned := range []bool{false, true} {
			for _, quad := range []bool{false, true} {
				step := 1
				if quad {
					step = 2
				}
				for source := 0; source < 32; source += step {
					for _, alias := range []bool{false, true} {
						target := source
						if !alias {
							target = (source + 7*step) % 32
						}
						fixtures = append(fixtures, armNEONConversionFixture{
							word:   armNEONConversionFixtureWord(toFloat, unsigned, quad, source, target),
							source: source, target: target, quad: quad, toFloat: toFloat, unsigned: unsigned,
						})
					}
				}
			}
		}
	}
	return fixtures
}

func armNEONConversionFixtureSource(fixtures []armNEONConversionFixture) (string, map[string]FuncSig) {
	var source strings.Builder
	sigs := make(map[string]FuncSig, len(fixtures))
	loadBank := func() {
		for register := 0; register < 32; register++ {
			// VLDR Dn,[R0,#8*n], including the raw-only D16–31 bank.
			word := uint32(0xed900b00 | (register%16)<<12 | (register/16)<<22 | register*2)
			fmt.Fprintf(&source, "WORD $%#x\n", word)
		}
	}
	for index, fixture := range fixtures {
		name := fmt.Sprintf("neonStatus%d", index)
		fmt.Fprintf(&source, "TEXT %s(SB),4,$0-8\nMOVW input+0(FP),R0\nMOVW output+4(FP),R1\n", name)
		loadBank()
		source.WriteString("WORD $0xeef14a10\nMOVW 256(R0),R3\nWORD $0xeee13a10\n")
		fmt.Fprintf(&source, "WORD $%#x\n", fixture.word)
		if fixture.dead {
			// Every conversion output is overwritten. Its exception effect is
			// nevertheless observable in the following real VMRS.
			loadBank()
		}
		source.WriteString("WORD $0xeef13a10\nWORD $0xeee14a10\n")
		for register := 0; register < 32; register++ {
			// VSTR Dn,[R1,#8*n]. Observe every D alias, not just the result.
			word := uint32(0xed810b00 | (register%16)<<12 | (register/16)<<22 | register*2)
			fmt.Fprintf(&source, "WORD $%#x\n", word)
		}
		source.WriteString("MOVW R3,256(R1)\nRET\n")
		sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr, Ptr}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1},
				{Offset: 4, Type: Ptr, Index: 1, Field: -1},
			}},
		}
	}
	return source.String(), sigs
}

func TestARMNEONConversionStatusRetainsNativeSideEffects(t *testing.T) {
	fixtures := armNEONConversionStatusFixtures()
	source, sigs := armNEONConversionFixtureSource(fixtures)
	file, err := Parse(ArchARM, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf", Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	for _, variant := range []struct{ name, ir string }{{"unoptimized", ir}, {"optimized", armFloatEffectOptimizedIR(t, ir)}} {
		if count := strings.Count(variant.ir, `asm sideeffect "vcvt.`); count != len(fixtures) {
			t.Errorf("%s loses native NEON/dead exception effects: %d conversions, want %d", variant.name, count, len(fixtures))
		}
		for _, cast := range []string{" = fptosi ", " = fptoui ", " = sitofp ", " = uitofp "} {
			if strings.Contains(variant.ir, cast) {
				t.Errorf("%s replaces Advanced SIMD status with a pure conversion: %s", variant.name, cast)
			}
		}
	}
}

func TestARMNEONConversionAllBankAndAliasObjects(t *testing.T) {
	fixtures := armNEONConversionEndpointFixtures()
	if len(fixtures) != 384 {
		t.Fatalf("incomplete full D/Q bank and alias matrix: %d", len(fixtures))
	}
	source, sigs := armNEONConversionFixtureSource(fixtures)
	file, err := Parse(ArchARM, source)
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc not found")
	}
	for _, triple := range []string{"armv5te-unknown-linux-gnueabi", "armv6-unknown-linux-gnueabihf", "armv7-unknown-linux-gnueabihf", "thumbv7-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{Goarch: "arm", TargetTriple: triple, Sigs: sigs})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, triple, "arm-neon-conversion-banks.ll", "arm-neon-conversion-banks.o", ir)
		})
	}
}

func TestARMNEONConversionNativeTargetAndInvalidSourceBoundary(t *testing.T) {
	for _, fixture := range armNEONConversionStatusFixtures() {
		if fixture.dead {
			continue
		}
		for _, api := range []string{"text", "module", "Go"} {
			for _, triple := range []string{"armv5te-unknown-linux-gnueabi", "armv6-unknown-linux-gnueabihf", "armv7-unknown-linux-gnueabihf", "thumbv7-pc-windows-msvc"} {
				source := fmt.Sprintf("TEXT conversion(SB),4,$0-0\nWORD $%#x\nRET\n", fixture.word)
				if err := armWordFloatBoundaryAPI(t, api, source, triple); err != nil {
					t.Fatalf("%s %s %#x rejects explicit native target: %v", api, triple, fixture.word, err)
				}
			}
			for _, triple := range []string{"", "x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu", "arm64-apple-darwin", "armeb-unknown-linux-gnueabi", "thumbeb-unknown-linux-gnu"} {
				source := fmt.Sprintf("TEXT conversion(SB),4,$0-0\nWORD $%#x\nRET\n", fixture.word)
				if err := armWordFloatBoundaryAPI(t, api, source, triple); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("%s %s %#x did not require native state: %v", api, triple, fixture.word, err)
				}
				for _, body := range []string{
					fmt.Sprintf("WORD $%#x\nWORD $0xffffffff", fixture.word),
					fmt.Sprintf("RET\nWORD $0xffffffff\nWORD $%#x", fixture.word),
				} {
					source := "TEXT conversion(SB),4,$0-0\n" + body + "\nRET\n"
					if err := armWordFloatBoundaryAPI(t, api, source, triple); err == nil || errors.Is(err, ErrProbeNeedsContext) {
						t.Fatalf("%s %s malformed raw input became target context: %v", api, triple, err)
					}
				}
			}
		}
	}
}
