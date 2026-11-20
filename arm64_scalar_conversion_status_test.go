package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

// This table is independent of the production decoder. Go asm7's case 29
// exposes eight F->GP and eight GP->F names. Arm DDI0602 additionally defines
// the registered H/S/D WORDs, five explicit F->GP rounding modes and scalar
// SIMD integer carriers. Arranged vector, SVE and fixed-point forms are absent.
type arm64ScalarConversionFixture struct {
	name                          string
	word                          uint32
	floatBits, integerBits        int
	toFloat, unsigned, simd, dead bool
	zero                          bool
	rounding                      int // N, A, P, M, Z in architecture order below.
}

func (fixture arm64ScalarConversionFixture) sourceWord() int {
	if fixture.toFloat && !fixture.simd {
		return 64
	}
	if fixture.word != 0 {
		return int(fixture.word>>5&31) * 2
	}
	return 12
}

func (fixture arm64ScalarConversionFixture) resultWord() int {
	if !fixture.toFloat && !fixture.simd {
		return 65
	}
	if fixture.word != 0 {
		return int(fixture.word&31) * 2
	}
	return 46
}

func arm64ScalarConversionFixtures() []arm64ScalarConversionFixture {
	var fixtures []arm64ScalarConversionFixture
	for _, unsigned := range []bool{false, true} {
		for _, width := range []struct {
			bits int
			code uint32
		}{{16, 3}, {32, 0}, {64, 1}} {
			for _, integerBits := range []int{32, 64} {
				fields := width.code<<22 | 6<<5 | 3
				if unsigned {
					fields |= 1 << 16
				}
				if integerBits == 64 {
					fields |= 1 << 31
				}
				for rounding, base := range []uint32{0x1e200000, 0x1e240000, 0x1e280000, 0x1e300000, 0x1e380000} {
					fixtures = append(fixtures, arm64ScalarConversionFixture{
						word: base | fields, floatBits: width.bits, integerBits: integerBits,
						unsigned: unsigned, rounding: rounding,
					})
				}
				fixtures = append(fixtures, arm64ScalarConversionFixture{
					word:      0x1e220000 | fields&^uint32(31<<5|31) | 2<<5 | 23,
					floatBits: width.bits, integerBits: integerBits, unsigned: unsigned, toFloat: true,
				})
			}
			base := map[int]uint32{16: 0x5ef9b800, 32: 0x5ea1b800, 64: 0x5ee1b800}[width.bits]
			if unsigned {
				base |= 1 << 29
			}
			fixtures = append(fixtures, arm64ScalarConversionFixture{
				word: base | 6<<5 | 23, floatBits: width.bits, integerBits: width.bits,
				unsigned: unsigned, simd: true, rounding: 4,
			})
			base = map[int]uint32{16: 0x5e79d800, 32: 0x5e21d800, 64: 0x5e61d800}[width.bits]
			if unsigned {
				base |= 1 << 29
			}
			fixtures = append(fixtures, arm64ScalarConversionFixture{
				word: base | 6<<5 | 23, floatBits: width.bits, integerBits: width.bits,
				unsigned: unsigned, simd: true, toFloat: true,
			})
		}
	}
	// Named forms are separate witnesses, not decoder-generated spellings.
	for _, unsigned := range []bool{false, true} {
		for _, floatBits := range []int{32, 64} {
			for _, integerBits := range []int{32, 64} {
				kind, width, integer := "S", "S", ""
				if unsigned {
					kind = "U"
				}
				if floatBits == 64 {
					width = "D"
				}
				if integerBits == 32 {
					integer = "W"
				}
				fixtures = append(fixtures,
					arm64ScalarConversionFixture{name: "FCVTZ" + kind + width + integer, floatBits: floatBits, integerBits: integerBits, unsigned: unsigned, rounding: 4},
					arm64ScalarConversionFixture{name: kind + "CVTF" + integer + width, floatBits: floatBits, integerBits: integerBits, unsigned: unsigned, toFloat: true},
				)
			}
		}
	}
	return fixtures
}

func arm64ScalarConversionSource(fixtures []arm64ScalarConversionFixture) (string, map[string]FuncSig) {
	var source strings.Builder
	sigs := make(map[string]FuncSig)
	for index, fixture := range fixtures {
		name := fmt.Sprintf("scalarStatus%d", index)
		sigs[name] = arm64SM3Signature(name)
		fmt.Fprintf(&source, "TEXT %s(SB),4,$0-16\nMOVD in+0(FP),R0\nMOVD out+8(FP),R1\n", name)
		for register := 0; register < 32; register++ {
			fmt.Fprintf(&source, "VLD1.P 16(R0),[V%d.B16]\n", register)
		}
		source.WriteString("MOVD (R0),R2\nMOVD 8(R0),R3\nMRS FPCR,R10\nMRS FPSR,R11\n")
		source.WriteString("MOVD 16(R0),R12\nMSR R12,FPCR\nMOVD 24(R0),R12\nMSR R12,FPSR\n")
		source.WriteString(arm64ScalarConversionInstruction(fixture) + "\n")
		if fixture.dead {
			source.WriteString("SUB $512,R0,R4\n")
			for register := 0; register < 32; register++ {
				fmt.Fprintf(&source, "VLD1.P 16(R4),[V%d.B16]\n", register)
			}
			source.WriteString("MOVD 8(R0),R3\n")
		}
		for register := 0; register < 32; register++ {
			fmt.Fprintf(&source, "VST1.P [V%d.B16],16(R1)\n", register)
		}
		source.WriteString("MOVD R2,(R1)\nMOVD R3,8(R1)\nMRS FPCR,R12\nMOVD R12,16(R1)\n")
		source.WriteString("MRS FPSR,R12\nMOVD R12,24(R1)\nMSR R10,FPCR\nMSR R11,FPSR\nRET\n")
	}
	return source.String(), sigs
}

func TestARM64ScalarConversionStatusRetainsNativeEffects(t *testing.T) {
	fixtures := arm64ScalarConversionFixtures()
	if len(fixtures) != 100 {
		t.Fatalf("independent family changed: %d", len(fixtures))
	}
	for i := range fixtures {
		fixtures[i].dead = true
	}
	source, sigs := arm64ScalarConversionSource(fixtures)
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: "aarch64-unknown-linux-gnu", Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	for _, variant := range []string{ir, armFloatEffectOptimizedIR(t, ir)} {
		count := 0
		for _, line := range strings.Split(variant, "\n") {
			if strings.Contains(line, "asm sideeffect") && strings.Contains(line, "cvt") {
				count++
			}
		}
		if count != len(fixtures) {
			t.Errorf("retained %d/%d native conversion effects with dead outputs", count, len(fixtures))
		}
	}
}

func arm64ScalarConversionBankFixtures() []arm64ScalarConversionFixture {
	var fixtures []arm64ScalarConversionFixture
	for _, fixture := range arm64ScalarConversionFixtures() {
		if fixture.simd {
			for source := 0; source < 32; source++ {
				for _, destination := range []int{source, 31 - source} {
					alias := fixture
					alias.word = alias.word&^uint32(31<<5|31) | uint32(source)<<5 | uint32(destination)
					fixtures = append(fixtures, alias)
				}
			}
		} else {
			fixture.zero = true
			fixtures = append(fixtures, fixture)
		}
	}
	return fixtures
}

func arm64ScalarConversionBankPartitions() [][]arm64ScalarConversionFixture {
	fixtures := arm64ScalarConversionBankFixtures()
	var partitions [][]arm64ScalarConversionFixture
	for start := 0; start < len(fixtures); start += 128 {
		end := start + 128
		if end > len(fixtures) {
			end = len(fixtures)
		}
		partitions = append(partitions, fixtures[start:end])
	}
	return partitions
}

func requireARM64ScalarConversionBankPartition(t *testing.T) {
	t.Helper()
	complete := arm64ScalarConversionBankFixtures()
	partitions := arm64ScalarConversionBankPartitions()
	if len(complete) != 856 || len(partitions) != 7 {
		t.Fatalf("bank matrix changed: %d functions, %d partitions", len(complete), len(partitions))
	}
	seen := make(map[string]bool)
	position := 0
	for _, partition := range partitions {
		if len(partition) == 0 || len(partition) > 128 {
			t.Fatalf("unbounded/empty native bank partition: %d", len(partition))
		}
		for _, fixture := range partition {
			instruction := arm64ScalarConversionInstruction(fixture)
			if seen[instruction] || position >= len(complete) || fixture != complete[position] {
				t.Fatalf("duplicated, reordered or foreign function at %d: %s", position, instruction)
			}
			seen[instruction] = true
			position++
		}
	}
	if position != len(complete) || len(seen)*2 != 1712 {
		t.Fatalf("native bank partition omitted functions/rows: %d functions, %d unique rows", position, len(seen)*2)
	}
}

func TestARM64ScalarConversionBankPartitionIsExact(t *testing.T) {
	requireARM64ScalarConversionBankPartition(t)
}
