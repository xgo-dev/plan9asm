package plan9asm

import "testing"

func TestCrossLinuxRuntimeMatrixARM64ScalarConversionNativeMerge(t *testing.T) {
	var fixtures []arm64ScalarConversionFixture
	for _, fixture := range arm64ScalarConversionFixtures() {
		if !fixture.toFloat && !fixture.simd {
			continue // GP results do not use IsMerging(FPCR).
		}
		fixtures = append(fixtures, fixture)
		if fixture.simd {
			alias := fixture
			alias.word = alias.word&^uint32(31) | alias.word>>5&31
			fixtures = append(fixtures, alias)
		}
	}
	for _, fixture := range append([]arm64ScalarConversionFixture(nil), fixtures...) {
		fixture.dead = true
		fixtures = append(fixtures, fixture)
	}

	var rows []arm64ScalarConversionObservation
	for index, fixture := range fixtures {
		for _, control := range []uint64{0, 4, 0x03400000, 0x03400004} {
			row := arm64ScalarConversionKnownObservation(index, fixture, control)
			source, destination := fixture.sourceWord(), fixture.resultWord()
			if !fixture.toFloat || fixture.simd {
				sourceBits := fixture.floatBits
				if fixture.toFloat {
					sourceBits = fixture.integerBits
				}
				mask := ^uint64(0) >> uint(64-sourceBits)
				row.input[source] |= 0xfedcba9876543210 &^ mask
				if fixture.dead || source != destination {
					row.want[source] = row.input[source]
				}
			}
			if control&4 != 0 && !fixture.dead {
				resultBits := fixture.integerBits
				if fixture.toFloat {
					resultBits = fixture.floatBits
				}
				mask := ^uint64(0) >> uint(64-resultBits)
				// DDI0602's covered GP->F and scalar SIMD conversions merge
				// old V[d], including the remainder of its low 64-bit word.
				row.want[destination] = row.input[destination]&^mask | row.want[destination]&mask
				row.want[destination+1] = row.input[destination+1]
			}
			rows = append(rows, row)
		}
	}
	if len(fixtures) != 88 || len(rows) != 352 {
		t.Fatalf("native merge matrix changed: %d functions, %d rows", len(fixtures), len(rows))
	}
	// The independent full-state expectation requires actual NEP readback and
	// high-lane preservation. An emulator ignoring NEP cannot pass this root.
	// This observes these opcodes, not the entire advertised FEAT_AFP contract.
	runARM64ScalarConversionObservations(t, fixtures, rows)
}
