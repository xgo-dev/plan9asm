package plan9asm

import "fmt"

type arm64RawContinuationEffects struct {
	gpReads  uint32
	gpWrites uint32
	readsSP  bool
	stores   bool
}

// These effects track source GP outputs and external memory stores for caller
// continuation provenance. FP/SIMD/ZA state is a different register bank, and
// backend scratch clobbers are not writes to source virtual GP registers.
// Each concrete decoder retains its complete operand and reserved-bit grammar.
type arm64RawFamily struct {
	effects func(uint32) (arm64RawContinuationEffects, bool)
	lower   func(*arm64Ctx, uint32) error
}

func arm64RawForm[T any](
	decode func(uint32) (T, bool),
	lower func(*arm64Ctx, T) error,
	effects func(T) arm64RawContinuationEffects,
) arm64RawFamily {
	return arm64RawFamily{
		effects: func(word uint32) (arm64RawContinuationEffects, bool) {
			form, ok := decode(word)
			if !ok {
				return arm64RawContinuationEffects{}, false
			}
			return effects(form), true
		},
		lower: func(c *arm64Ctx, word uint32) error {
			form, ok := decode(word)
			if !ok {
				return fmt.Errorf("ARM64 raw family rejected its selected encoding %#08x", word)
			}
			return lower(c, form)
		},
	}
}

// Only explicitly registered forms with no GP outputs or external memory
// access use this constructor. Their FP/SIMD/ZA effects are still lowered;
// GP conversions and memory forms provide typed bank/direction effects.
func arm64RawNoGPOrMemoryForm[T any](decode func(uint32) (T, bool), lower func(*arm64Ctx, T) error) arm64RawFamily {
	return arm64RawForm(decode, lower, func(T) arm64RawContinuationEffects {
		return arm64RawContinuationEffects{}
	})
}

func arm64RawGPBit(index int) uint32 {
	if index >= 0 && index < 31 {
		return 1 << uint(index)
	}
	return 0 // Encoding 31 is WZR/XZR, not SP.
}

// Lowering, raw-pool writes and source continuation proof share typed decoders.
// Unregistered encodings still fall through to conservative effect analysis.
func arm64RawContinuationEffectsForWord(word uint32) (arm64RawContinuationEffects, bool) {
	if _, effects, ok := decodeARM64RawFloatFamily(word); ok {
		return effects, true
	}
	if _, effects, ok := decodeARM64RawVectorFamily(word); ok {
		return effects, true
	}
	if _, effects, ok := decodeARM64RawStateFamily(word); ok {
		return effects, true
	}
	return arm64RawContinuationEffects{}, false
}
