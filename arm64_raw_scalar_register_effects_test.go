package plan9asm

import (
	"encoding/binary"
	"testing"

	"golang.org/x/arch/arm64/arm64asm"
)

func TestARM64NativeScratchScalarRegisterStackAndZeroRoles(t *testing.T) {
	// Independent physical fixtures follow obj7 oprrr/opxrrr. Every valid
	// synthetic word is also decoded by x/arch; it is not a Go object or a
	// numerical execution certificate. In extended arithmetic Rn/non-S Rd
	// 31 is SP, but Rm 31 is always zero. Shifted families use zero throughout.
	for _, family := range []uint32{0x0a000000, 0x0a200000, 0x0b000000, 0x0b200000} {
		for _, width := range []int{32, 64} {
			for operation := uint32(0); operation < 4; operation++ {
				for _, first := range []uint32{1, 27, 30, 31} {
					for _, second := range []uint32{0, 1, 27, 30, 31} {
						for _, destination := range []uint32{4, 27, 30, 31} {
							word := family | operation<<29 | second<<16 | first<<5 | destination
							if width == 64 {
								word |= 1 << 31
							}
							var code [4]byte
							binary.LittleEndian.PutUint32(code[:], word)
							instruction, err := arm64asm.Decode(code[:])
							if err != nil {
								t.Fatalf("independent scalar word %08x: %v", word, err)
							}
							form, valid := decodeARM64RawScalarRegister(word)
							if !valid || form.width != width {
								t.Fatalf("valid scalar grammar rejected %08x", word)
							}
							extended := family == 0x0b200000
							flags := operation&1 != 0
							if family&0x1f000000 == 0x0a000000 {
								flags = operation == 3
							}
							var reads, writes uint32
							if first != 31 {
								reads |= 1 << first
							}
							if second != 31 {
								reads |= 1 << second
							}
							if destination != 31 {
								writes = 1 << destination
							}
							stack := extended && (first == 31 || destination == 31 && !flags)
							actualReads, actualWrites, actualStack := form.gpEffects()
							if actualReads != reads || actualWrites != writes || actualStack != stack || form.flags != flags {
								t.Fatalf("physical operand role changed for %08x", word)
							}
							effect, accepted := arm64ScratchNativeInputEffect(instruction, false)
							if stack || (reads|writes)&(1<<30) != 0 {
								if accepted {
									t.Fatalf("scalar SP/LR acquired an input contract: %08x", word)
								}
							} else {
								want := arm64ScratchInputEffect{reads: uint64(reads), writes: uint64(writes)}
								if flags {
									want.writes |= 15 << 31
								}
								if !accepted || effect != want {
									t.Fatalf("scalar input effect changed for %08x: %+v", word, effect)
								}
							}
							scratch, valid := arm64ScratchNativeEffect(instruction)
							wantScratch := arm64ScratchEffect{reads: reads&(1<<27) != 0, defines: writes&(1<<27) != 0}
							if !valid || scratch != wantScratch {
								t.Fatalf("scalar R27 role changed for %08x", word)
							}
							gp, valid := arm64RawPoolGPWrites(word)
							if !valid || gp != writes || arm64RawPoolInstructionPreservesNZCV(instruction) != !flags {
								t.Fatalf("scalar GP/NZCV consumers differ for %08x", word)
							}
						}
					}
				}
			}
		}
	}
}

func TestARM64NativeScratchScalarRegisterReservedFields(t *testing.T) {
	for _, word := range []uint32{
		0x0a008000,                         // W logical shift >=32.
		0x0b008000,                         // W arithmetic shift >=32.
		0x8bc00000,                         // Arithmetic ROR is reserved.
		0x0b201400, 0x0b201800, 0x0b201c00, // Extension shifts 5/6/7.
		0x8b600000, 0x8ba00000, // Fixed extended-class bits are reserved.
		0xd503201f, // NOP is not this scalar operand family.
		0x9a000000, // ADC has a separate incoming-carry contract.
		0x93407c24, // SXTW has its separate bitfield grammar.
		0x4e201c00, // SIMD logical operands are not scalar GP inputs.
	} {
		if _, valid := decodeARM64RawScalarRegister(word); valid {
			t.Fatalf("reserved/foreign word acquired scalar effects: %08x", word)
		}
	}
}
