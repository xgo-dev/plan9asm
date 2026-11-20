package plan9asm

import (
	"encoding/binary"

	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
)

// This offline, private observation is not a live caller region or authority.
// The consumer must independently bind its complete source, allocation,
// continuation, initialized bytes and native effects before using a carrier.
type arm64ByteCarrierEntryObservation struct {
	allocation, dataStart, dataBytes int64
	callPC, continuationPC           int64
	parameterStores, resultLoads     []arm64ByteCarrierMemory
}

func arm64ByteCarrierTypedEntry(text gostaticstorage.TextRecord, declaration FuncSig) (arm64ByteCarrierEntryObservation, error) {
	var observed arm64ByteCarrierEntryObservation
	fail := func() (arm64ByteCarrierEntryObservation, error) {
		return arm64ByteCarrierEntryObservation{}, arm64ByteCarrierContext("complete actual numeric compiler entry/effects differ")
	}
	if text.Name != declaration.Name || text.ABI != 1 || text.Size != int64(len(text.Code)) || len(text.Code)%4 != 0 ||
		len(text.Code) < 36 || len(text.Relocations) != 1 || len(declaration.Args) < 1 || len(declaration.Args) > 2 ||
		declaration.Args[0] != I64 || len(declaration.Frame.Params) != len(declaration.Args) ||
		len(declaration.Frame.Results) == 0 || len(declaration.Frame.Results) > 8 {
		return fail()
	}
	parameter := declaration.Frame.Params[0]
	if parameter.Offset != 0 || parameter.Type != I64 || parameter.Index != 0 || len(frameSlotFields(parameter)) != 0 {
		return fail()
	}
	parameterEnd := int64(8)
	if len(declaration.Args) == 2 {
		second := declaration.Frame.Params[1]
		if declaration.Args[1] != I32 || second.Offset != 8 || second.Type != I32 || second.Index != 1 ||
			len(frameSlotFields(second)) != 0 {
			return fail()
		}
		parameterEnd = 12
	}
	fields, aggregate := parseLiteralStructFields(declaration.Ret)
	if !aggregate {
		fields = []LLVMType{declaration.Ret}
	}
	if len(fields) != len(declaration.Frame.Results) {
		return fail()
	}
	word := func(pc int64) uint32 { return binary.LittleEndian.Uint32(text.Code[pc:]) }
	// The entire observed wrapper is straight-line. The new saved LR at SP+0,
	// saved FP below SP, and previous caller's live saved FP at SP+allocation-8
	// are not data. Neither a SUB alone nor a rounded signature size can
	// produce this observation.
	first := word(0)
	if first&^uint32(511<<12) != 0xf8000ffe || word(4) != 0xf81f83fd || word(8) != 0xd10023fd || word(12) != 0xf90007e0 {
		return fail()
	}
	allocation := int64(first >> 12 & 511)
	if allocation&256 != 0 {
		allocation -= 512
	}
	allocation = -allocation
	if allocation <= 8 || allocation > 240 || allocation%16 != 0 {
		return fail()
	}
	pc := int64(16)
	observed.parameterStores = []arm64ByteCarrierMemory{{PC: 12, Offset: 8, Bytes: 8, Instruction: word(12)}}
	if len(declaration.Args) == 2 {
		// The original compiler writes only W1 to the declared four-byte
		// parameter. The following alignment gap is not an initialized field.
		if len(text.Code) < 40 || word(pc) != 0xb90013e1 {
			return fail()
		}
		observed.parameterStores = append(observed.parameterStores,
			arm64ByteCarrierMemory{PC: pc, Offset: 16, Bytes: 4, Instruction: word(pc)})
		pc += 4
	}
	call := text.Relocations[0]
	if call.Offset != pc || call.Size != 4 || call.Type != 9 || call.Add != 0 || call.Target.Name != text.Name ||
		!call.Target.ABIKnown || call.Target.ABI != 0 || word(pc) != 0x94000000 {
		return fail()
	}
	observed.allocation, observed.dataStart, observed.dataBytes = allocation, 8, allocation-16
	observed.callPC, observed.continuationPC = pc, pc+4
	pc += 4
	previousEnd := parameterEnd
	for index := 0; index < len(fields); {
		field := declaration.Frame.Results[index]
		if field.Index != index || field.Type != fields[index] || len(frameSlotFields(field)) != 0 ||
			field.Type != I8 && field.Type != I16 && field.Type != I32 && field.Type != I64 ||
			field.Offset < previousEnd || field.Offset+8+frameTypeSize(field.Type, 8) > allocation-8 || pc+16 > int64(len(text.Code)) {
			return fail()
		}
		instruction := word(pc)
		width := frameTypeSize(field.Type, 8)
		if instruction&0xffc003e0 == 0xa94003e0 {
			// Integer LDP is one complete instruction with two typed read effects.
			if index+1 >= len(fields) || field.Type != I64 || fields[index+1] != I64 ||
				declaration.Frame.Results[index+1].Type != I64 || declaration.Frame.Results[index+1].Index != index+1 ||
				declaration.Frame.Results[index+1].Offset != field.Offset+8 ||
				len(frameSlotFields(declaration.Frame.Results[index+1])) != 0 || instruction&31 != uint32(index) ||
				instruction>>10&31 != uint32(index+1) || field.Offset+24 > allocation-8 {
				return fail()
			}
			offset := int64(instruction >> 15 & 127)
			if offset&64 != 0 {
				offset -= 128
			}
			if offset*8 != field.Offset+8 {
				return fail()
			}
			observed.resultLoads = append(observed.resultLoads,
				arm64ByteCarrierMemory{PC: pc, Offset: field.Offset + 8, Bytes: 8, Instruction: instruction},
				arm64ByteCarrierMemory{PC: pc, Offset: field.Offset + 16, Bytes: 8, Instruction: instruction})
			previousEnd = field.Offset + 16
			index += 2
		} else {
			// Actual gc wrappers use LDRSB/LDRSH/LDRSW into X registers for
			// signed narrow Go results, and unsigned LDR for unsigned ones.
			// Both read exactly the declared bytes. The typed adapter returns
			// that same narrow bit pattern; it never narrows the source body
			// store or an assembly caller's shared-carrier observation.
			load := instruction & 0x3fc003e0
			if load != 0x394003e0 && (load != 0x398003e0 || width == 8) || instruction&31 != uint32(index) ||
				int64(1)<<(instruction>>30) != width || int64(instruction>>10&4095)*width != field.Offset+8 {
				return fail()
			}
			observed.resultLoads = append(observed.resultLoads, arm64ByteCarrierMemory{
				PC: pc, Offset: field.Offset + 8, Bytes: width, Instruction: instruction,
			})
			previousEnd = field.Offset + width
			index++
		}
		pc += 4
	}
	if word(pc) != 0xf85f83fd || word(pc+4) != 0xf84007fe|uint32(allocation)<<12 || word(pc+8) != 0xd65f03c0 {
		return fail()
	}
	for pc += 12; pc < int64(len(text.Code)); pc += 4 {
		if word(pc) != 0 {
			return fail()
		}
	}
	return observed, nil
}
