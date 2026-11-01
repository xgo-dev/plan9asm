package plan9asm

import (
	"math"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"

	"golang.org/x/arch/x86/x86asm"
)

// This separate physical-vector observation cannot enter the generic scalar
// decoder map or raw translation. A source read must additionally join its
// exact instruction ordinal, original/expanded objects, relocation and owner.
type numericalNativeRead struct {
	length, width, addressBits, addressField int
	pcRelative                               bool
	memory                                   MemRef
	vector                                   *Instr
	scalar                                   *x86asm.Inst
}

func numericalNativeReads(code []byte, mode int) (map[int64]numericalNativeRead, error) {
	boundaries, scalar, err := x86NumericalNativeBoundaries(code, mode)
	if err != nil {
		return nil, err
	}
	reads := make(map[int64]numericalNativeRead)
	for pc, native := range scalar {
		memories := 0
		for _, argument := range native.Args {
			if _, valid := argument.(x86asm.Mem); valid {
				memories++
			}
		}
		if memories != 1 {
			continue // A source SB read still needs one unique native memory operand.
		}
		original := native // Root Go 1.20 range variables are reused.
		reads[pc] = numericalNativeRead{length: native.Len, width: native.MemBytes, addressBits: native.AddrSize,
			addressField: native.PCRelOff, pcRelative: native.PCRel == 4, scalar: &original}
	}
	decoders := [...]func([]byte, int, x86RawMemoryDecoder) (Instr, int, bool, error){
		decodedX86AESInstructionWithMemory,
		decodedX86VEXPackedFloatLogicalInstructionWithMemory,
		decodedX86VEXPackedIntegerLogicalInstructionWithMemory,
		decodedX86EVEXPackedLogicalInstructionWithMemory,
		decodedX86RawEVEXFloatLogicalInstructionWithMemory,
	}
	for _, boundary := range boundaries {
		physical := code[boundary.PC : boundary.PC+int64(boundary.Length)]
		if !x86NumericalVectorPrefix(physical, mode) {
			continue
		}
		for _, decode := range decoders {
			ins, length, known, err := decode(physical, mode, x86RawMemoryDecoder{physicalPC: true})
			if !known && err == nil {
				continue
			}
			if err != nil || length != boundary.Length {
				return nil, numericalSBContext("physical vector read differs from complete native boundary: %v", err)
			}
			shape := ins
			shape.Args = append([]Operand(nil), ins.Args...)
			for index, operand := range shape.Args {
				if operand.Kind == OpMem {
					// The complete physical decoder retains RIP independently.
					// Public source grammar receives a symbolic read shape only;
					// this temporary view supplies no raw translation permission.
					shape.Args[index] = Operand{Kind: OpSym, Sym: "·observed(SB)"}
				}
			}
			memory, width := -1, 0
			if aes, known, err := x86AESProperties(shape.Op, shape, map[int]string{32: "386", 64: "amd64"}[mode]); known && err == nil {
				memory, width = aes.memory, aes.byteWidth
			} else if logical, known, err := x86PackedLogicalProperties(shape, map[int]string{32: "386", 64: "amd64"}[mode]); known && err == nil {
				memory, width = logical.memory, logical.memoryBytes
			}
			if memory < 0 {
				break // No physical memory; this can never supply an SB-read candidate.
			}
			p, valid := decodeX86RawVectorEncoding(physical)
			if !valid || p.addressOverride || p.segment != "" || p.modRM >= len(physical) || physical[p.modRM]&0xc7 != 5 ||
				p.x != 0 || p.b != 0 || ins.Args[memory].Kind != OpMem {
				break // Ordinary native addresses cannot provide a symbolic-read candidate.
			}
			reads[boundary.PC] = numericalNativeRead{length: length, width: width, addressBits: mode,
				addressField: p.modRM + 1, pcRelative: mode == 64, memory: ins.Args[memory].Mem, vector: &ins}
			break
		}
	}
	return reads, nil
}

func (native numericalNativeRead) matchesSource(ins Instr, operand int, arch string) bool {
	if native.scalar != nil {
		for _, prefix := range native.scalar.Prefix {
			value := uint8(prefix)
			if value != 0 && value != 0x66 && !(arch == "amd64" && value >= 0x40 && value <= 0x4f) {
				return false
			}
		}
		memory := x86asm.Mem{}
		for _, argument := range native.scalar.Args {
			if value, valid := argument.(x86asm.Mem); valid {
				memory = value
			}
		}
		return memory.Segment == 0 && memory.Index == 0 && memory.Scale == 0 &&
			(arch == "amd64" && memory.Base == x86asm.RIP || arch == "386" && memory.Base == 0)
	}
	if native.vector == nil || operand < 0 || operand >= len(ins.Args) || len(native.vector.Args) != len(ins.Args) {
		return false
	}
	if native.memory.Index != "" || native.memory.Scale != 0 || native.memory.Segment != "" ||
		arch == "amd64" && native.memory.Base != "RIP" || arch == "386" && native.memory.Base != "" {
		return false
	}
	physical := *native.vector
	physical.Args = append([]Operand(nil), physical.Args...)
	physical.Args[operand] = ins.Args[operand]
	// VAESKEYGENASSIST's source signed imm8 and decoded byte have identical
	// hardware bits. Both were independently validated by the complete grammar.
	if strings.HasSuffix(string(ins.Op), "KEYGENASSIST") {
		if uint8(physical.Args[0].Imm) != uint8(ins.Args[0].Imm) {
			return false
		}
		physical.Args[0].Imm = ins.Args[0].Imm
	}
	return numericalSameInstruction(ins, physical, "", arch)
}

func (native numericalNativeRead) relocation(text gostaticstorage.TextRecord, pc int64, arch string) (gostaticstorage.TextRelocation, int64, error) {
	if native.scalar != nil {
		return numericalInstructionRelocation(text, pc, *native.scalar, arch)
	}
	var selected []gostaticstorage.TextRelocation
	for _, relocation := range text.Relocations {
		if relocation.Offset < pc+int64(native.length) && relocation.Offset+relocation.Size > pc {
			selected = append(selected, relocation)
		}
	}
	if native.vector == nil || len(selected) != 1 || native.addressField < 0 || native.addressField+4 > native.length {
		return gostaticstorage.TextRelocation{}, 0, numericalSBContext("vector read lacks its complete displacement relocation")
	}
	r := selected[0]
	if r.Offset != pc+int64(native.addressField) || r.Size != 4 || !r.Target.ABIKnown || r.Target.ABI != 0 ||
		arch == "amd64" && (!native.pcRelative || native.addressBits != 64 || r.Type != 14) ||
		arch == "386" && (native.pcRelative || native.addressBits != 32 || r.Type != 1) {
		return r, 0, numericalSBContext("vector read native displacement/ABI/target role differs")
	}
	offset := r.Add
	if native.pcRelative {
		tail := int64(native.length - native.addressField - 4)
		if offset > math.MaxInt64-tail {
			return r, 0, numericalSBContext("vector PC-relative addend overflow")
		}
		offset += tail
	}
	return r, offset, nil
}
