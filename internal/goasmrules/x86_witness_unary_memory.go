package goasmrules

import "fmt"

// A unary vector memory alternative has independent encoded width, register
// carrier and tuple. Direction owns operand transport, never memory authority.
type x86PackedUnaryMemoryFormat struct {
	width, tuple, carrier int
	masked, store         bool
	encoding              x86PackedAVXOpcode
}

func (f x86PackedUnaryMemoryFormat) witnesses(opcode string) []X86PackedBinaryWitness {
	bank := 16
	if f.encoding.kind == "vex" {
		bank = 0
	}
	source := fmt.Sprint(map[int]string{128: "X", 256: "Y", 512: "Z"}[f.width], bank)
	destination := fmt.Sprint(map[int]string{16: "X", 32: "Y", 64: "Z"}[f.carrier], bank+2)
	var witnesses []X86PackedBinaryWitness
	for _, memory := range []bool{false, true} {
		first, last, modrm := source, destination, byte(0xd0)
		if f.store {
			modrm = 0xc2
		}
		p0 := byte(0xa0)
		if memory {
			p0 = 0xe0
			if f.store {
				last, modrm = "(AX)", 0
			} else {
				first, modrm = "(AX)", 0x10
			}
		}
		for _, zeroing := range []bool{false, true} {
			if zeroing && !f.masked {
				continue
			}
			operands, suffix, p2 := first+","+last, "", f.encoding.length<<5|8
			if f.masked {
				operands, p2 = first+",K1,"+last, p2|1
			}
			if zeroing {
				suffix, p2 = ".Z", p2|0x80
			}
			witnesses = append(witnesses, X86PackedBinaryWitness{
				Instruction: opcode + suffix + " " + operands, Generation: f.encoding.kind,
				First: first, Destination: last, Width: f.width, Memory: !f.store && memory,
				Masked: f.masked, Zeroing: zeroing,
				Encoding: f.encoding.bytes(0x78, p0, p2, modrm),
			})
		}
	}
	return witnesses
}
