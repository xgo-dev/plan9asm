package goasmrules

// Fixed VEX/EVEX prefix fields, shared by the audited operand transports.
// Operand roles and legal controls are validated before these bytes are made.
type x86PackedAVXOpcode struct {
	kind                              string
	mapByte, wBit, pp, length, opcode byte
}

func (op x86PackedAVXOpcode) bytes(vvvv, p0, p2, modrm byte) []byte {
	if op.kind == "evex" {
		return []byte{0x62, p0 | op.mapByte, op.wBit | vvvv | 0x04 | op.pp, p2, op.opcode, modrm}
	}
	if op.mapByte == 1 && op.wBit == 0 {
		return []byte{0xc5, 0x80 | vvvv | op.pp | op.length<<2, op.opcode, modrm}
	}
	return []byte{0xc4, 0xe0 | op.mapByte, op.wBit | vvvv | op.pp | op.length<<2, op.opcode, modrm}
}
