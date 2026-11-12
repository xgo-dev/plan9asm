package plan9asm

// Test-only unsigned byte mathematics. It knows no producer/parser/LLVM
// helper and is also used to construct the separate original-Go oracle.
func x86SADReference(op string, width, control int, first, second []byte) []uint16 {
	result := make([]uint16, width/2)
	difference := func(a, b byte) uint16 {
		if a >= b {
			return uint16(a) - uint16(b)
		}
		return uint16(b) - uint16(a)
	}
	if op == "PSADBW" || op == "VPSADBW" {
		for byteIndex := 0; byteIndex < width; byteIndex++ {
			result[byteIndex/8*4] += difference(first[byteIndex], second[byteIndex])
		}
		return result
	}
	if op == "MPSADBW" || op == "VMPSADBW" {
		for lane := 0; lane < width/16; lane++ {
			selector := control >> (lane * 3)
			block := lane*16 + (selector&3)*4
			window := lane*16 + (selector>>2&1)*4
			for word := 0; word < 8; word++ {
				for byteIndex := 0; byteIndex < 4; byteIndex++ {
					result[lane*8+word] += difference(first[block+byteIndex], second[window+word+byteIndex])
				}
			}
		}
		return result
	}
	for lane := 0; lane < width/16; lane++ {
		var permuted [16]byte
		for word := 0; word < 4; word++ {
			copy(permuted[word*4:word*4+4], first[lane*16+(control>>(2*word)&3)*4:])
		}
		for word := 0; word < 8; word++ {
			block := word / 4 * 8
			window := block + word%4
			other := lane*16 + block + (word%4/2)*4
			for byteIndex := 0; byteIndex < 4; byteIndex++ {
				result[lane*8+word] += difference(permuted[window+byteIndex], second[other+byteIndex])
			}
		}
	}
	return result
}
