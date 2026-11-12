package plan9asm

// x86RawSegmentPrefixes retains physical prefix observations without deciding
// whether a particular instruction or source mode accepts them.
func x86RawSegmentPrefixes(code []byte) (length int, segment Reg, addressOverride bool) {
	for length < len(code) {
		switch code[length] {
		case 0x64:
			segment = FS
		case 0x65:
			segment = GS
		case 0x67:
			addressOverride = true
		default:
			return
		}
		length++
	}
	return
}
