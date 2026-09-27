package plan9asm

// Pseudo-SP names annotate a frame slot; names relative to hardware RSP or a
// GP register instead need the generated header's displacement definition.
func arm64NamedStackOffset(memory MemRef) bool {
	if memory.Base != SP || memory.OffRaw == "" {
		return false
	}
	if offset, ok := parseNamedStackConstantOffset(memory.OffRaw); ok {
		return offset == memory.Off
	}
	_, named := parseIdent(memory.OffRaw)
	return named && memory.Off == 0
}

func arm64MemoryOffsetNeedsContext(memory MemRef) bool {
	if memory.OffRaw == "" || arm64NamedStackOffset(memory) {
		return false
	}
	if _, scalable := parseVectorLengthScaleExpr(memory.OffRaw); scalable {
		return false // VL is a typed address unit, not an include macro.
	}
	return memoryOffsetExpressionNeedsContext(memory.OffRaw)
}
