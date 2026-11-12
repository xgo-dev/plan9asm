package plan9asm

// frameTypeSize returns the byte width occupied by a scalar FrameLayout slot.
// Pointer width is target-specific, so architecture lowerers provide it.
func frameTypeSize(ty LLVMType, pointerSize int64) int64 {
	switch ty {
	case I1, I8:
		return 1
	case I16:
		return 2
	case Ptr:
		return pointerSize
	case I32, LLVMType("float"):
		return 4
	case I64, LLVMType("double"):
		return 8
	default:
		// FrameLayout normally contains scalar parts. Keep enough room for an
		// unexpected aggregate so address formation remains within the alloca.
		return 16
	}
}
