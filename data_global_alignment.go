package plan9asm

// goAssemblyDataAlignment follows cmd/link/internal/ld.symalign for assembly
// DATA/GLOBL definitions without an explicit symbol alignment. Go reduces the
// target's maximum alignment until it fits the size; divisibility is irrelevant.
// This describes source-owned globals, not external declarations, caller memory
// or private literal pools synthesized by the translator.
func goAssemblyDataAlignment(arch Arch, size int64) int64 {
	alignment := int64(32)
	if arch == ArchARM {
		alignment = 8
	}
	for alignment > size && alignment > 1 {
		alignment >>= 1
	}
	return alignment
}
