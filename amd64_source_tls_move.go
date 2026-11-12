package plan9asm

import "fmt"

func validateX86TLSMoveFile(file *File, arch string) error {
	if file == nil || file.Arch != ArchAMD64 {
		return nil
	}
	if arch == "" {
		arch = "amd64"
	}
	for _, function := range file.Funcs {
		for _, instruction := range function.Instrs {
			if err := x86SourceTLSMoveError(instruction, arch); err != nil {
				return fmt.Errorf("%s: %w", function.Sym, err)
			}
		}
	}
	return nil
}

// Validate TLS's complete ymovb/w/l/q memory rows before scalar, MMX or XMM
// dispatch. This does not rewrite TLS to a GP register or a guessed segment.
// No API here owns Go's runtime TLS relocation, g layout or thread transport.
func x86SourceTLSMoveError(ins Instr, arch string) error {
	form, present, err := x86TLSMoveProperties(ins, arch)
	if !present || err != nil {
		return err
	}
	if form.memory < 0 {
		return fmt.Errorf("%w: %s needs its actual Go OS/arch/shared TLS source contract: %q", ErrProbeNeedsContext, ins.Op, ins.Raw)
	}
	return fmt.Errorf("%w: %s TLS memory needs its actual Go OS/arch/shared progedit, relocation and native TLS address contract: %q", ErrProbeNeedsContext, ins.Op, ins.Raw)
}
