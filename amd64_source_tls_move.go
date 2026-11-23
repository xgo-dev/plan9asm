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

// Check the exact runtime binding or validate the unbound ymovb/w/l/q row
// before scalar, MMX or XMM dispatch.
func x86SourceTLSMoveError(ins Instr, arch string) error {
	if _, valid := x86CertifiedTLSRuntimeRead(ins, arch); valid {
		return nil
	}
	form, present, err := x86TLSMoveProperties(ins, arch)
	if !present || err != nil {
		return err
	}
	if form.memory < 0 {
		return fmt.Errorf("%w: %s needs its actual Go OS/arch/shared TLS source contract: %q", ErrProbeNeedsContext, ins.Op, ins.Raw)
	}
	return fmt.Errorf("%w: %s TLS memory needs its actual Go OS/arch/shared progedit, relocation and native TLS address contract: %q", ErrProbeNeedsContext, ins.Op, ins.Raw)
}
