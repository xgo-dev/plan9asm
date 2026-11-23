package plan9asm

import (
	"fmt"
	"strings"
)

func x86HasLiteralControlOperand(ins Instr) bool {
	if len(ins.Args) != 1 || ins.Args[0].Kind != OpImm {
		return false
	}
	op := normalizeInstructionOpcode(ins.Op)
	return op == "CALL" || op == "JMP"
}

// Go's Zcallcon/Zjmpcon rows emit a direct near transfer with an absolute
// relocation addend. Keep a complete frameless entry together:
// a regular LLVM function prologue or synthesized indirect transfer could
// change the machine stack, registers, or return path.
func emitX86LiteralControl(b *strings.Builder, fn Func, sig FuncSig, arch, triple string) (bool, error) {
	if len(fn.Instrs) < 2 || !x86HasLiteralControlOperand(fn.Instrs[1]) {
		return false, nil
	}
	if !x86ABI0NoArgumentVoidCallRole(sig) || fn.x86DirectTailRoot != nil ||
		fn.x86ContinuationFlow != nil || fn.x86RawReplay != nil ||
		validateX86AddressSensitiveRawText(fn, arch) != nil {
		return true, fmt.Errorf("%w: literal x86 transfer needs a complete frameless native entry: %s", ErrProbeNeedsContext, fn.Sym)
	}
	format := x86LiteralControlObjectFormat(arch, triple)
	if format == "" {
		return true, fmt.Errorf("%w: literal x86 transfer needs a matching ELF, COFF, or Mach-O backend", ErrProbeNeedsContext)
	}
	var assembly []string
	terminates := false
	hasCall := false
	for index, ins := range fn.Instrs[1:] {
		if !x86ResultNamedPredicateInstruction(ins) {
			return true, fmt.Errorf("%w: literal x86 transfer needs its named native source: %s", ErrProbeNeedsContext, ins.Raw)
		}
		if ins.Op == OpRET && len(ins.Args) == 0 {
			assembly = append(assembly, "ret")
			terminates = true
			continue
		}
		if !x86HasLiteralControlOperand(ins) || ins.Op != OpJMP && ins.Op != OpCALL {
			return true, fmt.Errorf("%w: literal x86 transfer has unbound native instructions: %s", ErrProbeNeedsContext, ins.Raw)
		}
		arg := ins.Args[0]
		if arg.ImmIsFloat || arg.ImmRaw != "" || arg.Imm < -1<<31 || arg.Imm > 1<<32-1 {
			return true, fmt.Errorf("%w: literal x86 transfer needs a representable address: %s", ErrProbeNeedsContext, ins.Raw)
		}
		mnemonic := strings.ToLower(string(ins.Op))
		label := fmt.Sprintf(".Lplan9asm_abs_${:uid}_%d", index)
		switch format {
		case "coff":
			// Retain the absolute symbol for REL32. LLVM otherwise folds
			// the constant. A negative address belongs in the signed
			// addend because COFF absolute symbol values are unsigned.
			base, addend := arg.Imm, int64(0)
			if base < 0 {
				base, addend = 0, base
			}
			assembly = append(assembly, fmt.Sprintf(".def %s; .scl 3; .endef; .set %s, %d", label, label, base))
			assembly = append(assembly, fmt.Sprintf("%s %s@IMGREL%+d", mnemonic, label, addend))
		case "macho":
			// MC keeps the absolute symbol in the branch relocation but
			// also folds its value into the addend. Cancel that duplicate.
			assembly = append(assembly, fmt.Sprintf(".set %s, %d; %s %s%+d", label, arg.Imm, mnemonic, label, -arg.Imm))
		case "elf":
			assembly = append(assembly, fmt.Sprintf("%s %d", mnemonic, arg.Imm))
		}
		terminates = terminates || ins.Op == OpJMP
		hasCall = hasCall || ins.Op == OpCALL
	}
	if !terminates {
		return true, fmt.Errorf("%w: literal x86 CALL needs its original return or jump", ErrProbeNeedsContext)
	}
	// Go can insert a BP frame for a non-leaf amd64 TEXT $0-0.
	// A naked literal transfer has no Go object layout to prove otherwise.
	if arch == "amd64" {
		if err := x86InteriorCallText(fn, arch, hasCall); err != nil {
			return true, err
		}
	}
	emitX86NakedVoidAssembly(b, sig.Name, strings.Join(assembly, "; "), "~{memory}", "")
	return true, nil
}

func x86LiteralControlObjectFormat(arch, triple string) string {
	if !x86ScalarFloatIntegerNativeTarget(arch, triple) {
		return ""
	}
	for _, field := range strings.Split(strings.ToLower(triple), "-")[1:] {
		switch field {
		case "windows", "win32", "mingw32":
			return "coff"
		case "linux", "freebsd", "netbsd", "openbsd", "dragonfly":
			return "elf"
		default:
			if arch == "amd64" && (strings.HasPrefix(field, "darwin") || strings.HasPrefix(field, "macos")) {
				return "macho"
			}
		}
	}
	return ""
}
