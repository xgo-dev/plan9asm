package plan9asm

import (
	"fmt"
	"strings"
)

type x86LinuxSyscallForm struct {
	instruction string
	inputs      [7]Reg
	clobbers    [2]Reg
	width       int64
	observesDX  bool
}

func x86LinuxSyscallCandidate(ins Instr) bool {
	// Go's yint table accepts an integer and encodes its low byte (Zib_).
	return ins.Op == "SYSCALL" || ins.Op == "INT" && len(ins.Args) == 1 &&
		ins.Args[0].Kind == OpImm && uint8(ins.Args[0].Imm) == 0x80
}

// Only the normal-return raw kernel entry has this input and result
// contract. Both emitter and audit consume the same mode-specific roles.
func x86LinuxSyscallProperties(ins Instr, arch, target string) (x86LinuxSyscallForm, bool, error) {
	if !x86LinuxSyscallCandidate(ins) {
		return x86LinuxSyscallForm{}, false, nil
	}
	fail := func(reason string) (x86LinuxSyscallForm, bool, error) {
		return x86LinuxSyscallForm{}, true, fmt.Errorf("%w: %s %s: %q", ErrProbeNeedsContext, ins.Op, reason, ins.Raw)
	}
	if !x86ResultNamedPredicateInstruction(ins) {
		return fail("requires its original named kernel entry form")
	}
	if ins.Op == "SYSCALL" {
		if arch != "amd64" || len(ins.Args) != 0 {
			return fail("requires the complete AMD64 zero-operand form")
		}
	} else if arch != "386" || ins.Args[0].ImmRaw != "" || ins.Args[0].ImmIsFloat {
		return fail("requires the complete 386 integer-vector form")
	}
	normalized := llvmNormalizedTargetTriple(target)
	parts := strings.Split(normalized, "-")
	if len(parts) < 3 || parts[2] != "linux" || !x86ScalarFloatIntegerNativeTarget(arch, normalized) {
		return fail("requires a Linux target triple matching the source mode")
	}
	if arch == "386" {
		return x86LinuxSyscallForm{
			instruction: "int $$0x80", inputs: [7]Reg{AX, BX, CX, DX, SI, DI, BP}, width: 4, observesDX: true,
		}, true, nil
	}
	return x86LinuxSyscallForm{
		instruction: "syscall", inputs: [7]Reg{AX, DI, SI, DX, "R10", "R8", "R9"},
		clobbers: [2]Reg{CX, "R11"}, width: 8,
	}, true, nil
}

func x86LoweredLinuxSyscallStep(ins Instr, state *x86ResultState, owned []bool,
	resultOffset int64, arch, target string) (bool, bool) {
	form, known, err := x86LinuxSyscallProperties(ins, arch, target)
	if !known || err != nil {
		return false, known
	}
	for _, register := range form.inputs {
		index, mask, valid := x86ResultGP(register, form.width, arch)
		if !valid || state.gp[index]&mask != mask || state.pointerGP[index] || state.callerAddressGP[index] ||
			state.resultAddressGP[index].valid || state.boolFrameGP != nil && state.boolFrameGP[index].valid {
			return false, true // Numerical arguments never expose a logical/private frame to the kernel.
		}
	}
	// SYSCALL's CX and R11 contain host continuation/FLAGS. The
	// separately virtualized source machine cannot recover them.
	for _, register := range form.clobbers {
		if index, _, valid := x86ResultGP(register, form.width, arch); valid {
			state.gp[index] = 0
		}
	}
	state.canonicalGP = [16]uint8{}
	state.pointerGP = [16]bool{}
	state.callerAddressGP = [16]bool{}
	state.callerAddressOrigin = [16]uint16{}
	state.resultAddressGP = [16]x86ResultSlotAddress{}
	if state.boolFrameGP != nil {
		state.boolFrameGP = new([16]x86ResultSlotAddress)
	}
	state.flags = 0
	state.direction = x86ResultDirectionUnknown
	state.predicate = x86ResultPredicate{}
	state.bitScanPending = x86ResultBitScanPending{}
	state.gpBits = x86ResultGPBits{}
	state.shiftBits = x86ResultShiftBits{}
	state.lowMasks = 0
	state.nativeLEAAddressBits = x86NativeLEAAddressBits{}
	state.stringCount = x86StringCountUnknown
	state.cpuidRootLeaf = false
	if form.observesDX && !x86ResultStore(Operand{Kind: OpReg, Reg: DX}, form.width, state, owned, resultOffset, arch) {
		return false, true
	}
	return x86ResultStore(Operand{Kind: OpReg, Reg: AX}, form.width, state, owned, resultOffset, arch), true
}
