package plan9asm

import (
	"fmt"
	"strings"
)

// Linux's normal-return AMD64 syscall convention is separate from libc's
// errno-setting API. This descriptor supplies no pointer, backing or private
// frame permission, and is consumed only by target-aware paired lowering.
func x86LinuxSyscallByteEffect(ins Instr, arch, target string) (x86TypedByteEffect, bool, error) {
	if ins.Op != "SYSCALL" {
		return x86TypedByteEffect{}, false, nil
	}
	fail := func(reason string) (x86TypedByteEffect, bool, error) {
		return x86TypedByteEffect{}, true, fmt.Errorf("SYSCALL %s: %q", reason, ins.Raw)
	}
	if arch != "amd64" || len(ins.Args) != 0 || !x86ResultNamedPredicateInstruction(ins) {
		return fail("requires the complete named AMD64 zero-operand form")
	}
	parts := strings.Split(llvmNormalizedTargetTriple(target), "-")
	if len(parts) < 3 || parts[0] != "x86_64" || parts[2] != "linux" {
		return fail("requires an explicit Linux x86-64 target")
	}
	effect := x86TypedByteEffect{requiresResultProof: true, flagsKilled: x86ByteFlagsAll}
	for _, register := range []Reg{AX, DI, SI, DX, "R10", "R8", "R9"} {
		effect.operands = append(effect.operands, x86TypedByteOperand{
			index: -1, operand: Operand{Kind: OpReg, Reg: register}, width: 8, read: true,
		})
	}
	effect.operands = append(effect.operands, x86TypedByteOperand{
		index: -1, operand: Operand{Kind: OpReg, Reg: AX}, width: 8, write: true,
	})
	return effect, true, nil
}

func x86LoweredLinuxSyscallStep(ins Instr, state *x86ResultState, owned []bool,
	resultOffset int64, arch, target string) (bool, bool) {
	effect, known, err := x86LinuxSyscallByteEffect(ins, arch, target)
	if !known || err != nil {
		return false, known
	}
	for _, operand := range effect.operands {
		if operand.read && !x86ResultRead(operand.operand, operand.width, state, owned, arch) {
			return false, true
		}
		if operand.read {
			index, _, valid := x86ResultGP(operand.operand.Reg, operand.width, arch)
			if !valid || state.pointerGP[index] || state.callerAddressGP[index] ||
				state.resultAddressGP[index].valid || state.boolFrameGP != nil && state.boolFrameGP[index].valid {
				return false, true // Numerical arguments never expose a logical/private frame to the kernel.
			}
		}
	}
	// CX contains a native continuation and R11 the physical incoming flags.
	// LLVM's separately virtualized source flags cannot be recovered from
	// either host register. No old NUM/canonical/address facts survive there.
	for _, register := range []Reg{CX, "R11"} {
		index, _, _ := x86ResultGP(register, 8, arch)
		state.gp[index] = 0
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
	state.nativeLEAAddressBits = x86NativeLEAAddressBits{}
	state.stringCount = x86StringCountUnknown
	state.cpuidRootLeaf = false
	for _, operand := range effect.operands {
		if operand.write && !x86ResultStore(operand.operand, operand.width, state, owned, resultOffset, arch) {
			return false, true
		}
	}
	return true, true // AX is the raw numerical return; DX and other input GP words are preserved.
}
