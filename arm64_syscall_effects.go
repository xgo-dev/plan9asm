package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
)

type arm64SyscallOS uint8

const (
	arm64SyscallLinux arm64SyscallOS = iota + 1
	arm64SyscallDarwinCarry
)

// This is the ordinary return of the typed libc bridge, not a source-entry,
// memory-borrow, restart, sigreturn, SME or exclusive-monitor certificate.
// The same descriptor drives lowering, continuation taint and IR effects.
type arm64SyscallForm struct {
	target           string
	os               arm64SyscallOS
	trap             uint16
	number           Reg
	gpWrites         uint32
	gpUnavailable    uint32
	flagsWrites      arm64FlagMask
	flagsUnavailable arm64FlagMask
}

type arm64SyscallIRProof struct {
	identity                   *arm64SyscallIRProof
	owner                      *arm64Ctx
	control                    *arm64LocalControlPlan
	form                       arm64SyscallForm
	nanosleep                  *arm64NanosleepInputProof
	source                     Instr
	block, instruction, offset int
}

func (proof *arm64SyscallIRProof) matches(c *arm64Ctx, original Instr, offset int) bool {
	if proof == nil || proof.identity != proof || proof.owner != c || proof.offset != offset ||
		proof.block != c.currentBlock || proof.instruction != c.currentInstruction ||
		proof.block < 0 || proof.block >= len(c.blocks) || proof.instruction < 0 ||
		proof.instruction >= len(c.blocks[proof.block].instrs) || c.localControl == nil || proof.control != c.localControl {
		return false
	}
	if !reflect.DeepEqual(proof.source, original) ||
		!reflect.DeepEqual(proof.source, c.blocks[proof.block].instrs[proof.instruction]) {
		return false
	}
	form, err := parseARM64SyscallForm(c.targetTriple, arm64ControlDecode(original))
	if err != nil || form != proof.form || proof.nanosleep != c.nanosleepInput {
		return false
	}
	if proof.nanosleep != nil {
		input, valid := c.nanosleepInputAt([2]int{proof.block, proof.instruction})
		return valid && input.form == form
	}
	return true
}

func parseARM64SyscallForm(target string, ins Instr) (arm64SyscallForm, error) {
	var form arm64SyscallForm
	if strings.ToUpper(string(ins.Op)) != "SVC" || len(ins.Args) > 1 {
		return form, fmt.Errorf("arm64 SVC expects no suffix and an optional integer immediate: %q", ins.Raw)
	}
	if len(ins.Args) == 1 {
		operand := ins.Args[0]
		if operand.Kind != OpImm || operand.ImmRaw != "" || operand.ImmIsFloat {
			return form, fmt.Errorf("arm64 SVC expects a resolved integer immediate: %q", ins.Raw)
		}
		// Go accepts its entire C_VCON class, then encodes Offset & 0xffff.
		form.trap = uint16(operand.Imm)
	}
	parts := strings.Split(target, "-")
	if len(parts) < 3 || (parts[0] != "aarch64" && parts[0] != "arm64") {
		return form, fmt.Errorf("%w: ARM64 syscall requires an explicit ARM64 target: %q", ErrProbeNeedsContext, target)
	}
	form.target = target
	switch {
	case parts[2] == "linux":
		// Linux selects the A64 syscall ABI from R8, never the SVC immediate.
		form.os, form.number, form.gpWrites = arm64SyscallLinux, "R8", 1
	case arm64SyscallDarwinComponent(parts[2]):
		if form.trap != 0x80 {
			return form, fmt.Errorf("%w: unmodeled Darwin ARM64 trap %#x", ErrProbeNeedsContext, form.trap)
		}
		form.os, form.number, form.gpWrites = arm64SyscallDarwinCarry, "R16", 3
		// A single-result libc call cannot supply Darwin's secondary return
		// or certify its other native flags. Keep only the existing C role.
		form.gpUnavailable = 1 << 1
		form.flagsWrites = arm64FlagC
		form.flagsUnavailable = arm64FlagAll &^ arm64FlagC
	default:
		return form, fmt.Errorf("%w: unmodeled ARM64 syscall target %q", ErrProbeNeedsContext, target)
	}
	return form, nil
}

func arm64SyscallDarwinComponent(component string) bool {
	for _, name := range []string{"darwin", "macosx"} {
		if component == name {
			return true
		}
		if !strings.HasPrefix(component, name) {
			continue
		}
		version := strings.TrimPrefix(component, name)
		if len(version) == 0 || version[0] < '0' || version[0] > '9' {
			continue
		}
		valid := true
		for _, digit := range version {
			if (digit < '0' || digit > '9') && digit != '.' {
				valid = false
			}
		}
		if valid {
			return true
		}
	}
	return false
}

// Register only these actual typed call lines, and retain their real memory
// effects. The reader rebinds the descriptor to this source instruction and
// target; a callee name, another native line or changed descriptor is opaque.
func (c *arm64Ctx) emitARM64SyscallIR(form arm64SyscallForm, format string, args ...any) {
	start := c.b.Len()
	fmt.Fprintf(c.b, format, args...)
	if flow := c.machineAvailability; flow != nil {
		if c.localControl == nil || c.currentBlock < 0 || c.currentBlock >= len(c.blocks) ||
			c.currentInstruction < 0 || c.currentInstruction >= len(c.blocks[c.currentBlock].instrs) {
			return // No complete original CFG/frame guard supplied this bridge.
		}
		source := c.blocks[c.currentBlock].instrs[c.currentInstruction]
		actual, err := parseARM64SyscallForm(c.targetTriple, arm64ControlDecode(source))
		if err != nil || actual != form {
			return
		}
		source.Args = append([]Operand(nil), source.Args...)
		for index := range source.Args {
			source.Args[index].RegList = append([]Reg(nil), source.Args[index].RegList...)
		}
		proof := &arm64SyscallIRProof{owner: c, control: c.localControl, form: form, source: source,
			block: c.currentBlock, instruction: c.currentInstruction, offset: start, nanosleep: c.nanosleepInput}
		proof.identity = proof
		if flow.nativeIR == nil {
			flow.nativeIR = make(map[int]arm64MachineNativeProof)
		}
		flow.nativeIR[start] = arm64MachineNativeProof{line: c.b.String()[start:], store: true, syscall: proof}
	}
}
