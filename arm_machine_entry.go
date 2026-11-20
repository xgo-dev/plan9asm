package plan9asm

import (
	"fmt"
	"strings"
)

// ARMMachineReturn describes the physical source continuation, not an LLVM
// result type. The first closed entry contract supports a source RET through
// the unchanged incoming LR. Stack-PC resumptions require a separate proof.
type ARMMachineReturn uint8

const (
	ARMMachineReturnLR ARMMachineReturn = iota + 1
)

// ARMMachineEntry is an explicitly requested physical-register interface.
// It requires NOSPLIT|NOFRAME, zero Go arguments and no implicit source frame.
// StackBelow reserves source-owned bytes below the real incoming SP. A fresh
// private capture region sits below that range, never in source stack storage.
// The caller provides ordinary callee-owned stack space below StackBelow; no
// source pointer may alias that fresh private storage. Source SP-derived memory
// accesses must instead be proved inside the declared source-owned range.
// VFP requires an incoming VFP2 machine and transports D0..D15 and FPSCR.
// The caller supplies a valid at-least-four-byte-aligned native ARM stack;
// the private AAPCS body bridge separately aligns its physical SP to eight.
// Neither a symbol name nor a missing Go declaration establishes this contract.
type ARMMachineEntry struct {
	StackBelow uint32
	VFP        bool
	Return     ARMMachineReturn
}

const (
	armMachineCPSROffset  = 60
	armMachineFPSCROffset = 64
	armMachineVFPOffset   = 72
	armMachineStateBytes  = 200
)

func validateARMMachineEntryArchitecture(file *File, opt Options) error {
	if file == nil || file.Arch == ArchARM {
		return nil
	}
	for name, sig := range opt.Sigs {
		if sig.ARMEntry != nil {
			return fmt.Errorf("ARM machine-entry contract supplied for non-ARM function %q", name)
		}
	}
	return nil
}

func validateARMMachineEntry(fn Func, sig FuncSig, triple string) error {
	entry := sig.ARMEntry
	if entry == nil || entry.Return != ARMMachineReturnLR {
		return fmt.Errorf("ARM machine entry requires an explicit supported return contract")
	}
	if !(strings.HasPrefix(triple, "arm") || strings.HasPrefix(triple, "thumb")) ||
		!(strings.Contains(triple, "linux") || strings.Contains(triple, "windows")) {
		return fmt.Errorf("ARM machine entry needs an explicit supported ARM Linux/Windows target: %q", triple)
	}
	if len(sig.Args) != 0 || sig.Ret != Void || len(sig.ArgRegs) != 0 || len(sig.Frame.Params) != 0 || len(sig.Frame.Results) != 0 {
		return fmt.Errorf("ARM machine entry is address-only, not a zero-argument C/Go signature")
	}
	if fn.FrameSize != 0 || fn.ArgSize != 0 || len(fn.Instrs) == 0 || fn.Instrs[0].Op != OpTEXT {
		return fmt.Errorf("%w: ARM machine entry needs exact zero Go TEXT frame/arguments", ErrProbeNeedsContext)
	}
	parts := splitTopLevelCSV(fn.Instrs[0].Raw)
	if len(parts) != 3 {
		return fmt.Errorf("ARM machine entry requires explicit NOSPLIT|NOFRAME TEXT flags")
	}
	expression := globlFlagName.ReplaceAllStringFunc(parts[1], func(name string) string {
		if value, ok := goTextFlagValues[name]; ok {
			return value
		}
		return name
	})
	flags, ok := parseImmExpr(strings.TrimSpace(expression))
	if !ok || flags != 4|512 {
		return fmt.Errorf("ARM machine entry requires exactly NOSPLIT|NOFRAME flags")
	}
	if entry.StackBelow > 1<<20 || entry.StackBelow%8 != 0 {
		return fmt.Errorf("ARM source stack bound must be eight-byte aligned and at most 1MiB")
	}
	// This initial closed layer does not yet model SP/LR writes, source-call
	// continuations, raw machine effects, or aliased source stack accesses.
	// Fail closed; none of these become a signature guess or source N/A.
	stackAliases := map[Reg]bool{"R13": true}
	for changed := true; changed; {
		changed = false
		for _, ins := range fn.Instrs {
			op, _, _, _ := armDecodeOp(string(ins.Op))
			if len(ins.Args) < 2 || op == "CMP" || op == "CMN" || op == "TST" || op == "TEQ" {
				continue
			}
			dst := ins.Args[len(ins.Args)-1]
			var destinations []Reg
			if dst.Kind == OpReg {
				destinations = []Reg{dst.Reg}
			} else if dst.Kind == OpRegList {
				destinations = dst.RegList
			} else {
				continue
			}
			for _, arg := range ins.Args[:len(ins.Args)-1] {
				if (arg.Kind == OpReg || arg.Kind == OpRegShift || arg.Kind == OpRegExtend) && (stackAliases[arg.Reg] || stackAliases[arg.ShiftReg]) {
					for _, reg := range destinations {
						if !stackAliases[reg] {
							stackAliases[reg], changed = true, true
						}
					}
				}
			}
		}
	}
	for _, ins := range fn.Instrs[1:] {
		op, _, _, _ := armDecodeOp(string(ins.Op))
		switch op {
		case "TEXT", "LABEL", "RET", "MOVW", "MOVB", "MOVBS", "MOVBU", "MOVH", "MOVHS", "MOVHU", "MOVD", "CMP", "CMN", "TST", "TEQ", "MOVM", "ADD", "SUB", "RSB", "AND", "ORR", "EOR", "BIC", "MVN", "ADC", "SBC", "RSC", "SLL", "SRL", "SRA", "MUL", "MULU", "MULA", "MULL", "MULLU", "MULAL", "MULALU":
		case "BL", "CALL", "BX", "B", "JMP":
			return fmt.Errorf("%w: ARM machine-entry control transfer needs a closed native/Go call-site continuation contract: %s", ErrProbeNeedsContext, ins.Raw)
		default:
			return fmt.Errorf("ARM machine-entry source effect is not implemented in its typed state layer: %s", ins.Raw)
		}
		if op == "RET" && (len(ins.Args) != 0 || len(armInstructionSuffixes(ins)) != 0) {
			return fmt.Errorf("%w: ARM machine entry needs unconditional unchanged-LR RET: %s", ErrProbeNeedsContext, ins.Raw)
		}
		for i, arg := range ins.Args {
			if armKernelOperandUsesReg(arg, "R15") || armKernelOperandUsesReg(arg, PC) || armKernelOperandUsesReg(arg, SP) {
				return fmt.Errorf("%w: ARM source PC/pseudo-SP needs a separate layout/frame contract: %s", ErrProbeNeedsContext, ins.Raw)
			}
			if arg.Kind == OpFP || arg.Kind == OpFPAddr || arg.Kind == OpSym {
				return fmt.Errorf("%w: ARM native source reference needs an explicit frame/symbol contract: %s", ErrProbeNeedsContext, ins.Raw)
			}
			if i == len(ins.Args)-1 && op != "CMP" && op != "CMN" && op != "TST" && op != "TEQ" &&
				(arg.Kind == OpReg || arg.Kind == OpRegList) && (armKernelOperandUsesReg(arg, "R13") || armKernelOperandUsesReg(arg, "R14")) {
				return fmt.Errorf("%w: ARM native source SP/LR write needs an explicit continuation proof: %s", ErrProbeNeedsContext, ins.Raw)
			}
			if arg.Kind == OpIdent {
				name := strings.ToUpper(arg.Ident)
				if i != 0 || name != "CPSR" && name != "FPCR" && name != "FPSR" || name != "CPSR" && !entry.VFP {
					return fmt.Errorf("%w: ARM native status effect lacks a typed source contract: %s", ErrProbeNeedsContext, ins.Raw)
				}
			}
			if arg.Kind == OpReg && isARMFReg(arg.Reg) && !entry.VFP {
				return fmt.Errorf("ARM native VFP operand requires the explicit VFP entry contract: %s", ins.Raw)
			}
			if op == "MOVW" && arg.Kind == OpReg && isARMFReg(arg.Reg) {
				return fmt.Errorf("ARM native partial-FP lane effect requires a separate complete subregister model: %s", ins.Raw)
			}
			if arg.Kind != OpMem {
				continue
			}
			if armKernelOperandUsesReg(arg, "R14") {
				return fmt.Errorf("%w: ARM native LR-address access needs code-layout/continuation context: %s", ErrProbeNeedsContext, ins.Raw)
			}
			if stackAliases[arg.Mem.Base] && arg.Mem.Base != "R13" || stackAliases[arg.Mem.Index] {
				return fmt.Errorf("%w: ARM native stack alias needs an explicit source-address proof: %s", ErrProbeNeedsContext, ins.Raw)
			}
			if shift, ok := armMemoryShift(arg.Mem); ok && (stackAliases[shift.Reg] || stackAliases[shift.ShiftReg]) {
				return fmt.Errorf("%w: ARM native shifted stack alias needs an explicit source-address proof: %s", ErrProbeNeedsContext, ins.Raw)
			}
			if arg.Mem.Base == "R13" {
				width := int64(4)
				if spec, ok := armIntegerMemorySpecs[op]; ok {
					width = int64(spec.bits / 8)
				} else if op == "MOVD" {
					width = 8
				} else if op != "MOVF" {
					return fmt.Errorf("%w: ARM native stack access has no typed width: %s", ErrProbeNeedsContext, ins.Raw)
				}
				post, writeback, _, err := armMemoryModifiers(ins)
				if err != nil {
					return err
				}
				if post || writeback || arg.Mem.Index != "" || arg.Mem.OffRaw != "" || arg.Mem.Off < -int64(entry.StackBelow) || arg.Mem.Off > -width {
					return fmt.Errorf("%w: ARM native stack access exceeds its real source-owned backing: %s", ErrProbeNeedsContext, ins.Raw)
				}
			}
		}
	}
	if fn.Instrs[len(fn.Instrs)-1].Op != OpRET {
		return fmt.Errorf("%w: ARM native entry requires an explicit source RET", ErrProbeNeedsContext)
	}
	return nil
}

func translateFuncARMMachineEntry(b *strings.Builder, fn Func, sig FuncSig, resolve func(string) string, sigs map[string]FuncSig, triple string, annotate bool) error {
	if err := validateARMMachineEntry(fn, sig, triple); err != nil {
		return err
	}
	if err := proveARMStatusReads(fn, sig); err != nil {
		return err
	}
	bodyName := sig.Name + ".machine_body"
	attrs := sig.Attrs
	if sig.ARMEntry.VFP {
		// The transport itself uses VFP even when the source does not mention
		// an F register, so source-opcode inference alone is insufficient.
		attrs += ` "target-features"="+vfp2"`
	}
	frameBytes := sig.ARMEntry.StackBelow + armMachineStateBytes
	var assembly []string
	adjustSP := func(op string) {
		for shift := uint(0); shift < 32; shift += 8 {
			if amount := frameBytes & (255 << shift); amount != 0 {
				assembly = append(assembly, fmt.Sprintf("%s sp, sp, #%d", op, amount))
			}
		}
	}
	adjustSP("sub")
	assembly = append(assembly, "stmia sp, {r0-r12}", "mrs r1, cpsr", "str r1, [sp, #60]", "str lr, [sp, #56]")
	assembly = append(assembly, "mov r1, sp")
	for shift := uint(0); shift < 32; shift += 8 {
		if amount := frameBytes & (255 << shift); amount != 0 {
			assembly = append(assembly, fmt.Sprintf("add r1, r1, #%d", amount))
		}
	}
	assembly = append(assembly, "str r1, [sp, #52]")
	if sig.ARMEntry.VFP {
		assembly = append(assembly, "vmrs r1, fpscr", "str r1, [sp, #64]", "add r1, sp, #72", "vstmia r1, {d0-d15}")
	}
	// Source Go ARM stacks may be only four-byte aligned. Keep the capture
	// pointer in AAPCS-preserved R4, align only the private body's SP, and
	// restore the exact capture base after its typed call.
	assembly = append(assembly, "mov r4, sp", "bic r1, r4, #7", "mov sp, r1", "mov r0, r4", "bl ${0:c}", "mov sp, r4")
	if sig.ARMEntry.VFP {
		assembly = append(assembly, "ldr r1, [sp, #64]", "vmsr fpscr, r1", "add r1, sp, #72", "vldmia r1, {d0-d15}")
	}
	assembly = append(assembly, "ldr r1, [sp, #60]", "msr APSR_nzcvq, r1", "ldr lr, [sp, #56]", "ldmia sp, {r0-r12}")
	adjustSP("add")
	assembly = append(assembly, "bx lr")
	fmt.Fprintf(b, "define void %s() naked noinline %s {\nentry:\n", llvmGlobal(sig.Name), attrs)
	fmt.Fprintf(b, "  call void asm sideeffect %q, %q(ptr %s)\n", strings.Join(assembly, "; "), "i,~{memory}", llvmGlobal(bodyName))
	b.WriteString("  unreachable\n}\n\n")
	fmt.Fprintf(b, "define internal void %s(ptr %%machine_state) noinline %s {\n", llvmGlobal(bodyName), attrs)
	c := newARMCtx(b, fn, sig, resolve, sigs, annotate)
	c.machineState, c.flagsWritten = "%machine_state", true
	if err := c.emitEntryAllocasAndArgInit(); err != nil {
		return err
	}
	if err := c.lowerBlocks(); err != nil {
		return err
	}
	b.WriteString("}\n")
	return nil
}

func (c *armCtx) machinePointer(offset int) string {
	tmp := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = getelementptr i8, ptr %s, i32 %d\n", tmp, c.machineState, offset)
	return "%" + tmp
}

func (c *armCtx) loadMachineValue(offset int, typ LLVMType) string {
	ptr, tmp := c.machinePointer(offset), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load %s, ptr %s, align 4\n", tmp, typ, ptr)
	return "%" + tmp
}

func (c *armCtx) initializeMachineState() error {
	for i := 0; i <= 14; i++ {
		if err := c.storeReg(Reg(fmt.Sprintf("R%d", i)), c.loadMachineValue(i*4, I32)); err != nil {
			return err
		}
	}
	if err := c.storeReg(SP, c.loadMachineValue(52, I32)); err != nil {
		return err
	}
	if c.sig.ARMEntry.VFP {
		for i := 0; i < 16; i++ {
			if err := c.storeFReg(Reg(fmt.Sprintf("F%d", i)), c.loadMachineValue(armMachineVFPOffset+i*8, I64)); err != nil {
				return err
			}
		}
	}
	c.storeFlagsFromStatus(c.loadMachineValue(armMachineCPSROffset, I32))
	return nil
}

func (c *armCtx) returnMachineState() error {
	for i := 0; i <= 14; i++ {
		value, err := c.loadReg(Reg(fmt.Sprintf("R%d", i)))
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  store i32 %s, ptr %s\n", value, c.machinePointer(i*4))
	}
	if c.sig.ARMEntry.VFP {
		for i := 0; i < 16; i++ {
			value, err := c.loadFReg(Reg(fmt.Sprintf("F%d", i)))
			if err != nil {
				return err
			}
			fmt.Fprintf(c.b, "  store i64 %s, ptr %s, align 4\n", value, c.machinePointer(armMachineVFPOffset+i*8))
		}
	}
	status := c.statusWithModeledNZCV(c.loadMachineValue(armMachineCPSROffset, I32))
	fmt.Fprintf(c.b, "  store i32 %s, ptr %s\n  ret void\n", status, c.machinePointer(armMachineCPSROffset))
	return nil
}
