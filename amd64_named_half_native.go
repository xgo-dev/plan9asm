package plan9asm

import (
	"fmt"
	"strings"
)

func (c *amd64Ctx) lowerNamedHalfConversion(op Op, ins Instr) (bool, bool, error) {
	f, known, err := x86NamedHalfProperties(op, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	ins.Op = op
	if f.undefinedOpcode() {
		return c.lowerX86UndefinedTrap("UD2", Instr{Op: "UD2"})
	}
	if !x86ScalarFloatIntegerNativeTarget(c.goarch, c.targetTriple) {
		return true, false, fmt.Errorf("%w: %s needs its matching native x86 MXCSR target", ErrProbeNeedsContext, op)
	}
	if c.fpScalarSource.x86SourceStack != nil || c.fpScalarSource.x86FixedLocal != nil {
		return true, false, fmt.Errorf("%w: %s retains its independent frame/native source owner", ErrProbeNeedsContext, op)
	}
	if f.memory >= 0 {
		memory := ins.Args[f.memory]
		if memory.Kind == OpFP && f.memory == f.source {
			if err := c.validateX86PackedShiftFPSpan(memory.FPOffset, f.inputBytes); err != nil {
				return true, false, err
			}
			for at := memory.FPOffset; at < memory.FPOffset+int64(f.inputBytes); at++ {
				if slot, _, _ := c.fpVectorSlot(at); slot.Type == Ptr {
					return true, false, fmt.Errorf("%w: %s cannot convert opaque pointer bits", ErrProbeNeedsContext, op)
				}
			}
		} else if !x86OrdinaryNativeMemoryOperand(memory, c.goarch) {
			return true, false, fmt.Errorf("%w: %s requires its original native address", ErrProbeNeedsContext, op)
		}
	}
	if f.memory == f.destination {
		return true, false, c.emitNamedHalfNativeStore(ins, f)
	}
	base, _, _ := strings.Cut(strings.ToLower(string(op)), ".")
	var immediate *byte
	if f.narrow {
		immediate = &f.immediate
	}
	return true, false, c.emitNativePackedConversion(ins, x86NativePackedConversion{
		byteWidth: f.destinationBytes, sourceBytes: f.sourceBytes, memoryBytes: f.inputBytes,
		outputBits: 32, logicalFPBits: 16, lanes: f.lanes, source: f.source,
		destination: f.destination, mask: f.mask, evex: f.evex, zeroing: f.zeroing, sae: f.sae,
		mnemonic: base, immediate: immediate,
	})
}

// Narrowing's masked memory opcode is the actual write. A register conversion
// followed by an ordinary store loses inactive-lane faults, FP traps and dead
// effects; an indirect inline-asm output retains all three without metadata.
func (c *amd64Ctx) emitNamedHalfNativeStore(ins Instr, f x86NamedHalfForm) error {
	value, err := c.loadPackedCompareBytes(ins.Args[f.source], f.sourceBytes)
	if err != nil {
		return err
	}
	input := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i8> %s to <%d x float>\n", input, f.sourceBytes, value, f.sourceBytes/4)
	pointer, pointerType, _, err := c.packedVectorMemoryPointer(ins.Args[f.destination])
	if err != nil {
		return err
	}
	output := "$0"
	if pointerType == "ptr addrspace(256)" {
		output = "%gs:" + output
	}
	if pointerType == "ptr addrspace(257)" {
		output = "%fs:" + output
	}
	constraint, mnemonic := "x", "vcvtps2ph"
	if f.evex {
		constraint, mnemonic = "v", "{evex} "+mnemonic
	}
	constraints := "=*m," + constraint
	arguments := fmt.Sprintf("%s elementtype([%d x i8]) %s, <%d x float> %%%s",
		pointerType, f.outputBytes, pointer, f.sourceBytes/4, input)
	assembly, prefix := fmt.Sprintf("%s $$%d, $1, %s", mnemonic, f.immediate, output), ""
	if f.mask >= 0 {
		mask, err := c.loadK(ins.Args[f.mask].Reg)
		if err != nil {
			return err
		}
		prefix = "kmovw ${2:k}, %k1; "
		constraints += ",r,~{k1}"
		arguments += ", i32 " + c.approximateMathMask32(mask)
		assembly += " {%k1}"
	}
	fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q(%s)\n", prefix+assembly, constraints+",~{memory},~{fpsr}", arguments)
	return nil
}
