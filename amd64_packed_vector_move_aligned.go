package plan9asm

import (
	"fmt"
	"strings"
)

// Alignment faults are part of the original instruction, including its exact
// mask and zeroing behavior. Neither LLVM align metadata nor a masked load can
// replace this operation: the former asserts alignment instead of checking it,
// and the latter can remove a dead read. Pass an opaque address in a register,
// without granting the optimizer any pointee, extent or alignment assumption.
// Intel SDM Vol. 2A Table 2-46 keeps E1 alignment separate from page-fault
// suppression; the runtime oracle compares both against original Go opcodes.
func (c *amd64Ctx) lowerAlignedPackedMoveMemory(ins Instr, form amd64PackedVectorMoveForm) error {
	return c.lowerNativeAlignedVectorMemory(ins, form, false)
}

func (c *amd64Ctx) lowerNativeAlignedVectorMemory(ins Instr, form amd64PackedVectorMoveForm, legacy bool) error {
	pointer, pointerType, _, err := c.packedVectorMemoryPointer(ins.Args[form.memory])
	if err != nil {
		return err
	}
	segment := ""
	if pointerType == "ptr addrspace(256)" {
		segment = "%gs:"
	} else if pointerType == "ptr addrspace(257)" {
		segment = "%fs:"
	}
	name, _, _ := strings.Cut(strings.ToLower(string(ins.Op)), ".")
	constraint, prefix := "x", ""
	if form.nativeEVEX(ins) {
		constraint = "v"
		// Retain EVEX for high source registers even if LLVM allocates a low
		// carrier. APD/APS otherwise also have a VEX encoding at X/Y widths.
		prefix = "{evex} "
	}
	vectorType := fmt.Sprintf("<%d x float>", form.byteWidth/4)
	vector := func(operand Operand) (string, error) {
		value, err := c.loadPackedCompareBytes(operand, form.byteWidth)
		if err != nil {
			return "", err
		}
		carrier := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i8> %s to %s\n", carrier, form.byteWidth, value, vectorType)
		return "%" + carrier, nil
	}
	mask := ""
	if form.mask >= 0 {
		value, err := c.loadK(ins.Args[form.mask].Reg)
		if err != nil {
			return err
		}
		narrow := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", narrow, value)
		mask = "%" + narrow
	}
	if form.memoryWrite {
		value, err := vector(ins.Args[0])
		if err != nil {
			return err
		}
		assembly := prefix + name + " $0, " + segment + "($1)"
		constraints := constraint + ",r"
		arguments := fmt.Sprintf("%s %s, %s %s", vectorType, value, pointerType, pointer)
		if mask != "" {
			assembly = "kmovw ${2:k}, %k1; " + assembly + " {%k1}"
			constraints += ",r,~{k1}"
			arguments += ", i32 " + mask
		}
		fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q(%s)\n", assembly, constraints+",~{memory}", arguments)
		return nil
	}
	assembly := prefix + name + " " + segment + "($1), $0"
	constraints := "=" + constraint + ",r"
	arguments := pointerType + " " + pointer
	if mask != "" {
		if form.zeroing {
			assembly = "kmovw ${2:k}, %k1; " + assembly + " {%k1} {z}"
		} else {
			old, err := vector(ins.Args[form.destination])
			if err != nil {
				return err
			}
			assembly = "kmovw ${3:k}, %k1; " + prefix + name + " " + segment + "($2), $0 {%k1}"
			constraints = "=" + constraint + ",0,r"
			arguments = vectorType + " " + old + ", " + arguments
		}
		constraints += ",r,~{k1}"
		arguments += ", i32 " + mask
	}
	loaded, bytes := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s asm sideeffect %q, %q(%s)\n", loaded, vectorType, assembly, constraints+",~{memory}", arguments)
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %%%s to <%d x i8>\n", bytes, vectorType, loaded, form.byteWidth)
	if legacy {
		return c.storeLegacyPackedLogical(ins.Args[form.destination], "%"+bytes)
	}
	return c.storePackedMoveOperand(ins.Args[form.destination], form.byteWidth, "%"+bytes)
}
