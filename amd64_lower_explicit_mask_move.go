package plan9asm

import (
	"fmt"
	"strings"
)

func (c *amd64Ctx) lowerExplicitMaskMove(op Op, ins Instr) (bool, bool, error) {
	f, known, err := x86ExplicitMaskMoveProperties(op, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	if err := x86Mode32VectorRegisterContext(ins, c.goarch); err != nil {
		return true, false, err
	}
	if ins.x86AddressBits != 0 || ins.x86UnboundAddressOverride ||
		!x86ResultNamedPredicateInstruction(ins) && !x86RawExplicitMaskMoveSource(ins, c.goarch) &&
			ins.x86NumericalRead == nil && ins.x86SDKLiteral == nil {
		return true, false, fmt.Errorf("%w: explicit mask move needs its exact physical source", ErrProbeNeedsContext)
	}
	if ins.Args[f.memory].Kind == OpFP {
		if err := c.validateX86PackedShiftFPSpan(ins.Args[f.memory].FPOffset, f.byteWidth); err != nil {
			return true, false, err
		}
	} else if x86ScalarFloatIntegerNativeTarget(c.goarch, c.targetTriple) &&
		(x86OrdinaryNativeMemoryOperand(ins.Args[f.memory], c.goarch) ||
			x86CallerMemoryCertified(ins, f.memory) || c.fixedLocalMemoryCertified(ins, f.memory)) {
		return true, false, c.lowerNativeExplicitMaskMove(op, ins, f)
	}
	return true, false, c.lowerPortableExplicitMaskMove(ins, f)
}

// Type 6 masks suppress only the corresponding lane's memory faults. Preserve
// the whole original VEX operation even with a dead output. The pointer stays
// opaque: no alignment, extent, initialization or pointee promise is asserted.
// Intel SDM Vol.2C, VMASKMOV/VPMASKMOV: no SIMD FP exceptions and no AC#.
// https://cdrdv2-public.intel.com/835757/325383-sdm-vol-2abcd.pdf
func (c *amd64Ctx) lowerNativeExplicitMaskMove(op Op, ins Instr, f x86ExplicitMaskMoveForm) error {
	pointer, pointerType, _, err := c.packedVectorMemoryPointer(ins.Args[f.memory])
	if err != nil {
		return err
	}
	segment := ""
	if pointerType == "ptr addrspace(256)" {
		segment = "%gs:"
	} else if pointerType == "ptr addrspace(257)" {
		segment = "%fs:"
	}
	typ := fmt.Sprintf("<%d x float>", f.byteWidth/4) // Bit carrier, not FP arithmetic.
	vector := func(operand Operand) (string, error) {
		bytes, err := c.loadPackedCompareBytes(operand, f.byteWidth)
		if err != nil {
			return "", err
		}
		value := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i8> %s to %s\n", value, f.byteWidth, bytes, typ)
		return "%" + value, nil
	}
	mask, err := vector(ins.Args[1])
	if err != nil {
		return err
	}
	mnemonic := strings.ToLower(string(op))
	if !f.load {
		data, err := vector(ins.Args[0])
		if err != nil {
			return err
		}
		assembly := mnemonic + " $0, $1, " + segment + "($2)"
		fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q(%s %s, %s %s, %s %s)\n",
			assembly, "x,x,r,~{memory}", typ, data, typ, mask, pointerType, pointer)
		return nil
	}
	loaded, bytes := c.newTmp(), c.newTmp()
	assembly := mnemonic + " " + segment + "($2), $1, $0"
	fmt.Fprintf(c.b, "  %%%s = call %s asm sideeffect %q, %q(%s %s, %s %s)\n",
		loaded, typ, assembly, "=x,x,r,~{memory}", typ, mask, pointerType, pointer)
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %%%s to <%d x i8>\n", bytes, typ, loaded, f.byteWidth)
	return c.storePackedMoveOperand(ins.Args[2], f.byteWidth, "%"+bytes)
}

// The other-target/value-field path has guarded volatile lane accesses. This
// is portable access/value evidence, not execution of the original x86 opcode.
// An inactive lane must not even eagerly read the old memory contents.
func (c *amd64Ctx) lowerPortableExplicitMaskMove(ins Instr, f x86ExplicitMaskMoveForm) error {
	bits, width := f.spec.laneBits, f.byteWidth
	lanes := width * 8 / bits
	vectorType := fmt.Sprintf("<%d x i%d>", lanes, bits)
	mask, err := c.loadPackedCompareLanes(ins.Args[1], width, bits, false)
	if err != nil {
		return err
	}
	value := "zeroinitializer"
	if !f.load {
		value, err = c.loadPackedCompareLanes(ins.Args[0], width, bits, false)
		if err != nil {
			return err
		}
	}
	memory := ins.Args[f.memory]
	pointer, pointerType := "", ""
	if memory.Kind != OpFP {
		pointer, pointerType, _, err = c.packedVectorMemoryPointer(memory)
		if err != nil {
			return err
		}
	}
	for lane := 0; lane < lanes; lane++ {
		element, active := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement %s %s, i32 %d\n", element, vectorType, mask, lane)
		fmt.Fprintf(c.b, "  %%%s = icmp slt i%d %%%s, 0\n", active, bits, element)
		field := memory
		address := ""
		if memory.Kind == OpFP {
			field.FPOffset += int64(lane * bits / 8)
		} else {
			address = c.newTmp()
			// No inbounds: masked-off null and page-boundary lanes need no allocation.
			fmt.Fprintf(c.b, "  %%%s = getelementptr i8, %s %s, i64 %d\n", address, pointerType, pointer, lane*bits/8)
		}
		if f.load {
			loaded, err := c.loadX86ScalarIf(bits, "%"+active, func() (string, error) {
				loaded := c.newTmp()
				if memory.Kind == OpFP {
					bytes, err := c.loadX86PackedShiftBytes(field, bits/8, true)
					if err != nil {
						return "", err
					}
					fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i8> %s to i%d\n", loaded, bits/8, bytes, bits)
				} else {
					fmt.Fprintf(c.b, "  %%%s = load volatile i%d, %s %%%s, align 1\n", loaded, bits, pointerType, address)
				}
				return "%" + loaded, nil
			})
			if err != nil {
				return err
			}
			inserted := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = insertelement %s %s, i%d %s, i32 %d\n", inserted, vectorType, value, bits, loaded, lane)
			value = "%" + inserted
			continue
		}
		data, store, join := c.newTmp(), c.newTmp()+"_mask_store", c.newTmp()+"_mask_join"
		fmt.Fprintf(c.b, "  %%%s = extractelement %s %s, i32 %d\n", data, vectorType, value, lane)
		fmt.Fprintf(c.b, "  br i1 %%%s, label %%%s, label %%%s\n%s:\n", active, store, join, store)
		if memory.Kind == OpFP {
			bytes := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast i%d %%%s to <%d x i8>\n", bytes, bits, data, bits/8)
			if err := c.storeVectorBytesOperand(field, bits/8, "%"+bytes); err != nil {
				return err
			}
		} else {
			fmt.Fprintf(c.b, "  store volatile i%d %%%s, %s %%%s, align 1\n", bits, data, pointerType, address)
		}
		fmt.Fprintf(c.b, "  br label %%%s\n%s:\n", join, join)
	}
	if !f.load {
		return nil
	}
	bytes := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to <%d x i8>\n", bytes, vectorType, value, width)
	return c.storePackedMoveOperand(ins.Args[2], width, "%"+bytes)
}
