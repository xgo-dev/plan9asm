package plan9asm

import (
	"fmt"
	"strings"
)

func (c *amd64Ctx) lowerInsertExtractFamily(op Op, ins Instr) (bool, bool, error) {
	ins, f, known, err := c.bindInsertExtractForm(op, ins)
	if !known || err != nil {
		return known, false, err
	}
	if f.undefinedOpcode() {
		return c.lowerX86UndefinedTrap(op, ins)
	}
	if f.mask >= 0 && f.memoryWrite {
		return true, false, c.lowerNativeMaskedExtract(ins, f)
	}
	if f.spec.scalar {
		if f.spec.insert {
			return c.lowerInsertPackedSingle(op, ins)
		}
		return c.lowerPackedScalarExtract(op, ins)
	}
	src, err := c.loadInsertExtractSource(ins.Args[f.source], f)
	if err != nil {
		return true, false, err
	}
	result := src
	if f.spec.insert {
		base, err := c.loadPackedCompareBytes(ins.Args[f.base], f.width)
		if err != nil {
			return true, false, err
		}
		// Widen the insertion source only with defined zero bytes; then one
		// shuffle reads the two old inputs before an aliased destination write.
		wide := c.newTmp()
		indices := make([]int, f.width)
		for i := range indices {
			indices[i] = i
			if i >= f.spec.chunk {
				indices[i] = f.spec.chunk
			}
		}
		fmt.Fprintf(c.b, "  %%%s = shufflevector <%d x i8> %s, <%d x i8> zeroinitializer, <%d x i32> %s\n", wide, f.spec.chunk, src, f.spec.chunk, f.width, llvmI32Mask(indices))
		for i := range indices {
			indices[i] = i
			if i >= f.offset && i < f.offset+f.spec.chunk {
				indices[i] = f.width + i - f.offset
			}
		}
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shufflevector <%d x i8> %s, <%d x i8> %%%s, <%d x i32> %s\n", out, f.width, base, f.width, wide, f.width, llvmI32Mask(indices))
		result = "%" + out
	} else {
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shufflevector <%d x i8> %s, <%d x i8> poison, <%d x i32> %s\n", out, f.width, src, f.width, f.output, llvmI32RangeMask(f.offset, f.output))
		result = "%" + out
	}
	if f.mask >= 0 {
		mask, err := c.loadK(ins.Args[f.mask].Reg)
		if err != nil {
			return true, false, err
		}
		lanes := f.output * 8 / f.spec.laneBits
		computed := c.bitcastVectorBytesToIntegerLanes(f.output, lanes, f.spec.laneBits, result)
		old := "zeroinitializer"
		if !f.zeroing {
			bytes, err := c.loadPackedCompareBytes(ins.Args[f.destination], f.output)
			if err != nil {
				return true, false, err
			}
			old = c.bitcastVectorBytesToIntegerLanes(f.output, lanes, f.spec.laneBits, bytes)
		}
		masked := amd64ApplyIntegerLaneMask(c, lanes, f.spec.laneBits, computed, old, mask, f.zeroing)
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <%d x i8>\n", out, lanes, f.spec.laneBits, masked, f.output)
		result = "%" + out
	}
	destination := ins.Args[f.destination]
	if f.memoryWrite && destination.Kind != OpFP {
		pointer, pointerType, _, err := c.packedVectorMemoryPointer(destination)
		if err != nil {
			return true, false, err
		}
		// Preserve every original unmasked write, including overwritten
		// chunks, without reading old destination bytes or adding alignment.
		fmt.Fprintf(c.b, "  store volatile <%d x i8> %s, %s %s, align 1\n", f.output, result, pointerType, pointer)
		return true, false, nil
	}
	return true, false, c.storePackedMoveOperand(destination, f.output, result)
}

func (c *amd64Ctx) lowerNativeMaskedExtract(ins Instr, f x86InsertExtractForm) error {
	destination := ins.Args[f.destination]
	if destination.Kind == OpFP && c.classicFrame == "" {
		return fmt.Errorf("%w: %s E6NF masked extraction needs contiguous original FP storage, not separately allocated virtual slots", ErrProbeNeedsContext, ins.Op)
	}
	pointer, pointerType, _, err := c.packedVectorMemoryPointer(destination)
	if err != nil {
		return err
	}
	mask, err := c.loadK(ins.Args[f.mask].Reg)
	if err != nil {
		return err
	}
	index, _ := amd64VectorRegisterIndex(ins.Args[f.source].Reg, f.width)
	buffer := c.yRegSlot[index]
	if f.width == 64 {
		buffer = c.zRegSlot[index]
	}
	if buffer == "" {
		return fmt.Errorf("%w: missing private virtual source buffer for %s", ErrProbeNeedsContext, ins.Args[f.source].Reg)
	}
	bank := "ymm"
	if f.width == 64 {
		bank = "zmm"
	}
	segment := ""
	if pointerType == "ptr addrspace(256)" {
		segment = "%gs:"
	}
	if pointerType == "ptr addrspace(257)" {
		segment = "%fs:"
	}
	// This write-only native instruction supplies E6NF's nonsuppressing
	// address/fault behavior without inventing old destination read access
	// or writing inactive lanes. Only private physical scratch is clobbered;
	// virtual SIMD/K state and CPU flags are unchanged. No target feature is
	// enabled globally. Native execution still requires the source's ISA.
	assembly := fmt.Sprintf("vmovdqu64 ($0), %%%s0; kmovq $1, %%k1; %s $$%d, %%%s0, %s($2) {%%k1}", bank, strings.ToLower(string(ins.Op)), f.immediate, bank, segment)
	fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q(ptr %s, i64 %s, %s %s)\n", assembly, "r,r,r,~{zmm0},~{k1},~{memory}", buffer, mask, pointerType, pointer)
	return nil
}

func (c *amd64Ctx) loadInsertExtractSource(arg Operand, f x86InsertExtractForm) (string, error) {
	if f.spec.insert && f.memory >= 0 && arg.Kind != OpFP {
		pointer, pointerType, _, err := c.packedVectorMemoryPointer(arg)
		if err != nil {
			return "", err
		}
		value := c.newTmp()
		// Intel E6NF retains the entire native access even if every result
		// lane is inactive or subsequently overwritten. Volatile prevents
		// LLVM O2 from deleting that original observable faulting load.
		fmt.Fprintf(c.b, "  %%%s = load volatile <%d x i8>, %s %s, align 1\n", value, f.spec.chunk, pointerType, pointer)
		return "%" + value, nil
	}
	width := f.width
	if f.spec.insert {
		width = f.spec.chunk
	}
	return c.loadPackedCompareBytes(arg, width)
}
