package plan9asm

import (
	"fmt"
	"strings"
)

// A relation-only fcmp (including constrained fcmp/fcmps) is not the source
// CMP immediate's MXCSR contract. Keep a single sideeffecting native instruction:
// its complete vector, immediate, active mask and SAE decide IA/DE and traps.
// In particular, a per-lane loop changes packed exception priority.
func (c *amd64Ctx) emitNativeFloatingCompare(ins Instr, f x86FloatCompareForm) error {
	first := ins.Args[f.first]
	if first.Kind == OpFP && !f.scalar {
		return fmt.Errorf("%w: %s packed FP comparison needs original contiguous native storage", ErrProbeNeedsContext, ins.Op)
	}
	if !f.scalar && first.Kind == OpMem && !x86OrdinaryNativeMemoryOperand(first, c.goarch) && !c.fixedLocalMemoryCertified(ins, f.first) {
		// A word-aligned virtual source stack is neither the original native
		// address nor an m128 alignment witness. Do not strengthen its alloca
		// alignment or synthesize a native shadow to suppress source faults.
		return fmt.Errorf("%w: %s packed source stack lacks original native backing", ErrProbeNeedsContext, ins.Op)
	}
	if ins.x86AddressBits != 0 {
		return fmt.Errorf("%w: %s native compare needs its original address-size binding", ErrProbeNeedsContext, ins.Op)
	}
	if first.Kind == OpFP {
		if err := c.validateFPVectorSpan(first.FPOffset, f.bits/8); err != nil {
			return err
		}
	}

	mask := ""
	if f.mask >= 0 {
		value, err := c.loadK(ins.Args[f.mask].Reg)
		if err != nil {
			return err
		}
		mask = value
	}
	typ := amd64FloatingVectorType(f.byteWidth*8/f.bits, f.bits)
	second, err := c.loadFloatingVectorOperand(ins.Args[f.second], f.byteWidth, f.byteWidth*8/f.bits, f.bits)
	if err != nil {
		return err
	}
	firstValue, firstType, firstConstraint, firstTemplate, err := c.nativeFloatingCompareSource(first, f, typ, mask)
	if err != nil {
		return err
	}
	if !f.maskResult && firstConstraint == "v" {
		// A mixed function can also contain EVEX and therefore enable AVX512.
		// Legacy/VEX still cannot encode registers 16-31 in this operand.
		firstConstraint = "x"
	}
	mnemonic := strings.ToLower(strings.Split(string(ins.Op), ".")[0])
	immediate := f.immediate
	result := c.newTmp()
	clobbers := "~{memory},~{fpsr}"

	if f.maskResult {
		// The K result is private physical scratch. Inputs/outputs remain
		// virtual; real k1/k2 do not become public caller transports.
		assembly := ""
		constraints := "=r," + firstConstraint + ",v"
		args := fmt.Sprintf("%s %s, %s %s", firstType, firstValue, typ, second)
		if mask != "" {
			assembly = "kmovw ${3:k}, %k2; "
			constraints += ",r,~{k2}"
			args += ", i32 " + c.approximateMathMask32(mask)
		}
		assembly += fmt.Sprintf("%s $$%d, ", mnemonic, immediate)
		if f.sae {
			assembly += "{sae}, "
		}
		if f.broadcast {
			firstTemplate += fmt.Sprintf(" {1to%d}", f.byteWidth*8/f.bits)
		}
		assembly += firstTemplate + ", $2, %k1"
		if mask != "" {
			assembly += " {%k2}"
		}
		assembly += "; kmovw %k1, ${0:k}"
		fmt.Fprintf(c.b, "  %%%s = call i32 asm sideeffect %q, %q(%s)\n", result, assembly, constraints+",~{k1},"+clobbers, args)
		wide := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", wide, result)
		return c.storeK(ins.Args[f.destination].Reg, "%"+wide)
	}

	assembly := fmt.Sprintf("%s $$%d, ", mnemonic, immediate)
	constraints := "=x,"
	args := ""
	if f.legacy {
		// Tie the full old X value: scalar compares preserve upper X bytes.
		assembly += strings.Replace(firstTemplate, "$1", "$2", 1) + ", $0"
		constraints += "0," + firstConstraint
		args = fmt.Sprintf("%s %s, %s %s", typ, second, firstType, firstValue)
	} else {
		assembly += firstTemplate + ", $2, $0"
		constraints += firstConstraint + ",x"
		args = fmt.Sprintf("%s %s, %s %s", firstType, firstValue, typ, second)
	}
	fmt.Fprintf(c.b, "  %%%s = call %s asm sideeffect %q, %q(%s)\n", result, typ, assembly, constraints+","+clobbers, args)
	bytes := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %%%s to <%d x i8>\n", bytes, typ, result, f.byteWidth)
	if f.legacy {
		return c.storeLegacyXViews(ins.Args[f.destination].Reg, "%"+bytes)
	}
	return c.storePackedMoveOperand(ins.Args[f.destination], f.byteWidth, "%"+bytes)
}

func (c *amd64Ctx) nativeFloatingCompareSource(source Operand, f x86FloatCompareForm, typ, mask string) (value, sourceType, constraint, template string, err error) {
	if source.Kind == OpFP {
		// Scalar compare observes only the low field. Assemble its checked
		// bytes as integer data, not a fabricated contiguous native FP pointer.
		bits, loadErr := c.loadFloatBinaryScalar(source, f.bits, mask)
		if loadErr != nil {
			return "", "", "", "", loadErr
		}
		inserted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement %s zeroinitializer, %s %s, i32 0\n", inserted, typ, amd64FloatingScalarType(f.bits), bits)
		return "%" + inserted, typ, "v", "$1", nil
	}
	if source.Kind == OpReg {
		value, err = c.loadFloatingVectorOperand(source, f.byteWidth, f.byteWidth*8/f.bits, f.bits)
		return value, typ, "v", "$1", err
	}
	if source.Kind != OpMem && source.Kind != OpSym {
		return "", "", "", "", fmt.Errorf("%w: native compare source lacks original memory binding", ErrProbeNeedsContext)
	}
	pointer, pointerType, _, err := c.packedVectorMemoryPointer(source)
	if err != nil {
		return "", "", "", "", err
	}
	segment := ""
	if source.Kind == OpMem && source.Mem.Segment != "" {
		segment = "%" + strings.ToLower(string(source.Mem.Segment)) + ":"
	}
	return pointer, fmt.Sprintf("%s elementtype([%d x i8])", pointerType, f.memoryBytes), "*m", segment + "$1", nil
}
