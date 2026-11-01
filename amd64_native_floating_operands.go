package plan9asm

import (
	"fmt"
	"strings"
)

// Floating families share native operand transport, not arithmetic semantics.
// Preserve the actual opcode and memory operand so masking, rounding,
// exceptions and dead accesses survive. Legacy SSE ties its destination.
type x86NativeFloatingOperands struct {
	byteWidth, lanes, memoryBytes int
	second, destination, mask     int
	controls                      amd64FMA3Suffix
	sae, readDestination          bool
	legacy                        bool
	lowBank, forceEVEX            bool
	logicalFPBits                 int // Explicit scalar-value projection, not native FP backing.
}

func (c *amd64Ctx) emitNativeFloatingOperands(ins Instr, f x86NativeFloatingOperands) error {
	source := ins.Args[0]
	logicalFP := source.Kind == OpFP && (f.logicalFPBits == 32 || f.logicalFPBits == 64)
	if source.Kind == OpFP && !logicalFP || ins.x86AddressBits != 0 || source.Kind == OpMem &&
		!x86OrdinaryNativeMemoryOperand(source, c.goarch) {
		return fmt.Errorf("%w: %s needs original native backing", ErrProbeNeedsContext, ins.Op)
	}
	typ := fmt.Sprintf("<%d x float>", f.byteWidth/4) // Bit carrier, never arithmetic precision.
	load := func(index int) (string, error) {
		bytes, err := c.loadPackedCompareBytes(ins.Args[index], f.byteWidth)
		if err != nil {
			return "", err
		}
		value := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i8> %s to %s\n", value, f.byteWidth, bytes, typ)
		return "%" + value, nil
	}
	second, err := load(f.second)
	if err != nil {
		return err
	}
	old := "zeroinitializer"
	if f.legacy {
		old = second
	} else if f.readDestination || f.mask >= 0 && !f.controls.zeroing {
		old, err = load(f.destination)
		if err != nil {
			return err
		}
	}
	registerConstraint := "v"
	if f.legacy || f.lowBank {
		registerConstraint = "x" // Legacy/VEX cannot acquire registers 16-31 from an EVEX sibling.
	}
	inputType, inputConstraint, inputTemplate := typ, registerConstraint, "$3"
	var input string
	if ins.Args[0].Kind == OpReg {
		input, err = load(0)
	} else if logicalFP {
		// A declared scalar FP field supplies its exact value, not an original
		// physical stack address. Scalar MIN/MAX ignores the other source
		// lanes; zeros in this private carrier grant no upper-byte facts.
		var raw string
		raw, err = c.loadFloatBinaryFPBits(source, f.logicalFPBits)
		if err == nil {
			lanes := 128 / f.logicalFPBits
			value, carrier := c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = insertelement <%d x i%d> zeroinitializer, i%d %s, i32 0\n", value, lanes, f.logicalFPBits, f.logicalFPBits, raw)
			fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %%%s to %s\n", carrier, lanes, f.logicalFPBits, value, typ)
			input = "%" + carrier
		}
	} else {
		var pointerType string
		input, pointerType, _, err = c.packedVectorMemoryPointer(ins.Args[0])
		inputType = fmt.Sprintf("%s elementtype([%d x i8])", pointerType, f.memoryBytes)
		inputConstraint = "*m"
		if pointerType == "ptr addrspace(256)" {
			inputTemplate = "%gs:" + inputTemplate
		} else if pointerType == "ptr addrspace(257)" {
			inputTemplate = "%fs:" + inputTemplate
		}
	}
	if err != nil {
		return err
	}
	args := fmt.Sprintf("%s %s, %s %s, %s %s", typ, old, typ, second, inputType, input)
	constraints := "=" + registerConstraint + ",0," + registerConstraint + "," + inputConstraint
	mnemonic, _, _ := strings.Cut(strings.ToLower(string(ins.Op)), ".")
	assembly := mnemonic + " "
	if f.forceEVEX {
		assembly = "{evex} " + assembly
	}
	if f.controls.rounding != "" {
		assembly += "{" + strings.ToLower(strings.TrimSuffix(f.controls.rounding, "_SAE")) + "-sae}, "
	} else if f.sae {
		assembly += "{sae}, "
	}
	assembly += inputTemplate
	if f.controls.broadcast {
		assembly += fmt.Sprintf("{1to%d}", f.lanes)
	}
	if f.legacy {
		assembly += ", $0"
	} else {
		assembly += ", $2, $0"
	}
	if f.mask >= 0 {
		mask, err := c.loadK(ins.Args[f.mask].Reg)
		if err != nil {
			return err
		}
		maskMove := "kmovw"
		if f.lanes > 16 {
			maskMove = "kmovd"
		}
		assembly = maskMove + " ${4:k}, %k1; " + assembly + " {%k1}"
		if f.controls.zeroing {
			assembly += " {z}"
		}
		constraints += ",r,~{k1}"
		args += ", i32 " + c.approximateMathMask32(mask)
	}
	result, bytes := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s asm sideeffect %q, %q(%s)\n", result, typ, assembly, constraints+",~{memory},~{fpsr}", args)
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %%%s to <%d x i8>\n", bytes, typ, result, f.byteWidth)
	if f.legacy {
		return c.storeLegacyPackedLogical(ins.Args[f.destination], "%"+bytes)
	}
	return c.storePackedMoveOperand(ins.Args[f.destination], f.byteWidth, "%"+bytes)
}
