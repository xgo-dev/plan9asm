package plan9asm

import "fmt"

func (c *amd64Ctx) lowerNumericalRead(ins Instr) (bool, error) {
	return c.lowerNumericalReadAt(ins, -1, -1)
}

func (c *amd64Ctx) lowerNumericalReadAt(ins Instr, block, ordinal int) (bool, error) {
	if ins.x86SDKLiteral != nil {
		fact, valid := certifiedSDKLiteralAccess(ins, c.goarch)
		if !valid || c.sig.Name != fact.Function || c.targetTriple != ins.x86SDKLiteral.binding.options.TargetTriple {
			return true, numericalSBContext("emitted private literal source/function/profile differs")
		}
		if c.fixedLocal != nil || c.sourceStack != nil {
			return true, numericalSBContext("literal address cannot borrow private/native frame authority")
		}
		if err := c.scalarFPResultInitialized(); err != nil {
			return true, err
		}
		// Keep the original opcode/address emission. The byte fact supplies
		// no align-1 replacement, fault suppression or constant-folded data.
		return false, nil
	}
	if ins.x86NumericalRead == nil {
		return false, nil
	}
	read, form, valid := numericalCertifiedRead(ins, c.goarch)
	cert := ins.x86NumericalRead
	if !valid || !c.numericalReadAtOriginalSource(ins, read, block, ordinal) || c.targetTriple != cert.binding.options.TargetTriple {
		return true, numericalSBContext("emitted function/profile/read certificate changed")
	}
	var comparison x86ScalarCompareForm
	if form.spec.compare {
		var known bool
		var err error
		comparison, known, err = x86ScalarCompareProperties(ins.Op, ins, c.goarch)
		if !known || err != nil {
			return true, numericalSBContext("certified comparison lost its complete operand form: %v", err)
		}
	}
	if c.fixedLocal == nil {
		if err := c.scalarFPResultInitialized(); err != nil {
			return true, err
		}
	} else if c.fixedLocal.binding == nil || c.fixedLocal.binding != c.sig.x86FixedLocal ||
		c.fixedLocal.binding.numericalReads == nil || c.fixedLocal.binding.numericalReads.source != cert.binding.source {
		return true, numericalSBContext("numerical read lost its independent complete fixed-local proof")
	}
	if form.spec.vector == x86NumericalSBAES {
		_, _, err := c.lowerAES(ins.Op, ins)
		return true, err
	}
	if form.spec.vector == x86NumericalSBLogical {
		_, _, err := c.lowerPackedLogicalFamily(ins.Op, ins)
		return true, err
	}
	// No ptrFromSB call: only this exact typed read can consume the immutable
	// native source offset. The global remains externally mutable, and every
	// read is volatile even when its result/condition is later overwritten.
	pointer := llvmGlobal(read.Variable.NativeName)
	if read.Offset != 0 {
		address := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = getelementptr i8, ptr %s, i64 %d\n", address, pointer, read.Offset)
		pointer = "%" + address
	}
	sourceType := amd64IntegerTypeForBits(int(read.Width * 8))
	loaded := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load volatile %s, ptr %s, align 1\n", loaded, sourceType, pointer)
	value := "%" + loaded
	if form.spec.compare {
		// Certification already checked this shared complete operand grammar.
		// Preserve Go's immediate truncation/sign extension and byte views.
		partner := comparison.args[form.partner]
		other, err := c.evalIntSized(partner, sourceType)
		if err != nil {
			return true, err
		}
		if form.operand == 0 {
			c.setCmpFlagsSized(sourceType, value, other)
		} else {
			c.setCmpFlagsSized(sourceType, other, value)
		}
		return true, nil
	}
	destinationType := amd64IntegerTypeForBits(int(form.spec.gpBytes * 8))
	if read.Width < form.spec.gpBytes {
		extension := "zext"
		if amd64ScalarExtensionMoveSpecs[ins.Op].signed {
			extension = "sext"
		}
		extended := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = %s %s %s to %s\n", extended, extension, sourceType, value, destinationType)
		value = "%" + extended
	}
	return true, c.storeRegSized(ins.Args[form.partner].Reg, destinationType, value)
}
