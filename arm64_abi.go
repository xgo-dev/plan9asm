package plan9asm

import "fmt"

type arm64ABIRegisterCursor struct {
	integer  int
	floating int
}

func isARM64ABIFloatingType(typ LLVMType) bool {
	return typ == LLVMType("float") || typ == LLVMType("double")
}

func isARM64ABIIntegerType(typ LLVMType) bool {
	switch typ {
	case I1, I8, I16, I32, I64, Ptr:
		return true
	default:
		return false
	}
}

func (cursor *arm64ABIRegisterCursor) next(typ LLVMType) (Reg, error) {
	if isARM64ABIFloatingType(typ) {
		if cursor.floating >= 16 {
			return "", fmt.Errorf("floating argument exceeds F0-F15")
		}
		reg := Reg(fmt.Sprintf("F%d", cursor.floating))
		cursor.floating++
		return reg, nil
	}
	if !isARM64ABIIntegerType(typ) {
		return "", fmt.Errorf("unsupported ABI scalar type %s", typ)
	}
	if cursor.integer >= 16 {
		return "", fmt.Errorf("integer argument exceeds R0-R15")
	}
	reg := Reg(fmt.Sprintf("R%d", cursor.integer))
	cursor.integer++
	return reg, nil
}

func (c *arm64Ctx) loadABIRegisterValue(reg Reg, typ LLVMType) (string, error) {
	raw, err := c.loadReg(reg)
	if err != nil {
		return "", err
	}
	switch typ {
	case LLVMType("float"):
		bits := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", bits, raw)
		value := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast i32 %%%s to float\n", value, bits)
		return "%" + value, nil
	case LLVMType("double"):
		value := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast i64 %s to double\n", value, raw)
		return "%" + value, nil
	default:
		return c.castI64RegToArg(raw, typ)
	}
}

func (c *arm64Ctx) storeABIRegisterValue(reg Reg, typ LLVMType, value string) error {
	raw, scalar, err := arm64ValueAsI64(c, typ, value)
	if err != nil {
		return err
	}
	if !scalar {
		return fmt.Errorf("unsupported ABI scalar type %s", typ)
	}
	return c.storeReg(reg, raw)
}

func (c *arm64Ctx) abiRegisterCallArgs(callee string, sig FuncSig) ([]string, error) {
	args := make([]string, 0, len(sig.Args))
	cursor := arm64ABIRegisterCursor{}
	for argIndex, argType := range sig.Args {
		if len(sig.ArgRegs) != 0 {
			if argIndex >= len(sig.ArgRegs) {
				return nil, fmt.Errorf("arm64 call %q: missing explicit register for argument %d", callee, argIndex)
			}
			if _, aggregate := parseLiteralStructFields(argType); aggregate {
				return nil, fmt.Errorf("arm64 call %q: explicit register for aggregate argument %d is ambiguous", callee, argIndex)
			}
			value, err := c.loadABIRegisterValue(sig.ArgRegs[argIndex], argType)
			if err != nil {
				return nil, err
			}
			args = append(args, fmt.Sprintf("%s %s", argType, value))
			continue
		}
		if fields, aggregate := parseLiteralStructFields(argType); aggregate {
			value := "undef"
			for fieldIndex, fieldType := range fields {
				reg, err := cursor.next(fieldType)
				if err != nil {
					return nil, fmt.Errorf("arm64 call %q argument %d field %d: %w", callee, argIndex, fieldIndex, err)
				}
				field, err := c.loadABIRegisterValue(reg, fieldType)
				if err != nil {
					return nil, err
				}
				inserted := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = insertvalue %s %s, %s %s, %d\n", inserted, argType, value, fieldType, field, fieldIndex)
				value = "%" + inserted
			}
			args = append(args, fmt.Sprintf("%s %s", argType, value))
			continue
		}
		reg, err := cursor.next(argType)
		if err != nil {
			return nil, fmt.Errorf("arm64 call %q argument %d: %w", callee, argIndex, err)
		}
		value, err := c.loadABIRegisterValue(reg, argType)
		if err != nil {
			return nil, err
		}
		args = append(args, fmt.Sprintf("%s %s", argType, value))
	}
	if len(sig.ArgRegs) > len(sig.Args) {
		return nil, fmt.Errorf("arm64 call %q: %d explicit argument registers for %d arguments", callee, len(sig.ArgRegs), len(sig.Args))
	}
	return args, nil
}

func (c *arm64Ctx) storeABIRegisterResult(callee string, typ LLVMType, result string) error {
	cursor := arm64ABIRegisterCursor{}
	if fields, aggregate := parseLiteralStructFields(typ); aggregate {
		for fieldIndex, fieldType := range fields {
			reg, err := cursor.next(fieldType)
			if err != nil {
				return fmt.Errorf("arm64 call %q return field %d: %w", callee, fieldIndex, err)
			}
			extracted := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = extractvalue %s %s, %d\n", extracted, typ, result, fieldIndex)
			if err := c.storeABIRegisterValue(reg, fieldType, "%"+extracted); err != nil {
				return err
			}
		}
		return nil
	}
	reg, err := cursor.next(typ)
	if err != nil {
		return fmt.Errorf("arm64 call %q unsupported return type %s", callee, typ)
	}
	return c.storeABIRegisterValue(reg, typ, result)
}
