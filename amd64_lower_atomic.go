package plan9asm

import "fmt"

func (c *amd64Ctx) lowerAtomic(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if known, terminated, err := c.lowerLockScalarRMW(op, ins); known {
		return known, terminated, err
	}
	if spec, recognized := amd64ExchangeSpecs[Op(normalizeInstructionOpcode(op))]; recognized {
		return c.lowerExchange(op, spec, ins)
	}
	if _, _, recognized := amd64CompareExchangeProperties(normalizeInstructionOpcode(op)); recognized {
		return c.lowerCompareExchange(op, ins)
	}
	switch op {
	case "LOCK":
		if len(ins.Args) != 0 {
			return true, false, fmt.Errorf("%w: LOCK operands cannot substitute for a complete following atomic instruction: %q", ErrProbeNeedsContext, ins.Raw)
		}
		// Only the whole-source consumer can bind this prefix to an adjacent
		// complete native operation. An isolated helper has no such body.
		return true, false, fmt.Errorf("%w: standalone LOCK has no source-adjacent complete atomic operation", ErrProbeNeedsContext)
	}
	return false, false, nil
}

func (c *amd64Ctx) amd64AtomicPtrFromMem(mem MemRef) (string, error) {
	ptr, ptrType, err := c.ptrFromMem(mem)
	if err != nil {
		return "", err
	}
	if ptrType != "ptr" {
		return "", fmt.Errorf("amd64 atomic operation does not support segment-relative memory")
	}
	return ptr, nil
}

func (c *amd64Ctx) amd64AtomicTruncFromI64(v64 string, ty LLVMType) (string, error) {
	switch ty {
	case I64:
		return v64, nil
	case I32, I16, I8, I1:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to %s\n", t, v64, ty)
		return "%" + t, nil
	default:
		return "", fmt.Errorf("amd64: unsupported trunc target %s", ty)
	}
}

func (c *amd64Ctx) amd64AtomicExtendToI64(v string, ty LLVMType) (string, error) {
	switch ty {
	case I64:
		return v, nil
	case I32, I16, I8, I1:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext %s %s to i64\n", t, ty, v)
		return "%" + t, nil
	default:
		return "", fmt.Errorf("amd64: unsupported extend source %s", ty)
	}
}
