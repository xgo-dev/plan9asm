package plan9asm

import (
	"fmt"
	"strings"
)

type arm64RawException struct {
	mnemonic  string
	immediate uint16
}

func decodeARM64RawException(word uint32) (arm64RawException, bool) {
	base := word &^ (0xffff << 5)
	mnemonic := ""
	switch base {
	case 0xd4000002:
		mnemonic = "hvc"
	case 0xd4000003:
		mnemonic = "smc"
	case 0xd4200000:
		mnemonic = "brk"
	default:
		return arm64RawException{}, false
	}
	return arm64RawException{mnemonic: mnemonic, immediate: uint16(word >> 5)}, true
}

func (c *arm64Ctx) emitARM64Exception(mnemonic string, immediate uint16) {
	fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q()\n", fmt.Sprintf("%s #%d", mnemonic, immediate), "~{memory}")
}

func (c *arm64Ctx) lowerRawException(form arm64RawException) error {
	c.emitARM64Exception(form.mnemonic, form.immediate)
	return nil
}

func (c *arm64Ctx) lowerARM64Exception(op Op, ins Instr) (ok bool, terminated bool, err error) {
	switch op {
	case "HLT", "HVC", "SMC", "DCPS1", "DCPS2", "DCPS3":
		if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) > 1 {
			return true, false, fmt.Errorf("arm64 %s accepts no operand or one constant operand, with no suffix: %q", op, ins.Raw)
		}
		var immediate uint16
		if len(ins.Args) == 1 {
			if ins.Args[0].Kind != OpImm || ins.Args[0].ImmRaw != "" {
				return true, false, fmt.Errorf("arm64 %s operand must be a constant: %q", op, ins.Raw)
			}
			immediate = uint16(ins.Args[0].Imm)
		}
		mnemonic := strings.ToLower(string(op))
		c.emitARM64Exception(mnemonic, immediate)
		if op == "HLT" || strings.HasPrefix(string(op), "DCPS") {
			c.b.WriteString("  unreachable\n")
			return true, true, nil
		}
		return true, false, nil
	case "BRK":
		if strings.ToUpper(string(ins.Op)) != "BRK" || len(ins.Args) > 1 {
			return true, false, fmt.Errorf("arm64 BRK accepts no operand or one constant operand, with no suffix: %q", ins.Raw)
		}
		var immediate uint64
		if len(ins.Args) == 1 {
			if ins.Args[0].Kind != OpImm || ins.Args[0].ImmRaw != "" {
				return true, false, fmt.Errorf("arm64 BRK operand must be a constant: %q", ins.Raw)
			}
			immediate = uint64(ins.Args[0].Imm) & 0xffff
		}
		// A debugger or signal handler may resume after BRK, so keep the
		// following source instructions reachable.
		c.emitARM64Exception("brk", uint16(immediate))
		return true, false, nil
	case "DRPS", "ERET":
		if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 0 {
			return true, false, fmt.Errorf("arm64 %s takes no operands or suffix: %q", op, ins.Raw)
		}
		fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q()\n", strings.ToLower(string(op)), "~{memory}")
		c.b.WriteString("  unreachable\n")
		return true, true, nil
	case "UNDEF":
		if strings.ToUpper(string(ins.Op)) != "UNDEF" || len(ins.Args) != 0 {
			return true, false, fmt.Errorf("arm64 UNDEF takes no operands or suffix: %q", ins.Raw)
		}
		c.b.WriteString("  call void asm sideeffect \"udf #0\", \"~{memory}\"()\n")
		c.b.WriteString("  unreachable\n")
		return true, true, nil
	default:
		return false, false, nil
	}
}
