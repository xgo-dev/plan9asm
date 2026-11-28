package arm

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/asm"
)

func armNextReg(r asm.Reg) (asm.Reg, error) {
	s := strings.ToUpper(string(r))
	if !strings.HasPrefix(s, "R") {
		return "", fmt.Errorf("arm: expected integer reg, got %s", r)
	}
	n, err := strconv.Atoi(strings.TrimPrefix(s, "R"))
	if err != nil {
		return "", err
	}
	if n < 0 || n >= 15 {
		return "", fmt.Errorf("arm: cannot compute next reg for %s", r)
	}
	return asm.Reg(fmt.Sprintf("R%d", n+1)), nil
}

// Fixed A32 encodings also assemble in GOARM=5 objects that guard the
// instruction at runtime. Use the processor's exclusive monitor across
// instructions and calls. Matching a saved address and value cannot detect ABA.
func (c *armCtx) lowerAtomic(op, cond string, ins asm.Instr) (ok, terminated bool, err error) {
	var word uint32
	switch op {
	case "LDREXB":
		word = 0xe1d20f9f
	case "LDREX":
		word = 0xe1920f9f
	case "LDREXD":
		word = 0xe1b20f9f
	case "STREXB":
		word = 0xe1c23f90
	case "STREX":
		word = 0xe1823f90
	case "STREXD":
		word = 0xe1a23f90
	default:
		return false, false, nil
	}
	if !c.nativeA32 {
		return true, false, fmt.Errorf("%w: %s needs an A32 exclusive monitor", asm.ErrProbeNeedsContext, op)
	}
	store := op[0] == 'S'
	if store && len(ins.Args) != 3 || !store && len(ins.Args) != 2 {
		return true, false, fmt.Errorf("arm: invalid operands for %s: %q", op, ins.Raw)
	}
	mem, data := ins.Args[0], ins.Args[1]
	if store && data.Kind == asm.OpMem {
		mem, data = data, mem
	}
	if mem.Kind != asm.OpMem || mem.Mem.Base == "" || mem.Mem != (asm.MemRef{Base: mem.Mem.Base}) || data.Kind != asm.OpReg {
		return true, false, fmt.Errorf("arm: %s requires an unmodified base and a data register: %q", op, ins.Raw)
	}
	var high, status asm.Reg
	if strings.HasSuffix(op, "D") {
		n, err := strconv.Atoi(strings.TrimPrefix(string(data.Reg), "R"))
		if err != nil || n < 0 || n > 12 || n%2 != 0 {
			return true, false, fmt.Errorf("arm: %s requires an even register pair: %q", op, ins.Raw)
		}
		high, _ = armNextReg(data.Reg)
	}
	if store {
		status = ins.Args[2].Reg
		if ins.Args[2].Kind != asm.OpReg || status == data.Reg || status == mem.Mem.Base || status == high {
			return true, false, fmt.Errorf("arm: %s needs a distinct status register: %q", op, ins.Raw)
		}
	}
	return true, false, c.emitConditionalEffect(cond, func() error {
		addr, _, _, err := c.addrI32(mem.Mem, false)
		if err != nil {
			return err
		}
		if store {
			lo, err := c.loadReg(data.Reg)
			if err != nil {
				return err
			}
			result := c.newTmp()
			if high == "" {
				fmt.Fprintf(c.b, "  %%%s = call i32 asm sideeffect \".inst 0x%08x\", \"={r3},{r0},{r2},~{memory}\"(i32 %s, i32 %s)\n", result, word, lo, addr)
			} else {
				hi, err := c.loadReg(high)
				if err != nil {
					return err
				}
				fmt.Fprintf(c.b, "  %%%s = call i32 asm sideeffect \".inst 0x%08x\", \"={r3},{r0},{r1},{r2},~{memory}\"(i32 %s, i32 %s, i32 %s)\n", result, word, lo, hi, addr)
			}
			return c.storeReg(status, "%"+result)
		}
		result := c.newTmp()
		if high == "" {
			fmt.Fprintf(c.b, "  %%%s = call i32 asm sideeffect \".inst 0x%08x\", \"={r0},{r2},~{memory}\"(i32 %s)\n", result, word, addr)
			return c.storeReg(data.Reg, "%"+result)
		}
		fmt.Fprintf(c.b, "  %%%s = call {i32, i32} asm sideeffect \".inst 0x%08x\", \"={r0},={r1},{r2},~{memory}\"(i32 %s)\n", result, word, addr)
		for i, reg := range []asm.Reg{data.Reg, high} {
			v := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = extractvalue {i32, i32} %%%s, %d\n", v, result, i)
			if err := c.storeReg(reg, "%"+v); err != nil {
				return err
			}
		}
		return nil
	})
}

// Go's ARM assembler accepts these eight barrier options by name or number.
// Encode A32 directly so a runtime GOARM check can guard a DMB in an ARMv5 object.
func (c *armCtx) emitDMB(ins asm.Instr) error {
	if !c.nativeA32 {
		return fmt.Errorf("%w: DMB needs an A32 target for its barrier domain", asm.ErrProbeNeedsContext)
	}
	options := [...]string{2: "MB_OSHST", 3: "MB_OSH", 6: "MB_NSHST", 7: "MB_NSH", 10: "MB_ISHST", 11: "MB_ISH", 14: "MB_ST", 15: "MB_SY"}
	option := 15
	if len(ins.Args) != 0 {
		if len(ins.Args) != 1 {
			return fmt.Errorf("arm DMB expects at most one option: %q", ins.Raw)
		}
		arg := ins.Args[0]
		option = -1
		for n, name := range options {
			if name != "" && ((arg.Kind == asm.OpImm && arg.ImmRaw == "" && arg.Imm == int64(n)) || strings.EqualFold(arg.String(), name)) {
				option = n
				break
			}
		}
		if option < 0 {
			return fmt.Errorf("arm DMB unsupported option %q", arg.String())
		}
	}
	fmt.Fprintf(c.b, "  call void asm sideeffect \".inst 0x%08x\", \"~{memory}\"()\n", 0xf57ff050|uint32(option))
	return nil
}
