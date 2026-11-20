package plan9asm

import "fmt"

//go:generate go run ./cmd/plan9asmgenregs -out arm64_sysregs_generated.go

// A named Go register and a raw MRS/MSR word share the same physical operand
// grammar. Canonical encodings avoid LLVM's feature-gated aliases without
// replacing a system-register read with an invented constant.
type arm64SystemRegisterSpec struct {
	encoding           uint16
	readable, writable bool
}

func arm64CheckedSystemRegister(name string, read bool) (string, error) {
	if spec, ok := arm64GoSystemRegisters[name]; ok {
		if (read && !spec.readable) || (!read && !spec.writable) {
			access := "writable"
			if read {
				access = "readable"
			}
			return "", fmt.Errorf("arm64 system register %s is not %s", name, access)
		}
		return arm64EncodedSystemRegisterName(spec.encoding), nil
	}
	// Encoded names also occur in decoded raw instructions. Their grammar is
	// validated by the raw decoder and LLVM's assembler, not a named alias table.
	return arm64CanonicalSysReg(name), nil
}

// SR_READ alone is not an execution or source-machine-state contract. Most
// registers require privileged entry state, feature state, or access to the
// source's virtual NZCV/FP state. DCZID_EL0 is an architectural EL0 read whose
// only data effect is defining Xt; even prohibited DC ZVA is reported as a bit
// in the value rather than performed by this read.
func arm64SystemReadHasTypedEffects(encoding uint16) bool {
	spec, ok := arm64GoSystemRegisters["DCZID_EL0"]
	return ok && spec.readable && encoding == spec.encoding
}

func (c *arm64Ctx) emitARM64SystemRegisterRead(sysreg string, encoding uint16, known bool, dst Reg) string {
	value := c.newTmp()
	format := "  %%%s = call i64 asm sideeffect %q, %q()\n"
	// A virtual data value cannot grant a hidden platform/g entry contract.
	if known && arm64SystemReadHasTypedEffects(encoding) && dst != "R18" && dst != "R28" {
		c.emitMachineNeutralNativeIR(format, value, "mrs $0, "+sysreg, "=r,~{memory}")
	} else {
		fmt.Fprintf(c.b, format, value, "mrs $0, "+sysreg, "=r,~{memory}")
	}
	return "%" + value
}
