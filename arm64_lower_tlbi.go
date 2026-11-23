package plan9asm

import (
	"fmt"
	"sort"
	"strings"
)

type arm64TLBIOperation struct {
	arm64SystemFields
	hasOperand bool
}

// arm64TLBIOperations is the TLBI portion of Go's ARM64 sysInstFields table.
// Keeping the table explicit prevents an arbitrary SYS encoding from being
// accepted under a TLBI alias.
var arm64TLBIOperations = map[string]arm64TLBIOperation{
	"VMALLE1IS": {arm64SystemFields{0, 3, 0}, false}, "VAE1IS": {arm64SystemFields{0, 3, 1}, true},
	"ASIDE1IS": {arm64SystemFields{0, 3, 2}, true}, "VAAE1IS": {arm64SystemFields{0, 3, 3}, true},
	"VALE1IS": {arm64SystemFields{0, 3, 5}, true}, "VAALE1IS": {arm64SystemFields{0, 3, 7}, true},
	"VMALLE1": {arm64SystemFields{0, 7, 0}, false}, "VAE1": {arm64SystemFields{0, 7, 1}, true},
	"ASIDE1": {arm64SystemFields{0, 7, 2}, true}, "VAAE1": {arm64SystemFields{0, 7, 3}, true},
	"VALE1": {arm64SystemFields{0, 7, 5}, true}, "VAALE1": {arm64SystemFields{0, 7, 7}, true},
	"IPAS2E1IS": {arm64SystemFields{4, 0, 1}, true}, "IPAS2LE1IS": {arm64SystemFields{4, 0, 5}, true},
	"ALLE2IS": {arm64SystemFields{4, 3, 0}, false}, "VAE2IS": {arm64SystemFields{4, 3, 1}, true},
	"ALLE1IS": {arm64SystemFields{4, 3, 4}, false}, "VALE2IS": {arm64SystemFields{4, 3, 5}, true},
	"VMALLS12E1IS": {arm64SystemFields{4, 3, 6}, false}, "IPAS2E1": {arm64SystemFields{4, 4, 1}, true},
	"IPAS2LE1": {arm64SystemFields{4, 4, 5}, true}, "ALLE2": {arm64SystemFields{4, 7, 0}, false},
	"VAE2": {arm64SystemFields{4, 7, 1}, true}, "ALLE1": {arm64SystemFields{4, 7, 4}, false},
	"VALE2": {arm64SystemFields{4, 7, 5}, true}, "VMALLS12E1": {arm64SystemFields{4, 7, 6}, false},
	"ALLE3IS": {arm64SystemFields{6, 3, 0}, false}, "VAE3IS": {arm64SystemFields{6, 3, 1}, true},
	"VALE3IS": {arm64SystemFields{6, 3, 5}, true}, "ALLE3": {arm64SystemFields{6, 7, 0}, false},
	"VAE3": {arm64SystemFields{6, 7, 1}, true}, "VALE3": {arm64SystemFields{6, 7, 5}, true},
	"VMALLE1OS": {arm64SystemFields{0, 1, 0}, false}, "VAE1OS": {arm64SystemFields{0, 1, 1}, true},
	"ASIDE1OS": {arm64SystemFields{0, 1, 2}, true}, "VAAE1OS": {arm64SystemFields{0, 1, 3}, true},
	"VALE1OS": {arm64SystemFields{0, 1, 5}, true}, "VAALE1OS": {arm64SystemFields{0, 1, 7}, true},
	"RVAE1IS": {arm64SystemFields{0, 2, 1}, true}, "RVAAE1IS": {arm64SystemFields{0, 2, 3}, true},
	"RVALE1IS": {arm64SystemFields{0, 2, 5}, true}, "RVAALE1IS": {arm64SystemFields{0, 2, 7}, true},
	"RVAE1OS": {arm64SystemFields{0, 5, 1}, true}, "RVAAE1OS": {arm64SystemFields{0, 5, 3}, true},
	"RVALE1OS": {arm64SystemFields{0, 5, 5}, true}, "RVAALE1OS": {arm64SystemFields{0, 5, 7}, true},
	"RVAE1": {arm64SystemFields{0, 6, 1}, true}, "RVAAE1": {arm64SystemFields{0, 6, 3}, true},
	"RVALE1": {arm64SystemFields{0, 6, 5}, true}, "RVAALE1": {arm64SystemFields{0, 6, 7}, true},
	"RIPAS2E1IS": {arm64SystemFields{4, 0, 2}, true}, "RIPAS2LE1IS": {arm64SystemFields{4, 0, 6}, true},
	"ALLE2OS": {arm64SystemFields{4, 1, 0}, false}, "VAE2OS": {arm64SystemFields{4, 1, 1}, true},
	"ALLE1OS": {arm64SystemFields{4, 1, 4}, false}, "VALE2OS": {arm64SystemFields{4, 1, 5}, true},
	"VMALLS12E1OS": {arm64SystemFields{4, 1, 6}, false}, "RVAE2IS": {arm64SystemFields{4, 2, 1}, true},
	"RVALE2IS": {arm64SystemFields{4, 2, 5}, true}, "IPAS2E1OS": {arm64SystemFields{4, 4, 0}, true},
	"RIPAS2E1": {arm64SystemFields{4, 4, 2}, true}, "RIPAS2E1OS": {arm64SystemFields{4, 4, 3}, true},
	"IPAS2LE1OS": {arm64SystemFields{4, 4, 4}, true}, "RIPAS2LE1": {arm64SystemFields{4, 4, 6}, true},
	"RIPAS2LE1OS": {arm64SystemFields{4, 4, 7}, true}, "RVAE2OS": {arm64SystemFields{4, 5, 1}, true},
	"RVALE2OS": {arm64SystemFields{4, 5, 5}, true}, "RVAE2": {arm64SystemFields{4, 6, 1}, true},
	"RVALE2": {arm64SystemFields{4, 6, 5}, true}, "ALLE3OS": {arm64SystemFields{6, 1, 0}, false},
	"VAE3OS": {arm64SystemFields{6, 1, 1}, true}, "VALE3OS": {arm64SystemFields{6, 1, 5}, true},
	"RVAE3IS": {arm64SystemFields{6, 2, 1}, true}, "RVALE3IS": {arm64SystemFields{6, 2, 5}, true},
	"RVAE3OS": {arm64SystemFields{6, 5, 1}, true}, "RVALE3OS": {arm64SystemFields{6, 5, 5}, true},
	"RVAE3": {arm64SystemFields{6, 6, 1}, true}, "RVALE3": {arm64SystemFields{6, 6, 5}, true},
}

var arm64TLBIOperands = func() map[arm64SystemFields]bool {
	operands := make(map[arm64SystemFields]bool, len(arm64TLBIOperations))
	for _, operation := range arm64TLBIOperations {
		operands[operation.arm64SystemFields] = operation.hasOperand
	}
	return operands
}()

func (form arm64SystemOperation) isKnownTLBI() bool {
	if form.read || form.cn != 8 {
		return false
	}
	fields := arm64SystemFields{form.op1, form.cm, form.op2}
	hasOperand, known := arm64TLBIOperands[fields]
	return known && (hasOperand || form.register == ZR)
}

func arm64TLBIOperationNames() []string {
	names := make([]string, 0, len(arm64TLBIOperations))
	for name := range arm64TLBIOperations {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func parseARM64TLBI(ins Instr) (arm64SystemOperation, bool, error) {
	if strings.ToUpper(string(ins.Op)) != "TLBI" || len(ins.Args) < 1 || len(ins.Args) > 2 || ins.Args[0].Kind != OpIdent {
		return arm64SystemOperation{}, true, fmt.Errorf("arm64 TLBI expects a Go operation and optional R/ZR operand, with no suffix: %q", ins.Raw)
	}
	operation, exists := arm64TLBIOperations[strings.ToUpper(ins.Args[0].Ident)]
	if !exists {
		return arm64SystemOperation{}, true, fmt.Errorf("arm64 TLBI operation %q is outside Go's sysInstFields table: %q", ins.Args[0].Ident, ins.Raw)
	}
	if operation.hasOperand != (len(ins.Args) == 2) {
		return arm64SystemOperation{}, true, fmt.Errorf("arm64 TLBI operation %q operand form is invalid: %q", ins.Args[0].Ident, ins.Raw)
	}
	form := arm64SystemOperation{
		arm64SYSFields: arm64SYSFields{op1: operation.op1, cn: 8, cm: operation.cm, op2: operation.op2},
		register:       ZR,
	}
	if operation.hasOperand {
		operand := ins.Args[1]
		if operand.Kind != OpReg || !isARM64GeneralOrZeroReg(operand.Reg) {
			return arm64SystemOperation{}, true, fmt.Errorf("arm64 TLBI operation %q expects an R/ZR operand: %q", ins.Args[0].Ident, ins.Raw)
		}
		form.register = operand.Reg
	}
	return form, true, nil
}
