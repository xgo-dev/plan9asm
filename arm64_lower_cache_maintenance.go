package plan9asm

import (
	"fmt"
	"strings"
)

type arm64CacheOperation string

type arm64SystemFields struct {
	op1 uint8
	cm  uint8
	op2 uint8
}

// arm64CacheOperations mirrors exactly the cn=7 entries in Go's ARM64
// sysInstFields table. DC is a SYS alias whose second operand is mandatory for
// every operation currently accepted by Go.
var arm64CacheOperations = map[arm64CacheOperation]arm64SystemFields{
	"IVAC":    {0, 6, 1},
	"ISW":     {0, 6, 2},
	"CSW":     {0, 10, 2},
	"CISW":    {0, 14, 2},
	"ZVA":     {3, 4, 1},
	"CVAC":    {3, 10, 1},
	"CVAU":    {3, 11, 1},
	"CIVAC":   {3, 14, 1},
	"IGVAC":   {0, 6, 3},
	"IGSW":    {0, 6, 4},
	"IGDVAC":  {0, 6, 5},
	"IGDSW":   {0, 6, 6},
	"CGSW":    {0, 10, 4},
	"CGDSW":   {0, 10, 6},
	"CIGSW":   {0, 14, 4},
	"CIGDSW":  {0, 14, 6},
	"GVA":     {3, 4, 3},
	"GZVA":    {3, 4, 4},
	"CGVAC":   {3, 10, 3},
	"CGDVAC":  {3, 10, 5},
	"CGVAP":   {3, 12, 3},
	"CGDVAP":  {3, 12, 5},
	"CGVADP":  {3, 13, 3},
	"CGDVADP": {3, 13, 5},
	"CIGVAC":  {3, 14, 3},
	"CIGDVAC": {3, 14, 5},
	"CVAP":    {3, 12, 1},
	"CVADP":   {3, 13, 1},
}

func (c *arm64Ctx) lowerARM64CacheMaintenance(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if op != "DC" {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != "DC" || len(ins.Args) != 2 ||
		ins.Args[0].Kind != OpIdent || ins.Args[1].Kind != OpReg ||
		!isARM64GeneralOrZeroReg(ins.Args[1].Reg) {
		return true, false, fmt.Errorf("arm64 DC expects a Go cache-operation name and one R/ZR operand, with no suffix: %q", ins.Raw)
	}
	operation := arm64CacheOperation(strings.ToUpper(strings.TrimSpace(ins.Args[0].Ident)))
	fields, exists := arm64CacheOperations[operation]
	if !exists {
		return true, false, fmt.Errorf("arm64 DC operation %q is outside Go's sysInstFields table: %q", operation, ins.Raw)
	}

	prefix := fmt.Sprintf("sys #%d, c7, c%d, #%d", fields.op1, fields.cm, fields.op2)
	if ins.Args[1].Reg == ZR {
		fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q()\n", prefix+", xzr", "~{memory}")
		return true, false, nil
	}
	value, err := c.loadReg(ins.Args[1].Reg)
	if err != nil {
		return true, false, err
	}
	fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q(i64 %s)\n", prefix+", $0", "r,~{memory}", value)
	return true, false, nil
}
