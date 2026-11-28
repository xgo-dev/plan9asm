package arm64

import (
	"fmt"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/asm"
)

// DC aliases of SYS <op1>, C7, <CRm>, <op2>, Xt in the Go assembler.
var cacheOperations = map[string][3]int{
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

// Go TLBI aliases all encode SYS with Cn=8. The final field determines
// whether the instruction requires a register or an implicit XZR.
var tlbOperations = map[string]struct {
	op1, crm, op2 int
	register      bool
}{
	"VMALLE1IS":    {0, 3, 0, false},
	"VAE1IS":       {0, 3, 1, true},
	"ASIDE1IS":     {0, 3, 2, true},
	"VAAE1IS":      {0, 3, 3, true},
	"VALE1IS":      {0, 3, 5, true},
	"VAALE1IS":     {0, 3, 7, true},
	"VMALLE1":      {0, 7, 0, false},
	"VAE1":         {0, 7, 1, true},
	"ASIDE1":       {0, 7, 2, true},
	"VAAE1":        {0, 7, 3, true},
	"VALE1":        {0, 7, 5, true},
	"VAALE1":       {0, 7, 7, true},
	"IPAS2E1IS":    {4, 0, 1, true},
	"IPAS2LE1IS":   {4, 0, 5, true},
	"ALLE2IS":      {4, 3, 0, false},
	"VAE2IS":       {4, 3, 1, true},
	"ALLE1IS":      {4, 3, 4, false},
	"VALE2IS":      {4, 3, 5, true},
	"VMALLS12E1IS": {4, 3, 6, false},
	"IPAS2E1":      {4, 4, 1, true},
	"IPAS2LE1":     {4, 4, 5, true},
	"ALLE2":        {4, 7, 0, false},
	"VAE2":         {4, 7, 1, true},
	"ALLE1":        {4, 7, 4, false},
	"VALE2":        {4, 7, 5, true},
	"VMALLS12E1":   {4, 7, 6, false},
	"ALLE3IS":      {6, 3, 0, false},
	"VAE3IS":       {6, 3, 1, true},
	"VALE3IS":      {6, 3, 5, true},
	"ALLE3":        {6, 7, 0, false},
	"VAE3":         {6, 7, 1, true},
	"VALE3":        {6, 7, 5, true},
	"VMALLE1OS":    {0, 1, 0, false},
	"VAE1OS":       {0, 1, 1, true},
	"ASIDE1OS":     {0, 1, 2, true},
	"VAAE1OS":      {0, 1, 3, true},
	"VALE1OS":      {0, 1, 5, true},
	"VAALE1OS":     {0, 1, 7, true},
	"RVAE1IS":      {0, 2, 1, true},
	"RVAAE1IS":     {0, 2, 3, true},
	"RVALE1IS":     {0, 2, 5, true},
	"RVAALE1IS":    {0, 2, 7, true},
	"RVAE1OS":      {0, 5, 1, true},
	"RVAAE1OS":     {0, 5, 3, true},
	"RVALE1OS":     {0, 5, 5, true},
	"RVAALE1OS":    {0, 5, 7, true},
	"RVAE1":        {0, 6, 1, true},
	"RVAAE1":       {0, 6, 3, true},
	"RVALE1":       {0, 6, 5, true},
	"RVAALE1":      {0, 6, 7, true},
	"RIPAS2E1IS":   {4, 0, 2, true},
	"RIPAS2LE1IS":  {4, 0, 6, true},
	"ALLE2OS":      {4, 1, 0, false},
	"VAE2OS":       {4, 1, 1, true},
	"ALLE1OS":      {4, 1, 4, false},
	"VALE2OS":      {4, 1, 5, true},
	"VMALLS12E1OS": {4, 1, 6, false},
	"RVAE2IS":      {4, 2, 1, true},
	"RVALE2IS":     {4, 2, 5, true},
	"IPAS2E1OS":    {4, 4, 0, true},
	"RIPAS2E1":     {4, 4, 2, true},
	"RIPAS2E1OS":   {4, 4, 3, true},
	"IPAS2LE1OS":   {4, 4, 4, true},
	"RIPAS2LE1":    {4, 4, 6, true},
	"RIPAS2LE1OS":  {4, 4, 7, true},
	"RVAE2OS":      {4, 5, 1, true},
	"RVALE2OS":     {4, 5, 5, true},
	"RVAE2":        {4, 6, 1, true},
	"RVALE2":       {4, 6, 5, true},
	"ALLE3OS":      {6, 1, 0, false},
	"VAE3OS":       {6, 1, 1, true},
	"VALE3OS":      {6, 1, 5, true},
	"RVAE3IS":      {6, 2, 1, true},
	"RVALE3IS":     {6, 2, 5, true},
	"RVAE3OS":      {6, 5, 1, true},
	"RVALE3OS":     {6, 5, 5, true},
	"RVAE3":        {6, 6, 1, true},
	"RVALE3":       {6, 6, 5, true},
}

func (c *arm64Ctx) emitCacheMaintenance(op1, crm, op2 int, r asm.Reg) error {
	if !c.nativeAArch64 {
		return fmt.Errorf("%w: DC needs an AArch64 target", asm.ErrProbeNeedsContext)
	}
	value, err := c.loadReg(r)
	if err != nil {
		return err
	}
	fmt.Fprintf(c.b, "  call void asm sideeffect \"sys #%d, c7, c%d, #%d, $0\", \"r,~{memory}\"(i64 %s)\n", op1, crm, op2, value)
	return nil
}

func (c *arm64Ctx) lowerSystemEffect(op asm.Op, ins asm.Instr) (bool, error) {
	switch op {
	case "UNDEF":
		if c.nativeAArch64 {
			c.b.WriteString("  call void asm sideeffect \".inst 0\", \"~{memory}\"()\n")
		} else {
			c.b.WriteString("  call void @llvm.trap()\n")
		}
		c.b.WriteString("  unreachable\n")
		return true, nil
	case "DC":
		if len(ins.Args) == 2 && ins.Args[1].Kind == asm.OpReg {
			if fields, ok := cacheOperations[strings.ToUpper(ins.Args[0].String())]; ok {
				return false, c.emitCacheMaintenance(fields[0], fields[1], fields[2], ins.Args[1].Reg)
			}
		}
		return false, fmt.Errorf("unsupported arm64 cache operation: %s", ins.Raw)
	}
	if !c.nativeAArch64 {
		return false, fmt.Errorf("%w: %s needs an AArch64 target", asm.ErrProbeNeedsContext, op)
	}
	if op == "SB" && len(ins.Args) == 0 {
		c.b.WriteString("  call void asm sideeffect \".inst 0xd50330ff\", \"~{memory}\"()\n")
		return false, nil
	}
	imm, limit := int64(0), int64(15)
	if op == "BREAK" || op == "BRK" {
		op = "BRK"
		limit = 65535
	}
	if len(ins.Args) == 1 && ins.Args[0].Kind == asm.OpImm && ins.Args[0].ImmRaw == "" && ins.Args[0].Imm >= 0 && ins.Args[0].Imm <= limit {
		imm = ins.Args[0].Imm
	} else if op != "BRK" || len(ins.Args) != 0 {
		return false, fmt.Errorf("invalid arm64 %s immediate: %s", op, ins.Raw)
	}
	fmt.Fprintf(c.b, "  call void asm sideeffect \"%s #%d\", \"~{memory}\"()\n", strings.ToLower(string(op)), imm)
	return false, nil
}

func (c *arm64Ctx) lowerSystemRegisterOp(op asm.Op, ins asm.Instr) error {
	if !c.nativeAArch64 {
		return fmt.Errorf("%w: %s needs an AArch64 target", asm.ErrProbeNeedsContext, op)
	}
	if len(ins.Args) < 1 || len(ins.Args) > 2 || (len(ins.Args) == 2 && ins.Args[1].Kind != asm.OpReg) {
		return fmt.Errorf("invalid arm64 system instruction: %s", ins.Raw)
	}
	var op1, cn, cm, op2 int
	if op == "TLBI" {
		d, ok := tlbOperations[strings.ToUpper(ins.Args[0].String())]
		if !ok || d.register != (len(ins.Args) == 2) {
			return fmt.Errorf("invalid arm64 TLBI operands: %s", ins.Raw)
		}
		op1, cn, cm, op2 = d.op1, 8, d.crm, d.op2
	} else {
		v := ins.Args[0]
		if v.Kind != asm.OpImm || v.ImmRaw != "" || v.Imm&^0x7ffe0 != 0 || (op == "SYSL" && len(ins.Args) != 2) {
			return fmt.Errorf("invalid arm64 system instruction fields: %s", ins.Raw)
		}
		op1, cn, cm, op2 = int(v.Imm>>16)&7, int(v.Imm>>12)&15, int(v.Imm>>8)&15, int(v.Imm>>5)&7
	}
	fields := fmt.Sprintf("#%d, c%d, c%d, #%d", op1, cn, cm, op2)
	if op == "SYSL" {
		result := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call i64 asm sideeffect %q, \"=r,~{memory}\"()\n", result, "sysl $0, "+fields)
		return c.storeReg(ins.Args[1].Reg, "%"+result)
	}
	if len(ins.Args) == 1 {
		fmt.Fprintf(c.b, "  call void asm sideeffect %q, \"~{memory}\"()\n", "sys "+fields)
		return nil
	}
	v, err := c.loadReg(ins.Args[1].Reg)
	if err != nil {
		return err
	}
	fmt.Fprintf(c.b, "  call void asm sideeffect %q, \"r,~{memory}\"(i64 %s)\n", "sys "+fields+", $0", v)
	return nil
}

func (c *arm64Ctx) lowerAddress(op asm.Op, ins asm.Instr) error {
	if len(ins.Args) != 2 || ins.Args[1].Kind != asm.OpReg {
		return fmt.Errorf("invalid arm64 address operands: %s", ins.Raw)
	}
	src := ins.Args[0]
	var addr string
	if src.Kind == asm.OpSym && strings.HasSuffix(src.Sym, "(SB)") {
		ptr, err := c.ptrFromSB(src.Sym)
		if err != nil {
			return err
		}
		addr = ptr
	} else {
		if !c.nativeAArch64 {
			return fmt.Errorf("%w: %s code address needs an AArch64 target", asm.ErrProbeNeedsContext, op)
		}
		target, _ := arm64BranchTarget(src)
		for i, b := range c.blocks {
			if i == 0 {
				continue
			}
			if (target != "" && target == b.name) || (src.Kind == asm.OpMem && src.Mem.Base == asm.PC && b.startPC == c.pc+src.Mem.Off && len(b.instrs) > 0) {
				addr = fmt.Sprintf("blockaddress(%s, %%%s)", asm.LLVMGlobal(c.sig.Name), asm.LLVMBlockName(b.name))
				break
			}
		}
		if addr == "" {
			return fmt.Errorf("%w: %s needs a local code label or symbol", asm.ErrProbeNeedsContext, op)
		}
	}
	value := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = ptrtoint ptr %s to i64\n", value, addr)
	if op == "ADRP" {
		page := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i64 %%%s, -4096\n", page, value)
		value = page
	}
	return c.storeReg(ins.Args[1].Reg, "%"+value)
}
