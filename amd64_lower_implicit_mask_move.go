package plan9asm

import (
	"fmt"
	"strings"
)

type amd64ImplicitMaskMoveSpec struct {
	byteWidth int
	vector    bool
}

// Go's frontend exposes the legacy SSE spelling both as MASKMOVOU and via
// the Intel-name alias MASKMOVDQU. MASKMOVQ is the corresponding MMX form;
// VMASKMOVDQU is the VEX spelling. All use the first operand as a byte mask,
// the second as data, and DI as the implicit memory destination.
var amd64ImplicitMaskMoveSpecs = map[Op]amd64ImplicitMaskMoveSpec{
	"MASKMOVQ":    {byteWidth: 8},
	"MASKMOVOU":   {byteWidth: 16},
	"MASKMOVDQU":  {byteWidth: 16},
	"VMASKMOVDQU": {byteWidth: 16, vector: true},
}

func (c *amd64Ctx) lowerImplicitMaskMove(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp = rawOp[:dot]
	}
	spec, recognized := amd64ImplicitMaskMoveSpecs[Op(baseOp)]
	if !recognized {
		return false, false, nil
	}
	if rawOp != baseOp {
		return true, false, fmt.Errorf("%s %s has no suffixed forms in Go 1.27: %q", c.goarch, baseOp, ins.Raw)
	}
	if len(ins.Args) != 2 {
		return true, false, fmt.Errorf("%s %s expects mask and data registers: %q", c.goarch, baseOp, ins.Raw)
	}
	if spec.byteWidth == 8 {
		for _, arg := range ins.Args {
			if arg.Kind != OpReg {
				return true, false, fmt.Errorf("%s %s uses Go's MMX-register-only ymr table: %q", c.goarch, baseOp, ins.Raw)
			}
			if _, ok := amd64ParseMReg(arg.Reg); !ok {
				return true, false, fmt.Errorf("%s %s uses Go's MMX-register-only ymr table: %q", c.goarch, baseOp, ins.Raw)
			}
		}
		maskBits, err := c.loadReg(ins.Args[0].Reg)
		if err != nil {
			return true, false, err
		}
		dataBits, err := c.loadReg(ins.Args[1].Reg)
		if err != nil {
			return true, false, err
		}
		mask := c.bitcastI64ToIntegerLanes(8, 8, maskBits)
		data := c.bitcastI64ToIntegerLanes(8, 8, dataBits)
		return true, false, c.emitImplicitByteMaskStore(data, mask, 8)
	}

	valid := func(arg Operand) bool {
		if spec.vector {
			return c.isGoVEXVectorRegister(arg, 16, false)
		}
		return arg.Kind == OpReg && c.isGoLegacyXReg(arg.Reg)
	}
	if !valid(ins.Args[0]) || !valid(ins.Args[1]) {
		return true, false, fmt.Errorf("%s %s uses Go's X-register-only table: %q", c.goarch, baseOp, ins.Raw)
	}
	mask, err := c.loadX(ins.Args[0].Reg)
	if err != nil {
		return true, false, err
	}
	data, err := c.loadX(ins.Args[1].Reg)
	if err != nil {
		return true, false, err
	}
	return true, false, c.emitImplicitByteMaskStore(data, mask, 16)
}

func (c *amd64Ctx) emitImplicitByteMaskStore(data, mask string, byteWidth int) error {
	predicate := c.newTmp()
	addressInteger, err := c.loadReg(DI)
	if err != nil {
		return err
	}
	address := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp slt <%d x i8> %s, zeroinitializer\n", predicate, byteWidth, mask)
	fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", address, addressInteger)
	fmt.Fprintf(c.b, "  call void @llvm.masked.store.v%di8.p0(<%d x i8> %s, ptr align 1 %%%s, <%d x i1> %%%s)\n", byteWidth, byteWidth, data, address, byteWidth, predicate)
	return nil
}
