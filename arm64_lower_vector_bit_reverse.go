package plan9asm

import (
	"fmt"
	"strings"
)

func (c *arm64Ctx) lowerARM64VectorBitReverse(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if op != "VRBIT" {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != "VRBIT" || len(ins.Args) != 2 ||
		ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpReg {
		return true, false, fmt.Errorf("arm64 VRBIT expects Vm.B8/B16, Vd.B8/B16: %q", ins.Raw)
	}
	sourceArrangement, sourceOK := parseARM64VectorArrangement(ins.Args[0].Reg)
	destinationArrangement, destinationOK := parseARM64VectorArrangement(ins.Args[1].Reg)
	if !sourceOK || !destinationOK || sourceArrangement != destinationArrangement ||
		sourceArrangement.elementBits != 8 || sourceArrangement.lanes != 8 && sourceArrangement.lanes != 16 {
		return true, false, fmt.Errorf("arm64 VRBIT requires matching B8 or B16 arrangements: %q", ins.Raw)
	}
	source, err := c.loadARM64VectorInteger(ins.Args[0].Reg, sourceArrangement)
	if err != nil {
		return true, false, err
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call <%d x i8> @llvm.bitreverse.v%di8(<%d x i8> %s)\n",
		result, sourceArrangement.lanes, sourceArrangement.lanes, sourceArrangement.lanes, source)
	return true, false, c.storeARM64VectorInteger(ins.Args[1].Reg, destinationArrangement, "%"+result)
}
