package plan9asm

import (
	"fmt"
	"strings"
)

type arm64SVEBFloatMLASpec struct {
	intrinsic     string
	laneIntrinsic string
	widening      bool
	subtractLong  bool
}

var arm64SVEBFloatMLASpecs = map[Op]arm64SVEBFloatMLASpec{
	"ZBFMLA":   {intrinsic: "fmla", laneIntrinsic: "fmla.lane"},
	"ZBFMLS":   {intrinsic: "fmls", laneIntrinsic: "fmls.lane"},
	"ZBFMLALB": {intrinsic: "bfmlalb", laneIntrinsic: "bfmlalb.lane.v2", widening: true},
	"ZBFMLALT": {intrinsic: "bfmlalt", laneIntrinsic: "bfmlalt.lane.v2", widening: true},
	"ZBFMLSLB": {intrinsic: "bfmlslb", laneIntrinsic: "bfmlslb.lane", widening: true, subtractLong: true},
	"ZBFMLSLT": {intrinsic: "bfmlslt", laneIntrinsic: "bfmlslt.lane", widening: true, subtractLong: true},
}

type arm64SVEBFloatMLAForm struct {
	spec                          arm64SVEBFloatMLASpec
	first, second, destination    int
	predicate, lane               int
	predicated, indexed, widening bool
}

func (c *arm64Ctx) lowerARM64SVEBFloatMLA(op Op, ins Instr) (ok bool, terminated bool, err error) {
	spec, ok := arm64SVEBFloatMLASpecs[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) {
		return true, false, fmt.Errorf("arm64 %s does not accept an instruction suffix: %q", op, ins.Raw)
	}
	form := arm64SVEBFloatMLAForm{spec: spec, widening: spec.widening}
	if len(ins.Args) == 4 && !spec.widening {
		second, secondBits, secondOK := arm64ParseSVEZElementReg(ins.Args[0])
		first, firstBits, firstOK := arm64ParseSVEZElementReg(ins.Args[1])
		predicate, predicateOK := arm64ParseSVEPredicateMode(ins.Args[2], "M", 7)
		destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[3])
		if !secondOK || !firstOK || !predicateOK || !destinationOK || secondBits != 16 || firstBits != 16 || destinationBits != 16 {
			return true, false, fmt.Errorf("arm64 %s requires H sources, H accumulator, and P0..P7/M: %q", op, ins.Raw)
		}
		form.first, form.second, form.destination = first, second, destination
		form.predicate, form.predicated = predicate, true
		return true, false, c.lowerARM64SVEBFloatMLAForm(form)
	}
	if len(ins.Args) != 3 {
		return true, false, fmt.Errorf("arm64 %s operands are outside its complete Go 1.27 BF16 MLA forms: %q", op, ins.Raw)
	}
	first, firstBits, firstOK := arm64ParseSVEZElementReg(ins.Args[1])
	destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[2])
	wantDestinationBits := 16
	if spec.widening {
		wantDestinationBits = 32
	}
	if !firstOK || !destinationOK || firstBits != 16 || destinationBits != wantDestinationBits {
		return true, false, fmt.Errorf("arm64 %s source/destination widths are outside its Go 1.27 forms: %q", op, ins.Raw)
	}
	form.first, form.destination = first, destination
	if second, secondBits, secondOK := arm64ParseSVEZElementReg(ins.Args[0]); secondOK {
		if !spec.widening || secondBits != 16 {
			return true, false, fmt.Errorf("arm64 %s has no unpredicated non-indexed same-width form: %q", op, ins.Raw)
		}
		form.second = second
	} else {
		second, secondBits, lane, secondOK := arm64ParseSVEZIndexedElementRegUnbounded(ins.Args[0])
		if !secondOK || secondBits != 16 || second > 7 || lane > 7 {
			return true, false, fmt.Errorf("arm64 %s indexed source must use Z0..Z7.H[0..7]: %q", op, ins.Raw)
		}
		form.second, form.lane, form.indexed = second, lane, true
	}
	return true, false, c.lowerARM64SVEBFloatMLAForm(form)
}

func (c *arm64Ctx) lowerARM64SVEBFloatMLAForm(form arm64SVEBFloatMLAForm) error {
	firstValue, err := c.loadARM64SVEBFloatVector(form.first)
	if err != nil {
		return err
	}
	secondValue, err := c.loadARM64SVEBFloatVector(form.second)
	if err != nil {
		return err
	}
	result := c.newTmp()
	if form.widening {
		accumulator, accumulatorType, err := c.loadRawSVEFloatVector(form.destination, 32)
		if err != nil {
			return err
		}
		if form.indexed {
			fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s(%s %s, <vscale x 8 x bfloat> %s, <vscale x 8 x bfloat> %s, i32 %d)\n", result, accumulatorType, form.spec.laneIntrinsic, accumulatorType, accumulator, firstValue, secondValue, form.lane)
		} else {
			fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s(%s %s, <vscale x 8 x bfloat> %s, <vscale x 8 x bfloat> %s)\n", result, accumulatorType, form.spec.intrinsic, accumulatorType, accumulator, firstValue, secondValue)
		}
		return c.storeRawSVEFloatVector(form.destination, 32, "%"+result, accumulatorType)
	}
	accumulator, err := c.loadARM64SVEBFloatVector(form.destination)
	if err != nil {
		return err
	}
	if form.predicated {
		predicate, predicateType, err := c.loadPRegElements(form.predicate, 16)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  %%%s = call <vscale x 8 x bfloat> @llvm.aarch64.sve.%s.nxv8bf16(%s %s, <vscale x 8 x bfloat> %s, <vscale x 8 x bfloat> %s, <vscale x 8 x bfloat> %s)\n", result, form.spec.intrinsic, predicateType, predicate, accumulator, firstValue, secondValue)
	} else {
		fmt.Fprintf(c.b, "  %%%s = call <vscale x 8 x bfloat> @llvm.aarch64.sve.%s.nxv8bf16(<vscale x 8 x bfloat> %s, <vscale x 8 x bfloat> %s, <vscale x 8 x bfloat> %s, i32 %d)\n", result, form.spec.laneIntrinsic, accumulator, firstValue, secondValue, form.lane)
	}
	return c.storeARM64SVEBFloatVector(form.destination, "%"+result)
}

func emitARM64SVEBFloatMLADeclarations(b *strings.Builder) {
	for _, intrinsic := range []string{"fmla", "fmls"} {
		fmt.Fprintf(b, "declare <vscale x 8 x bfloat> @llvm.aarch64.sve.%s.nxv8bf16(<vscale x 8 x i1>, <vscale x 8 x bfloat>, <vscale x 8 x bfloat>, <vscale x 8 x bfloat>)\n", intrinsic)
		fmt.Fprintf(b, "declare <vscale x 8 x bfloat> @llvm.aarch64.sve.%s.lane.nxv8bf16(<vscale x 8 x bfloat>, <vscale x 8 x bfloat>, <vscale x 8 x bfloat>, i32 immarg)\n", intrinsic)
	}
	for _, spec := range []arm64SVEBFloatMLASpec{
		arm64SVEBFloatMLASpecs["ZBFMLALB"], arm64SVEBFloatMLASpecs["ZBFMLALT"],
		arm64SVEBFloatMLASpecs["ZBFMLSLB"], arm64SVEBFloatMLASpecs["ZBFMLSLT"],
	} {
		fmt.Fprintf(b, "declare <vscale x 4 x float> @llvm.aarch64.sve.%s(<vscale x 4 x float>, <vscale x 8 x bfloat>, <vscale x 8 x bfloat>)\n", spec.intrinsic)
		fmt.Fprintf(b, "declare <vscale x 4 x float> @llvm.aarch64.sve.%s(<vscale x 4 x float>, <vscale x 8 x bfloat>, <vscale x 8 x bfloat>, i32 immarg)\n", spec.laneIntrinsic)
	}
}
