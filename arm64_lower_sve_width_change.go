package plan9asm

import (
	"fmt"
	"strings"
)

type arm64SVEWidthChangeKind uint8

const (
	arm64SVEWidenTop arm64SVEWidthChangeKind = iota
	arm64SVENarrowPair
	arm64SVEShiftNarrowPair
)

type arm64SVEWidthChangeSpec struct {
	mnemonic string
	kind     arm64SVEWidthChangeKind
	rawBase  uint32
}

var arm64SVEWidthChangeSpecs = map[Op]arm64SVEWidthChangeSpec{
	"ZSCVTFLT": {mnemonic: "scvtflt", kind: arm64SVEWidenTop, rawBase: 0x650c3800},
	"ZUCVTFLT": {mnemonic: "ucvtflt", kind: arm64SVEWidenTop, rawBase: 0x650c3c00},
	"ZFCVTZSN": {mnemonic: "fcvtzsn", kind: arm64SVENarrowPair, rawBase: 0x650d3000},
	"ZFCVTZUN": {mnemonic: "fcvtzun", kind: arm64SVENarrowPair, rawBase: 0x650d3400},
	"ZSQSHRN":  {mnemonic: "sqshrn", kind: arm64SVEShiftNarrowPair, rawBase: 0x45a00000},
	"ZSQSHRUN": {mnemonic: "sqshrun", kind: arm64SVEShiftNarrowPair, rawBase: 0x45a02000},
	"ZUQSHRN":  {mnemonic: "uqshrn", kind: arm64SVEShiftNarrowPair, rawBase: 0x45a01000},
}

type arm64SVEWidthChangeForm struct {
	spec            arm64SVEWidthChangeSpec
	source          int
	sourceBits      int
	destination     int
	destinationBits int
	shift           int // Zero for conversions without an immediate.
}

func decodeARM64RawSVEWidthChange(word uint32) (arm64SVEWidthChangeForm, bool) {
	if word>>24 != 0x65 && word>>24 != 0x45 {
		return arm64SVEWidthChangeForm{}, false
	}
	for _, spec := range arm64SVEWidthChangeSpecs {
		var variable uint32
		switch spec.kind {
		case arm64SVEWidenTop:
			variable = 0x00c003ff // Size, Zn and Zd.
		case arm64SVENarrowPair:
			variable = 0x00c003df // Size, even Zn and Zd.
		case arm64SVEShiftNarrowPair:
			variable = 0x001f03df // Combined shift/size, even Zn and Zd.
		}
		if word&^variable != spec.rawBase {
			continue
		}

		form := arm64SVEWidthChangeForm{
			spec: spec, source: int(word>>5) & 31, destination: int(word) & 31,
		}
		if spec.kind == arm64SVEShiftNarrowPair {
			sizeShift := int(word>>16) & 31
			if sizeShift < 8 {
				return arm64SVEWidthChangeForm{}, false
			}
			form.destinationBits = 8
			if sizeShift >= 16 {
				form.destinationBits = 16
			}
			form.sourceBits = 2 * form.destinationBits
			form.shift = form.sourceBits - sizeShift
		} else {
			size := (word >> 22) & 3
			if size == 0 {
				return arm64SVEWidthChangeForm{}, false
			}
			form.sourceBits, form.destinationBits = 8<<size, 4<<size
			if spec.kind == arm64SVEWidenTop {
				form.sourceBits, form.destinationBits = form.destinationBits, form.sourceBits
			}
		}
		return form, true
	}
	return arm64SVEWidthChangeForm{}, false
}

func (c *arm64Ctx) lowerARM64SVEWidthChange(op Op, ins Instr) (bool, bool, error) {
	spec, ok := arm64SVEWidthChangeSpecs[op]
	if !ok {
		return false, false, nil
	}
	wantArgs := 2
	if spec.kind == arm64SVEShiftNarrowPair {
		wantArgs = 3
	}
	if !strings.EqualFold(string(ins.Op), string(op)) || len(ins.Args) != wantArgs {
		return true, false, fmt.Errorf("arm64 %s requires a width-changing operand form without a suffix: %q", op, ins.Raw)
	}
	form := arm64SVEWidthChangeForm{spec: spec}
	sourceArg := ins.Args[wantArgs-2]
	var sourceOK bool
	if spec.kind == arm64SVEWidenTop {
		form.source, form.sourceBits, sourceOK = arm64ParseSVEZElementReg(sourceArg)
	} else {
		form.source, _, form.sourceBits, sourceOK = arm64ParseSVEEvenVectorPair(sourceArg)
	}
	var destinationOK bool
	form.destination, form.destinationBits, destinationOK = arm64ParseSVEZElementReg(ins.Args[wantArgs-1])
	validWidth := form.sourceBits == 2*form.destinationBits
	if spec.kind == arm64SVEWidenTop {
		validWidth = form.destinationBits == 2*form.sourceBits
	}
	if !sourceOK || !destinationOK || !validWidth {
		return true, false, fmt.Errorf("arm64 %s requires the matching source shape and doubled or halved element width: %q", op, ins.Raw)
	}
	if spec.kind == arm64SVEShiftNarrowPair {
		immediate := ins.Args[0]
		if immediate.Kind != OpImm || immediate.ImmRaw != "" || immediate.ImmIsFloat ||
			form.destinationBits > 16 || immediate.Imm < 1 || immediate.Imm > int64(form.destinationBits) {
			return true, false, fmt.Errorf("arm64 %s requires an H-to-B or S-to-H range and shift $1..$destinationBits: %q", op, ins.Raw)
		}
		form.shift = int(immediate.Imm)
	}
	return true, false, c.lowerARM64SVEWidthChangeForm(form)
}

func (c *arm64Ctx) lowerARM64SVEWidthChangeForm(form arm64SVEWidthChangeForm) error {
	source, sourceType, err := c.loadZRegElements(form.source, form.sourceBits)
	if err != nil {
		return err
	}
	destinationType, _, err := arm64SVEVectorType(form.destinationBits)
	if err != nil {
		return err
	}
	sourceSuffix := strings.ToLower(arm64SVEElementLetter(form.sourceBits))
	destinationSuffix := strings.ToLower(arm64SVEElementLetter(form.destinationBits))
	operands := fmt.Sprintf("$0.%s, $1.%s", destinationSuffix, sourceSuffix)
	constraints := "=w,w"
	args := sourceType + " " + source
	if form.spec.kind != arm64SVEWidenTop {
		second, _, err := c.loadZRegElements(form.source+1, form.sourceBits)
		if err != nil {
			return err
		}
		// Bind the inputs to an even/odd vector pair and allow the backend
		// to choose the destination independently.
		operands = fmt.Sprintf("$0.%[1]s, { $1.%[2]s, $2.%[2]s }", destinationSuffix, sourceSuffix)
		constraints = "=&w,{z30},{z31}"
		args += ", " + sourceType + " " + second
	}
	if form.shift != 0 {
		operands += fmt.Sprintf(", #%d", form.shift)
	}
	// LLVM 22 has no intrinsics for these SVE2p3 forms. Keep the hardware
	// operation and its floating-point status effects even with a dead result.
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s asm sideeffect %q, %q(%s)\n",
		result, destinationType, form.spec.mnemonic+" "+operands, constraints, args)
	return c.storeZRegElements(form.destination, form.destinationBits, "%"+result)
}
