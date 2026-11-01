package plan9asm

import (
	"fmt"
	"strings"
)

type arm64SVEPredicateBreakKind uint8

const (
	arm64SVEPredicateBreakSimple arm64SVEPredicateBreakKind = iota
	arm64SVEPredicateBreakNext
	arm64SVEPredicateBreakPair
)

type arm64SVEPredicateBreakSpec struct {
	intrinsic  string
	kind       arm64SVEPredicateBreakKind
	allowMerge bool
	flags      bool
}

var arm64SVEPredicateBreakSpecs = map[Op]arm64SVEPredicateBreakSpec{
	"PBRKA":   {intrinsic: "brka", kind: arm64SVEPredicateBreakSimple, allowMerge: true},
	"PBRKAS":  {intrinsic: "brka.z", kind: arm64SVEPredicateBreakSimple, flags: true},
	"PBRKB":   {intrinsic: "brkb", kind: arm64SVEPredicateBreakSimple, allowMerge: true},
	"PBRKBS":  {intrinsic: "brkb.z", kind: arm64SVEPredicateBreakSimple, flags: true},
	"PBRKN":   {intrinsic: "brkn.z", kind: arm64SVEPredicateBreakNext},
	"PBRKNS":  {intrinsic: "brkn.z", kind: arm64SVEPredicateBreakNext, flags: true},
	"PBRKPA":  {intrinsic: "brkpa.z", kind: arm64SVEPredicateBreakPair},
	"PBRKPAS": {intrinsic: "brkpa.z", kind: arm64SVEPredicateBreakPair, flags: true},
	"PBRKPB":  {intrinsic: "brkpb.z", kind: arm64SVEPredicateBreakPair},
	"PBRKPBS": {intrinsic: "brkpb.z", kind: arm64SVEPredicateBreakPair, flags: true},
}

// decodeARM64RawSVEPredicateBreak covers all ten predicate-break encoding
// rows in Go 1.27. The raw operand fields are shared across the simple,
// next, and pair forms; only the simple forms permit a merging Pg mode.
func decodeARM64RawSVEPredicateBreak(word uint32) (Instr, bool) {
	const (
		predicateBits = uint32(0x00003def)
		modeBit       = uint32(1 << 4)
		pairBits      = uint32(0x000f0000)
	)
	forms := [...]struct {
		op        Op
		base      uint32
		kind      arm64SVEPredicateBreakKind
		allowMode bool
	}{
		{"PBRKA", 0x25104000, arm64SVEPredicateBreakSimple, true},
		{"PBRKAS", 0x25504000, arm64SVEPredicateBreakSimple, false},
		{"PBRKB", 0x25904000, arm64SVEPredicateBreakSimple, true},
		{"PBRKBS", 0x25d04000, arm64SVEPredicateBreakSimple, false},
		{"PBRKN", 0x25184000, arm64SVEPredicateBreakNext, false},
		{"PBRKNS", 0x25584000, arm64SVEPredicateBreakNext, false},
		{"PBRKPA", 0x2500c000, arm64SVEPredicateBreakPair, false},
		{"PBRKPAS", 0x2540c000, arm64SVEPredicateBreakPair, false},
		{"PBRKPB", 0x2500c010, arm64SVEPredicateBreakPair, false},
		{"PBRKPBS", 0x2540c010, arm64SVEPredicateBreakPair, false},
	}
	for _, form := range forms {
		variableBits := predicateBits
		if form.allowMode {
			variableBits |= modeBit
		}
		if form.kind == arm64SVEPredicateBreakPair {
			variableBits |= pairBits
		}
		if word&^variableBits != form.base {
			continue
		}
		first := int(word>>5) & 15
		governing := int(word>>10) & 15
		destination := int(word) & 15
		predicate := func(number int) Operand {
			return Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("P%d.B", number))}
		}
		governingMode := "Z"
		if form.allowMode && word&modeBit != 0 {
			governingMode = "M"
		}
		governingOperand := Operand{
			Kind: OpReg,
			Reg:  Reg(fmt.Sprintf("P%d.%s", governing, governingMode)),
		}
		args := []Operand{predicate(first)}
		if form.kind == arm64SVEPredicateBreakPair {
			second := int(word>>16) & 15
			args = []Operand{predicate(second), predicate(first)}
		} else if form.kind == arm64SVEPredicateBreakNext {
			args = []Operand{predicate(destination), predicate(first)}
		}
		args = append(args, governingOperand, predicate(destination))
		return Instr{Op: form.op, Args: args, Raw: fmt.Sprintf("WORD $%#08x", word)}, true
	}
	return Instr{}, false
}

func (c *arm64Ctx) lowerARM64SVEPredicateBreak(op Op, ins Instr) (ok bool, terminated bool, err error) {
	spec, ok := arm64SVEPredicateBreakSpecs[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) {
		return true, false, fmt.Errorf("arm64 %s does not accept an instruction suffix: %q", op, ins.Raw)
	}
	wantArgs := 3
	if spec.kind != arm64SVEPredicateBreakSimple {
		wantArgs = 4
	}
	if len(ins.Args) != wantArgs {
		return true, false, fmt.Errorf("arm64 %s expects its %d-operand Go 1.27 predicate-break form: %q", op, wantArgs, ins.Raw)
	}

	first, firstBits, firstOK := arm64ParseSVEPredicateElement(ins.Args[0])
	if !firstOK || firstBits != 8 {
		return true, false, fmt.Errorf("arm64 %s first predicate must be P0..P15.B: %q", op, ins.Raw)
	}
	if spec.kind == arm64SVEPredicateBreakSimple {
		governing, merging := arm64ParseSVEPredicateMode(ins.Args[1], "M", 15)
		if merging && !spec.allowMerge {
			return true, false, fmt.Errorf("arm64 %s only accepts a zeroing governing predicate: %q", op, ins.Raw)
		}
		if !merging {
			var zeroing bool
			governing, zeroing = arm64ParseSVEPredicateMode(ins.Args[1], "Z", 15)
			if !zeroing {
				return true, false, fmt.Errorf("arm64 %s governing predicate must be P0..P15/M or P0..P15/Z: %q", op, ins.Raw)
			}
		}
		destination, destinationBits, destinationOK := arm64ParseSVEPredicateElement(ins.Args[2])
		if !destinationOK || destinationBits != 8 {
			return true, false, fmt.Errorf("arm64 %s destination predicate must be P0..P15.B: %q", op, ins.Raw)
		}
		return true, false, c.lowerARM64SVEPredicateBreakSimple(spec, first, governing, destination, merging)
	}

	second, secondBits, secondOK := arm64ParseSVEPredicateElement(ins.Args[1])
	governing, governingOK := arm64ParseSVEPredicateMode(ins.Args[2], "Z", 15)
	destination, destinationBits, destinationOK := arm64ParseSVEPredicateElement(ins.Args[3])
	if !secondOK || secondBits != 8 || !governingOK || !destinationOK || destinationBits != 8 {
		return true, false, fmt.Errorf("arm64 %s only accepts .B predicates and P0..P15/Z: %q", op, ins.Raw)
	}
	if spec.kind == arm64SVEPredicateBreakNext && first != destination {
		return true, false, fmt.Errorf("arm64 %s requires the first and destination predicates to be identical: %q", op, ins.Raw)
	}
	return true, false, c.lowerARM64SVEPredicateBreakThreeSource(spec, first, second, governing, destination)
}

func (c *arm64Ctx) lowerARM64SVEPredicateBreakSimple(spec arm64SVEPredicateBreakSpec, source, governing, destination int, merging bool) error {
	sourceValue, predicateType, err := c.loadPRegElements(source, 8)
	if err != nil {
		return err
	}
	governingValue, _, err := c.loadPRegElements(governing, 8)
	if err != nil {
		return err
	}
	result := c.newTmp()
	if merging {
		destinationValue, _, err := c.loadPRegElements(destination, 8)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.nxv16i1(%s %s, %s %s, %s %s)\n", result, predicateType, spec.intrinsic, predicateType, destinationValue, predicateType, governingValue, predicateType, sourceValue)
	} else {
		intrinsic := spec.intrinsic
		if spec.allowMerge {
			intrinsic += ".z"
		}
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.nxv16i1(%s %s, %s %s)\n", result, predicateType, intrinsic, predicateType, governingValue, predicateType, sourceValue)
	}
	if err := c.storePRegElements(destination, 8, "%"+result); err != nil {
		return err
	}
	if spec.flags {
		c.setSVEPredicateFlags(governingValue, "%"+result, predicateType, 16)
	}
	return nil
}

func (c *arm64Ctx) lowerARM64SVEPredicateBreakThreeSource(spec arm64SVEPredicateBreakSpec, first, second, governing, destination int) error {
	firstValue, predicateType, err := c.loadPRegElements(first, 8)
	if err != nil {
		return err
	}
	secondValue, _, err := c.loadPRegElements(second, 8)
	if err != nil {
		return err
	}
	governingValue, _, err := c.loadPRegElements(governing, 8)
	if err != nil {
		return err
	}
	result := c.newTmp()
	if spec.kind == arm64SVEPredicateBreakNext {
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.nxv16i1(%s %s, %s %s, %s %s)\n", result, predicateType, spec.intrinsic, predicateType, firstValue, predicateType, governingValue, predicateType, secondValue)
	} else {
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.nxv16i1(%s %s, %s %s, %s %s)\n", result, predicateType, spec.intrinsic, predicateType, governingValue, predicateType, secondValue, predicateType, firstValue)
	}
	if err := c.storePRegElements(destination, 8, "%"+result); err != nil {
		return err
	}
	if spec.flags {
		c.setSVEPredicateFlags(governingValue, "%"+result, predicateType, 16)
	}
	return nil
}
