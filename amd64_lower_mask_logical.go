package plan9asm

import "fmt"

type amd64MaskLogicalKind uint8

const (
	amd64MaskAnd amd64MaskLogicalKind = iota
	amd64MaskAndNot
	amd64MaskOr
	amd64MaskXNOR
	amd64MaskXOR
	amd64MaskNot
	amd64MaskTest
	amd64MaskOrTest
)

type amd64MaskLogicalSpec struct {
	kind amd64MaskLogicalKind
	bits int
}

// amd64MaskLogicalSpecs is the complete Go 1.27 x86 mask-register logical
// family. Binary forms use _ykaddb (K,K,K); unary and flag-setting forms use
// _yknotb (K,K). Go accepts every listed form in both amd64 and 386 mode.
var amd64MaskLogicalSpecs = map[Op]amd64MaskLogicalSpec{
	"KANDB": {amd64MaskAnd, 8}, "KANDW": {amd64MaskAnd, 16}, "KANDD": {amd64MaskAnd, 32}, "KANDQ": {amd64MaskAnd, 64},
	"KANDNB": {amd64MaskAndNot, 8}, "KANDNW": {amd64MaskAndNot, 16}, "KANDND": {amd64MaskAndNot, 32}, "KANDNQ": {amd64MaskAndNot, 64},
	"KORB": {amd64MaskOr, 8}, "KORW": {amd64MaskOr, 16}, "KORD": {amd64MaskOr, 32}, "KORQ": {amd64MaskOr, 64},
	"KXNORB": {amd64MaskXNOR, 8}, "KXNORW": {amd64MaskXNOR, 16}, "KXNORD": {amd64MaskXNOR, 32}, "KXNORQ": {amd64MaskXNOR, 64},
	"KXORB": {amd64MaskXOR, 8}, "KXORW": {amd64MaskXOR, 16}, "KXORD": {amd64MaskXOR, 32}, "KXORQ": {amd64MaskXOR, 64},
	"KNOTB": {amd64MaskNot, 8}, "KNOTW": {amd64MaskNot, 16}, "KNOTD": {amd64MaskNot, 32}, "KNOTQ": {amd64MaskNot, 64},
	"KTESTB": {amd64MaskTest, 8}, "KTESTW": {amd64MaskTest, 16}, "KTESTD": {amd64MaskTest, 32}, "KTESTQ": {amd64MaskTest, 64},
	"KORTESTB": {amd64MaskOrTest, 8}, "KORTESTW": {amd64MaskOrTest, 16}, "KORTESTD": {amd64MaskOrTest, 32}, "KORTESTQ": {amd64MaskOrTest, 64},
}

func (c *amd64Ctx) lowerMaskLogical(op Op, ins Instr) error {
	spec := amd64MaskLogicalSpecs[op]
	wantArgs := 3
	if spec.kind == amd64MaskNot || spec.kind == amd64MaskTest || spec.kind == amd64MaskOrTest {
		wantArgs = 2
	}
	if len(ins.Args) != wantArgs {
		return fmt.Errorf("amd64 %s expects %d K-register operands: %q", op, wantArgs, ins.Raw)
	}
	for _, arg := range ins.Args {
		if arg.Kind != OpReg {
			return fmt.Errorf("amd64 %s expects only K-register operands: %q", op, ins.Raw)
		}
		if _, ok := amd64ParseKReg(arg.Reg); !ok {
			return fmt.Errorf("amd64 %s operand is not K0..K7: %q", op, ins.Raw)
		}
	}

	load := func(arg Operand) (string, error) {
		value, err := c.loadK(arg.Reg)
		if err != nil {
			return "", err
		}
		if spec.bits == 64 {
			return value, nil
		}
		masked := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i64 %s, %s\n", masked, value, amd64MaskWidthLiteral(spec.bits))
		return "%" + masked, nil
	}

	first, err := load(ins.Args[0])
	if err != nil {
		return err
	}
	second, err := load(ins.Args[1])
	if err != nil {
		return err
	}
	if spec.kind == amd64MaskTest || spec.kind == amd64MaskOrTest {
		return c.lowerMaskLogicalFlags(spec, first, second)
	}

	var result string
	switch spec.kind {
	case amd64MaskNot:
		not := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = xor i64 %s, %s\n", not, first, amd64MaskWidthLiteral(spec.bits))
		result = "%" + not
	case amd64MaskAnd, amd64MaskOr, amd64MaskXOR, amd64MaskXNOR, amd64MaskAndNot:
		operation := "and"
		lhs, rhs := first, second
		switch spec.kind {
		case amd64MaskOr:
			operation = "or"
		case amd64MaskXOR, amd64MaskXNOR:
			operation = "xor"
		case amd64MaskAndNot:
			// Go's first source is the r/m operand and its second source is
			// VEX.vvvv, so KANDN computes first & ~second.
			notSecond := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = xor i64 %s, %s\n", notSecond, second, amd64MaskWidthLiteral(spec.bits))
			rhs = "%" + notSecond
		}
		combined := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = %s i64 %s, %s\n", combined, operation, lhs, rhs)
		result = "%" + combined
		if spec.kind == amd64MaskXNOR {
			not := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = xor i64 %s, %s\n", not, result, amd64MaskWidthLiteral(spec.bits))
			result = "%" + not
		}
	default:
		return fmt.Errorf("amd64 %s has unknown mask logical operation", op)
	}
	if spec.bits != 64 {
		masked := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i64 %s, %s\n", masked, result, amd64MaskWidthLiteral(spec.bits))
		result = "%" + masked
	}
	return c.storeK(ins.Args[wantArgs-1].Reg, result)
}

func (c *amd64Ctx) lowerMaskLogicalFlags(spec amd64MaskLogicalSpec, first, second string) error {
	operation := "and"
	if spec.kind == amd64MaskOrTest {
		operation = "or"
	}
	combined := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = %s i64 %s, %s\n", combined, operation, first, second)
	zero := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp eq i64 %%%s, 0\n", zero, combined)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", zero, c.flagsZSlot)

	carry := c.newTmp()
	if spec.kind == amd64MaskTest {
		notSecond := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = xor i64 %s, %s\n", notSecond, second, amd64MaskWidthLiteral(spec.bits))
		andNot := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i64 %s, %%%s\n", andNot, first, notSecond)
		fmt.Fprintf(c.b, "  %%%s = icmp eq i64 %%%s, 0\n", carry, andNot)
	} else {
		and := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i64 %s, %s\n", and, first, second)
		fmt.Fprintf(c.b, "  %%%s = icmp eq i64 %%%s, %s\n", carry, and, amd64MaskWidthLiteral(spec.bits))
	}
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", carry, c.flagsCFSlot)
	fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsSltSlot)
	fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsPFSlot)
	fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsOFSlot)
	return nil
}

func amd64MaskWidthLiteral(bits int) string {
	if bits == 64 {
		return "-1"
	}
	return fmt.Sprintf("%d", uint64(1)<<bits-1)
}
