package plan9asm

import (
	"fmt"
	"math"
	"strings"
	"testing"
)

type x86X87ValueFixture struct {
	name, body string
	want       float64
	bits       uint64
	bitResult  bool
}

// All parameters have their actual classic 386 scalar layout. The first
// source half forces the existing byte-view/whole-source consumer to run;
// neither a mnemonic nor a floating declaration authenticates an x87 input.
const x86X87ValueDeclaration = "func Value(gate uint64, f float32, d float64, w int16, l int32) float64"

func x86X87ValueSource(body string) string {
	return "TEXT ·Value(SB),4,$0-36\nMOVL gate+4(FP),AX\n" + body + "RET\n"
}

func x86X87ValueFixturesThreeAPIs(t *testing.T, fixtures []x86X87ValueFixture) {
	t.Helper()
	for _, target := range x86RawReturnTargets {
		if target.arch != "386" {
			continue
		}
		for _, row := range fixtures {
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(target.triple+"/"+row.name+"/"+api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, x86X87ValueSource(row.body), x86X87ValueDeclaration,
						target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("complete typed logical x87 value flow did not close", err)
					}
					probe := "\ndefine i64 @Probe() {\n" +
						" %r = call double @Value(i64 0, float 2.000000e+00, double 4.000000e+00, i16 2, i32 2)\n" +
						" %b = bitcast double %r to i64\n ret i64 %b\n}\n"
					want := row.bits
					if !row.bitResult {
						want = math.Float64bits(row.want)
					}
					// This is optimized logical-double evidence, not execution of
					// physical x87, its control word, exceptions or 80-bit values.
					x86ScalarFPNamedConstantResult(t, ir+probe, "Probe", []uint64{want})
				})
			}
		}
	}
}

func TestX86X87FloatingMovesConstantsAndUnaryValueFlow(t *testing.T) {
	rows := []x86X87ValueFixture{
		{name: "FMOVD/memory-push", body: "FMOVD d+12(FP),F0\nFMOVDP F0,ret+28(FP)\n", want: 4},
		{name: "FMOVF/memory-push", body: "FMOVF f+8(FP),F0\nFMOVDP F0,ret+28(FP)\n", want: 2},
		{name: "FMOVD/memory-store", body: "FLD1\nFMOVD F0,ret+28(FP)\nFMOVDP F0,F0\n", want: 1},
		{name: "FMOVDP/memory-store-pop", body: "FLD1\nFMOVDP F0,ret+28(FP)\n", want: 1},
		{name: "FMOVF/memory-store", body: "FLD1\nFMOVF F0,ret+28(FP)\nMOVL $0,ret+32(FP)\nFMOVDP F0,F0\n", bits: 0x3f800000, bitResult: true},
		{name: "FMOVFP/memory-store-pop", body: "FLD1\nFMOVFP F0,ret+28(FP)\nMOVL $0,ret+32(FP)\n", bits: 0x3f800000, bitResult: true},
		{name: "FABS", body: "FLD1\nFCHS\nFABS\nFMOVDP F0,ret+28(FP)\n", want: 1},
		{name: "FCHS", body: "FLD1\nFCHS\nFMOVDP F0,ret+28(FP)\n", want: -1},
		{name: "FSQRT", body: "FMOVD d+12(FP),F0\nFSQRT\nFMOVDP F0,ret+28(FP)\n", want: 2},
	}
	for _, constant := range []struct {
		op   string
		want float64
	}{
		{"FLD1", 1}, {"FLDL2E", math.Log2E}, {"FLDL2T", math.Log2E * math.Ln10},
		{"FLDLG2", math.Log10E * math.Ln2}, {"FLDLN2", math.Ln2}, {"FLDPI", math.Pi}, {"FLDZ", 0},
	} {
		rows = append(rows, x86X87ValueFixture{
			name: constant.op, body: constant.op + "\nFMOVDP F0,ret+28(FP)\n", want: constant.want,
		})
	}
	for lane := 1; lane < 8; lane++ {
		// Every referenced ST(i) is source-defined. The two exchange rows
		// and both store rows use their own exact operand direction.
		push := strings.Repeat("FLD1\n", lane) + "FMOVD d+12(FP),F0\n"
		for _, instruction := range []string{
			fmt.Sprintf("FXCHD F0,F%d", lane), fmt.Sprintf("FXCHD F%d,F0", lane),
		} {
			rows = append(rows, x86X87ValueFixture{
				name: instruction, want: 1,
				body: push + instruction + "\nFMOVDP F0,ret+28(FP)\n" + strings.Repeat("FMOVDP F0,F0\n", lane),
			})
		}
		for _, op := range []string{"FMOVD", "FMOVDP"} {
			// Store 4 into an already authored destination, then pop each
			// shallower value before observing that exact destination.
			pops := lane
			if op == "FMOVDP" {
				pops--
			}
			rows = append(rows, x86X87ValueFixture{
				name: fmt.Sprintf("%s/F0-to-F%d", op, lane), want: 4,
				body: push + fmt.Sprintf("%s F0,F%d\n", op, lane) +
					strings.Repeat("FMOVDP F0,F0\n", pops) + "FMOVDP F0,ret+28(FP)\n",
			})
		}
	}
	x86X87ValueFixturesThreeAPIs(t, rows)
}

func TestX86X87ArithmeticCompleteValueDependencies(t *testing.T) {
	var rows []x86X87ValueFixture
	for _, operation := range []struct {
		stem             string
		memory2, memory4 float64
		regToF0, f0ToReg float64
		alias            float64
	}{
		{"FADD", 3, 5, 5, 5, 2},
		{"FMUL", 2, 4, 4, 4, 1},
		{"FSUB", -1, -3, -3, 3, 0},
		{"FSUBR", 1, 3, 3, -3, 0},
		{"FDIV", 0.5, 0.25, 0.25, 4, 1},
		{"FDIVR", 2, 4, 4, 0.25, 1},
	} {
		for _, source := range []struct{ suffix, operand string }{
			{"W", "w+20(FP)"}, {"L", "l+24(FP)"}, {"F", "f+8(FP)"}, {"D", "d+12(FP)"},
		} {
			want := operation.memory2
			if source.suffix == "D" {
				want = operation.memory4
			}
			op := operation.stem + source.suffix
			rows = append(rows, x86X87ValueFixture{
				name: op + "/memory", want: want,
				body: "FLD1\n" + op + " " + source.operand + ",F0\nFMOVDP F0,ret+28(FP)\n",
			})
		}
		for _, source := range []struct {
			form, instruction, tail string
			want                    float64
		}{
			{"D/reg-to-F0", operation.stem + "D F1,F0\n", "FMOVDP F0,ret+28(FP)\nFMOVDP F0,F0\n", operation.regToF0},
			{"D/F0-to-reg", operation.stem + "D F0,F1\n", "FMOVDP F0,F0\nFMOVDP F0,ret+28(FP)\n", operation.f0ToReg},
			{"DP/F0-to-reg", operation.stem + "DP F0,F1\n", "FMOVDP F0,ret+28(FP)\n", operation.f0ToReg},
		} {
			rows = append(rows, x86X87ValueFixture{
				name: operation.stem + source.form, want: source.want,
				body: "FMOVD d+12(FP),F0\nFLD1\n" + source.instruction + source.tail,
			})
		}
		for _, suffix := range []string{"D", "DP"} {
			tail := "FMOVDP F0,ret+28(FP)\n"
			push := "FLD1\n"
			want := operation.alias
			if suffix == "DP" {
				push = "FLD1\nFLD1\n"
				// F0,F0 writes the old top, then pops it. The next original
				// cell is still 1, independent of the discarded arithmetic.
				want = 1
			}
			rows = append(rows, x86X87ValueFixture{
				name: operation.stem + suffix + "/F0-alias", want: want,
				body: push + operation.stem + suffix + " F0,F0\n" + tail,
			})
		}
	}
	x86X87ValueFixturesThreeAPIs(t, rows)
}

func x86X87StatusResultStores(mask uint16) string {
	return fmt.Sprintf("FSTSW AX\nANDW $%d,AX\nMOVW AX,ret+28(FP)\nMOVW $0,ret+30(FP)\nMOVL $0,ret+32(FP)\n", mask)
}

func TestX86X87CompareAndStatusNeedIndependentDefinedBits(t *testing.T) {
	var rows []x86X87ValueFixture
	for _, form := range []struct {
		op, operand string
		pops        int
	}{
		{"FCOMW", "w+20(FP),F0", 0}, {"FCOMWP", "w+20(FP),F0", 1},
		{"FCOML", "l+24(FP),F0", 0}, {"FCOMLP", "l+24(FP),F0", 1},
		{"FCOMF", "f+8(FP),F0", 0}, {"FCOMFP", "f+8(FP),F0", 1},
		{"FCOMD", "d+12(FP),F0", 0}, {"FCOMDP", "d+12(FP),F0", 1},
		{"FCOMDPP", "F0,F1", 2},
		{"FUCOM", "F0,F1", 0}, {"FUCOMP", "F0,F1", 1}, {"FUCOMPP", "F0,F1", 2},
	} {
		// The source-created stack is [1,4]. Every compare observes 1<rhs;
		// the two-pop row intentionally uses its actual F1 encoding.
		rows = append(rows, x86X87ValueFixture{
			name: form.op, bits: 0x100, bitResult: true,
			body: "FMOVD d+12(FP),F0\nFLD1\n" + form.op + " " + form.operand + "\n" +
				x86X87StatusResultStores(0x4500) + strings.Repeat("FMOVDP F0,F0\n", 2-form.pops),
		})
	}
	for _, op := range []string{"FCOMI", "FCOMIP", "FUCOMI", "FUCOMIP"} {
		operands := "F1,F0"
		if strings.HasPrefix(op, "FUCOM") {
			operands = "F0,F1"
		}
		body := "FMOVD d+12(FP),F0\nFLD1\n" + op + " " + operands + "\n"
		for offset, condition := range []string{"EQ", "CS", "PS", "OS", "MI", "LT"} {
			// LT=SF xor OF also checks both architecturally cleared flags.
			body += fmt.Sprintf("SET%s AX\nMOVB AX,ret+%d(FP)\n", condition, 28+offset)
		}
		body += "MOVW $0,ret+34(FP)\n"
		pops := 2
		if strings.HasSuffix(op, "IP") {
			pops--
		}
		rows = append(rows, x86X87ValueFixture{
			name: op, body: body + strings.Repeat("FMOVDP F0,F0\n", pops), bits: 0x100, bitResult: true,
		})
	}
	for _, source := range []struct {
		name, body string
		status     uint16
	}{
		{"zero", "FLDZ\n", 0x4000}, {"positive", "FLD1\n", 0}, {"negative", "FLD1\nFCHS\n", 0x100},
		{"negative-zero", "FLDZ\nFCHS\n", 0x4000},
		{"unordered", "FLDZ\nFLDZ\nFDIVDP F0,F1\n", 0x4500},
	} {
		for _, mask := range []uint16{0, 0x100, 0x400, 0x4000, 0x4500} {
			rows = append(rows, x86X87ValueFixture{
				name: fmt.Sprintf("FTST/%s/mask-%04x", source.name, mask), bits: uint64(source.status & mask), bitResult: true,
				body: source.body + "FTST\n" + x86X87StatusResultStores(mask) + "FMOVDP F0,F0\n",
			})
		}
	}
	x86X87ValueFixturesThreeAPIs(t, rows)
}

// Register-source FMOVD selects Go's FLD ST(i) row, including the ambiguous
// F0,F0 spelling. A following pop must reveal the previous top, not an entry
// alloca's initial zero. This root does not use the new byte-view trigger, so
// its wrong-value counterexample remains separate from missing x87 proof.
func TestX86X87RegisterFloatingLoadUsesActualGoPush(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		if target.arch != "386" {
			continue
		}
		for _, row := range []struct {
			name, body string
		}{
			{"F0-alias", "FLD1\nFMOVD F0,F0\nFMOVDP F0,F0\nFMOVDP F0,ret+0(FP)\n"},
			{"F1-source", "FLDZ\nFLD1\nFMOVD F1,F0\nFMOVDP F0,F0\nFMOVDP F0,ret+0(FP)\nFMOVDP F0,F0\n"},
		} {
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(target.triple+"/"+row.name+"/"+api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, "TEXT ·Value(SB),4,$0-8\n"+row.body+"RET\n",
						"func Value() float64", target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("logical register-load fixture did not translate", err)
					}
					probe := "\ndefine i64 @Probe() {\n %r = call double @Value()\n %b = bitcast double %r to i64\n ret i64 %b\n}\n"
					x86ScalarFPNamedConstantResult(t, ir+probe, "Probe", []uint64{0x3ff0000000000000})
				})
			}
		}
	}
}
