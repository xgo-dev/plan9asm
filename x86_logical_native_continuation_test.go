package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

// Independent yxm/ymm, _yvandnpd, _yvaddsubpd and _yvblendmpd inventory.
// Each group retains the legacy X bank; physical MMX has its separate owner.
var x86LogicalNativeGroups = [][]string{
	{"ANDPS", "ANDPD", "PAND", "VANDPS", "VANDPD", "VPAND", "VPANDD", "VPANDQ"},
	{"ANDNPS", "ANDNPD", "PANDN", "VANDNPS", "VANDNPD", "VPANDN", "VPANDND", "VPANDNQ"},
	{"ORPS", "ORPD", "POR", "VORPS", "VORPD", "VPOR", "VPORD", "VPORQ"},
	{"XORPS", "XORPD", "PXOR", "VXORPS", "VXORPD", "VPXOR", "VPXORD", "VPXORQ"},
}

func x86LogicalNativeRows(arch string, groups [][]string) []struct{ op, bank, mode string } {
	var rows []struct{ op, bank, mode string }
	for _, group := range groups {
		for index, op := range group {
			if index == 5 {
				// These four integer names are VEX-only: X/Y, no mask or suffix.
				for _, bank := range []string{"X", "Y"} {
					rows = append(rows, struct{ op, bank, mode string }{op, bank, "plain"})
				}
				continue
			}
			rows = append(rows, x86FixedBinaryValueRows(arch, []string{op})...)
			if index >= 3 {
				rows = append(rows, x86FixedBinaryValueRows(arch, []string{op + ".BCST"})...)
			}
		}
	}
	return rows
}

func x86LogicalNativeGroupObjects(t *testing.T, group int) {
	t.Helper()
	x86FixedBinaryCompleteFamilyObjects(t, func(arch string) []struct{ op, bank, mode string } {
		return x86LogicalNativeRows(arch, x86LogicalNativeGroups[group:group+1])
	}, 77, 29)
}

func TestX86LogicalNativeAndCompleteObjects(t *testing.T) {
	x86LogicalNativeGroupObjects(t, 0)
}

func TestX86LogicalNativeAndNotCompleteObjects(t *testing.T) {
	x86LogicalNativeGroupObjects(t, 1)
}

func TestX86LogicalNativeOrCompleteObjects(t *testing.T) {
	x86LogicalNativeGroupObjects(t, 2)
}

func TestX86LogicalNativeXorCompleteObjects(t *testing.T) {
	x86LogicalNativeGroupObjects(t, 3)
}

func TestX86LogicalNativeReadCannotBorrowSourceFacts(t *testing.T) {
	x86FixedBinaryNativeInputBoundaries(t, func(arch string) []struct{ op, bank, mode string } {
		return x86LogicalNativeRows(arch, x86LogicalNativeGroups)
	})
}

func TestX86LogicalNativeEmitterRetainsDeadReadEffects(t *testing.T) {
	rows := x86LogicalNativeRows("amd64", x86LogicalNativeGroups)
	if len(rows) != 308 {
		t.Fatal("independent complete native logical inventory changed", len(rows))
	}
	for _, row := range rows {
		t.Run(row.op+"/"+row.bank+"/"+row.mode, func(t *testing.T) {
			wanted, _, _ := strings.Cut(row.op, ".")
			bits := 32
			if strings.HasSuffix(wanted, "PD") || strings.HasSuffix(wanted, "Q") {
				bits = 64
			}
			source, _ := x86FixedBinaryValueFixture("amd64", row.op, row.bank, row.mode, false)
			file := mustParseX86RawReturn(t, source)
			var instruction Instr
			matches := 0
			for _, ins := range file.Funcs[0].Instrs {
				name, _, _ := strings.Cut(string(ins.Op), ".")
				if name == wanted && len(ins.Args) > 0 && ins.Args[0].Kind == OpMem {
					instruction = ins
					matches++
				}
			}
			if matches != 1 {
				t.Fatal("emitter fixture lost its exact original memory operation", matches)
			}
			// This is an emitter-only observation, not a caller/NUM certificate.
			consumer, output := newAMD64CtxWithFuncForTest(t, file.Funcs[0], FuncSig{Ret: Void}, nil)
			before := output.Len()
			known, _, err := consumer.lowerPackedLogicalFamily(instruction.Op, instruction)
			if !known || err != nil {
				t.Fatal("valid original logical form rejected by its emitter", instruction.Raw, err)
			}
			text := output.String()[before:]
			if !strings.HasPrefix(row.op, "V") {
				if !strings.Contains(text, "asm sideeffect \""+strings.ToLower(row.op)) {
					t.Fatal("legacy dead read lost its original memory opcode", instruction.Raw)
				}
				return
			}
			if row.mode != "plain" {
				if !strings.Contains(text, fmt.Sprintf("load volatile i%d", bits)) || !strings.Contains(text, "br i1") {
					t.Fatal("dead masked logical read lost its E4 conditional volatile access", instruction.Raw)
				}
				return
			}
			width := amd64VectorByteWidth(Reg(row.bank + "0"))
			if strings.Contains(row.op, ".BCST") {
				width = bits / 8
			}
			if !strings.Contains(text, fmt.Sprintf("load volatile <%d x i8>", width)) {
				t.Fatal("dead unmasked logical read lost its complete volatile width", instruction.Raw)
			}
		})
	}
}
