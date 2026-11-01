package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

type fixedLocalTypedFPCase struct {
	typ, operation string
}

// Independent source families and legal memory-read positions from Go's
// yaddl/ycmpl/ytestl/yml_rl, ymovbe, yimul and VEX GP tables. The production
// effect registry must not decide this input inventory.
func fixedLocalTypedFPCases() []fixedLocalTypedFPCase {
	var rows []fixedLocalTypedFPCase
	for _, width := range []struct{ suffix, typ string }{
		{"B", "uint8"}, {"W", "uint16"}, {"L", "uint32"}, {"Q", "uint64"},
	} {
		add := func(operation string) {
			rows = append(rows, fixedLocalTypedFPCase{width.typ, operation})
		}
		for _, stem := range []string{"ADD", "ADC", "SUB", "SBB", "AND", "OR", "XOR"} {
			add(stem + width.suffix + " x+0(FP),AX")
		}
		for _, operands := range []string{"x+0(FP),AX", "AX,x+0(FP)", "x+0(FP),$1"} {
			add("CMP" + width.suffix + " " + operands)
		}
		for _, operands := range []string{"x+0(FP),AX", "AX,x+0(FP)", "$1,x+0(FP)"} {
			add("TEST" + width.suffix + " " + operands)
		}
		for _, stem := range []string{"MUL", "IMUL"} {
			add(stem + width.suffix + " x+0(FP)")
		}
		if width.suffix != "B" {
			add("IMUL" + width.suffix + " x+0(FP),AX")
			add("IMUL3" + width.suffix + " $3,x+0(FP),AX")
			for _, stem := range []string{"POPCNT", "LZCNT", "TZCNT"} {
				add(stem + width.suffix + " x+0(FP),AX")
			}
			add("MOVBE" + width.suffix + " x+0(FP),AX")
			add("MOVBE" + width.suffix + width.suffix + " x+0(FP),AX")
			add("BT" + width.suffix + " $1,x+0(FP)")
			for _, condition := range []string{
				"CC", "CS", "EQ", "GE", "GT", "HI", "LE", "LS",
				"LT", "MI", "NE", "OC", "OS", "PC", "PL", "PS",
			} {
				add("CMOV" + width.suffix + condition + " x+0(FP),AX")
			}
		}
		if width.suffix == "L" || width.suffix == "Q" {
			for _, stem := range []string{"ADCX", "ADOX", "BLSI", "BLSMSK", "BLSR"} {
				add(stem + width.suffix + " x+0(FP),AX")
			}
			for _, stem := range []string{"ANDN", "PDEP", "PEXT", "MULX"} {
				add(stem + width.suffix + " x+0(FP),CX,AX")
			}
			for _, stem := range []string{"BEXTR", "BZHI", "SHLX", "SHRX", "SARX"} {
				add(stem + width.suffix + " CX,x+0(FP),AX")
			}
			add("RORX" + width.suffix + " $3,x+0(FP),AX")
		}
	}
	for _, extension := range []struct{ typ, sizes string }{
		{"uint8", "BW"}, {"uint8", "BL"}, {"uint8", "BQ"},
		{"uint16", "WL"}, {"uint16", "WQ"}, {"uint32", "LQ"},
	} {
		for _, kind := range []string{"SX", "ZX"} {
			rows = append(rows, fixedLocalTypedFPCase{extension.typ,
				"MOV" + extension.sizes + kind + " x+0(FP),AX"})
		}
	}
	return rows
}

func fixedLocalTypedFPFixture(t *testing.T, typ, body string) (Func, FuncSig, string) {
	t.Helper()
	_, _, sig, source := x86ResultInitializationFixture(t, "amd64", "func Value(x "+typ+") uint64",
		"MOVQ $0x123456789abcdef,AX\nMOVQ $3,CX\nMOVQ $7,DX\nMOVQ AX,0(SP)\n"+
			body+"\nMOVQ AX,ret+8(FP)\nRET")
	source = strings.Replace(source, "$0-16", "$64-16", 1)
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	return file.Funcs[0], sig, source
}

func TestGoAMD64FixedLocalTypedFPReads(t *testing.T) {
	rows := fixedLocalTypedFPCases()
	if len(rows) != 174 {
		t.Fatal("independent typed GP FP-read inventory changed", len(rows))
	}
	var assembly strings.Builder
	for index, row := range rows {
		fn, sig, source := fixedLocalTypedFPFixture(t, row.typ, "CMPQ AX,AX\n"+row.operation)
		assembly.WriteString(strings.Replace(source, "·Value", fmt.Sprintf("·Value%d", index), 1))
		t.Run(row.operation, func(t *testing.T) {
			if _, err := proveX86FixedLocal(fn, sig); err != nil {
				t.Fatal("complete numerical FP input was rejected", err)
			}
		})
	}
	requireX86GoAssemblerResult(t, "amd64", assembly.String(), true)
}

func TestGoAMD64FixedLocalTypedFPBoundaries(t *testing.T) {
	t.Run("pointer machine bits multiply", func(t *testing.T) {
		fn, sig, _ := fixedLocalTypedFPFixture(t, "*uint64", "MULQ x+0(FP)")
		if _, err := proveX86FixedLocal(fn, sig); err != nil {
			t.Fatal("complete typed pointer machine multiply rejected", err)
		}
	})
	for _, row := range []struct {
		name, typ, body string
	}{
		{"pointer is not NUM", "*uint64", "ADDQ x+0(FP),AX"},
		{"pointer is not conditional NUM", "*uint64", "CMPQ AX,AX\nCMOVQEQ x+0(FP),AX"},
		{"partial pointer", "*uint64", "ADDL x+0(FP),AX"},
		{"partial numerical slot", "uint64", "ADDL x+0(FP),AX"},
		{"interior numerical slot", "uint64", "ADDL x+4(FP),AX"},
		{"cross parameter boundary", "uint64", "ADDQ x+1(FP),AX"},
		{"narrow parameter overread", "uint32", "ADDQ x+0(FP),AX"},
		{"padding", "uint8", "ADDB x+1(FP),AX"},
		{"negative slot", "uint64", "ADDQ x-8(FP),AX"},
		{"unwritten result is not input", "uint64", "ADDQ ret+8(FP),AX"},
		{"result transport is not input", "uint64", "MOVQ AX,ret+8(FP)\nADDQ ret+8(FP),AX"},
		{"parameter RMW is not import", "uint64", "ADDQ AX,x+0(FP)"},
		{"parameter unary write", "uint64", "INCQ x+0(FP)"},
		{"result RMW is not import", "uint64", "ADDQ AX,ret+8(FP)"},
		{"bit write is not import", "uint64", "BTSQ $1,x+0(FP)"},
		{"missing carry", "uint64", "ADCQ x+0(FP),AX"},
		{"missing conditional flags", "uint64", "CMOVQEQ x+0(FP),AX"},
		{"undefined register input", "uint64", "ADDQ x+0(FP),R12"},
		{"private destination is not NUM", "uint64", "LEAQ 8(SP),AX\nADDQ x+0(FP),AX"},
		{"changed SP cannot import FP", "uint64", "ADDQ $8,SP\nADDQ x+0(FP),AX\nADDQ $-8,SP"},
	} {
		t.Run(row.name, func(t *testing.T) {
			fn, sig, _ := fixedLocalTypedFPFixture(t, row.typ, row.body)
			if _, err := proveX86FixedLocal(fn, sig); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("FP read acquired unrelated bytes or write permission", err)
			}
		})
	}
}

func TestGoAMD64FixedLocalTypedFPLogicalInputs(t *testing.T) {
	for _, row := range []struct{ declaration, body string }{
		{"func Value(x bool) uint64", "MOVQ $0,AX\nTESTB $1,x+0(FP)\nSETNE AL\nMOVQ AX,ret+8(FP)\nRET"},
		{"func Value(prefix uint64,x []byte) uint64", "MOVQ prefix+0(FP),AX\nADDQ x_len+16(FP),AX\nADCQ x_cap+24(FP),AX\nMOVQ AX,ret+32(FP)\nRET"},
	} {
		t.Run(row.declaration, func(t *testing.T) {
			_, _, sig, source := x86ResultInitializationFixture(t, "amd64", row.declaration, row.body)
			source = strings.Replace(source, "$0-", "$64-", 1)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			requireX86GoAssemblerResult(t, "amd64", source, true)
			if _, err := proveX86FixedLocal(file.Funcs[0], sig); err != nil {
				t.Fatal("logical numeric component lost its declared FP input", err)
			}
		})
	}
}

func TestGoAMD64FixedLocalTypedFPCompleteObjects(t *testing.T) {
	rows := fixedLocalTypedFPCases()
	var assembly, declarations strings.Builder
	for index, row := range rows {
		_, _, source := fixedLocalTypedFPFixture(t, row.typ, "CMPQ AX,AX\n"+row.operation)
		name := fmt.Sprintf("Value%d", index)
		assembly.WriteString(strings.Replace(source, "·Value", "·"+name, 1))
		fmt.Fprintf(&declarations, "func %s(x %s) uint64\n", name, row.typ)
	}
	fixedLocalCompleteVectorObjects(t, assembly.String(), declarations.String(), len(rows))
}
