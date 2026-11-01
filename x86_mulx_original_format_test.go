package plan9asm

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"
)

// Keep the complete original raw sources, actual Go/LLVM physical priors and
// public Context results. Direct emitter objects describe formats only: their
// private register slots grant no entry, numerical input or address permission.
func x86MULXOriginalFormatObject(t *testing.T, source, arch, triple string, rows []string) string {
	t.Helper()
	original, err := Parse(ArchAMD64, source)
	if err != nil || len(original.Funcs) != len(rows) {
		t.Fatal("original MULX format directory changed", err)
	}
	mode := 64
	if arch == "386" {
		mode = 32
	}
	for index, function := range original.Funcs {
		if len(function.Instrs) < 3 || function.Instrs[0].Op != OpTEXT ||
			function.Instrs[len(function.Instrs)-1].Op != OpRET {
			t.Fatal("original MULX format lost its TEXT/RET envelope", function.Sym)
		}
		var expected []byte
		for _, instruction := range function.Instrs[1 : len(function.Instrs)-1] {
			chunk, err := x86RawDirectiveBytes(instruction)
			if instruction.Op != "BYTE" || err != nil || len(chunk) != 1 {
				t.Fatal("original MULX format lost a complete BYTE directive", instruction.Raw, err)
			}
			expected = append(expected, chunk...)
		}
		expected = append(expected, 0xc3)
		actual, pcs := x86NumericalBoundaryGoBytes(t, arch, rows[index]+"\nRET")
		if !bytes.Equal(actual, expected) || len(pcs) != 2 || pcs[1] != int64(len(expected)-1) {
			t.Fatalf("original MULX bytes differ from actual Go encoding: %s: %x want %x; PCs=%v", rows[index], actual, expected, pcs)
		}
		x86NumericalVEXGPRequireMC(t, expected, mode, 2)
	}
	file, signatures := x86UnboundVoidFormatSources(t, source, arch, triple)
	// Whole-source rejection must not hide a later absolute-address or other
	// original row that accidentally acquired its own public source permission.
	if len(file.Funcs) > 1 {
		for _, function := range file.Funcs {
			text, valid := x86RawReplaySourceText(function)
			if !valid {
				t.Fatal("original MULX function lost its source", function.Sym)
			}
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, text, "func "+function.Sym+"()", arch, triple, api)
				if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("one original MULX format invented DX, register or address inputs", function.Sym, api, err)
				}
			}
		}
	}
	file, err = normalizeX86RawFile(file, arch)
	if err != nil {
		t.Fatal("original MULX format bytes lost their complete decoder", err)
	}
	ir := x86InstructionFormatObjectUnit(t, file, signatures, arch, triple, 0,
		func(c *amd64Ctx, instruction Instr) (bool, bool, error) {
			form, known, err := x86MULXProperties(instruction.Op, instruction, arch)
			if !known || err != nil {
				return known, false, err
			}
			return true, false, c.emitMULX(form, instruction)
		})
	if strings.Count(ir, "define void @InstructionFormat") != len(rows) {
		t.Fatal("original MULX formats lost an externally visible emitter unit")
	}
	for index, row := range rows {
		body := x86StringMemoryFunction(t, ir, fmt.Sprintf("InstructionFormat%d", index))
		narrow, wide := "i32", "i64"
		if strings.HasPrefix(row, "MULXQ ") {
			narrow, wide = "i64", "i128"
		}
		// SIB address calculation may also multiply, but its scale is a
		// constant, not two independently zero-extended numerical inputs.
		products := regexp.MustCompile(`(?m)^[\t ]*%[^ \t=]+ = mul `+wide+` (%[^ \t,]+), (%[^ \t,]+)$`).FindAllStringSubmatch(body, -1)
		if len(products) != 1 {
			t.Fatal("original MULX format lost its one width-correct unsigned product", row, products)
		}
		for _, operand := range products[0][1:] {
			// Missing private register slots may render as literal zero. That
			// emitter representation is not a NUM fact: every original public
			// source above still requires Context, with no input producers added.
			extension := `(?m)^[\t ]*` + regexp.QuoteMeta(operand) + ` = zext ` + narrow + ` (%[^ \t]+|0) to ` + wide + `$`
			if !regexp.MustCompile(extension).MatchString(body) {
				t.Fatal("original MULX product lost an exact zero-extended source", row, operand)
			}
		}
	}
	return ir
}
