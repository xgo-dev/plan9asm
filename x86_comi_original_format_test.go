package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// Keep the complete original source, Go object and public missing-input
// Context. Private format objects use the unchanged native COMI lowerer;
// implementation slots are not numerical, pointer or native-entry witnesses.
func x86COMIOriginalFormatObject(t *testing.T, source, arch, triple string) string {
	t.Helper()
	original, signatures := x86UnboundVoidFormatSources(t, source, arch, triple)
	file, err := normalizeX86RawFile(original, arch)
	if err != nil {
		t.Fatal("complete original COMI formats could not normalize", err)
	}
	units := *file
	units.Funcs = nil
	physical, unbound := 0, 0
	for _, function := range file.Funcs {
		last := len(function.Instrs) - 1
		if last < 2 || function.Instrs[0].Op != OpTEXT || !x86InstructionFormatTerminal(function.Instrs[last]) {
			t.Fatal("complete COMI format lost its TEXT/return/fault envelope")
		}
		unit := function
		unit.Instrs = append([]Instr(nil), function.Instrs[:1]...)
		for _, instruction := range function.Instrs[1:last] {
			_, known, err := x86COMIProperties(instruction, arch)
			if !known {
				t.Fatal("original COMI format contains another instruction", instruction.Raw)
			}
			if err != nil {
				if arch != "386" || !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), "physical mode32 high-X") {
					t.Fatal("original COMI format became malformed", err)
				}
				unbound++ // Original Go accepts it; no physical high-X mode32 object is claimed.
				continue
			}
			unit.Instrs = append(unit.Instrs, instruction)
			physical++
		}
		unit.Instrs = append(unit.Instrs, function.Instrs[last])
		units.Funcs = append(units.Funcs, unit)
	}
	if physical == 0 {
		t.Fatal("complete original COMI directory lost every physical format")
	}
	ir := x86InstructionFormatObjectUnit(t, &units, signatures, arch, triple, 0,
		func(c *amd64Ctx, instruction Instr) (bool, bool, error) {
			return c.lowerVectorScalarFlagCompare(instruction.Op, instruction)
		})
	if strings.Count(ir, "~{flags},~{fpsr},~{memory}") != physical {
		t.Fatal("private format lost an actual whole COMI opcode", physical)
	}
	t.Logf("complete original Go/public Context retained; %d physical COMI formats, %d Go-accepted mode32 high-X Context rows; no initialized or native execution claim", physical, unbound)
	return ir
}

func x86COMIOriginalProbeFormatObject(t *testing.T, file *File, arch, triple string) string {
	t.Helper()
	var source strings.Builder
	for _, function := range file.Funcs {
		text, valid := x86RawReplaySourceText(function)
		if !valid {
			t.Fatal("original COMI probe lost its complete raw source")
		}
		source.WriteString(text)
	}
	ir := x86COMIOriginalFormatObject(t, source.String(), arch, triple)
	if !strings.Contains(ir, "ud2") || !strings.Contains(ir, "unreachable") {
		t.Fatal("private original COMI probe lost its actual terminal fault")
	}
	return ir
}

func x86COMICompileOriginalFormatObjects(t *testing.T, llc, triple, name, ir string) {
	t.Helper()
	for index, body := range []string{ir, x86DwordProductIROptimize(t, ir)} {
		compileLLVMToObject(t, llc, triple, fmt.Sprintf("%s-%d.ll", name, index), fmt.Sprintf("%s-%d.o", name, index), body)
	}
}
