package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

// Preserve complete original Go objects and their missing-input public Context
// before compiling a private format unit. This proves formats, never initialized
// numerical inputs, native entry, memory availability or executed semantics.
func x86UnboundVoidVectorMoveFormatObject(t *testing.T, source, arch, triple string) string {
	t.Helper()
	file, _ := x86UnboundVoidFormatSources(t, source, arch, triple)
	normalized, err := normalizeX86RawFile(file, arch)
	if err != nil {
		t.Fatal("complete original move format lost its decoded bytes", err)
	}
	// Preserve the complete original source above, but compile every format in
	// its own visible function below. A .Z memory store is terminal #UD and
	// must neither swallow later rows nor be replaced by an ordinary store.
	units := *normalized
	units.Funcs = nil
	signatures := make(map[string]FuncSig)
	rows := 0
	for _, function := range normalized.Funcs {
		last := len(function.Instrs) - 1
		if last < 2 || function.Instrs[0].Op != OpTEXT || !x86InstructionFormatTerminal(function.Instrs[last]) {
			t.Fatal("original move formats lost their complete TEXT/return/fault envelope")
		}
		for _, instruction := range function.Instrs[1:last] {
			name := fmt.Sprintf("MoveFormatRow%d", rows)
			unit := function
			unit.Sym = name
			unit.Instrs = []Instr{function.Instrs[0], instruction, function.Instrs[last]}
			units.Funcs = append(units.Funcs, unit)
			signatures[name] = FuncSig{Name: name, Ret: Void}
			rows++
		}
	}
	ir := x86SingleInstructionFormatObjectUnits(t, &units, signatures, arch, triple,
		func(c *amd64Ctx, instruction Instr) (bool, bool, error) {
			if known, terminated, err := c.lowerPackedVectorMove(instruction.Op, instruction); known {
				return known, terminated, err
			}
			return c.lowerVectorScalarMove(instruction.Op, instruction)
		})
	if rows == 0 || strings.Count(ir, "define void @InstructionFormat") != rows {
		t.Fatal("a complete original move row lost its visible backend function", rows)
	}
	t.Logf("%d original move formats each retain an externally visible LLVM object unit; no initialized/native execution claim", rows)
	return ir
}

func x86UnboundVoidRawVectorMoveProbeObject(t *testing.T, file *File, arch, triple string) string {
	t.Helper()
	var source strings.Builder
	for _, function := range file.Funcs {
		text, valid := x86RawReplaySourceText(function)
		if !valid {
			t.Fatal("move format probe lost its complete source")
		}
		source.WriteString(text)
	}
	return x86UnboundVoidVectorMoveFormatObject(t, source.String(), arch, triple)
}
