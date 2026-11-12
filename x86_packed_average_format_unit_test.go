package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

// Object-only instruction units retain every original format row, including
// MMX and unbound native operands. These are not public translations or runs.
// Actual typed entry arguments still describe logical FP byte layout only.
func x86AverageFormatObjectUnit(t *testing.T, file *File, signatures map[string]FuncSig, arch, triple string) string {
	t.Helper()
	return x86InstructionFormatObjectUnit(t, file, signatures, arch, triple, 0, func(c *amd64Ctx, ins Instr) (bool, bool, error) {
		return c.lowerPackedUnsignedAverage(ins.Op, ins)
	})
}

func x86WordMultiplyFormatObjectUnit(t *testing.T, file *File, signatures map[string]FuncSig, arch, triple string, frame int64) string {
	t.Helper()
	return x86InstructionFormatObjectUnit(t, file, signatures, arch, triple, frame, func(c *amd64Ctx, ins Instr) (bool, bool, error) {
		return c.lowerPackedWordMultiply(ins.Op, ins)
	})
}

func x86InstructionFormatObjectUnit(t *testing.T, file *File, signatures map[string]FuncSig, arch, triple string,
	frame int64, lower func(*amd64Ctx, Instr) (bool, bool, error)) string {
	t.Helper()
	return x86InstructionFormatObjectUnits(t, file, signatures, arch, triple, frame, false, lower)
}

// Each visible function owns exactly one original format row. This permits a
// terminal opcode without allowing it to hide later rows in an unreachable
// block. The ordinary multi-row format helper retains its stricter contract.
func x86SingleInstructionFormatObjectUnits(t *testing.T, file *File, signatures map[string]FuncSig, arch, triple string,
	lower func(*amd64Ctx, Instr) (bool, bool, error)) string {
	t.Helper()
	for _, function := range file.Funcs {
		if len(function.Instrs) != 3 || function.Instrs[0].Op != OpTEXT || !x86InstructionFormatTerminal(function.Instrs[2]) {
			t.Fatal("isolated format function must retain exactly TEXT, one row and its return/fault")
		}
	}
	return x86InstructionFormatObjectUnits(t, file, signatures, arch, triple, 0, true, lower)
}

func x86InstructionFormatTerminal(instruction Instr) bool {
	return len(instruction.Args) == 0 &&
		(instruction.Op == OpRET || instruction.Op == "UD2" || instruction.Op == "UNDEF")
}

func x86InstructionFormatObjectUnits(t *testing.T, file *File, signatures map[string]FuncSig, arch, triple string,
	frame int64, isolated bool, lower func(*amd64Ctx, Instr) (bool, bool, error)) string {
	t.Helper()
	resolve := func(name string) string { return strings.TrimPrefix(name, "·") }
	var ir strings.Builder
	fmt.Fprintf(&ir, "target triple = %q\n", triple)
	emitAMD64Prelude(&ir, arch, file)
	emitExternSBGlobals(&ir, file, resolve, signatures)
	if len(file.Data) != 0 || len(file.Globl) != 0 {
		if err := emitDataGlobalsWithSigs(&ir, file, resolve, signatures, WASMABIDirect); err != nil {
			t.Fatal("original format unit lost its actual DATA/GLOBL storage", err)
		}
	}
	attributes := newFeatureAttrRegistry()
	emitted := 0
	for index, function := range file.Funcs {
		sig, found := signatures[resolve(function.Sym)]
		registerI32 := sig.Ret == I32 && len(sig.Frame.Results) == 0
		scalarResult := (sig.Ret == I8 || sig.Ret == I16 || sig.Ret == I32 || sig.Ret == I64) &&
			len(sig.Frame.Results) == 1 && sig.Frame.Results[0].Type == sig.Ret
		if !found || sig.Ret != Void && !registerI32 && !scalarResult || function.FrameSize != frame || len(function.Instrs) < 2 {
			t.Fatal("instruction format unit lost its complete original return/frame role")
		}
		var arguments []string
		for ordinal, typ := range sig.Args {
			arguments = append(arguments, fmt.Sprintf("%s %%arg%d", typ, ordinal))
		}
		features := attributes.ref(inferFuncTargetFeaturesForGOARCH(file.Arch, arch, function))
		fmt.Fprintf(&ir, "define %s @InstructionFormat%d(%s) %s {\n", sig.Ret, index, strings.Join(arguments, ", "), features)
		consumer := newX86Ctx(&ir, function, sig, resolve, signatures, arch, triple, false)
		if err := consumer.emitEntryAllocas(); err != nil {
			t.Fatal(err)
		}
		terminal := false
		for ordinal, instruction := range function.Instrs {
			switch instruction.Op {
			case OpTEXT:
				if ordinal != 0 {
					t.Fatal("format unit has an additional original TEXT")
				}
			case OpRET:
				if ordinal != len(function.Instrs)-1 || len(instruction.Args) != 0 {
					t.Fatal("format unit lost its original final return")
				}
				if terminal {
					continue
				}
				if registerI32 || scalarResult {
					// Retain the emitter's original AX or declared scalar FP
					// transport. These format objects prove no initialized result.
					if err := consumer.lowerRET(); err != nil {
						t.Fatal(err)
					}
				} else {
					ir.WriteString("  ret void\n")
				}
			case "UNDEF", "UD2":
				if ordinal != len(function.Instrs)-1 || len(instruction.Args) != 0 {
					t.Fatal("format unit lost its original final fault")
				}
				if terminal {
					continue // An isolated architectural-fault row cannot reach its fault footer.
				}
				known, terminated, err := consumer.lowerX86UndefinedTrap(instruction.Op, instruction)
				if !known || !terminated || err != nil {
					t.Fatal("original format-unit fault was not emitted", err)
				}
			default:
				known, terminated, err := lower(consumer, instruction)
				if !known || terminated && (!isolated || ordinal != 1) || err != nil {
					t.Fatal("complete original instruction format row not emitted", instruction.Raw, err)
				}
				terminal = terminated
				emitted++
			}
		}
		ir.WriteString("}\n")
	}
	attributes.emit(&ir)
	if fileUsesX86NonTemporalMetadata(file) {
		ir.WriteString("!0 = !{i32 1}\n\n")
	}
	t.Logf("all %d original instruction format rows emitted as IR; object compilation belongs to the caller, no public or runtime success claim", emitted)
	return ir.String()
}

// The ordinary dispatcher can emit straight-line scalar format units without
// acquiring a public entry, numerical input or native storage certificate.
func x86ScalarFormatObjectUnit(t *testing.T, file *File, signatures map[string]FuncSig, arch, triple string, frame int64) string {
	t.Helper()
	return x86InstructionFormatObjectUnit(t, file, signatures, arch, triple, frame,
		func(c *amd64Ctx, instruction Instr) (bool, bool, error) {
			terminated, err := c.lowerInstr(0, 0, instruction, nil, nil)
			return true, terminated, err
		})
}
