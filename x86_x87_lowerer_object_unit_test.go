package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func x86X87UnboundOriginalAPI(t *testing.T, file *File, options Options, api string) (string, error) {
	t.Helper()
	if api == "text" {
		return Translate(file, options)
	}
	var module llvm.Module
	var err error
	if api == "module" {
		module, err = TranslateModule(file, options)
	} else if api == "owned-module" {
		context := llvm.NewContext()
		defer context.Dispose()
		module, err = TranslateModuleInContext(context, file, options)
	} else {
		t.Fatal("unknown complete-original API", api)
	}
	if !module.IsNil() {
		defer module.Dispose()
		if err == nil {
			return module.String(), nil
		}
	}
	return "", err
}

// This deliberately tests the instruction emitter, not Translate or a source
// permission. Keep every instruction of the complete original zero-argument
// fixture, including its final RET. Unknown entry registers/private zero slots
// are not executable input, pointee backing, or an x87 initialization proof.
// Public APIs must independently reject these original fixtures below.
func x86X87LowererObjectUnit(t *testing.T, original *File, arch, triple string) string {
	t.Helper()
	ir, err := x86X87LowererObjectUnitResult(t, original, arch, triple)
	if err != nil {
		t.Fatal(err)
	}
	return ir
}

func x86X87LowererObjectUnitResult(t *testing.T, original *File, arch, triple string) (string, error) {
	t.Helper()
	return x86ZeroArgumentLowererObjectUnitWithMode(t, original, arch, triple, "X87LowererObjectUnit", X87Hardware,
		func(consumer *amd64Ctx, instruction Instr) (bool, bool, error) {
			return consumer.lowerX87(instruction.Op, instruction)
		})
}

func x86ZeroArgumentLowererObjectUnit(t *testing.T, original *File, arch, triple, name string,
	lower func(*amd64Ctx, Instr) (bool, bool, error)) string {
	t.Helper()
	ir, err := x86ZeroArgumentLowererObjectUnitWithMode(t, original, arch, triple, name, X87Software, lower)
	if err != nil {
		t.Fatal(err)
	}
	return ir
}

func x86ZeroArgumentLowererObjectUnitWithMode(t *testing.T, original *File, arch, triple, name string,
	mode X87Mode, lower func(*amd64Ctx, Instr) (bool, bool, error)) (string, error) {
	t.Helper()
	if original == nil || len(original.Funcs) != 1 || len(original.Data) != 0 || len(original.Globl) != 0 {
		t.Fatal("instruction emitter unit requires one complete original TEXT without DATA")
	}
	file, err := normalizeX86RawFile(original, arch)
	if err != nil || len(file.Funcs) != 1 {
		t.Fatal("complete original raw source did not normalize", err)
	}
	function := file.Funcs[0]
	if function.ArgSize != 0 || function.FrameSize != 0 {
		t.Fatal("emitter unit cannot impersonate a typed or backed source frame")
	}
	var ir strings.Builder
	fmt.Fprintf(&ir, "target triple = %q\n", triple)
	emitAMD64Prelude(&ir, arch, file)
	emitExternSBGlobals(&ir, file, func(symbol string) string { return symbol }, nil)
	attributes := newFeatureAttrRegistry()
	features := attributes.ref(inferFuncTargetFeaturesForGOARCH(file.Arch, arch, function))
	fmt.Fprintf(&ir, "define void %s() %s {\n", llvmGlobal(name), features)
	consumer := newX86Ctx(&ir, function, FuncSig{Name: name, Ret: Void},
		func(name string) string { return name }, nil, arch, triple, false)
	consumer.x87Mode = mode
	if err := consumer.emitEntryAllocas(); err != nil {
		t.Fatal(err)
	}
	text, returns, emitted := 0, 0, 0
	for ordinal, instruction := range function.Instrs {
		switch instruction.Op {
		case OpTEXT:
			text++
			if ordinal != 0 {
				t.Fatal("emitter unit lost its original TEXT order")
			}
		case OpRET:
			returns++
			if ordinal != len(function.Instrs)-1 || len(instruction.Args) != 0 {
				t.Fatal("emitter unit cannot omit a source continuation")
			}
			ir.WriteString("  ret void\n")
		default:
			known, terminated, err := lower(consumer, instruction)
			if err != nil {
				return "", fmt.Errorf("complete original instruction %d was not emitted: %s: %w", ordinal, instruction.Raw, err)
			}
			if !known {
				return "", fmt.Errorf("complete original instruction %d was not recognized: %s", ordinal, instruction.Raw)
			}
			if terminated {
				// The complete format-only source can contain an invalid
				// encoding before later rows. Retain those original rows in
				// explicitly unreachable emitter-unit blocks, not by turning
				// #UD into a returning operation or claiming native execution.
				fmt.Fprintf(&ir, "%s_emitter_only_unreachable:\n", consumer.newTmp())
			}
			emitted++
		}
	}
	if text != 1 || returns != 1 || emitted != len(function.Instrs)-2 {
		t.Fatal("emitter unit did not consume every original instruction")
	}
	ir.WriteString("}\n")
	attributes.emit(&ir)
	t.Logf("emitter-only object source: all %d normalized instructions; no public translation or execution claim", emitted)
	return ir.String(), nil
}

// Original bytes and typed grammar still cover these eight forms. The exact
// native codec currently accepts only the default address space, so this is a
// Context observation and never an LLVM-object completion for FS/GS B/X.
func x86X87EncodedAddressSpaceNeedsContext(t *testing.T, original *File, arch, triple string) {
	t.Helper()
	file, err := normalizeX86RawFile(original, arch)
	if err != nil || len(file.Funcs) != 1 {
		t.Fatal("complete original segment source did not normalize", err)
	}
	count := 0
	for _, instruction := range file.Funcs[0].Instrs {
		form, known, err := x86X87ValueProperties(instruction, arch)
		if known && err != nil {
			t.Fatal("original segment form lost its typed grammar", instruction.Raw, err)
		}
		if known && form.memoryBytes() == 10 {
			count++
		}
	}
	if count != 8 {
		t.Fatal("incomplete original B/X FS/GS grammar inventory", count)
	}
	ir, err := x86X87LowererObjectUnitResult(t, original, arch, triple)
	if ir != "" || !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), "encoded native memory needs its bound default-address-space pointer") {
		t.Fatal("unproved native ten-byte address space acquired an object", err)
	}
}
