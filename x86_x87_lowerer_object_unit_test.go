package plan9asm

import (
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
	return x86ZeroArgumentLowererObjectUnit(t, original, arch, triple, "X87LowererObjectUnit",
		func(consumer *amd64Ctx, instruction Instr) (bool, bool, error) {
			return consumer.lowerX87(instruction.Op, instruction)
		})
}

func x86ZeroArgumentLowererObjectUnit(t *testing.T, original *File, arch, triple, name string,
	lower func(*amd64Ctx, Instr) (bool, bool, error)) string {
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
	consumer.x87Mode = X87Software
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
			if !known || err != nil {
				t.Fatalf("complete original instruction %d was not emitted: %s: %v", ordinal, instruction.Raw, err)
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
	return ir.String()
}
