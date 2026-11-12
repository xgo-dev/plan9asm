package plan9asm

import (
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

// Retain every original destination-form body. Only vectorResult has actual
// typed/initialized input and output; the remaining no-argument bodies are
// explicitly emitter-only objects, never public translations or executions.
func x86CompileOnlyDestinationEmitterModule(t *testing.T, original *File, options Options) string {
	t.Helper()
	context := llvm.NewContext()
	defer context.Dispose()
	module := context.NewModule("destination-emitter-observations")
	defer module.Dispose()
	for _, function := range original.Funcs {
		file := &File{Arch: original.Arch, Funcs: []Func{function}}
		var ir string
		if function.ArgSize != 0 {
			var err error
			ir, err = Translate(file, Options{Goarch: options.Goarch, TargetTriple: options.TargetTriple,
				Sigs: map[string]FuncSig{function.Sym: options.Sigs[function.Sym]}})
			if err != nil {
				t.Fatal("independent typed destination failed", err)
			}
		} else {
			ir = x86ZeroArgumentLowererObjectUnit(t, file, options.Goarch, options.TargetTriple, function.Sym,
				func(consumer *amd64Ctx, instruction Instr) (bool, bool, error) {
					if known, terminated, err := consumer.lowerVectorScalarIntegerMove(instruction.Op, instruction); known {
						return known, terminated, err
					}
					if known, terminated, err := consumer.lowerMov(instruction.Op, instruction); known {
						return known, terminated, err
					}
					if known, terminated, err := consumer.lowerVec(instruction.Op, instruction); known {
						return known, terminated, err
					}
					return consumer.lowerX87(instruction.Op, instruction)
				})
		}
		part, err := parseIRModuleInContext(context, ir)
		if err != nil {
			if !part.IsNil() {
				part.Dispose()
			}
			t.Fatal("complete original destination body produced invalid IR", err)
		}
		// LLVMLinkModules2 consumes part on both success and failure.
		if err := llvm.LinkModules(module, part); err != nil {
			t.Fatal(err)
		}
	}
	if err := llvm.VerifyModule(module, llvm.ReturnStatusAction); err != nil {
		t.Fatal(err)
	}
	return module.String()
}

func check386DestinationFormsIR(t *testing.T, ir string) {
	t.Helper()
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	module, err := parseIRModuleInContext(ctx, ir)
	if !module.IsNil() {
		defer module.Dispose()
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := verify386DestinationStores(module); err != nil {
		t.Fatalf("386 destination-store contract: %v\n%s", err, ir)
	}

	// Valid LLVM mutations must fail the semantic checker, rather than failing
	// parsing or benefiting from an unrelated store elsewhere in the module.
	native := destination386Store(module, "vectorMemory", false, -1).String()
	double := destination386Store(module, "x87DoubleSymbol", false, -1).String()
	word := destination386Store(module, "x87ControlSymbol", false, -1).String()
	integer := destination386Store(module, "x87IntegerSymbol", false, -1).String()
	byte0 := destination386Store(module, "vectorResult", true, 0).String()
	byte3 := destination386Store(module, "vectorResult", true, 3).Operand(1).String()
	mutations := []struct{ name, from, to string }{
		{"native-volatility", native, strings.Replace(native, "store volatile", "store", 1)},
		{"native-width", native, "store volatile i64 1" + native[strings.IndexByte(native, ','):]},
		{"symbol-identity", "ptr @\"\\C2\\B7vectorSink\", align 1", "ptr @\"\\C2\\B7doubleSink\", align 1"},
		{"x87-double-volatility", double, strings.Replace(double, "store ", "store volatile ", 1)},
		{"x87-word-volatility", word, strings.Replace(word, "store ", "store volatile ", 1)},
		{"x87-integer-volatility", integer, strings.Replace(integer, "store ", "store volatile ", 1)},
		{"FP-byte-volatility", byte0, strings.Replace(byte0, "store ", "store volatile ", 1)},
		{"FP-byte-offset", byte3, strings.Replace(byte3, "i64 3", "i64 2", 1)},
		{"FP-byte-missing", byte0, "; removed FP byte"},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			if strings.Count(ir, mutation.from) != 1 {
				t.Fatal("mutation does not bind one exact original instruction", mutation.from)
			}
			changed := strings.Replace(ir, mutation.from, mutation.to, 1)
			candidate, err := parseIRModuleInContext(ctx, changed)
			if !candidate.IsNil() {
				defer candidate.Dispose()
			}
			if err != nil {
				t.Fatal("mutation is not valid LLVM IR", err)
			}
			if err := llvm.VerifyModule(candidate, llvm.ReturnStatusAction); err != nil {
				t.Fatal("mutation is not a valid LLVM module", err)
			}
			if err := verify386DestinationStores(candidate); err == nil {
				t.Fatal("destination-store mutation escaped its role/width/effect check")
			}
		})
	}
}

func destination386Store(module llvm.Module, name string, frame bool, offset int) llvm.Value {
	function := module.NamedFunction(name)
	for block := function.FirstBasicBlock(); !block.IsNil(); block = llvm.NextBasicBlock(block) {
		for instruction := block.FirstInstruction(); !instruction.IsNil(); instruction = llvm.NextInstruction(instruction) {
			if instruction.IsAStoreInst().IsNil() {
				continue
			}
			pointer := instruction.Operand(1)
			if !frame && !x86GPSIMDStoreTargetsBackingAlloca(pointer) {
				return instruction
			}
			if frame && instruction.Operand(0).Type().TypeKind() == llvm.IntegerTypeKind &&
				instruction.Operand(0).Type().IntTypeWidth() == 8 && destination386FrameOffset(pointer, offset) {
				return instruction
			}
		}
	}
	return llvm.Value{}
}

func verify386DestinationStores(module llvm.Module) error {
	for _, want := range []struct {
		name     string
		kind     llvm.TypeKind
		bits     int
		volatile bool
		symbol   string
	}{
		{"vectorMemory", llvm.IntegerTypeKind, 32, true, ""},
		{"vectorSymbol", llvm.IntegerTypeKind, 32, true, "vectorSink"},
		// These x87 destinations retain their ordinary stores. The SP forms
		// are compile-only virtual-stack fixtures, not native-backing grants.
		{"x87DoubleMemory", llvm.DoubleTypeKind, 0, false, ""},
		{"x87DoubleSymbol", llvm.DoubleTypeKind, 0, false, "doubleSink"},
		{"x87ControlSymbol", llvm.IntegerTypeKind, 16, false, "controlSink"},
		{"x87IntegerMemory", llvm.IntegerTypeKind, 64, false, ""},
		{"x87IntegerSymbol", llvm.IntegerTypeKind, 64, false, "integerSink"},
	} {
		function := module.NamedFunction(want.name)
		if function.IsNil() {
			return fmt.Errorf("missing function %s", want.name)
		}
		stores := 0
		for block := function.FirstBasicBlock(); !block.IsNil(); block = llvm.NextBasicBlock(block) {
			for instruction := block.FirstInstruction(); !instruction.IsNil(); instruction = llvm.NextInstruction(instruction) {
				if instruction.IsAStoreInst().IsNil() || x86GPSIMDStoreTargetsBackingAlloca(instruction.Operand(1)) {
					continue // Do not let register-bank initialization satisfy a destination check.
				}
				stores++
				typ, pointer := instruction.Operand(0).Type(), instruction.Operand(1)
				if typ.TypeKind() != want.kind || (want.kind == llvm.IntegerTypeKind && typ.IntTypeWidth() != want.bits) ||
					instruction.IsVolatile() != want.volatile || instruction.Alignment() != 1 {
					return fmt.Errorf("%s incorrect destination type/width/volatility/alignment: %s", want.name, instruction.String())
				}
				if want.symbol != "" {
					if pointer.IsAGlobalVariable().IsNil() || pointer.Name() != "·"+want.symbol {
						return fmt.Errorf("%s lost exact SB destination: %s", want.name, instruction.String())
					}
				} else if pointer.IsAIntToPtrInst().IsNil() {
					return fmt.Errorf("%s lost memory destination: %s", want.name, instruction.String())
				}
			}
		}
		if stores != 1 {
			return fmt.Errorf("%s destination stores=%d, want one", want.name, stores)
		}
	}

	function := module.NamedFunction("vectorResult")
	if function.IsNil() {
		return fmt.Errorf("missing vectorResult")
	}
	bytes, initialization, returns := [4]bool{}, 0, 0
	for block := function.FirstBasicBlock(); !block.IsNil(); block = llvm.NextBasicBlock(block) {
		for instruction := block.FirstInstruction(); !instruction.IsNil(); instruction = llvm.NextInstruction(instruction) {
			if !instruction.IsAReturnInst().IsNil() {
				returns++
				if instruction.OperandsCount() != 1 || instruction.Operand(0).Type().TypeKind() != llvm.IntegerTypeKind ||
					instruction.Operand(0).Type().IntTypeWidth() != 32 || instruction.Operand(0).IsALoadInst().IsNil() ||
					!destination386FrameOffset(instruction.Operand(0).Operand(0), 0) {
					return fmt.Errorf("vectorResult lost its i32 FP return load")
				}
			}
			if instruction.IsAStoreInst().IsNil() {
				continue
			}
			pointer := instruction.Operand(1)
			if !x86GPSIMDStoreTargetsBackingAlloca(pointer) {
				return fmt.Errorf("vectorResult FP write escaped backing: %s", instruction.String())
			}
			if pointer.IsAGetElementPtrInst().IsNil() || pointer.Operand(0).Name() != "classic_frame" {
				continue
			}
			typ := instruction.Operand(0).Type()
			if typ.TypeKind() != llvm.IntegerTypeKind || instruction.IsVolatile() || instruction.Alignment() != 1 {
				return fmt.Errorf("vectorResult FP store role changed: %s", instruction.String())
			}
			if typ.IntTypeWidth() == 32 && !instruction.Operand(0).IsAConstantInt().IsNil() && instruction.Operand(0).ZExtValue() == 0 && destination386FrameOffset(pointer, 0) {
				initialization++
				continue
			}
			matched := false
			for offset := range bytes {
				if typ.IntTypeWidth() == 8 && destination386FrameOffset(pointer, offset) && !bytes[offset] {
					bytes[offset], matched = true, true
					break
				}
			}
			if !matched {
				return fmt.Errorf("vectorResult FP byte store widened/duplicated/moved: %s", instruction.String())
			}
		}
	}
	if bytes != [4]bool{true, true, true, true} || initialization != 1 || returns != 1 {
		return fmt.Errorf("vectorResult incomplete FP bytes/init/return: %v/%d/%d", bytes, initialization, returns)
	}
	return nil
}

func destination386FrameOffset(pointer llvm.Value, offset int) bool {
	return !pointer.IsAGetElementPtrInst().IsNil() && pointer.OperandsCount() == 3 &&
		!pointer.Operand(0).IsAAllocaInst().IsNil() && pointer.Operand(0).Name() == "classic_frame" &&
		!pointer.Operand(1).IsAConstantInt().IsNil() && pointer.Operand(1).SExtValue() == 0 &&
		!pointer.Operand(2).IsAConstantInt().IsNil() && pointer.Operand(2).SExtValue() == int64(offset)
}
