package plan9asm

import (
	"fmt"
	"testing"

	"github.com/xgo-dev/llvm"
)

// LLVM22 does not fold every constant vector.compress call. Check its actual
// typed zero inputs instead of requiring a particular optimization spelling.
// This deliberately small observer is not an instruction interpreter or a
// native-execution receipt. Unknown/poison values and unrelated calls fail.
func x86CompactExpandKnownZero(value llvm.Value, depth int) bool {
	if value.IsNil() || depth == 0 {
		return false
	}
	if !value.IsAConstantInt().IsNil() {
		return value.ZExtValue() == 0
	}
	if !value.IsAConstantAggregateZero().IsNil() {
		return true
	}
	if value.IsAInstruction().IsNil() {
		return false
	}
	switch value.InstructionOpcode() {
	case llvm.BitCast, llvm.Trunc, llvm.ZExt, llvm.SExt:
		return x86CompactExpandKnownZero(value.Operand(0), depth-1)
	case llvm.ExtractElement:
		vector, index := value.Operand(0), value.Operand(1)
		return !index.IsAConstantInt().IsNil() && vector.Type().TypeKind() == llvm.VectorTypeKind &&
			index.ZExtValue() < uint64(vector.Type().VectorSize()) && x86CompactExpandKnownZero(vector, depth-1)
	case llvm.Call:
		function := value.CalledValue()
		if function.IsAFunction().IsNil() || value.OperandsCount() != 4 ||
			function.IntrinsicID() != llvm.LookupIntrinsicID("llvm.experimental.vector.compress") {
			return false
		}
		mask := value.Operand(1)
		if mask.Type().TypeKind() != llvm.VectorTypeKind {
			return false
		}
		if mask.IsAConstantAggregateZero().IsNil() {
			if mask.IsAConstantVector().IsNil() || mask.OperandsCount() != mask.Type().VectorSize() {
				return false
			}
			for index := 0; index < mask.OperandsCount(); index++ {
				if mask.Operand(index).IsAConstantInt().IsNil() {
					return false
				}
			}
		}
		return x86CompactExpandKnownZero(value.Operand(0), depth-1) &&
			x86CompactExpandKnownZero(value.Operand(2), depth-1)
	}
	return false
}

func x86CompactExpandZeroReturn(t *testing.T, ir string) bool {
	t.Helper()
	context := llvm.NewContext()
	defer context.Dispose()
	module, err := parseIRModuleInContext(context, ir)
	if !module.IsNil() {
		defer module.Dispose()
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := llvm.VerifyModule(module, llvm.ReturnStatusAction); err != nil {
		t.Fatal(err)
	}
	options := llvm.NewPassBuilderOptions()
	defer options.Dispose()
	if err := module.RunPasses("default<O2>", llvm.TargetMachine{}, options); err != nil {
		t.Fatal(err)
	}
	function := module.NamedFunction("Value")
	if function.IsNil() {
		t.Fatal("complete compact/expand fixture lost its actual entry")
	}
	returns := 0
	for block := function.FirstBasicBlock(); !block.IsNil(); block = llvm.NextBasicBlock(block) {
		for instruction := block.FirstInstruction(); !instruction.IsNil(); instruction = llvm.NextInstruction(instruction) {
			if instruction.IsAReturnInst().IsNil() {
				continue
			}
			returns++
			if instruction.OperandsCount() != 1 || !x86CompactExpandKnownZero(instruction.Operand(0), 16) {
				return false
			}
		}
	}
	return returns == 1
}

func TestX86CompactZeroObserverRejectsNonzeroPoisonAndForeignCalls(t *testing.T) {
	for _, row := range []struct {
		name, source, mask, passthrough, callee string
		index                                   int
		zero                                    bool
	}{
		{"zero", "zeroinitializer", "<i1 true,i1 true,i1 true,i1 false>", "zeroinitializer", "llvm.experimental.vector.compress.v4i32", 0, true},
		{"nonzero-source", "<i32 1,i32 2,i32 3,i32 4>", "<i1 true,i1 true,i1 true,i1 false>", "zeroinitializer", "llvm.experimental.vector.compress.v4i32", 0, false},
		{"nonzero-tail", "zeroinitializer", "zeroinitializer", "<i32 1,i32 2,i32 3,i32 4>", "llvm.experimental.vector.compress.v4i32", 0, false},
		{"poison-mask", "zeroinitializer", "poison", "zeroinitializer", "llvm.experimental.vector.compress.v4i32", 0, false},
		{"foreign-call", "zeroinitializer", "zeroinitializer", "zeroinitializer", "ordinary_compress", 0, false},
		{"poison-index", "zeroinitializer", "zeroinitializer", "zeroinitializer", "llvm.experimental.vector.compress.v4i32", 4, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			ir := fmt.Sprintf(`declare <4 x i32> @%s(<4 x i32>,<4 x i1>,<4 x i32>)
define i32 @Value() {
  %%packed = call <4 x i32> @%s(<4 x i32> %s,<4 x i1> %s,<4 x i32> %s)
  %%result = extractelement <4 x i32> %%packed,i32 %d
  ret i32 %%result
}
`, row.callee, row.callee, row.source, row.mask, row.passthrough, row.index)
			if got := x86CompactExpandZeroReturn(t, ir); got != row.zero {
				t.Fatal("typed zero observer accepted a nonzero, poison or foreign value", got)
			}
		})
	}
}
