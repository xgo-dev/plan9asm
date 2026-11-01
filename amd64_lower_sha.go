package plan9asm

import (
	"fmt"
	"strings"
)

func (c *amd64Ctx) lowerSHA(op Op, ins Instr) (bool, bool, error) {
	f, known, err := x86SHAProperties(op, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	if c.fixedLocal == nil && len(c.fpResults) != 0 {
		if err := c.scalarFPResultInitialized(); err != nil {
			return true, false, err
		}
	}
	state, err := c.loadPackedCompareLanes(ins.Args[f.destination], 16, 32, false)
	if err != nil {
		return true, false, err
	}
	args := "<4 x i32> " + state
	implicit := ""
	if f.encoding == 0x38cb {
		implicit, err = c.loadPackedCompareLanes(ins.Args[0], 16, 32, false)
		if err != nil {
			return true, false, err
		}
	}
	call, result := c.newTmp(), c.newTmp()
	name := strings.ToLower(string(f.op))
	if f.memory >= 0 {
		source := f.sourceOperand
		if source.Kind == OpFP || !x86ScalarFloatIntegerNativeTarget(c.goarch, c.targetTriple) ||
			source.Kind == OpMem && !x86OrdinaryNativeMemoryOperand(source, c.goarch) &&
				!x86CallerMemoryCertified(ins, f.source) && !c.fixedLocalMemoryCertified(ins, f.source) {
			return true, false, fmt.Errorf("%w: SHA m128 needs original native storage and x86 target", ErrProbeNeedsContext)
		}
		pointer, pointerType, _, err := c.packedVectorMemoryPointer(source)
		if err != nil {
			return true, false, err
		}
		segment := ""
		if pointerType == "ptr addrspace(256)" {
			segment = "%gs:"
		} else if pointerType == "ptr addrspace(257)" {
			segment = "%fs:"
		}
		if f.encoding == 0x3acc {
			name += fmt.Sprintf(" $$%d,", f.immediate)
		}
		assembly, constraints := name+" "+segment+"($2), $0", "=x,0,r"
		args += fmt.Sprintf(", %s %s", pointerType, pointer)
		if implicit != "" {
			constraints += ",{xmm0}"
			args += ", <4 x i32> " + implicit
		}
		// The actual Type 4 opcode retains m128 extent, alignment and faults,
		// even when numerical dependencies or later dead code use fewer bytes.
		fmt.Fprintf(c.b, "  %%%s = call <4 x i32> asm sideeffect %q, %q(%s)\n", call, assembly, constraints+",~{memory}", args)
	} else {
		source, err := c.loadPackedCompareLanes(f.sourceOperand, 16, 32, false)
		if err != nil {
			return true, false, err
		}
		args += ", <4 x i32> " + source
		if implicit != "" {
			args += ", <4 x i32> " + implicit
		} else if f.encoding == 0x3acc {
			args += fmt.Sprintf(", i8 %d", f.immediate)
		}
		fmt.Fprintf(c.b, "  %%%s = call <4 x i32> @llvm.x86.%s(%s)\n", call, name, args)
	}
	fmt.Fprintf(c.b, "  %%%s = bitcast <4 x i32> %%%s to <16 x i8>\n", result, call)
	return true, false, c.storeLegacyPackedLogical(ins.Args[f.destination], "%"+result)
}

func emitX86SHADeclarations(b *strings.Builder, file *File) {
	seen := make(map[Op]bool)
	for _, fn := range file.Funcs {
		for _, ins := range fn.Instrs {
			op := Op(strings.ToUpper(string(ins.Op)))
			encoding, known := x86SHAEncodings[op]
			if !known || seen[op] {
				continue
			}
			seen[op] = true
			args := "<4 x i32>, <4 x i32>"
			if encoding == 0x38cb {
				args += ", <4 x i32>"
			} else if encoding == 0x3acc {
				args += ", i8 immarg"
			}
			fmt.Fprintf(b, "declare <4 x i32> @llvm.x86.%s(%s)\n", strings.ToLower(string(op)), args)
		}
	}
}
