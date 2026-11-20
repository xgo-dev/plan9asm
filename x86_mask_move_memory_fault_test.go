package plan9asm

import (
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

// Use the existing directly-owned process observer: no C signal handler, fork
// driver or new fault framework. A failed access is never followed by a C-side
// dereference which could disguise an optimized-away translated instruction.
func TestX86MaskMoveAllMemoryWidthsDeadPortableFaults(t *testing.T) {
	execution := x86ScalarCountHostExecution(t)
	arch, move, word, original := "amd64", "MOVQ", 8, "x86_64-unknown-linux-gnu"
	if strconv.IntSize == 32 {
		arch, move, word, original = "386", "MOVL", 4, "i386-unknown-linux-gnu"
	}
	var source, declarations, callbacks, cases strings.Builder
	var kernels []struct {
		name  string
		bits  int
		store bool
	}
	for _, row := range x86ResultMaskMoveWidthOracle {
		for _, store := range []bool{false, true} {
			name, body, arguments := fmt.Sprint("KMemoryDeadLoad", row.bits), row.op+" (AX),K0\nKXORQ K0,K0,K0\n", ""
			frame := word
			if store {
				name, frame, arguments = fmt.Sprint("KMemoryStore", row.bits), word+8, ",value uint64"
				body = fmt.Sprintf("KMOVQ value+%d(FP),K0\n%s K0,(AX)\n", word, row.op)
			}
			fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n%s p+0(FP),AX\n%sRET\n", name, frame, move, body)
			fmt.Fprintf(&declarations, "func %s(p *uint%d%s)\n", name, row.bits, arguments)
			argument, storeFlag := "", 0
			if store {
				argument, storeFlag = ",UINT64_C(0x8877665544332211)", 1
			}
			fmt.Fprintf(&callbacks, "extern void %s(uint%d_t*%s);\n", name, row.bits, strings.ReplaceAll(arguments, "value uint64", "uint64_t"))
			fmt.Fprintf(&callbacks, `static int run%s(const uint8_t *p) {
    int full=(uintptr_t)p>(uintptr_t)guard && (uintptr_t)p<=(uintptr_t)(guard+page)-%d;
    %s((uint%d_t*)p%s);
    if(full) {
        for(size_t i=0;i<page;i++) {
            uint8_t expected=(uint8_t)(i*13+17);
            if(%d && (uintptr_t)(guard+i)>=(uintptr_t)p && (uintptr_t)(guard+i)<(uintptr_t)p+%d)
                expected=(uint8_t)(UINT64_C(0x8877665544332211)>>(8*((uintptr_t)(guard+i)-(uintptr_t)p)));
            if(guard[i]!=expected) return 91;
        }
    }
    return 0;
}
`, name, row.bits/8, name, row.bits, argument, storeFlag, row.bits/8)
			fmt.Fprintf(&cases, "{run%s,%d,%d},\n", name, row.bits/8, row.bits/8-1)
			kernels = append(kernels, struct {
				name  string
				bits  int
				store bool
			}{name, row.bits, store})
		}
	}
	if len(kernels) != 8 {
		t.Fatal("incomplete four-width memory load/store fault directory", len(kernels))
	}
	x86LEAActualTargetGoObject(t, arch, original, source.String())
	driver := x86MemoryFaultDriver(callbacks.String(), cases.String())
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), arch, execution.triple, api)
			if err != nil {
				t.Fatal("bounded original KMOV source rejected before execution", err)
			}
			for _, pipeline := range []struct {
				name, level string
				optimize    bool
			}{
				{"default-O0", "-O0", false}, {"default-O2", "-O2", false}, {"opt-O2", "-O2", true},
			} {
				t.Run(pipeline.name, func(t *testing.T) {
					text := ir
					if pipeline.optimize {
						text = x86DwordProductIROptimize(t, text)
					}
					context := llvm.NewContext()
					defer context.Dispose()
					module, err := parseIRModuleInContext(context, text)
					if !module.IsNil() {
						defer module.Dispose()
					}
					if err != nil {
						t.Fatal(err)
					}
					for _, row := range kernels {
						function := module.NamedFunction(row.name)
						parameters := 1
						if row.store {
							parameters = 2
						}
						if function.IsNil() || function.FirstBasicBlock().IsNil() || function.ParamsCount() != parameters ||
							function.Param(0).Type().TypeKind() != llvm.PointerTypeKind || function.GlobalValueType().ReturnType().TypeKind() != llvm.VoidTypeKind {
							t.Fatal("actual pointer/void C ABI differs from bounded source", row.name)
						}
						if row.store && (function.Param(1).Type().TypeKind() != llvm.IntegerTypeKind || function.Param(1).Type().IntTypeWidth() != 64) {
							t.Fatal("actual store input is not the declared uint64", row.name)
						}
						accesses := 0
						for block := function.FirstBasicBlock(); !block.IsNil(); block = llvm.NextBasicBlock(block) {
							for instruction := block.FirstInstruction(); !instruction.IsNil(); instruction = llvm.NextInstruction(instruction) {
								opcode := instruction.InstructionOpcode()
								if (opcode != llvm.Load && opcode != llvm.Store) || !instruction.IsVolatile() {
									continue
								}
								typ := instruction.Type()
								if opcode == llvm.Store {
									typ = instruction.Operand(0).Type()
								}
								if (opcode == llvm.Store) != row.store || typ.TypeKind() != llvm.IntegerTypeKind || typ.IntTypeWidth() != row.bits || instruction.Alignment() != 1 {
									t.Fatal("function lost its exact memory width/direction/alignment", row.name, instruction.String())
								}
								accesses++
							}
						}
						if accesses != 1 {
							t.Fatal("dead native access was removed or duplicated", row.name, accesses)
						}
					}
					executable := execution.compileLLVM(t, "kmov-memory-width-faults", text, driver, pipeline.level)
					x86CheckMemoryFaultMatrix(t, execution, executable, len(kernels))
				})
			}
		})
	}
	t.Log("actual-host translated NULL/partial/full-page faults and complete-page canaries; byte-access reference, not original native KMOV/AVX512 execution")
}
