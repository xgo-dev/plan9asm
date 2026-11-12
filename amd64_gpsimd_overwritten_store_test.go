package plan9asm

import (
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

// Two different native writes to the same address must remain observable even
// when no numerical consumer reads the first one. Plan 9 MOVD is the 64-bit
// MOVQ alias; it is not Intel's 32-bit MOVD. Expected widths below are independent
// of the production GP/SIMD transfer grammar and emitter.
func TestX86GPSIMDOverwrittenNativeStoresThreeAPIsFiveTargets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	forms := []struct {
		op   string
		bits int
	}{{"MOVL", 32}, {"MOVQ", 64}, {"MOVD", 64}, {"VMOVD", 32}, {"VMOVQ", 64}}
	for _, target := range []struct{ arch, triple string }{
		{"amd64", "x86_64-apple-darwin"},
		{"amd64", "x86_64-unknown-linux-gnu"},
		{"amd64", "x86_64-pc-windows-msvc"},
		{"386", "i386-unknown-linux-gnu"},
		{"386", "i686-pc-windows-msvc"},
	} {
		t.Run(target.triple, func(t *testing.T) {
			var assembly, declarations strings.Builder
			declarations.WriteString("package stores\n")
			sigs := map[string]FuncSig{}
			pointerBytes, pointerMove := 8, "MOVQ"
			if target.arch == "386" {
				pointerBytes, pointerMove = 4, "MOVL"
			}
			for index, form := range forms {
				for _, memory := range []bool{true, false} {
					name := fmt.Sprintf("Store%d_%t", index, memory)
					destination := fmt.Sprintf("sink%d<>(SB)", index)
					sig := FuncSig{Name: name, Ret: Void}
					frame := 0
					if memory {
						frame, destination = pointerBytes, "(AX)"
						sig.Args = []LLVMType{Ptr}
						sig.Frame = FrameLayout{Params: []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}}}
						fmt.Fprintf(&declarations, "func %s(p *[8]byte)\n", name)
					} else {
						fmt.Fprintf(&declarations, "func %s()\n", name)
						fmt.Fprintf(&assembly, "GLOBL %s,8,$8\n", destination)
					}
					sigs[name] = sig
					fmt.Fprintf(&assembly, "TEXT ·%s(SB),4,$0-%d\n", name, frame)
					if memory {
						fmt.Fprintf(&assembly, "%s p+0(FP),AX\n", pointerMove)
					}
					fmt.Fprintf(&assembly, "PXOR X0,X0\n%s X0,%s\nPCMPEQB X1,X1\n%s X1,%s\nRET\n", form.op, destination, form.op, destination)
				}
			}
			// The original assembler independently establishes each store spelling
			// and its real 386/amd64 operand acceptance before any translation.
			goAssemblerOracleOutput(t, target.arch, assembly.String(), "", true)
			file, err := Parse(ArchAMD64, assembly.String())
			if err != nil {
				t.Fatal(err)
			}
			resolve := func(name string) string { return strings.TrimPrefix(name, "·") }
			options := Options{Goarch: target.arch, TargetTriple: target.triple, ResolveSym: resolve, Sigs: sigs}
			textIR, err := Translate(file, options)
			if err != nil {
				t.Fatal(err)
			}
			ctx := llvm.NewContext()
			defer ctx.Dispose()
			module, err := TranslateModuleInContext(ctx, file, options)
			if !module.IsNil() {
				defer module.Dispose()
			}
			if err != nil {
				t.Fatal(err)
			}
			pkg := mustGoPackage(t, "stores", declarations.String())
			goModule, err := translateGoModuleInContext(ctx, pkg, []byte(assembly.String()), GoModuleOptions{GOARCH: target.arch, TargetTriple: target.triple, ResolveSym: resolve})
			if goModule != nil && !goModule.Module.IsNil() {
				defer goModule.Module.Dispose()
			}
			if err != nil {
				t.Fatal(err)
			}
			for _, api := range []struct{ name, ir string }{{"text", textIR}, {"module", module.String()}, {"go-module", goModule.Module.String()}} {
				t.Run(api.name, func(t *testing.T) {
					for _, optimized := range []bool{false, true} {
						t.Run(fmt.Sprintf("IR_default_O2=%t", optimized), func(t *testing.T) {
							ir := api.ir
							if optimized {
								ir = x86MulDivRoundOptimize(t, ir)
							}
							for index, form := range forms {
								for _, memory := range []bool{true, false} {
									name := fmt.Sprintf("Store%d_%t", index, memory)
									t.Run(form.op+fmt.Sprintf("/OpMem=%t", memory), func(t *testing.T) {
										x86GPSIMDCheckNativeStoreEffects(t, ir, name, form.bits)
									})
								}
							}
							// Object emission is a separate backend-O0 axis, both before
							// and after the explicit LLVM IR default<O2> pass pipeline.
							compileLLVMToObject(t, llc, target.triple, "native-stores.ll", "native-stores.o", ir)
						})
					}
				})
			}
		})
	}
}

func x86GPSIMDCheckNativeStoreEffects(t *testing.T, ir, name string, bits int) {
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
	function := module.NamedFunction(name)
	if function.IsNil() {
		t.Fatal("native store function disappeared", name)
	}
	stores, observable := 0, 0
	for block := function.FirstBasicBlock(); !block.IsNil(); block = llvm.NextBasicBlock(block) {
		for instruction := block.FirstInstruction(); !instruction.IsNil(); instruction = llvm.NextInstruction(instruction) {
			if instruction.IsAStoreInst().IsNil() || x86GPSIMDStoreTargetsBackingAlloca(instruction.Operand(1)) {
				continue // Register banks and synthesized ABI0 frames are not native writes.
			}
			typ := instruction.Operand(0).Type()
			if typ.TypeKind() != llvm.IntegerTypeKind {
				t.Fatal("native scalar write widened to a non-integer type", instruction.String())
			}
			stores++
			if typ.IntTypeWidth() != bits {
				t.Errorf("native store width=%d want=%d: %s", typ.IntTypeWidth(), bits, instruction.String())
			}
			if instruction.IsVolatile() {
				observable++
			}
		}
	}
	t.Logf("native stores=%d observable=%d exact-width=%d", stores, observable, bits)
	if stores != 2 || observable != 2 {
		t.Errorf("overwritten native store effect lost: stores=%d observable=%d want=2/2\n%s", stores, observable, function.String())
	}
}

func x86GPSIMDStoreTargetsBackingAlloca(pointer llvm.Value) bool {
	for depth := 0; depth < 16; depth++ {
		if !pointer.IsAAllocaInst().IsNil() {
			return true
		}
		if pointer.IsAGetElementPtrInst().IsNil() && pointer.IsABitCastInst().IsNil() {
			return false
		}
		pointer = pointer.Operand(0)
	}
	return false
}
