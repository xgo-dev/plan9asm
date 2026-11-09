package plan9asm

import (
	"fmt"
	"go/types"
	"strings"
	"testing"
)

var x86X87NativeConstants = []Op{"FLDZ", "FLD1", "FLDPI", "FLDL2E", "FLDL2T", "FLDLG2", "FLDLN2"}

func x86X87NativeConstantProgram(t *testing.T, arch string) (string, string) {
	t.Helper()
	pkg := mustGoPackage(t, "nativeconstant", "package nativeconstant\nfunc Value(cw uint16,input float64) uint16")
	signature, err := DeriveGoFuncABI0Signature("Value", pkg.Types.Scope().Lookup("Value").(*types.Func), arch, types.SizesFor("gc", arch))
	if err != nil {
		t.Fatal(err)
	}
	if len(signature.Frame.Params) != 2 || len(signature.Frame.Results) != 1 || signature.Frame.Results[0].Type != I16 {
		t.Fatal("unexpected actual scalar declaration layout", signature)
	}
	cw, input, result := signature.Frame.Params[0].Offset, signature.Frame.Params[1].Offset, signature.Frame.Results[0].Offset
	var source, declarations strings.Builder
	for _, op := range x86X87NativeConstants {
		name := "Constant" + string(op)
		fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\nFINIT\nFLDCW cw+%d(FP)\nFMOVD input+%d(FP),F0\n%s\nFCOMD F1,F0\nFSTSW AX\nANDW $0x4500,AX\nMOVW AX,ret+%d(FP)\nFMOVDP F0,F0\nFMOVDP F0,F0\nRET\n", name, result+2, cw, input, op, result)
		fmt.Fprintf(&declarations, "func %s(cw uint16,input float64) uint16\n", name)
	}
	return source.String(), declarations.String()
}

func TestX86X87NativeCarrierUsesWholeValues(t *testing.T) {
	// This is a representation guard. Actual native values/RC and numerical
	// execution have independent owners; an alloca alone cannot prove them.
	for _, target := range x86RawReturnTargets {
		source, declaration := x86X87NativeConstantProgram(t, target.arch)
		for _, mode := range []X87Mode{X87Auto, X87Hardware} {
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(fmt.Sprintf("%s/mode%d/%s", target.triple, mode, api), func(t *testing.T) {
					ir, err := x86X87InitializedWordAPI(t, source, declaration, target.arch, target.triple, api, mode)
					if err != nil || ir == "" {
						t.Fatal("complete initialized constant/compare source rejected", err)
					}
					for slot := 0; slot < 8; slot++ {
						allocation := fmt.Sprintf("%%x87_f%d = alloca { i64, i16 }", slot)
						if strings.Count(ir, allocation) != 7 {
							t.Fatalf("all seven constant functions need the same complete binary80 cell %d", slot)
						}
					}
					if strings.Contains(ir, "@llvm.floor.f64") && strings.Contains(ir, "call double @llvm.floor.f64") {
						t.Fatal("native constant source entered the legacy binary64 provider")
					}
					llc := findLLVM22Tool("llc")
					if llc == "" {
						t.Fatal("LLVM22 llc is required")
					}
					for _, level := range []string{"-O0", "-O2"} {
						t.Run(level, func(t *testing.T) {
							x86PackedStringCompileObject(t, llc, target.triple, ir, level)
						})
					}
				})
			}
		}
	}
}

// A private numerical observer, with the same provider and entry scratch as
// public lowering. It exports parts to an explicit output pointer; it grants
// no FMOVX, native-memory or public Go signature permission.
func x86X87NativeConstantBitsIR(t *testing.T, arch, triple string) string {
	t.Helper()
	var ir strings.Builder
	fmt.Fprintf(&ir, "target triple = %q\n", triple)
	for _, op := range x86X87NativeConstants {
		fmt.Fprintf(&ir, "define void @NativeBits%s(ptr %%output, i16 %%cw) {\n", op)
		fn := Func{Instrs: []Instr{{Op: "FLD1"}}}
		ctx := newX86Ctx(&ir, fn, FuncSig{Ret: Void}, func(s string) string { return s }, nil, arch, triple, false)
		ctx.x87Mode = X87Hardware
		if err := ctx.emitEntryAllocas(); err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&ir, "  store i16 %%cw, ptr %s\n", ctx.x87ControlSlot)
		ctx.loadHardwareX87ControlWord()
		value, _, _ := ctx.evaluateX87Native(strings.ToLower(string(op)), nil, 1, 1)
		low, high := ctx.partsX87(value)
		fmt.Fprintf(&ir, "  store i64 %s, ptr %%output, align 1\n", low)
		fmt.Fprintf(&ir, "  %%high = getelementptr i8, ptr %%output, i32 8\n  store i16 %s, ptr %%high, align 1\n", high)
		narrow := ctx.x87NativeToFloat(value, 64)
		fmt.Fprintf(&ir, "  %%narrow = getelementptr i8, ptr %%output, i32 16\n  store double %s, ptr %%narrow, align 1\n  ret void\n}\n", narrow)
	}
	return ir.String()
}

func TestX86X87NativeConstantBitsFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc is required")
	}
	for _, target := range x86RawReturnTargets {
		ir := x86X87NativeConstantBitsIR(t, target.arch, target.triple)
		for _, level := range []string{"-O0", "-O2"} {
			t.Run(target.triple+"/"+level, func(t *testing.T) {
				x86PackedStringCompileObject(t, llc, target.triple, ir, level)
			})
		}
	}
}
