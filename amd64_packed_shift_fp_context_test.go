package plan9asm

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func TestX86PackedShiftCompleteFPSpanThreeAPIsFiveObjects(t *testing.T) {
	// Even a fully declared logical ABI0 span comprises independent LLVM
	// allocas. Read every bound byte without using a pointer to just the first
	// alloca, and retain mask-controlled reads. BCST at +4 crosses two slots.
	rows := []struct {
		instruction string
		masked      bool
	}{
		{"VPSRLW a+0(FP),Y1,Y2", false},
		{"VPSRLQ a+0(FP),Z1,Z2", false},
		{"VPSRLVW a+0(FP),Z1,Z2", false},
		{"VPSRLVD.BCST a+4(FP),Z1,Z2", false},
		{"VPSRLVQ.BCST a+4(FP),Z1,Z2", false},
		{"VPSRLD $1,a+0(FP),Z2", false},
		{"VPSRLQ.BCST $1,a+4(FP),Z2", false},
		{"VPSRLDQ $1,a+0(FP),Z2", false},
		{"VPSRLVW.Z a+0(FP),Z1,K1,Z2", true},
		{"VPSRLVD.BCST.Z a+4(FP),Z1,K1,Z2", true},
		{"VPSRLVQ.BCST.Z a+4(FP),Z1,K1,Z2", true},
		{"VPSRLQ.BCST.Z $1,a+4(FP),K1,Z2", true},
	}
	for _, target := range []struct{ arch, triple string }{
		{"amd64", "x86_64-apple-darwin"}, {"amd64", "x86_64-unknown-linux-gnu"}, {"amd64", "x86_64-pc-windows-msvc"},
		{"386", "i386-unknown-linux-gnu"}, {"386", "i686-pc-windows-msvc"},
	} {
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, "shifts.go", "package shifts\nfunc shifts(a,b,c,d,e,f,g,h uint64)\n", 0)
		if err != nil {
			t.Fatal(err)
		}
		sizes := types.SizesFor("gc", target.arch)
		typed, err := (&types.Config{Sizes: sizes}).Check("shifts", fset, []*ast.File{file}, nil)
		if err != nil {
			t.Fatal(err)
		}
		pkg := GoPackage{Path: "shifts", Types: typed, Syntax: []*ast.File{file}}
		sig, err := DeriveGoFuncABI0Signature("shifts", typed.Scope().Lookup("shifts").(*types.Func), target.arch, sizes)
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range rows {
			if row.masked && target.arch == "386" {
				continue // Go's 386 source frontend rejects this explicit mask row.
			}
			source := "TEXT shifts(SB),4,$0-64\n" + row.instruction + "\nRET\n"
			goAssemblerOracleOutput(t, target.arch, source, "", true)
			parsed, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			options := Options{Goarch: target.arch, TargetTriple: target.triple, Sigs: map[string]FuncSig{"shifts": sig}}
			original := parsed
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM22 llc required")
			}
			if row.masked {
				for _, api := range []string{"text", "module", "Go"} {
					if ir, err := x86ScalarFPBitViewPackageAPI(t, source, pkg, target.arch, target.triple, api); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("original logical FP source invented the incoming mask", row.instruction, api, err)
					}
				}
				format := x86InstructionFormatObjectUnit(t, original, options.Sigs, target.arch, target.triple, 0,
					func(c *amd64Ctx, ins Instr) (bool, bool, error) {
						return c.lowerX86PackedShift(ins.Op, ins)
					})
				compileLLVMToObject(t, llc, target.triple, "fp-original-format.ll", "fp-original-format.o", format)
				// The public positive source obtains its mask from an actual
				// typed input. Independent FP slots still have no contiguous
				// backing; the shift must gather precisely its complete span.
				source = strings.Replace(source, "\n"+row.instruction,
					"\nMOVQ a+0(FP),AX\nKMOVQ AX,K1\n"+row.instruction, 1)
				goAssemblerOracleOutput(t, target.arch, source, "", true)
				parsed, err = Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
			}
			ir, err := Translate(parsed, options)
			if err != nil {
				t.Fatalf("%s original FP read %s: Translate=%v", target.triple, row.instruction, err)
			}
			compileLLVMToObject(t, llc, target.triple, "fp-shift.ll", "fp-shift.o", ir)
			context := llvm.NewContext()
			func() {
				defer context.Dispose()
				module, err := TranslateModuleInContext(context, parsed, options)
				if !module.IsNil() {
					defer module.Dispose()
				}
				if err != nil {
					t.Fatalf("%s original FP read %s: Module=%v", target.triple, row.instruction, err)
				}
				compileLLVMToObject(t, llc, target.triple, "fp-module.ll", "fp-module.o", module.String())
				result, err := translateGoModuleInContext(context, pkg, []byte(strings.Replace(source, "shifts(SB)", "·shifts(SB)", 1)),
					GoModuleOptions{GOARCH: target.arch, Sizes: sizes, TargetTriple: target.triple})
				if result != nil && !result.Module.IsNil() {
					defer result.Module.Dispose()
				}
				if err != nil {
					t.Fatalf("%s original FP read %s: GoModule=%v", target.triple, row.instruction, err)
				}
				compileLLVMToObject(t, llc, target.triple, "fp-go-module.ll", "fp-go-module.o", result.Module.String())
			}()
			instruction := original.Funcs[0].Instrs[1]
			ctx, output := newAMD64CtxWithFuncForTest(t, original.Funcs[0], sig, nil)
			if _, _, err := ctx.lowerX86PackedShift(instruction.Op, instruction); err != nil {
				t.Fatalf("%s complete FP span: %v", row.instruction, err)
			}
			if row.masked && !strings.Contains(output.String(), "br i1") {
				t.Fatalf("%s lost conditional FP reads", row.instruction)
			}
		}
	}
}

func TestX86PackedShiftIncompleteFPSpansFailBeforeIR(t *testing.T) {
	for _, instruction := range []string{
		"VPSRLW a+8(FP),Y1,Y2", "VPSRLQ.BCST $1,a+12(FP),Z2",
		"VPSRLVD.BCST.Z a+14(FP),Z1,K1,Z2", "VPSRLDQ $1,a+0(FP),Z2",
		"VPSRLVW.Z a+0(FP),Z1,K1,Z2", "VPSRLQ.BCST $1,a-1(FP),Z2",
	} {
		source := "TEXT shifts(SB),4,$0-16\n" + instruction + "\nRET\n"
		goAssemblerOracleOutput(t, "amd64", source, "", true)
		file, err := Parse(ArchAMD64, source)
		if err != nil {
			t.Fatal(err)
		}
		for _, frame := range []FrameLayout{
			{Params: []FrameSlot{{Offset: 0, Type: I64, Index: 0, Field: -1}, {Offset: 8, Type: I64, Index: 1, Field: -1}}},
			{Params: []FrameSlot{{Offset: 0, Type: I8, Index: 0, Field: -1}, {Offset: 8, Type: I64, Index: 1, Field: -1}}},
		} {
			sig := FuncSig{Ret: Void, Args: []LLVMType{frame.Params[0].Type, frame.Params[1].Type}, Frame: frame}
			ctx, output := newAMD64CtxWithFuncForTest(t, file.Funcs[0], sig, nil)
			before := output.Len()
			ins := file.Funcs[0].Instrs[1]
			if _, _, err := ctx.lowerX86PackedShift(ins.Op, ins); !errors.Is(err, ErrProbeNeedsContext) || before != output.Len() {
				t.Fatalf("%s incomplete/padded FP span emitted IR: %v", instruction, err)
			}
		}
		for _, target := range []struct{ arch, triple string }{
			{"amd64", "x86_64-apple-darwin"}, {"amd64", "x86_64-unknown-linux-gnu"}, {"amd64", "x86_64-pc-windows-msvc"},
			{"386", "i386-unknown-linux-gnu"}, {"386", "i686-pc-windows-msvc"},
		} {
			if target.arch == "386" && strings.Contains(instruction, "K1") {
				continue
			}
			fset := token.NewFileSet()
			declaration, err := parser.ParseFile(fset, "shifts.go", "package shifts\nfunc shifts(a,b uint64)\n", 0)
			if err != nil {
				t.Fatal(err)
			}
			sizes := types.SizesFor("gc", target.arch)
			typed, err := (&types.Config{Sizes: sizes}).Check("shifts", fset, []*ast.File{declaration}, nil)
			if err != nil {
				t.Fatal(err)
			}
			sig, err := DeriveGoFuncABI0Signature("shifts", typed.Scope().Lookup("shifts").(*types.Func), target.arch, sizes)
			if err != nil {
				t.Fatal(err)
			}
			options := Options{Goarch: target.arch, TargetTriple: target.triple, Sigs: map[string]FuncSig{"shifts": sig}}
			if _, err := Translate(file, options); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("%s original unbound FP span %s: Translate=%v", target.triple, instruction, err)
			}
			context := llvm.NewContext()
			func() {
				defer context.Dispose()
				module, err := TranslateModuleInContext(context, file, options)
				if !module.IsNil() {
					defer module.Dispose()
				}
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("%s original unbound FP span %s: Module=%v", target.triple, instruction, err)
				}
				pkg := GoPackage{Path: "shifts", Types: typed, Syntax: []*ast.File{declaration}}
				result, err := translateGoModuleInContext(context, pkg, []byte(strings.Replace(source, "shifts(SB)", "·shifts(SB)", 1)),
					GoModuleOptions{GOARCH: target.arch, Sizes: sizes, TargetTriple: target.triple})
				if result != nil && !result.Module.IsNil() {
					defer result.Module.Dispose()
				}
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("%s original unbound FP span %s: GoModule=%v", target.triple, instruction, err)
				}
			}()
		}
	}
}
