//go:build go1.27

package plan9asm

import (
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func TestGoX86SDKCallerAddressOriginalCompleteMaps(t *testing.T) {
	for _, target := range []string{"linux/amd64", "darwin/amd64", "windows/amd64"} {
		t.Run(target, func(t *testing.T) { goX86SDKCallerAddressOriginalCompleteMaps(t, target) })
	}
}

func goX86SDKCallerAddressOriginalCompleteMaps(t *testing.T, target string) {
	source, err := numericalSDKMapsReadCapture(t, target, "memhash_amd64.s")
	if err != nil {
		t.Fatal(err)
	}
	ctx := source.sdk.originalContext
	minimum, err := CaptureGoX86SDKLiteralAlignment(ctx, source.literals.owner)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { minimum.Close() })
	pkg, file, options := numericalSDKLiteralPackage(t, source.literals.source, source.request.AssemblyFile)
	bound, err := source.BindNumericalReadsWithLiteralAlignment(ctx, pkg, file, options, minimum)
	if err != nil {
		t.Fatal(err)
	}
	frozen, frozenOptions, err := freezeNumericalReadInputs(file, bound)
	if err != nil || len(frozen.Funcs) != len(file.Funcs) || len(frozen.Data) != len(file.Data) || len(frozen.Globl) != len(file.Globl) {
		t.Fatal("complete original source inventory differs", err)
	}
	for _, fn := range frozen.Funcs {
		name := frozenOptions.ResolveSym(fn.Sym)
		if name != pkg.Path+".memHashAES" {
			continue
		}
		sig := frozenOptions.Sigs[name]
		t.Logf("actual original entry %q arguments=%+v frame=%+v", fn.Sym, sig.Args, sig.Frame)
		before := [16]bool{true}
		for ordinal, ins := range fn.Instrs {
			if ins.Op == "TESTW" {
				break
			}
			after := x86ResultCallerAddressesAfter(ins, before, nil, "amd64")
			if before[0] && !after[0] {
				t.Fatalf("actual GP-unwritten entry prefix lost caller AX at ordinal %d: %s", ordinal, ins.Raw)
			}
			before = after
		}
	}
	for _, api := range []string{"text", "context", "go-module"} {
		t.Run(api, func(t *testing.T) {
			ir := numericalFamilyTranslate(t, api, pkg, file, bound)
			if strings.Count(ir, "define ") != len(file.Funcs) || !strings.Contains(ir, "external global [128 x i8]") || strings.Contains(ir, "constant [128") {
				t.Fatal("complete original functions or mutable runtime AES global lost")
			}
			for _, read := range source.reads {
				if read.original.Op != "PXOR" {
					t.Fatal("actual selected SDK mutable read family changed", read.original.Op)
				}
			}
			if strings.Count(ir, "pxor ($2), $0") != len(source.reads) {
				t.Fatal("genuine original mutable AES/native-read inventory differs", len(source.reads))
			}
			func() {
				context := llvm.NewContext()
				defer context.Dispose()
				module, err := parseIRModuleInContext(context, ir)
				if !module.IsNil() {
					defer module.Dispose()
				}
				if err != nil {
					t.Fatal(err)
				}
				for _, global := range file.Globl {
					definition := module.NamedGlobal(bound.ResolveSym(global.Sym))
					floor := bound.NumericalReads.literalMinimum.Minima[global.Sym]
					if definition.IsNil() || definition.IsDeclaration() || !definition.IsGlobalConstant() || floor == 0 ||
						definition.Alignment() != int(goAssemblyDataAlignment(ArchAMD64, global.Size)) || definition.Alignment() < int(floor) {
						t.Fatal("emitted original literal definition differs from authenticated minimum/Go size rule", global.Sym, floor)
					}
				}
			}()
			numericalLLVM22Axes(t, ir, options.TargetTriple, nil)
		})
	}
	t.Log("complete original two TEXT/all DATA, exact mutable external AES/global join, authenticated minimum vs actual emitted alignment; logical objects only, not SDK-native caller/execution or frontend benchmark completion")
}
