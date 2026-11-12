package plan9asm

import (
	"errors"
	"go/types"
	"strings"
	"testing"
)

// These designated ordinary ABI0 controls choose the emitter's existing vector
// scratch values. They do not prove arbitrary physical entry registers, caller
// memory, or a reusable source/storage permission.
func x86VectorScratchCodegenControl(t *testing.T, source, declaration, arch, triple, ir string, codegenErr error) {
	t.Helper()
	pkg := mustGoPackage(t, "scratch", "package scratch\n"+declaration)
	x86VectorScratchCodegenPackageControl(t, source, pkg, arch, triple, ir, codegenErr)
}

func x86VectorScratchCodegenPackageControl(t *testing.T, source string, pkg GoPackage, arch, triple, ir string, codegenErr error) {
	t.Helper()
	if arch != "amd64" || codegenErr != nil || ir == "" {
		t.Fatal("ordinary AMD64 scratch code generation failed", arch, codegenErr)
	}
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	resolve := testResolveSym(pkg.Path)
	signatures, err := goSigsForAsmFile(pkg, file, resolve, arch, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	storage, err := bindGoReadOnlyStorage(pkg, file, types.SizesFor("gc", arch), arch, resolve)
	if err != nil {
		t.Fatal(err)
	}
	values := x86LoweredStaticAddressValues(file, resolve, signatures, arch)
	usedScratch := false
	for _, fn := range file.Funcs {
		sig := signatures[resolve(fn.Sym)]
		if len(sig.Frame.Params) == 0 && len(sig.Frame.Results) == 0 || !x86OrdinaryScalarCodegenSource(fn, sig, arch) {
			t.Fatal("scratch control lacks a typed logical frame or acquired a private entry role")
		}
		for _, query := range []func(Func, FuncSig, string) error{
			CheckX86ABI0ResultInitialization, checkX86ScalarFPResultInitialization,
		} {
			if err := query(fn, sig, arch); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("ordinary scratch choice escaped into a strict source query", err)
			}
		}
		var output strings.Builder
		consumer := newX86Ctx(&output, fn, sig, resolve, signatures, arch, triple, false)
		// Reconstruct only the ordinary immutable inputs used by Translate.
		// This grants no SDK, raw, caller-memory or fixed-frame owner.
		consumer.goReadOnlyStorage = storage
		consumer.fpStaticAddressValues = values
		consumer.fpScalarData = x86LoweredScalarDataReads(file, resolve, signatures, arch)
		consumer.fpShiftLiterals = x86LoweredShiftLiterals(file, resolve, values, arch)
		if err := consumer.scalarFPResultInitialized(); err != nil {
			t.Fatal("lowering-owned scratch plan lost its paired check", err)
		}
		cached := consumer.fpScalarCheckErr
		if !consumer.fpScalarChecked {
			t.Fatal("code generation omitted its source audit")
		}
		if cached != nil {
			if !errors.Is(cached, ErrProbeNeedsContext) {
				t.Fatal("scratch source lost its lowering-only audit error", cached)
			}
			usedScratch = true
		}
		if err := consumer.scalarFPResultInitialized(); err != nil || consumer.fpScalarCheckErr != cached || output.Len() != 0 {
			t.Fatal("cached strict error was replaced or emitted code", err)
		}
	}
	if !usedScratch {
		t.Fatal("the complete source did not exercise lowering-owned vector scratch")
	}
	x86NumericNativeAddressObject(t, ir, triple)
}
