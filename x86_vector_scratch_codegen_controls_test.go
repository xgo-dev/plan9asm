package plan9asm

import (
	"errors"
	"strings"
	"testing"
)

// These designated ordinary ABI0 controls choose the emitter's existing vector
// scratch values. They do not prove arbitrary physical entry registers, caller
// memory, or a reusable source/storage permission.
func x86VectorScratchCodegenControl(t *testing.T, source, declaration, arch, triple, ir string, codegenErr error) {
	t.Helper()
	if arch != "amd64" || codegenErr != nil || ir == "" {
		t.Fatal("ordinary AMD64 scratch code generation failed", arch, codegenErr)
	}
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	pkg := mustGoPackage(t, "scratch", "package scratch\n"+declaration)
	resolve := func(symbol string) string { return strings.TrimPrefix(goStripABISuffix(symbol), "·") }
	signatures, err := goSigsForAsmFile(pkg, file, resolve, arch, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, fn := range file.Funcs {
		sig := signatures[resolve(fn.Sym)]
		if !x86OrdinaryScalarCodegenSource(fn, sig, arch) {
			t.Fatal("scratch control acquired a private or physical entry role")
		}
		for _, query := range []func(Func, FuncSig, string) error{
			CheckX86ABI0ResultInitialization, checkX86ScalarFPResultInitialization,
		} {
			if err := query(fn, sig, arch); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("ordinary scratch choice escaped into a strict source query", err)
			}
		}
		var output strings.Builder
		consumer := newX86Ctx(&output, fn, sig, resolve, nil, arch, triple, false)
		if err := consumer.scalarFPResultInitialized(); err != nil {
			t.Fatal("lowering-owned scratch plan lost its paired check", err)
		}
		cached := consumer.fpScalarCheckErr
		if !errors.Is(cached, ErrProbeNeedsContext) || !consumer.fpScalarChecked {
			t.Fatal("code generation erased its strict audit error", cached)
		}
		if err := consumer.scalarFPResultInitialized(); err != nil || consumer.fpScalarCheckErr != cached || output.Len() != 0 {
			t.Fatal("cached strict error was replaced or emitted code", err)
		}
	}
	x86NumericNativeAddressObject(t, ir, triple)
}
