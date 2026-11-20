package plan9asm

import (
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// A complete NUM address owns this native access, never a private frame
// offset, a caller allocation, or the standalone result observer's authority.
func fixedLocalRequireNumericControl(t *testing.T, fn Func, sig FuncSig, assembly, declaration, operation string, operand int, width int64, write bool, emitted string) {
	t.Helper()
	if err := CheckX86ABI0ResultInitialization(fn, sig, "amd64"); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("paired native access became a standalone result proof", err)
	}
	ordinal := -1
	for index, ins := range fn.Instrs {
		if ins.Raw == operation {
			ordinal = index
		}
	}
	if ordinal < 0 {
		t.Fatal("original NUM operation is missing", operation)
	}
	goAMD64FramePrepareOwnedToolCache(t)
	const triple = "x86_64-unknown-linux-gnu"
	pkg, request, file, options := fixedLocalTransportFixture(t, assembly, declaration, "linux/amd64", triple)
	source := requireGoAMD64FrameCapture(t, pkg, request)
	original, err := goAMD64FrameRead(filepath.Join(request.Directory, request.AssemblyFile))
	if err != nil {
		t.Fatal(err)
	}
	expanded, err := source.preprocess(request.AssemblyFile, original)
	if err != nil {
		t.Fatal(err)
	}
	file, err = ParseWithDefines(ArchAMD64, expanded, nil)
	if err != nil {
		t.Fatal(err)
	}
	stage, cancel := runtimeOracleStageContext(t)
	defer cancel()
	bound, err := source.BindFixedLocal(stage, pkg, file, options)
	if err != nil {
		t.Fatal("actual original NUM source did not bind", err)
	}
	if len(file.Funcs) != 1 || len(file.Funcs[0].Instrs) != len(fn.Instrs) ||
		file.Funcs[0].Instrs[ordinal].Op != fn.Instrs[ordinal].Op || !reflect.DeepEqual(file.Funcs[0].Instrs[ordinal].Args, fn.Instrs[ordinal].Args) {
		t.Fatal("actual preprocessing changed the original NUM operation", operation)
	}
	proved, err := proveX86FixedLocal(file.Funcs[0], bound.Sigs[pkg.Path+".Value"])
	if err != nil {
		t.Fatal("initialized NUM native source rejected", err)
	}
	ctx := amd64Ctx{fixedLocal: proved.x86FixedLocal}
	found := false
	for index, ins := range proved.Instrs {
		if index != ordinal {
			continue
		}
		access, valid := ctx.fixedLocalMemoryAccess(ins, operand)
		if !valid || !access.nativeInput || ctx.fixedLocalMemoryCertified(ins, operand) ||
			access.width != width || access.write != write || len(ins.x86CallerMemory) != 0 || ins.x86NumericalRead != nil {
			t.Fatal("NUM access changed width/effect or acquired a separate storage role", operation, access)
		}
		found = true
	}
	if !found {
		t.Fatal("original NUM operation lost its exact access", operation)
	}
	ir, err := Translate(file, bound)
	if err != nil || !strings.Contains(ir, emitted) ||
		!strings.Contains(ir, "volatile") && !strings.Contains(ir, "asm sideeffect") {
		t.Fatal("NUM native instruction lost its emitted observable effect", emitted, err, ir)
	}
	x86NumericNativeAddressObject(t, ir, triple)
}
