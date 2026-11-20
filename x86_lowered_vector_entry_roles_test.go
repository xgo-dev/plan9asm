package plan9asm

import (
	"errors"
	"go/ast"
	goparser "go/parser"
	"go/token"
	"strings"
	"testing"
)

// This is a test-side field inventory, not a production capability registry.
// Every semantic role below must remain outside ordinary scratch refinement.
func x86VectorRefinementRoleControls() []struct {
	owner, field string
	change       func(*Func, *FuncSig)
} {
	return []struct {
		owner, field string
		change       func(*Func, *FuncSig)
	}{
		{"FuncSig", "ARMEntry", func(_ *Func, s *FuncSig) { s.ARMEntry = new(ARMMachineEntry) }},
		{"FuncSig", "WASMContext", func(_ *Func, s *FuncSig) { s.WASMContext = I64 }},
		{"FuncSig", "WASMNative", func(_ *Func, s *FuncSig) { s.WASMNative = true }},
		{"FuncSig", "ArgRegs", func(_ *Func, s *FuncSig) { s.ArgRegs = []Reg{AX} }},
		{"FuncSig", "ARM64GoRegisterABI", func(_ *Func, s *FuncSig) { s.ARM64GoRegisterABI = new(ARM64GoRegisterABI) }},
		{"FuncSig", "ARM64ClosureABI", func(_ *Func, s *FuncSig) { s.ARM64ClosureABI = new(ARM64ClosureABI) }},
		{"FuncSig", "x86CallerRegions", func(_ *Func, s *FuncSig) { s.x86CallerRegions = new(x86GoCallerRegionProof) }},
		{"FuncSig", "x86FixedLocal", func(_ *Func, s *FuncSig) { s.x86FixedLocal = new(x86FixedLocalBinding) }},
		{"FuncSig", "amd64GoArguments", func(_ *Func, s *FuncSig) { s.amd64GoArguments = new(amd64GoArgumentBinding) }},
		{"FuncSig", "arm64FPReadDeclaration", func(_ *Func, s *FuncSig) { s.arm64FPReadDeclaration = new(arm64FPReadDeclaration) }},
		{"FuncSig", "arm64ABI0Declaration", func(_ *Func, s *FuncSig) { s.arm64ABI0Declaration = new(arm64ABI0Declaration) }},
		{"FuncSig", "arm64ABI0TailDeclaration", func(_ *Func, s *FuncSig) { s.arm64ABI0TailDeclaration = new(arm64ABI0TailDeclaration) }},
		{"FuncSig", "arm64NativeScratch", func(_ *Func, s *FuncSig) { s.arm64NativeScratch = new(arm64ScratchBinding) }},
		{"FuncSig", "x86BorrowedBoolTail", func(_ *Func, s *FuncSig) { s.x86BorrowedBoolTail = true }},
		{"Func", "X86RawText", func(f *Func, _ *FuncSig) { f.X86RawText = []byte{0xc3} }},
		{"Func", "X86RawAlign", func(f *Func, _ *FuncSig) { f.X86RawAlign = 16 }},
		{"Func", "x86ContinuationAddresses", func(f *Func, _ *FuncSig) { f.x86ContinuationAddresses = map[string]x86Continuation{"label": {}} }},
		{"Func", "x86IndirectLabels", func(f *Func, _ *FuncSig) { f.x86IndirectLabels = []string{"label"} }},
		{"Func", "x86ContinuationFlow", func(f *Func, _ *FuncSig) { f.x86ContinuationFlow = new(x86ContinuationFlow) }},
		{"Func", "x86SourceStack", func(f *Func, _ *FuncSig) { f.x86SourceStack = new(x86SourceStackProof) }},
		{"Func", "x86FixedLocal", func(f *Func, _ *FuncSig) { f.x86FixedLocal = new(x86FixedLocalProof) }},
		{"Func", "arm64PrivateRegisterEntry", func(f *Func, _ *FuncSig) { f.arm64PrivateRegisterEntry = true }},
		{"Func", "arm64PrivateUnexposedFrame", func(f *Func, _ *FuncSig) { f.arm64PrivateUnexposedFrame = true }},
		{"Func", "arm64PrivateTailSource", func(f *Func, _ *FuncSig) { f.arm64PrivateTailSource = new(arm64PrivateTailSource) }},
		{"Func", "arm64PrivateCallSource", func(f *Func, _ *FuncSig) { f.arm64PrivateCallSource = new(arm64PrivateCallSource) }},
		{"Func", "arm64ABI0TailSource", func(f *Func, _ *FuncSig) { f.arm64ABI0TailSource = new(arm64ABI0TailSource) }},
		{"Func", "x86RawReplay", func(f *Func, _ *FuncSig) { f.x86RawReplay = new(x86RawReplaySource) }},
		{"Func", "x86DirectTailRoot", func(f *Func, _ *FuncSig) { f.x86DirectTailRoot = new(x86DirectTailRoot) }},
		{"Func", "x86BoolCalls", func(f *Func, _ *FuncSig) { f.x86BoolCalls = new(x86ABI0BoolCallPlan) }},
		{"Func", "x86BoolReadonlyInputs", func(f *Func, _ *FuncSig) { f.x86BoolReadonlyInputs = true }},
	}
}

func TestX86LoweredVectorEntryExcludesEveryRegisteredRole(t *testing.T) {
	for _, row := range x86VectorRefinementRoleControls() {
		t.Run(row.owner+"/"+row.field, func(t *testing.T) {
			fn, sig := x86LoweredVectorMaskFixture(t)
			row.change(&fn, &sig)
			var output strings.Builder
			consumer := newX86Ctx(&output, fn, sig, func(name string) string { return strings.TrimPrefix(name, "·") },
				nil, "amd64", "x86_64-unknown-linux-gnu", false)
			if err := consumer.scalarFPResultInitialized(); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("a registered role acquired ordinary ABI0 scratch refinement", err)
			}
		})
	}
}

func TestX86LoweredVectorEntryRoleFieldInventory(t *testing.T) {
	classified := map[string]map[string]bool{
		"FuncSig": {"Name": true, "Args": true, "Ret": true, "Attrs": true, "Frame": true},
		"Func": {
			"Sym": true, "FrameSize": true, "ArgSize": true, "Instrs": true,
			"x86ResultFlowBudget": true, "arm64PrivateSourceAdded": true, // Resource counters only.
			"x86SourceStackFailure": true, // Diagnostic only; never a source capability.
		},
	}
	for _, row := range x86VectorRefinementRoleControls() {
		if classified[row.owner][row.field] {
			t.Fatal("duplicate or contradictory role classification", row.owner, row.field)
		}
		classified[row.owner][row.field] = true
	}
	for _, owner := range []struct{ path, name string }{{"translate.go", "FuncSig"}, {"parser.go", "Func"}} {
		file, err := goparser.ParseFile(token.NewFileSet(), owner.path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		ast.Inspect(file, func(node ast.Node) bool {
			declaration, ok := node.(*ast.TypeSpec)
			if !ok || declaration.Name.Name != owner.name {
				return true
			}
			fields, ok := declaration.Type.(*ast.StructType)
			if !ok {
				t.Fatal("role owner is no longer a struct", owner.name)
			}
			found = true
			for _, field := range fields.Fields.List {
				for _, name := range field.Names {
					if !classified[owner.name][name.Name] {
						t.Error("new field requires explicit ordinary/semantic-role/resource classification", owner.name, name.Name)
					}
					delete(classified[owner.name], name.Name)
				}
			}
			return false
		})
		if !found || len(classified[owner.name]) != 0 {
			t.Fatal("role inventory is stale or incomplete", owner.name, classified[owner.name])
		}
	}
}
