package plan9asm

import (
	"errors"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
)

type x86PanicTerminalAssemblyFixture struct {
	pkg       GoPackage
	bodies    []x86GoPanicTerminalCompilerBody
	objects   *gostaticstorage.SDKASMDataObservation
	cpp       []AssemblyCPPObservation
	positions []sdkCPPPositionObservation
}

func x86PanicTerminalAssembly(t *testing.T) x86PanicTerminalAssemblyFixture {
	t.Helper()
	pkg, symABI, objects := x86PanicTerminalCompilerFixture(t)
	filename := filepath.Join(filepath.Dir(pkg.SourceSelection.SelectedGoFiles[0]), "terminal.s")
	const source = "TEXT ·entry(SB),4,$0-0\nCALL ·arbitraryName(SB)\nNOP\nCALL ·arbitraryName(SB)\nRET\nTEXT ·unrelated(SB),4,$0-0\nRET\n"
	cpp, positions, err := observeSDKAssemblyCPP(source, AssemblyPreprocessOptions{FileName: filename})
	if err != nil {
		t.Fatal(err)
	}
	file, err := Parse(ArchAMD64, cpp.Output)
	if err != nil {
		t.Fatal(err)
	}
	pkg.SourceSelection.SelectedAssemblyFiles = []string{filename}
	pkg.SourceSelection.Assembly = map[string]*File{filename: file}
	text := gostaticstorage.TextRecord{Name: "terminal.entry", Namespace: gostaticstorage.TextSymbolNonpkgDefinition, ABI: 0, Kind: 1,
		Size: 12, Code: []byte{0xe8, 0, 0, 0, 0, 0x90, 0xe8, 0, 0, 0, 0, 0xc3},
		Relocations: []gostaticstorage.TextRelocation{
			{Offset: 1, Size: 4, Type: 7, Target: gostaticstorage.TextReference{Name: "terminal.arbitraryName", ABI: 0, ABIKnown: true}},
			{Offset: 7, Size: 4, Type: 7, Target: gostaticstorage.TextReference{Name: "terminal.arbitraryName", ABI: 0, ABIKnown: true}},
		},
		Positions: []gostaticstorage.TextPosition{{Start: 0, End: 5, File: filename, Line: 2}, {Start: 5, End: 6, File: filename, Line: 3},
			{Start: 6, End: 11, File: filename, Line: 4}, {Start: 11, End: 12, File: filename, Line: 5}}}
	unrelated := gostaticstorage.TextRecord{Name: "terminal.unrelated", Namespace: gostaticstorage.TextSymbolNonpkgDefinition, Index: 1, Relative: 1,
		ABI: 0, Kind: 1, Size: 1, Code: []byte{0xc3}, Positions: []gostaticstorage.TextPosition{{Start: 0, End: 1, File: filename, Line: 7}}}
	member := gostaticstorage.ASMDataMember{Flags: 20, Texts: []gostaticstorage.TextRecord{text, unrelated}}
	order, err := gostaticstorage.ASMSourceTextOrder([]byte(cpp.Output), pkg.Path, member)
	if err != nil {
		t.Fatal(err)
	}
	objects.Members[2].Texts = []gostaticstorage.TextRecord{x86GoPanicTerminalCloneText(text), x86GoPanicTerminalCloneText(unrelated)}
	objects.Sources[0].Original, objects.Sources[0].Expanded, objects.Sources[0].TextOrder = member, member, order
	bodies, err := x86GoPanicTerminalCompilerBodies(pkg, symABI, objects, "")
	if err != nil {
		t.Fatal(err)
	}
	return x86PanicTerminalAssemblyFixture{pkg, bodies, objects, []AssemblyCPPObservation{cpp}, []sdkCPPPositionObservation{positions}}
}

func (fixture x86PanicTerminalAssemblyFixture) query(budget *x86ResultFlowBudget) ([]x86GoPanicTerminalAssemblyCall, error) {
	return x86GoPanicTerminalAssemblyCalls(fixture.pkg, fixture.bodies, fixture.objects, fixture.cpp, fixture.positions, "", budget)
}

func TestX86GoPanicTerminalAssemblyKeepsCompleteOriginalOrdinals(t *testing.T) {
	fixture := x86PanicTerminalAssembly(t)
	calls, err := fixture.query(&x86ResultFlowBudget{})
	if err != nil || len(calls) != 2 {
		t.Fatal("original direct CALLs were not joined to their actual compiler body", calls, err)
	}
	file := fixture.pkg.SourceSelection.Assembly[fixture.pkg.SourceSelection.SelectedAssemblyFiles[0]]
	for index, ordinal := range []int{1, 3} {
		if calls[index].ordinal != ordinal || calls[index].function != "·entry" || calls[index].target != "terminal.arbitraryName" ||
			!reflect.DeepEqual(calls[index].instruction, file.Funcs[0].Instrs[ordinal]) || calls[index].relocation.Offset != int64(index*6+1) {
			t.Fatal("CALL association borrowed another original node/target/native relocation", calls)
		}
	}
	if len(file.Funcs) != 2 || len(file.Funcs[0].Instrs) != 5 || len(file.Funcs[1].Instrs) != 2 {
		t.Fatal("an association query truncated original post-CALL or unrelated source")
	}
}

func TestX86GoPanicTerminalAssemblyRejectsDifferentNodeOrNativeCall(t *testing.T) {
	for name, mutate := range map[string]func(*x86PanicTerminalAssemblyFixture){
		"missing-CPP":           func(f *x86PanicTerminalAssemblyFixture) { f.cpp = nil },
		"missing-position-tape": func(f *x86PanicTerminalAssemblyFixture) { f.positions = nil },
		"missing-selection":     func(f *x86PanicTerminalAssemblyFixture) { f.pkg.SourceSelection.SelectedAssemblyFiles = nil },
		"source-opcode": func(f *x86PanicTerminalAssemblyFixture) {
			f.pkg.SourceSelection.Assembly[f.pkg.SourceSelection.SelectedAssemblyFiles[0]].Funcs[0].Instrs[1].Op = "NOP"
		},
		"source-target": func(f *x86PanicTerminalAssemblyFixture) {
			f.pkg.SourceSelection.Assembly[f.pkg.SourceSelection.SelectedAssemblyFiles[0]].Funcs[0].Instrs[1].Args[0].Sym = "·other"
		},
		"private-instruction-field": func(f *x86PanicTerminalAssemblyFixture) {
			f.pkg.SourceSelection.Assembly[f.pkg.SourceSelection.SelectedAssemblyFiles[0]].Funcs[0].Instrs[1].x86Encoded = true
		},
		"CPP-output":          func(f *x86PanicTerminalAssemblyFixture) { f.cpp[0].Output += "NOP\n" },
		"position-map":        func(f *x86PanicTerminalAssemblyFixture) { f.positions[0].Mapped += "NOP\n" },
		"physical-order":      func(f *x86PanicTerminalAssemblyFixture) { f.objects.Sources[0].TextOrder[0].ObjectOrdinal = 1 },
		"original-object":     func(f *x86PanicTerminalAssemblyFixture) { f.objects.Sources[0].Original.Texts = nil },
		"expanded-object":     func(f *x86PanicTerminalAssemblyFixture) { f.objects.Sources[0].Expanded.Texts = nil },
		"archive-object":      func(f *x86PanicTerminalAssemblyFixture) { f.objects.Members[2].Texts = nil },
		"callee-association":  func(f *x86PanicTerminalAssemblyFixture) { f.bodies[0].text.ABI = 0 },
		"missing-native-CALL": func(f *x86PanicTerminalAssemblyFixture) { f.objects.Sources[0].Original.Texts[0].Relocations = nil },
		"relocation-target": func(f *x86PanicTerminalAssemblyFixture) {
			f.objects.Sources[0].Original.Texts[0].Relocations[0].Target.Name = "terminal.other"
		},
		"relocation-ABI": func(f *x86PanicTerminalAssemblyFixture) {
			f.objects.Sources[0].Original.Texts[0].Relocations[0].Target.ABI = 1
		},
		"relocation-unknown-ABI": func(f *x86PanicTerminalAssemblyFixture) {
			f.objects.Sources[0].Original.Texts[0].Relocations[0].Target.ABIKnown = false
		},
		"relocation-addend": func(f *x86PanicTerminalAssemblyFixture) {
			f.objects.Sources[0].Original.Texts[0].Relocations[0].Add = 1
		},
		"relocation-offset": func(f *x86PanicTerminalAssemblyFixture) {
			f.objects.Sources[0].Original.Texts[0].Relocations[0].Offset = 0
		},
		"relocation-width": func(f *x86PanicTerminalAssemblyFixture) {
			f.objects.Sources[0].Original.Texts[0].Relocations[0].Size = 2
		},
		"opcode":          func(f *x86PanicTerminalAssemblyFixture) { f.objects.Sources[0].Original.Texts[0].Code[0] = 0xe9 },
		"native-position": func(f *x86PanicTerminalAssemblyFixture) { f.objects.Sources[0].Original.Texts[0].Positions[0].Line = 4 },
	} {
		t.Run(name, func(t *testing.T) {
			fixture := x86PanicTerminalAssembly(t)
			mutate(&fixture)
			if calls, err := fixture.query(&x86ResultFlowBudget{}); !errors.Is(err, ErrProbeNeedsContext) || len(calls) != 0 {
				t.Fatal("changed source/ordinal/compiler/native node retained its association", calls, err)
			}
		})
	}
}

func TestX86GoPanicTerminalAssemblySharesExistingFlowBudget(t *testing.T) {
	fixture := x86PanicTerminalAssembly(t)
	for _, budget := range []*x86ResultFlowBudget{nil, {visits: 16384}, {bytes: 64 << 20}} {
		if calls, err := fixture.query(budget); !errors.Is(err, ErrProbeNeedsContext) || len(calls) != 0 {
			t.Fatal("missing/exhausted shared source budget returned partial CALL associations", calls, err)
		}
	}
	budget := &x86ResultFlowBudget{}
	if _, err := fixture.query(budget); err != nil || budget.visits == 0 || budget.bytes == 0 {
		t.Fatal("association ignored the request-local source proof budget", budget, err)
	}
}

func TestX86GoPanicTerminalAssemblyBudgetUsesSharedByteWorkUnits(t *testing.T) {
	fixture := x86PanicTerminalAssembly(t)
	budget := &x86ResultFlowBudget{bytes: 8 << 20}
	work := len(fixture.cpp[0].Output) + len(fixture.positions[0].Mapped)
	if calls, err := fixture.query(budget); err != nil || len(calls) != 2 || budget.bytes != (8<<20)+work {
		t.Fatal("noniterative source bytes borrowed the CFG's separate8-copy initial-state reservation", calls, budget, err)
	}
	budget.bytes = (64 << 20) - work + 1
	if calls, err := fixture.query(budget); !errors.Is(err, ErrProbeNeedsContext) || len(calls) != 0 {
		t.Fatal("association exceeded the unchanged shared64MiB byte-work cap", calls, budget, err)
	}
}
