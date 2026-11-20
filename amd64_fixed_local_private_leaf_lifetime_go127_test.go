//go:build go1.27

package plan9asm

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"go/types"
	"strings"
	"testing"
)

func fixedLocalLeafLifetimeFixture(t *testing.T, roots, adds, frame int) (GoPackage, GoAMD64FrameCaptureRequest, Options, string) {
	t.Helper()
	var assembly, declarations strings.Builder
	names := make([]string, roots)
	for index := range names {
		name := "Value"
		if index != 0 {
			name = fmt.Sprintf("Other%d", index)
		}
		names[index] = name
		fmt.Fprintf(&declarations, "func %s(a uint64) uint64\n", name)
		fmt.Fprintf(&assembly, "TEXT ·%s(SB),4,$%d-16\n", name, frame)
		assembly.WriteString(" MOVQ a+0(FP),AX\n MOVQ AX,16(SP)\n LEAQ 16(SP),BP\n")
		assembly.WriteString(strings.Repeat(" ADDQ $1,AX\n", adds))
		assembly.WriteString(" CALL leaf<>(SB)\n MOVQ AX,ret+8(FP)\n RET\n")
	}
	assembly.WriteString("TEXT leaf<>(SB),4,$0\n ADDQ AX,(BP)\n MOVQ (BP),AX\n RET\n")
	source := assembly.String()
	listing := x86InsertExtractGoListing(t, "amd64", source)
	t.Logf("actual Go accepted complete source: sha256=%x listing_bytes=%d roots=%d", sha256.Sum256([]byte(source)), len(listing), roots)
	pkg, request, options := fixedLocalPrivateLeafFixture(t, source, declarations.String())
	for _, name := range names {
		sig, err := DeriveGoFuncABI0Signature(pkg.Path+"."+name,
			pkg.Types.Scope().Lookup(name).(*types.Func), "amd64", types.SizesFor("gc", "amd64"))
		if err != nil {
			t.Fatal(err)
		}
		options.Sigs[sig.Name] = sig
	}
	return pkg, request, options, source
}

func fixedLocalLeafLifetimeBinding(t *testing.T, pkg GoPackage, request GoAMD64FrameCaptureRequest,
	options Options, assembly string) (*File, Options, error) {
	t.Helper()
	ctx, cancel := runtimeOracleStageContext(t)
	t.Cleanup(cancel)
	owner, err := CaptureGoAMD64FrameSource(ctx, pkg, request)
	if err != nil {
		t.Fatal("complete original source observation must precede the graph bound", err)
	}
	t.Cleanup(func() {
		if err := owner.Close(); err != nil {
			t.Error(err)
		}
	})
	expanded, err := owner.preprocess(request.AssemblyFile, []byte(assembly))
	if err != nil {
		t.Fatal(err)
	}
	file, err := Parse(ArchAMD64, expanded)
	if err != nil {
		t.Fatal(err)
	}
	if len(file.Funcs) != len(options.Sigs)+1 || len(owner.functions) != len(file.Funcs) {
		t.Fatal("whole original root and leaf inventory was not retained")
	}
	bound, err := owner.BindFixedLocal(ctx, pkg, file, options)
	return file, bound, err
}

func fixedLocalLeafLifetimeObjects(t *testing.T, expectedRoots int, ir string, err error) {
	t.Helper()
	if err != nil || strings.Count(ir, "define ") != expectedRoots {
		t.Fatal("complete original roots did not all translate", err)
	}
	fixedLocalPrivateLeafObjects(t, ir)
}

func TestGoAMD64FixedLocalPrivateLeafPreservesPerRootWorkBudget(t *testing.T) {
	pkg, request, options, source := fixedLocalLeafLifetimeFixture(t, 2, 1500, 2048)
	fixedLocalFreshAPIs(t, pkg, request, options, []string{"Translate", "Module", "GoModule"},
		func(t *testing.T, ir string, err error) { fixedLocalLeafLifetimeObjects(t, 2, ir, err) })
	t.Run("actual_replay_work", func(t *testing.T) {
		file, bound, err := fixedLocalLeafLifetimeBinding(t, pkg, request, options, source)
		if err != nil {
			t.Fatal("old complete source must remain accepted", err)
		}
		prepared, err := PrepareX86DirectTailSource(file, bound)
		if err != nil {
			t.Fatal(err)
		}
		graph := prepared.x86DirectTails
		byName := make(map[string]int)
		for index, fn := range graph.original.Funcs {
			byName[fn.Sym] = index
		}
		totalNodes, totalBytes := 0, int64(0)
		for index, original := range graph.original.Funcs {
			if graph.helpers[original.Sym] {
				continue
			}
			// Use the real graph builder and transfer budget. This is a work
			// measurement, not a substitute certificate for the public API above.
			view, err := graph.root(index, byName, 4096, true)
			if err != nil {
				t.Fatal(err)
			}
			fn := original
			fn.x86DirectTailRoot = view
			fn = fixedLocalProofFunction(fn)
			sig := bound.Sigs[bound.ResolveSym(original.Sym)]
			proof := &x86FixedLocalProof{binding: sig.x86FixedLocal, frame: fn.FrameSize}
			budget := x86FixedLocalBudget{steps: 1 << 18, bytes: 64 << 20}
			for phase := 0; phase < 2; phase++ {
				current := fn
				current.Instrs = append([]Instr(nil), fn.Instrs...)
				effects, err := fixedLocalEffectPlan(current, sig.x86FixedLocal)
				if err != nil {
					t.Fatal(err)
				}
				for residue := 0; residue < 8; residue++ {
					if err := replayX86FixedLocal(&current, sig, proof, residue, &budget, effects, nil); err != nil {
						t.Fatal("unchanged per-proof work bound rejected the old source", err)
					}
				}
			}
			steps, bytes := (1<<18)-budget.steps, (64<<20)-budget.bytes
			if steps != 16*len(view.points) || bytes != int64(steps)*fn.FrameSize || budget.bytes <= 0 {
				t.Fatal("actual straight-line replay consumption differs", original.Sym, steps, bytes)
			}
			t.Logf("actual %s expansion=%d replay_steps=%d byte_work=%d", original.Sym, len(view.points), steps, bytes)
			totalNodes += len(view.points)
			totalBytes += bytes
		}
		if totalNodes > 4096 || totalBytes <= 64<<20 {
			t.Fatal("old accepted source no longer distinguishes per-proof from shared work", totalNodes, totalBytes)
		}
	})
}

func TestGoAMD64FixedLocalPrivateLeafSequentialRootCapacity(t *testing.T) {
	pkg, request, options, _ := fixedLocalLeafLifetimeFixture(t, 2, 2200, 80)
	fixedLocalFreshAPIs(t, pkg, request, options, []string{"Translate", "Module", "GoModule"},
		func(t *testing.T, ir string, err error) { fixedLocalLeafLifetimeObjects(t, 2, ir, err) })
}

func TestGoAMD64FixedLocalPrivateLeafSingleRootCapacity(t *testing.T) {
	for _, adds := range []int{4087, 4088} {
		t.Run(fmt.Sprint(adds+9), func(t *testing.T) {
			pkg, request, options, source := fixedLocalLeafLifetimeFixture(t, 1, adds, 80)
			file, bound, err := fixedLocalLeafLifetimeBinding(t, pkg, request, options, source)
			if adds == 4088 {
				if !errors.Is(err, ErrProbeNeedsContext) ||
					!strings.Contains(err.Error(), "oversized source continuation instruction budget") {
					t.Fatal("one oversized original root escaped its unchanged bound", err)
				}
				return
			}
			if err != nil {
				t.Fatal("root at the actual existing node bound was rejected", err)
			}
			ir, err := Translate(file, bound)
			fixedLocalLeafLifetimeObjects(t, 1, ir, err)
		})
	}
}

// Count the real retained expansion arrays, not original source text, total
// allocation or a GC-dependent heap estimate. Shared backing arrays are counted
// once; independently owned instruction/certificate arrays remain separate.
type fixedLocalLeafRetained struct{ views, points, instructions, ordinals, edges, tails, accesses int }

func fixedLocalLeafRetainedArrays(file *File) fixedLocalLeafRetained {
	var retained fixedLocalLeafRetained
	seen := make(map[*x86DirectTailRoot]bool)
	points := make(map[*x86DirectTailPoint]bool)
	instructions := make(map[*Instr]bool)
	ordinals := make(map[*int]bool)
	edges := make(map[*[]int]bool)
	targets := make(map[*int]bool)
	tails := make(map[*bool]bool)
	add := func(view *x86DirectTailRoot) {
		if view == nil || seen[view] {
			return
		}
		seen[view] = true
		if len(view.points) != 0 || len(view.instructions) != 0 {
			retained.views++
		}
		if cap(view.points) != 0 && !points[&view.points[:cap(view.points)][0]] {
			points[&view.points[:cap(view.points)][0]] = true
			retained.points += cap(view.points)
		}
		if cap(view.instructions) != 0 && !instructions[&view.instructions[:cap(view.instructions)][0]] {
			instructions[&view.instructions[:cap(view.instructions)][0]] = true
			retained.instructions += cap(view.instructions)
			for _, ins := range view.instructions {
				retained.accesses += len(ins.x86FixedLocalMemory)
			}
		}
		if cap(view.ordinals) != 0 && !ordinals[&view.ordinals[:cap(view.ordinals)][0]] {
			ordinals[&view.ordinals[:cap(view.ordinals)][0]] = true
			retained.ordinals += cap(view.ordinals)
		}
		if cap(view.edges) != 0 && !edges[&view.edges[:cap(view.edges)][0]] {
			edges[&view.edges[:cap(view.edges)][0]] = true
			retained.edges += cap(view.edges)
		}
		for _, edge := range view.edges {
			if cap(edge) != 0 && !targets[&edge[:cap(edge)][0]] {
				targets[&edge[:cap(edge)][0]] = true
				retained.edges += cap(edge)
			}
		}
		if cap(view.externalTails) != 0 && !tails[&view.externalTails[:cap(view.externalTails)][0]] {
			tails[&view.externalTails[:cap(view.externalTails)][0]] = true
			retained.tails += cap(view.externalTails)
		}
	}
	if file.x86DirectTails != nil {
		for _, view := range file.x86DirectTails.roots {
			add(view)
		}
	}
	for _, fn := range file.Funcs {
		add(fn.x86DirectTailRoot)
	}
	return retained
}

func TestGoAMD64FixedLocalPrivateLeafRetainedRootViews(t *testing.T) {
	var scopeBaseline fixedLocalLeafRetained
	for _, count := range []int{2, 8} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			pkg, request, options, source := fixedLocalLeafLifetimeFixture(t, count, 8, 80)
			file, bound, err := fixedLocalLeafLifetimeBinding(t, pkg, request, options, source)
			if err != nil {
				t.Fatal(err)
			}
			prepared, err := PrepareX86DirectTailSource(file, bound)
			if err != nil {
				t.Fatal(err)
			}
			measure := func(stage string, current *File) {
				retained := fixedLocalLeafRetainedArrays(current)
				t.Logf("roots=%d stage=%s actual retained expansion arrays=%+v", count, stage, retained)
				if retained != (fixedLocalLeafRetained{}) {
					t.Errorf("%s retained root expansions outside a single-function scope: %+v", stage, retained)
				}
			}
			measure("prepared", prepared)
			normalized, err := normalizeX86RawFile(prepared, "amd64", bound)
			if err != nil {
				t.Fatal(err)
			}
			measure("normalized", normalized)
			binding := bound.Sigs[pkg.Path+".Value"].x86FixedLocal
			snapshot, err := newX86FixedLocalResultSnapshot(binding, "amd64")
			if err != nil {
				t.Fatal(err)
			}
			for _, original := range file.Funcs {
				if prepared.x86DirectTailHelper(original.Sym) {
					continue
				}
				retained := snapshot.functions[bound.ResolveSym(original.Sym)].function
				if len(retained.Instrs) != len(original.Instrs) || retained.x86DirectTailRoot != nil {
					t.Errorf("result snapshot retained expanded instructions for %s: got %d original %d",
						original.Sym, len(retained.Instrs), len(original.Instrs))
				}
				sig := bound.Sigs[bound.ResolveSym(original.Sym)]
				current, err := proveX86FixedLocalRoot(original, sig, prepared.x86DirectTails)
				if err != nil {
					t.Fatal(err)
				}
				entry := snapshot.functions[sig.Name]
				reference, err := entry.graph.fixedLocalRoot(original.Sym)
				if err != nil || reference == nil || len(current.x86DirectTailRoot.points) > 4096 || len(reference.points) > 4096 {
					t.Fatal("current root/reference exceeded the unchanged node bound", err)
				}
				// Measure the actual proof and independent reference owners of a
				// single consumer scope. This temporary container is never sent to
				// translation and does not crop the authenticated input source.
				referenceFunc := entry.function
				referenceFunc.x86DirectTailRoot = reference
				scope := *prepared
				scope.Funcs = []Func{current, referenceFunc}
				live := fixedLocalLeafRetainedArrays(&scope)
				t.Logf("roots=%d current=%s proof+reference retained arrays=%+v", count, original.Sym, live)
				if scopeBaseline.views == 0 {
					scopeBaseline = live
				}
				if live.views != 2 || live != scopeBaseline {
					t.Fatal("single-root retained work grew with complete-file root count", live, scopeBaseline)
				}
			}
			measure("after_root_scopes", prepared)
		})
	}
}

func TestGoAMD64FixedLocalPrivateLeafScopedControlIdentity(t *testing.T) {
	pkg, request, options, source := fixedLocalLeafLifetimeFixture(t, 1, 2, 80)
	file, bound, err := fixedLocalLeafLifetimeBinding(t, pkg, request, options, source)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := PrepareX86DirectTailSource(file, bound)
	if err != nil {
		t.Fatal(err)
	}
	sig := bound.Sigs[pkg.Path+".Value"]
	fn, err := proveX86FixedLocalRoot(prepared.Funcs[0], sig, prepared.x86DirectTails)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := newX86FixedLocalResultSnapshot(sig.x86FixedLocal, "amd64")
	if err != nil {
		t.Fatal(err)
	}
	entry := snapshot.functions[sig.Name]
	check := func(function Func) error {
		var output strings.Builder
		consumer := newX86Ctx(&output, function, sig, bound.ResolveSym, bound.Sigs, "amd64", bound.TargetTriple, false)
		consumer.fixedLocalResult = snapshot
		consumer.fpFeatureAttrs, consumer.sig.Attrs = entry.inferred, entry.attributes
		return consumer.checkFixedLocalResultInitialization()
	}
	if err := check(fn); err != nil {
		t.Fatal("independent complete source/reference precondition", err)
	}
	for _, axis := range []string{"text", "point", "ordinal", "edge", "return", "external_tail"} {
		t.Run(axis, func(t *testing.T) {
			changed := fn
			view := *fn.x86DirectTailRoot
			changed.x86DirectTailRoot = &view
			switch axis {
			case "text":
				view.text++
			case "point":
				view.points = append([]x86DirectTailPoint(nil), view.points...)
				view.points[0].instruction++
			case "ordinal":
				view.ordinals = append([]int(nil), view.ordinals...)
				view.ordinals[0]++
			case "edge", "return":
				view.edges = append([][]int(nil), view.edges...)
				pc := 0
				if axis == "return" {
					pc = len(view.instructions) - 1 // The private helper's RET.
					if view.instructions[pc].Op != OpRET || len(view.edges[pc]) != 1 {
						t.Fatal("fixture lost its distinct private return continuation")
					}
				}
				view.edges[pc] = []int{0}
			case "external_tail":
				view.externalTails = append([]bool(nil), view.externalTails...)
				view.externalTails[0] = true
			}
			if err := check(changed); !errors.Is(err, ErrProbeNeedsContext) ||
				!strings.Contains(err.Error(), "original private root control/source coordinates differ") {
				t.Fatal("unchanged instruction bytes hid a changed private control graph", err)
			}
		})
	}
}

func TestGoAMD64FixedLocalPrivateLeafRootDirectoryIdentity(t *testing.T) {
	pkg, request, options, source := fixedLocalLeafLifetimeFixture(t, 1, 2, 80)
	file, bound, err := fixedLocalLeafLifetimeBinding(t, pkg, request, options, source)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := PrepareX86DirectTailSource(file, bound)
	if err != nil {
		t.Fatal(err)
	}
	graph := prepared.x86DirectTails
	if view, err := graph.fixedLocalRoot("·Value"); err != nil || view == nil {
		t.Fatal("complete original directory precondition", err)
	}
	original := graph.texts
	for _, axis := range []string{"missing", "negative", "outside", "different_symbol"} {
		t.Run(axis, func(t *testing.T) {
			changed := make(map[string]int, len(original))
			for name, index := range original {
				changed[name] = index
			}
			switch axis {
			case "missing":
				delete(changed, "leaf<>")
			case "negative":
				changed["leaf<>"] = -1
			case "outside":
				changed["leaf<>"] = len(graph.original.Funcs)
			case "different_symbol":
				changed["leaf<>"] = original["·Value"]
			}
			graph.texts = changed
			t.Cleanup(func() { graph.texts = original })
			if _, err := graph.fixedLocalRoot("·Value"); !errors.Is(err, ErrProbeNeedsContext) ||
				!strings.Contains(err.Error(), "tail target is not an original source TEXT") {
				t.Fatal("retained source directory selected a different or invalid helper index", err)
			}
		})
	}
}
