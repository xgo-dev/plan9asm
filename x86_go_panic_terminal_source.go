package plan9asm

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"

	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
)

// These observations are private inputs for a future terminal capability.
// They neither bind Options nor change a CALL's normal or unwind successors.
type x86GoPanicTerminalSourceObservation struct {
	bodies []x86GoPanicTerminalCompilerBody
	calls  []x86GoPanicTerminalAssemblyCall
}

func (source *GoX86SDKASMDataSource) panicTerminalObservation(ctx context.Context, budget *x86ResultFlowBudget) (observed *x86GoPanicTerminalSourceObservation, result error) {
	if source == nil || source.identity != source || source.guard == nil || source.guard != source.originalGuard ||
		source.captureRole != sdkASMDataOriginalSourceRole || source.request.Target != "linux/386" || budget == nil ||
		budget.visits >= 16384 || budget.bytes >= 64<<20 {
		return nil, sdkASMDataContext("panic association requires its original private386 source observation")
	}
	if err := source.Verify(ctx); err != nil {
		return nil, err
	}
	// Retain the existing artifact lifetime across private typechecking and the
	// final callback-bearing Verify. A reentrant Close revokes publication but
	// cannot delete files underneath the in-flight query.
	source.mu.Lock()
	generation, ready := source.generation, source.ready
	if ready {
		source.active++
	}
	source.mu.Unlock()
	if !ready {
		return nil, sdkASMDataContext("panic association source closed before its query")
	}
	defer func() {
		result = errors.Join(result, source.Verify(ctx))
		source.mu.Lock()
		if !source.ready || source.generation != generation {
			result = errors.Join(result, sdkASMDataContext("panic association source revoked before publication"))
		}
		source.active--
		cleanup := source.closePending && source.active == 0
		source.mu.Unlock()
		if cleanup {
			source.operation.Lock()
			result = errors.Join(result, source.guard.Close())
			source.operation.Unlock()
		}
		if result != nil {
			observed = nil
		}
	}()
	private, stop, err := sdkASMDataPrivateContext(ctx, source.context, source.originalDeadline)
	if err != nil {
		return nil, err
	}
	defer stop()
	source.operation.Lock()
	defer source.operation.Unlock()
	if err := x86GoPanicTerminalCompilerSources(source.guard.env, func(role string) ([]byte, error) {
		return source.guard.read(filepath.Join(source.guard.env["GOROOT"], filepath.FromSlash(role)))
	}); err != nil {
		return nil, err
	}
	count := len(source.guard.selection.SFiles)
	if count == 0 || len(source.observation.CPP) != count || len(source.observation.Positions) != count ||
		len(source.observation.ObjectInputs.Sources) != count || source.observation.Objects == nil ||
		len(source.observation.Objects.Sources) != count {
		return nil, sdkASMDataContext("panic association lost its complete actual Go/ASM selection")
	}
	pkg, err := source.typedPackage(source.observation.Header.LanguageVersion)
	if err != nil {
		return nil, err
	}
	for ordinal, name := range source.guard.selection.SFiles {
		if source.observation.ObjectInputs.Sources[ordinal].Name != name || source.observation.Objects.Sources[ordinal].Name != name {
			return nil, sdkASMDataContext("panic association changed a complete selected ASM route")
		}
	}
	bodies, err := x86GoPanicTerminalCompilerBodies(pkg, source.observation.Header.SymABI, source.observation.Objects, source.guard.env["GOROOT"])
	if err != nil {
		return nil, err
	}
	// Reuse the existing complete SDK header-compiler object observer. No new
	// decoder, caller report, fake ABI0 body or AMD64 wrapper is introduced.
	generated, err := gostaticstorage.ObserveX86SDKCompilerText(source.observation.Header.CompilerObject,
		source.observation.ObjectInputs.BuiltinSource, source.request.Target, source.observation.ObjectInputs.Referenced)
	if err != nil {
		return nil, sdkASMDataContext("panic association lacks the complete actual header compiler object: %v", err)
	}
	if err := x86GoPanicTerminalGeneratedBodies(bodies, generated, source.guard.env["GOROOT"]); err != nil {
		return nil, err
	}
	calls, err := x86GoPanicTerminalAssemblyCalls(pkg, bodies, source.observation.Objects, source.observation.CPP,
		source.observation.Positions, source.guard.env["GOROOT"], budget)
	if err != nil {
		return nil, err
	}
	return &x86GoPanicTerminalSourceObservation{bodies: bodies, calls: calls}, errors.Join(private.Err(), source.guard.verifyInputs())
}

func x86GoPanicTerminalGeneratedBodies(bodies []x86GoPanicTerminalCompilerBody, generated []gostaticstorage.TextRecord, root string) error {
	index := make(map[string][]gostaticstorage.TextRecord)
	for _, text := range generated {
		index[text.Name] = append(index[text.Name], text)
	}
	normalize := func(text gostaticstorage.TextRecord) (gostaticstorage.TextRecord, bool) {
		text = x86GoPanicTerminalCloneText(text)
		for ordinal := range text.Positions {
			name, valid := originalGoObjectSourcePath(text.Positions[ordinal].File, root)
			if !valid {
				return text, false
			}
			text.Positions[ordinal].File = name
		}
		return text, true
	}
	for _, body := range bodies {
		candidates := index[body.declaration.nativeName]
		if len(candidates) != 1 {
			return sdkASMDataContext("panic body lacks its unique independently compiled source association")
		}
		actual, valid := normalize(candidates[0])
		selected, selectedValid := normalize(body.text)
		if !valid || !selectedValid || !reflect.DeepEqual(actual, selected) {
			return sdkASMDataContext("panic body differs between complete header compiler and actual selected archive")
		}
	}
	return nil
}
