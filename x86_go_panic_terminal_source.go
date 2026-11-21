package plan9asm

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"

	"github.com/xgo-dev/llvm"
	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
	"github.com/xgo-dev/plan9asm/internal/gosym"
)

// The capture is retained through translation. Only its exact original CALLs
// can lose the normal successor; the call's side effects and unwind remain.
type x86GoPanicTerminalSourceObservation struct {
	pkg    GoPackage
	bodies []x86GoPanicTerminalCompilerBody
	calls  []x86GoPanicTerminalAssemblyCall
}

func (source *GoX86SDKASMDataSource) panicTerminalObservation(ctx context.Context, budget *x86ResultFlowBudget) (observed *x86GoPanicTerminalSourceObservation, result error) {
	if source == nil || source.identity != source || source.guard == nil || source.guard != source.originalGuard ||
		source.captureRole != sdkASMDataOriginalSourceRole || !x86SDK386OriginalTarget(source.request.Target) || budget == nil ||
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
		source.observation.Objects.Target != source.request.Target ||
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
	return &x86GoPanicTerminalSourceObservation{pkg: pkg, bodies: bodies, calls: calls}, errors.Join(private.Err(), source.guard.verifyInputs())
}

// TranslateGoX86SDKPanicTerminalModuleInContext translates a selected Linux
// or Windows 386 SDK member with its original non-returning Go CALLs. The
// capture remains live until translation and symbol resolution finish.
func TranslateGoX86SDKPanicTerminalModuleInContext(ctx context.Context, irCtx llvm.Context,
	request GoX86SDKASMDataCaptureRequest, opt GoModuleOptions,
) (result *GoModuleTranslation, resultErr error) {
	if !x86SDK386OriginalTargetMatchesBackend(request.Target, opt) ||
		opt.ManualSig != nil || opt.Sizes != nil || opt.FrameSizes != nil ||
		opt.NumericalReads != nil || opt.X86TLSMoves != nil || opt.ARM64ByteCarrierSource != nil ||
		len(opt.ARM64ClosureABIs) != 0 {
		return nil, sdkASMDataContext("panic CALL translation needs the original target-matched 386 Go transport")
	}
	source, err := captureGoX86SDKASMDataSourceRole(ctx, request, sdkASMDataOriginalSourceRole)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := source.Close(); err != nil {
			if result != nil {
				result.Module.Dispose()
			}
			result, resultErr = nil, errors.Join(resultErr, err)
		}
	}()
	observation, err := source.panicTerminalObservation(ctx, new(x86ResultFlowBudget))
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := source.Verify(ctx); err != nil {
			if result != nil {
				result.Module.Dispose()
			}
			result, resultErr = nil, errors.Join(resultErr, err)
		}
	}()
	if opt.ResolveSym == nil {
		prefix := gosym.PackagePrefix(request.PackagePath)
		opt.ResolveSym = func(symbol string) string {
			return numericalNativeName(goStripABISuffix(symbol), prefix)
		}
	}
	for index, filename := range observation.pkg.SourceSelection.SelectedAssemblyFiles {
		if filename != opt.FileName {
			continue
		}
		opt.SourcePreprocessed, opt.x86PanicCalls = true, observation
		src := source.observation.CPP[index].Output
		return translateGoModuleInContext(irCtx, observation.pkg, []byte(src), opt)
	}
	return nil, sdkASMDataContext("panic CALL member differs from the selected SDK input")
}

func (observation *x86GoPanicTerminalSourceObservation) bindMember(file *File, member string) error {
	if !reflect.DeepEqual(file, observation.pkg.SourceSelection.Assembly[member]) {
		return sdkASMDataContext("panic CALL member lost its original complete instruction inventory")
	}
	functions := make(map[string]*Func, len(file.Funcs))
	for i := range file.Funcs {
		fn := &file.Funcs[i]
		functions[fn.Sym] = fn
	}
	for _, call := range observation.calls {
		if call.file != member {
			continue
		}
		fn := functions[call.function]
		if fn == nil || call.ordinal < 0 || call.ordinal >= len(fn.Instrs) ||
			!reflect.DeepEqual(fn.Instrs[call.ordinal], call.instruction) {
			return sdkASMDataContext("original panic CALL moved or changed")
		}
		if fn.x86PanicCalls == nil {
			fn.x86PanicCalls = make(map[string]x86GoPanicTerminalAssemblyCall)
		}
		fn.x86PanicCalls[call.instruction.Raw] = call
	}
	return nil
}

func (fn Func) x86PanicTarget(ins Instr) string {
	if ins.Op == OpCALL {
		if call, ok := fn.x86PanicCalls[ins.Raw]; ok && reflect.DeepEqual(ins, call.instruction) {
			return call.target
		}
	}
	return ""
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
