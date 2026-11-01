package plan9asm

import (
	"errors"
	"fmt"

	"github.com/xgo-dev/llvm"
)

// TranslateModule converts a parsed Plan 9 asm File into an llvm.Module.
//
// Caller owns the returned module and should call Dispose when finished.
func TranslateModule(file *File, opt Options) (llvm.Module, error) {
	return TranslateModuleInContext(llvm.GlobalContext(), file, opt)
}

// TranslateModuleInContext builds the module in a caller-owned LLVM context.
// Dispose the returned module before disposing ctx. High-volume callers should
// create a fresh context per file so LLVM can release context-owned caches.
func TranslateModuleInContext(ctx llvm.Context, file *File, opt Options) (result llvm.Module, resultErr error) {
	if err := validateBackendSourceGoarch(file, opt); err != nil {
		return llvm.Module{}, err
	}
	// Register first so this also checks early byte-carrier returns, after
	// every source-owner completion guard. Never return a partial module when
	// its actual LLVM target cannot represent the emitted operations.
	defer func() {
		if result.IsNil() {
			return
		}
		if resultErr == nil && file != nil && file.Arch == ArchARM64 {
			resultErr = completeARM64SVECountFeatures(result)
		}
		if resultErr == nil {
			resultErr = validateTranslatedBackend(file, opt, result)
		}
		if resultErr != nil {
			result.Dispose()
			result = llvm.Module{}
		}
	}()
	callOriginal := file
	if opt.x86OriginalFile != nil {
		callOriginal = opt.x86OriginalFile
	}
	boolCalls := opt.x86BoolCallSource
	var err error
	if boolCalls == nil {
		boolCalls, err = prepareX86ABI0BoolCalls(callOriginal, opt)
	} else {
		err = boolCalls.verify()
	}
	if err != nil {
		return llvm.Module{}, err
	}
	if boolCalls != nil {
		opt.x86BoolCallSource = boolCalls
		defer func() {
			if err := boolCalls.verify(); err != nil {
				if !result.IsNil() {
					result.Dispose()
				}
				result = llvm.Module{}
				resultErr = errors.Join(resultErr, err)
			}
		}()
	}
	file, err = PrepareX86DirectTailSource(file, opt)
	if err != nil {
		return llvm.Module{}, err
	}
	if file != nil && file.x86DirectTails != nil {
		graph, request := file.x86DirectTails, file
		defer func() {
			if err := graph.verify(request, opt); err != nil {
				if !result.IsNil() {
					result.Dispose()
				}
				result = llvm.Module{}
				resultErr = errors.Join(resultErr, err)
			}
		}()
	}
	if err := rejectMixedNativeAuthorities(opt.NumericalReads, opt.ARM64ByteCarrierSource); err != nil {
		return llvm.Module{}, err
	}
	if opt.ARM64ByteCarrierSource != nil {
		return translateARM64ByteCarrierModule(ctx, file, opt)
	}
	originalFile, originalOptions := file, opt
	file, opt, err = freezeTLSMoveInputs(file, opt)
	if err != nil {
		return llvm.Module{}, err
	}
	defer func() {
		if err := finishTLSMoves(originalFile, originalOptions); err != nil {
			if !result.IsNil() {
				result.Dispose()
			}
			result, resultErr = llvm.Module{}, errors.Join(resultErr, err)
		}
	}()
	file, opt, err = freezeNumericalReadInputs(file, opt)
	if err != nil {
		return llvm.Module{}, err
	}
	defer func() {
		if err := finishNumericalReads(originalFile, originalOptions); err != nil {
			if !result.IsNil() {
				result.Dispose()
			}
			result = llvm.Module{}
			resultErr = errors.Join(resultErr, err)
		}
	}()
	bindings, err := verifyX86FixedLocalBindings(file, opt)
	if err != nil {
		return llvm.Module{}, err
	}
	file, err = freezeX86FixedLocalFile(file, bindings)
	if err != nil {
		return llvm.Module{}, err
	}
	opt, err = freezeX86FixedLocalOptions(opt, bindings)
	if err != nil {
		return llvm.Module{}, err
	}
	if len(bindings) != 0 {
		// The actual fixed-local source is independently reparsed, so none of
		// the earlier certificates survive. Rejoin the current sealed numerical
		// token by the complete source and exact original instruction ordinal.
		if err := joinNumericalReadCertificates(file, opt); err != nil {
			return llvm.Module{}, err
		}
	}
	defer func() {
		if err := finishX86FixedLocalBindings(bindings); err != nil {
			if !result.IsNil() {
				result.Dispose()
			}
			result = llvm.Module{}
			resultErr = errors.Join(resultErr, err)
		}
	}()
	if err := validateARMMachineEntryArchitecture(file, opt); err != nil {
		return llvm.Module{}, err
	}
	if err := validateARMWordFloatNativeTarget(file, opt); err != nil {
		return llvm.Module{}, err
	}
	if err := validateARM64NativeTargets(file, opt); err != nil {
		return llvm.Module{}, err
	}
	resolve := opt.ResolveSym
	if resolve == nil {
		resolve = func(symbol string) string { return symbol }
	}
	if err := validateARM64ClosureFile(file, opt, resolve); err != nil {
		return llvm.Module{}, err
	}
	if err := validateFileResolvedImmediates(file); err != nil {
		return llvm.Module{}, err
	}
	if err := validateX86TLSMoveFile(file, opt.Goarch); err != nil {
		return llvm.Module{}, err
	}
	if err := validateX86GPSIMDTransferFile(file, opt.Goarch); err != nil {
		return llvm.Module{}, err
	}
	file, err = PrepareGoARM64ABI0TailContinuations(file, opt.Sigs, resolve)
	if err != nil {
		return llvm.Module{}, err
	}
	file, err = normalizeX86RawFile(file, opt.Goarch, opt)
	if err != nil {
		return llvm.Module{}, err
	}
	// The direct emitter may use a derived address view. A textual fallback
	// must start from the sealed source and derive its own lowering view.
	sourceForFallback := file
	file, err = normalizeX86SourceIntegerAddresses(file, opt)
	if err != nil {
		return llvm.Module{}, err
	}
	file, err = coalesceX86Continuations(file, opt)
	if err != nil {
		return llvm.Module{}, err
	}
	if graph := file.x86ContinuationGraph; graph != nil {
		request := file
		defer func() {
			if err := graph.verify(request, opt); err != nil {
				if !result.IsNil() {
					result.Dispose()
				}
				result, resultErr = llvm.Module{}, errors.Join(resultErr, err)
			}
		}()
	}
	if err := verifyNormalizedNumericalReads(file, opt); err != nil {
		return llvm.Module{}, err
	}
	mod, err := translateModuleDirectInContext(ctx, file, opt)
	if err == nil {
		return finishTranslatedModule(file, mod)
	}
	if err != nil && !errors.Is(err, errDirectModuleUnsupported) {
		return llvm.Module{}, err
	}

	var fixedLocalResult *x86FixedLocalResultSnapshot
	if len(bindings) == 1 {
		// Share only pure original-source calculations within this call. The
		// live module completion guard above still runs after every consumer.
		// freezeX86FixedLocalFile already rejects multiple source owners.
		fixedLocalResult, err = newX86FixedLocalResultSnapshot(bindings[0], opt.Goarch)
		if err != nil {
			return llvm.Module{}, err
		}
	}
	ir, err := translateIRTextWithFixedLocalResult(sourceForFallback, opt, fixedLocalResult)
	if err != nil {
		return llvm.Module{}, err
	}
	mod, err = parseIRModuleInContext(ctx, ir)
	if err != nil {
		return llvm.Module{}, err
	}
	return finishTranslatedModule(file, mod)
}

func finishTranslatedModule(file *File, mod llvm.Module) (llvm.Module, error) {
	if file.Arch != ArchWASM {
		return mod, nil
	}

	// WebAssembly Plan 9 assembly names virtual registers explicitly. The
	// textual lowering models those mutable locals with entry-block allocas so
	// structured branches remain straightforward and verifiable. Promote them
	// before returning the module: leaving the allocas for an unoptimized clang
	// invocation spills every virtual register into linear memory and makes the
	// generated wasm both larger and slower.
	pbo := llvm.NewPassBuilderOptions()
	defer pbo.Dispose()
	if err := mod.RunPasses("mem2reg", llvm.TargetMachine{}, pbo); err != nil {
		mod.Dispose()
		return llvm.Module{}, fmt.Errorf("promote wasm virtual registers: %w", err)
	}
	return mod, nil
}

func parseIRModule(ir string) (llvm.Module, error) {
	return parseIRModuleInContext(llvm.GlobalContext(), ir)
}

func parseIRModuleInContext(ctx llvm.Context, ir string) (llvm.Module, error) {
	buf := llvmIRMemoryBuffer(ir)
	// LLVM22 ParseIR consumes this buffer on both success and error. The caller
	// still owns a successful module and must dispose it before its context.
	mod, err := (&ctx).ParseIR(buf)
	if err != nil {
		return llvm.Module{}, fmt.Errorf("parse generated ir: %w", err)
	}
	return mod, nil
}
