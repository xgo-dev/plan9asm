package plan9asm

import (
	"errors"
	"fmt"
	"os"

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
func TranslateModuleInContext(ctx llvm.Context, file *File, opt Options) (llvm.Module, error) {
	file, err := normalizeX86RawFile(file, opt.Goarch)
	if err != nil {
		return llvm.Module{}, err
	}
	file, err = coalesceX86Continuations(file, opt)
	if err != nil {
		return llvm.Module{}, err
	}
	mod, err := translateModuleDirectInContext(ctx, file, opt)
	if err == nil {
		return finishTranslatedModule(file, mod)
	}
	if err != nil && !errors.Is(err, errDirectModuleUnsupported) {
		return llvm.Module{}, err
	}

	ir, err := translateIRText(file, opt)
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
	f, err := os.CreateTemp("", "plan9asm-*.ll")
	if err != nil {
		return llvm.Module{}, fmt.Errorf("create temp ir file: %w", err)
	}
	name := f.Name()
	_ = f.Close()
	defer os.Remove(name)

	if err := os.WriteFile(name, []byte(ir), 0644); err != nil {
		return llvm.Module{}, fmt.Errorf("write temp ir file: %w", err)
	}
	buf, err := llvm.NewMemoryBufferFromFile(name)
	if err != nil {
		return llvm.Module{}, fmt.Errorf("open temp ir file: %w", err)
	}
	// NOTE: do not dispose MemoryBuffer here. In this llvm binding, ParseIR
	// may take ownership and disposing the buffer can crash.
	mod, err := (&ctx).ParseIR(buf)
	if err != nil {
		return llvm.Module{}, fmt.Errorf("parse generated ir: %w", err)
	}
	return mod, nil
}
