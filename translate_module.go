package plan9asm

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/xgo-dev/llvm"
	"github.com/xgo-dev/plan9asm/internal/arm64"
	"github.com/xgo-dev/plan9asm/internal/x86"
)

// TranslateModule converts a parsed Plan 9 asm File into an llvm.Module.
//
// Caller owns the returned module and should call Dispose when finished.
func TranslateModule(file *File, opt Options) (llvm.Module, error) {
	if !opt.X87Mode.Valid() {
		return llvm.Module{}, fmt.Errorf("invalid x87 mode %d", opt.X87Mode)
	}
	if !opt.WASMABI.Valid() {
		return llvm.Module{}, fmt.Errorf("invalid wasm ABI %d", opt.WASMABI)
	}
	if file != nil {
		for _, fn := range file.Funcs {
			name := fn.Sym
			if opt.ResolveSym != nil {
				name = opt.ResolveSym(name)
			}
			if lease := opt.Sigs[name].FrameLease; lease != nil {
				if err := lease(); err != nil {
					return llvm.Module{}, fmt.Errorf("%s: %w", name, err)
				}
			}
		}
	}
	if file != nil && file.Arch == ArchAMD64 {
		if opt.Goarch == "" {
			opt.Goarch = "amd64"
		}
		var err error
		file, err = x86.PrepareFile(file, opt.Goarch, opt.TargetTriple)
		if err != nil {
			return llvm.Module{}, err
		}
	}
	// MRS is also accepted by the direct module builder. Validate it before
	// either path emits target-specific inline assembly.
	if file != nil && file.Arch == ArchARM64 && !arm64.IsTarget(opt.TargetTriple) {
		for _, fn := range file.Funcs {
			for _, ins := range fn.Instrs {
				switch ins.Op {
				case OpMRS, "MSR", "MRS_TPIDR_R0":
					return llvm.Module{}, fmt.Errorf("%w: %s in %s needs an AArch64 target", ErrProbeNeedsContext, ins.Op, fn.Sym)
				}
			}
		}
	}
	mod, err := translateModuleDirect(file, opt)
	if err == nil {
		return finishTranslatedModule(file, mod, opt.TargetTriple)
	}
	if err != nil && !errors.Is(err, errDirectModuleUnsupported) {
		return llvm.Module{}, err
	}

	ir, err := translateIRText(file, opt)
	if err != nil {
		return llvm.Module{}, err
	}
	mod, err = parseIRModule(ir)
	if err != nil {
		return llvm.Module{}, err
	}
	return finishTranslatedModule(file, mod, opt.TargetTriple)
}

func finishTranslatedModule(file *File, mod llvm.Module, triple string) (llvm.Module, error) {
	if triple != "" && targetInstructionSet(triple) != file.Arch {
		if err := checkCrossTargetModule(mod, triple); err != nil {
			mod.Dispose()
			return llvm.Module{}, err
		}
	}
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

func targetInstructionSet(triple string) Arch {
	cpu, _, _ := strings.Cut(strings.ToLower(triple), "-")
	switch {
	case cpu == "x86_64" || cpu == "x86_64h" || cpu == "amd64" || (len(cpu) == 4 && cpu[0] == 'i' && strings.HasSuffix(cpu, "86")):
		return ArchAMD64
	case arm64.IsTarget(triple):
		return ArchARM64
	case strings.HasPrefix(cpu, "arm") || strings.HasPrefix(cpu, "thumb"):
		return ArchARM
	case cpu == "wasm32" || cpu == "wasm64":
		return ArchWASM
	}
	return Arch(cpu)
}

// Inspect only mixed-ISA modules. The architecture preludes also contain unused
// declarations, so a declaration alone does not constrain the target.
func checkCrossTargetModule(mod llvm.Module, triple string) error {
	for fn := mod.FirstFunction(); !fn.IsNil(); fn = llvm.NextFunction(fn) {
		if fn.FirstBasicBlock().IsNil() {
			continue
		}
		for block := fn.FirstBasicBlock(); !block.IsNil(); block = llvm.NextBasicBlock(block) {
			for ins := block.FirstInstruction(); !ins.IsNil(); ins = llvm.NextInstruction(ins) {
				if ins.InstructionOpcode() != llvm.Call {
					continue
				}
				callee := ins.CalledValue()
				if !callee.IsAInlineAsm().IsNil() {
					// An empty compiler memory barrier is target independent.
					if !strings.Contains(callee.String(), `asm sideeffect "", "~{memory}"`) {
						return fmt.Errorf("%w: %s uses source-specific inline assembly on target %s", ErrProbeNeedsContext, fn.Name(), triple)
					}
					continue
				}
				name := callee.Name()
				for _, prefix := range []string{"llvm.x86.", "llvm.aarch64.", "llvm.arm.", "llvm.wasm.", "llvm.vscale."} {
					if strings.HasPrefix(name, prefix) {
						return fmt.Errorf("%w: %s uses %s on target %s", ErrProbeNeedsContext, fn.Name(), name, triple)
					}
				}
			}
		}
	}
	return nil
}

func parseIRModule(ir string) (llvm.Module, error) {
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
	ctx := llvm.GlobalContext()
	mod, err := (&ctx).ParseIR(buf)
	if err != nil {
		return llvm.Module{}, fmt.Errorf("parse generated ir: %w", err)
	}
	return mod, nil
}
