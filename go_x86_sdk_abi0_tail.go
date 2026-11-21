package plan9asm

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/xgo-dev/llvm"
	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
	"github.com/xgo-dev/plan9asm/internal/gosym"
)

// GoX86SDKABI0TailCandidate only routes a context failure to the SDK observer.
// The source, callers and original assembler object still need verification.
func GoX86SDKABI0TailCandidate(file *File) bool {
	return len(x86SDKABI0TailHelpers(file)) != 0
}

func x86SDKABI0TailHelpers(file *File) map[string]bool {
	if file == nil || file.Arch != ArchAMD64 {
		return nil
	}
	var possible map[string]bool
	for _, fn := range file.Funcs {
		if fn.FrameSize != 0 || fn.ArgSize != 0 || !nativeName.MatchString(fn.Sym) ||
			len(fn.Instrs) < 2 || fn.Instrs[0].Op != OpTEXT {
			continue
		}
		_, operands := splitOpcode(fn.Instrs[0].Raw)
		fields := strings.Split(operands, ",")
		if len(fields) != 3 {
			continue
		}
		flags, ok := parseImmExpr(strings.TrimSpace(fields[1]))
		if !ok || flags != 4|512 { // Go objabi NOSPLIT | NOFRAME.
			continue
		}
		for _, ins := range fn.Instrs[1:] {
			for _, arg := range ins.Args {
				if arg.Kind == OpFP {
					if possible == nil {
						possible = make(map[string]bool)
					}
					possible[fn.Sym] = true
				}
			}
		}
	}
	if len(possible) == 0 {
		return nil
	}
	helpers := make(map[string]bool)
	for _, fn := range file.Funcs {
		if possible[fn.Sym] || fn.FrameSize != 0 || fn.ArgSize <= 0 || !strings.HasPrefix(fn.Sym, "·") {
			continue
		}
		for _, ins := range fn.Instrs {
			if ins.Op != OpJMP || len(ins.Args) != 1 || ins.Args[0].Kind != OpSym {
				continue
			}
			name, offset, valid := parseSBRef(ins.Args[0].Sym)
			if valid && offset == 0 && possible[name] {
				helpers[name] = true
			}
		}
	}
	return helpers
}

// TranslateGoX86SDKABI0TailModuleInContext lowers same-file ABI0 continuation
// edges using the caller's typed frame and reaching register values. It keeps
// a global helper's original machine entry for independently assembled callers.
// The caller owns the returned module and its LLVM context.
func TranslateGoX86SDKABI0TailModuleInContext(ctx context.Context, irCtx llvm.Context,
	request GoX86SDKASMDataCaptureRequest, opt GoModuleOptions,
) (result *GoModuleTranslation, resultErr error) {
	triple := llvmNormalizedTargetTriple(opt.TargetTriple)
	if request.Target != "linux/386" || opt.GOOS != "linux" || opt.GOARCH != "386" ||
		!strings.Contains(triple, "-linux-") || !x86ScalarFloatIntegerNativeTarget("386", triple) ||
		opt.KeepFunc != nil || opt.ManualSig != nil || opt.Sizes != nil || opt.FrameSizes != nil ||
		opt.NumericalReads != nil || opt.X86TLSMoves != nil || opt.ARM64ByteCarrierSource != nil ||
		len(opt.ARM64ClosureABIs) != 0 || opt.SourcePreprocessed {
		return nil, sdkASMDataContext("global ABI0 tail needs the complete original Linux i386 member")
	}
	source, err := captureGoX86SDKASMDataSourceRole(ctx, request, sdkASMDataOriginalSourceRole)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := errors.Join(source.Verify(ctx), source.Close()); err != nil {
			if result != nil {
				result.Module.Dispose()
			}
			result, resultErr = nil, errors.Join(resultErr, err)
		}
	}()
	pkg, err := source.typedPackage(source.observation.Header.LanguageVersion)
	if err != nil {
		return nil, err
	}
	objects := source.observation.Objects
	for ordinal, name := range pkg.SourceSelection.SelectedAssemblyFiles {
		if name == opt.FileName && objects != nil && ordinal < len(objects.Sources) {
			if opt.ResolveSym == nil {
				prefix := gosym.PackagePrefix(request.PackagePath)
				opt.ResolveSym = func(symbol string) string {
					return numericalNativeName(goStripABISuffix(symbol), prefix)
				}
			}
			return translateSDK386ABI0Tail(irCtx, pkg, pkg.SourceSelection.Assembly[name], objects.Sources[ordinal], opt)
		}
	}
	return nil, sdkASMDataContext("global ABI0 tail has no matching original SDK member")
}

func translateSDK386ABI0Tail(ctx llvm.Context, pkg GoPackage, original *File,
	object gostaticstorage.ASMDataSourceObservation, opt GoModuleOptions,
) (*GoModuleTranslation, error) {
	helpers := x86SDKABI0TailHelpers(original)
	if len(helpers) == 0 || len(object.TextOrder) != len(original.Funcs) {
		return nil, sdkASMDataContext("original source has no complete global ABI0 tail inventory")
	}
	var native strings.Builder
	for ordinal, fn := range original.Funcs {
		if !helpers[fn.Sym] {
			continue
		}
		identity := object.TextOrder[ordinal]
		index := identity.ObjectOrdinal
		if identity.SourceOrdinal != ordinal || identity.Name != fn.Sym || identity.ABI != 0 ||
			identity.Namespace != gostaticstorage.TextSymbolNonpkgDefinition || opt.ResolveSym(fn.Sym) != fn.Sym ||
			index < 0 || index >= len(object.Original.Texts) || index >= len(object.Expanded.Texts) {
			return nil, sdkASMDataContext("global ABI0 helper %s changed its physical symbol identity", fn.Sym)
		}
		first, second := object.Original.Texts[index], object.Expanded.Texts[index]
		if first.Name != fn.Sym || first.Index != identity.Index || len(first.Code) == 0 ||
			first.Size != int64(len(first.Code)) || len(first.Relocations) != 0 ||
			len(second.Relocations) != 0 || !bytes.Equal(first.Code, second.Code) {
			return nil, sdkASMDataContext("global ABI0 helper %s needs its exact relocation-free native code", fn.Sym)
		}
		fmt.Fprintf(&native, ".text\n.p2align 4\n.globl %[1]s\n.type %[1]s,@function\n%[1]s:\n.byte ", fn.Sym)
		for i, value := range first.Code {
			if i != 0 {
				native.WriteByte(',')
			}
			fmt.Fprint(&native, value)
		}
		fmt.Fprintf(&native, "\n.size %[1]s,.-%[1]s\n", fn.Sym)
	}

	projected, err := projectSDK386ABI0Tail(original, helpers)
	if err != nil {
		return nil, err
	}
	sigs, err := goSigsForAsmFile(pkg, projected, opt.ResolveSym, "386", nil, nil, nil)
	if err != nil {
		return nil, err
	}
	options := Options{Goarch: "386", TargetTriple: opt.TargetTriple, ResolveSym: opt.ResolveSym,
		Sigs: sigs, AnnotateSource: opt.AnnotateSource, X87Mode: opt.X87Mode, goPackage: &pkg}
	module, err := TranslateModuleInContext(ctx, projected, options)
	if err != nil {
		return nil, err
	}
	if err := promoteSDK386TailFrame(module); err != nil {
		module.Dispose()
		return nil, fmt.Errorf("promote SDK i386 tail registers and frame slots: %w", err)
	}
	var functions []GoFunction
	for _, fn := range original.Funcs {
		name := opt.ResolveSym(fn.Sym)
		if helpers[fn.Sym] {
			if name != fn.Sym || !module.NamedGlobal(name).IsNil() || !module.NamedFunction(name).IsNil() {
				module.Dispose()
				return nil, sdkASMDataContext("global ABI0 helper %s collided with a typed definition", fn.Sym)
			}
			continue
		}
		if emitted := module.NamedFunction(name); !emitted.IsNil() && emitted.BasicBlocksCount() != 0 {
			functions = append(functions, GoFunction{TextSymbol: fn.Sym, ResolvedSymbol: name})
		}
	}
	if llvmModuleHasAssembly(module) {
		module.Dispose()
		return nil, sdkASMDataContext("global ABI0 helpers need their own original module assembly")
	}
	module.SetInlineAsm(native.String())
	if err := validateTranslatedBackend(projected, options, module); err != nil {
		module.Dispose()
		return nil, err
	}
	return &GoModuleTranslation{Module: module, Signatures: sigs, Functions: functions}, nil
}

var sdkTailLLVMTargets sync.Once

// Frame slots contain target-sized pointers. Give LLVM its actual i386 layout
// before scalarizing the frame and promoting virtual registers into SSA.
func promoteSDK386TailFrame(module llvm.Module) error {
	sdkTailLLVMTargets.Do(func() {
		llvm.InitializeAllTargetInfos()
		llvm.InitializeAllTargets()
		llvm.InitializeAllTargetMCs()
	})
	triple := module.Target()
	target, err := llvm.GetTargetFromTriple(triple)
	if err != nil {
		return err
	}
	machine := target.CreateTargetMachine(triple, "", "", llvm.CodeGenLevelDefault, llvm.RelocDefault, llvm.CodeModelDefault)
	if machine.C == nil {
		return fmt.Errorf("LLVM has no target machine for %q", triple)
	}
	defer machine.Dispose()
	layout := machine.CreateTargetData()
	defer layout.Dispose()
	module.SetDataLayout(layout.String())
	passes := llvm.NewPassBuilderOptions()
	defer passes.Dispose()
	return module.RunPasses("function(sroa,mem2reg,instcombine,simplifycfg)", machine, passes)
}

// Private aliases are an IR projection only. Native names are retained in the
// module assembly. Only direct same-file tail branches can see the aliases.
func projectSDK386ABI0Tail(original *File, helpers map[string]bool) (*File, error) {
	file := x86DirectTailSnapshot(original)
	for i := range file.Funcs {
		fn := &file.Funcs[i]
		if helpers[fn.Sym] {
			fn.Sym += "<>"
		}
		for ordinal := range fn.Instrs {
			ins := &fn.Instrs[ordinal]
			for k, arg := range ins.Args {
				symbol := arg.Sym
				if arg.Kind == OpMem {
					symbol = arg.Mem.Sym
				}
				name, offset, valid := parseSBRef(strings.TrimPrefix(symbol, "$"))
				if !valid || !helpers[name] {
					continue
				}
				if ins.Op != OpJMP || len(ins.Args) != 1 || arg.Kind != OpSym || offset != 0 ||
					strings.HasPrefix(symbol, "$") {
					return nil, sdkASMDataContext("global ABI0 helper is used outside a direct tail: %s", ins.Raw)
				}
				ins.Args[k].Sym = name + "<>(SB)"
			}
		}
	}
	for _, data := range file.Data {
		name, _, valid := parseSBRef(strings.TrimPrefix(data.Addr, "$"))
		if helpers[data.Sym] || valid && helpers[name] {
			return nil, sdkASMDataContext("global ABI0 helper address escapes through DATA")
		}
	}
	for _, global := range file.Globl {
		if helpers[global.Sym] {
			return nil, sdkASMDataContext("global ABI0 helper also names storage")
		}
	}
	return file, nil
}
