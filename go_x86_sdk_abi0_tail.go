package plan9asm

import (
	"bytes"
	"context"
	"encoding/binary"
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
	return file != nil && file.Arch == ArchAMD64 && len(sdkABI0TailHelpers(file)) != 0
}

// GoARM64SDKABI0TailCandidate selects the same-file continuation observer.
func GoARM64SDKABI0TailCandidate(file *File) bool {
	return file != nil && file.Arch == ArchARM64 && len(sdkABI0TailHelpers(file)) != 0
}

// GoARMSDKABI0TailCandidate reports ARM's same-file global continuation shape.
// The ordinary translator needs the SDK path to bind the caller's ABI0 frame.
func GoARMSDKABI0TailCandidate(file *File) bool {
	return file != nil && file.Arch == ArchARM && len(sdkABI0TailHelpers(file)) != 0
}

func sdkABI0TailEdge(arch Arch, ins Instr) bool {
	return (ins.Op == OpJMP || (arch == ArchARM || arch == ArchARM64) && (ins.Op == "B" || ins.Op == OpRET)) &&
		len(ins.Args) == 1 && ins.Args[0].Kind == OpSym
}

func sdkABI0TailHelpers(file *File) map[string]bool {
	var possible map[string]bool
	for _, fn := range file.Funcs {
		if !nativeName.MatchString(fn.Sym) || !abi0FramelessHelper(fn) || !arm64TailUsesFrame(fn) {
			continue
		}
		if possible == nil {
			possible = make(map[string]bool)
		}
		possible[fn.Sym] = true
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
			if !sdkABI0TailEdge(file.Arch, ins) {
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
) (*GoModuleTranslation, error) {
	if !x86SDK386OriginalTargetMatchesBackend(request.Target, opt) {
		return nil, sdkASMDataContext("global ABI0 tail needs the original target-matched 386 Go transport")
	}
	return translateGoSDKABI0TailModule(ctx, irCtx, request, opt, sdkASMDataOriginalSourceRole)
}

// TranslateGoARM64SDKABI0TailModuleInContext translates the typed caller
// entries and retains the actual relocation-free native ARM64 entry.
func TranslateGoARM64SDKABI0TailModuleInContext(ctx context.Context, irCtx llvm.Context,
	request GoSDKAssemblyCaptureRequest, opt GoModuleOptions,
) (*GoModuleTranslation, error) {
	triple := llvmNormalizedTargetTriple(opt.TargetTriple)
	if request.Target != "linux/arm64" || opt.GOOS != "linux" || opt.GOARCH != "arm64" ||
		!strings.HasPrefix(triple, "aarch64-") || !strings.Contains(triple, "-linux-") {
		return nil, sdkASMDataContext("global ABI0 tail needs the original little-endian Linux ARM64 target")
	}
	return translateGoSDKABI0TailModule(ctx, irCtx, request, opt, sdkASMDataARMTailRole)
}

// TranslateGoARMSDKABI0TailModuleInContext translates the typed ARM callers
// and retains the original A32 entry for native Go ABI0 callers.
func TranslateGoARMSDKABI0TailModuleInContext(ctx context.Context, irCtx llvm.Context,
	request GoSDKAssemblyCaptureRequest, opt GoModuleOptions,
) (*GoModuleTranslation, error) {
	triple := llvmNormalizedTargetTriple(opt.TargetTriple)
	if request.Target != "linux/arm" || opt.GOOS != "linux" || opt.GOARCH != "arm" ||
		!armWordFloatNativeTarget(triple) || !strings.HasPrefix(triple, "arm") || !strings.Contains(triple, "-linux-") {
		return nil, sdkASMDataContext("global ABI0 tail needs the original little-endian Linux ARM target")
	}
	return translateGoSDKABI0TailModule(ctx, irCtx, request, opt, sdkASMDataARMTailRole)
}

func translateGoSDKABI0TailModule(ctx context.Context, irCtx llvm.Context,
	request GoSDKAssemblyCaptureRequest, opt GoModuleOptions, role sdkASMDataCaptureRole,
) (result *GoModuleTranslation, resultErr error) {
	if opt.KeepFunc != nil || opt.ManualSig != nil || opt.Sizes != nil || opt.FrameSizes != nil ||
		opt.NumericalReads != nil || opt.X86TLSMoves != nil || opt.ARM64ByteCarrierSource != nil ||
		len(opt.ARM64ClosureABIs) != 0 || opt.SourcePreprocessed {
		return nil, sdkASMDataContext("global ABI0 tail needs the complete original SDK member")
	}
	source, err := captureGoX86SDKASMDataSourceRole(ctx, request, role)
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
	if objects == nil || objects.Target != request.Target ||
		len(objects.Sources) != len(pkg.SourceSelection.SelectedAssemblyFiles) {
		return nil, sdkASMDataContext("global ABI0 tail lost its target-matched source objects")
	}
	for ordinal, name := range pkg.SourceSelection.SelectedAssemblyFiles {
		if name == opt.FileName {
			if opt.ResolveSym == nil {
				prefix := gosym.PackagePrefix(request.PackagePath)
				opt.ResolveSym = func(symbol string) string {
					return numericalNativeName(goStripABISuffix(symbol), prefix)
				}
			}
			return translateSDKABI0Tail(irCtx, pkg, pkg.SourceSelection.Assembly[name], objects.Sources[ordinal], opt)
		}
	}
	return nil, sdkASMDataContext("global ABI0 tail has no matching original SDK member")
}

func translateSDKABI0Tail(ctx llvm.Context, pkg GoPackage, original *File,
	object gostaticstorage.ASMDataSourceObservation, opt GoModuleOptions,
) (*GoModuleTranslation, error) {
	helpers := sdkABI0TailHelpers(original)
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
		native.WriteString(".text\n")
		if original.Arch == ArchARM {
			native.WriteString(".arm\n")
		}
		fmt.Fprintf(&native, ".p2align 4\n.globl %s\n", fn.Sym)
		if opt.GOOS == "windows" {
			// Module assembly retains the Go name verbatim. LLVM's C ABI
			// decoration applies to the separate typed wrapper definitions.
			fmt.Fprintf(&native, ".def %s; .scl 2; .type 32; .endef\n", fn.Sym)
		} else {
			fmt.Fprintf(&native, ".type %s,%%function\n", fn.Sym)
		}
		fmt.Fprintf(&native, "%s:\n", fn.Sym)
		if original.Arch == ArchARM64 || original.Arch == ArchARM {
			if len(first.Code)%4 != 0 {
				return nil, sdkASMDataContext("global ARM helper %s does not have complete instruction words", fn.Sym)
			}
			for code := first.Code; len(code) != 0; code = code[4:] {
				fmt.Fprintf(&native, ".inst 0x%08x\n", binary.LittleEndian.Uint32(code))
			}
		} else {
			native.WriteString(".byte ")
			for i, value := range first.Code {
				if i != 0 {
					native.WriteByte(',')
				}
				fmt.Fprint(&native, value)
			}
			native.WriteByte('\n')
		}
		if opt.GOOS != "windows" {
			fmt.Fprintf(&native, ".size %[1]s,.-%[1]s\n", fn.Sym)
		}
	}

	projected, err := projectSDKABI0Tail(original, helpers)
	if err != nil {
		return nil, err
	}
	var tailSigs map[string]FuncSig
	switch original.Arch {
	case ArchARM:
		projected, tailSigs, err = prepareSDKARMABI0Tails(pkg, projected, helpers, opt.ResolveSym)
		if err != nil {
			return nil, err
		}
	case ArchARM64:
		tailSigs, err = goBindARM64ABI0TailDeclarations(pkg, projected, opt.ResolveSym, opt)
		if err != nil {
			return nil, err
		}
		if len(tailSigs) == 0 {
			return nil, sdkASMDataContext("global ARM64 tails need the original ABI0 caller declarations")
		}
		projected, err = PrepareGoARM64ABI0TailContinuations(projected, tailSigs, opt.ResolveSym)
		if err != nil {
			return nil, err
		}
	}
	sigs, err := goSigsForAsmFile(pkg, projected, opt.ResolveSym, opt.GOARCH, nil, nil, nil)
	if err != nil {
		return nil, err
	}
	if err := rebindARM64ABI0TailDeclarations(sigs, tailSigs); err != nil {
		return nil, err
	}
	if original.Arch == ArchARM {
		for name, sig := range tailSigs {
			sigs[name] = sig
		}
	}
	options := Options{Goarch: opt.GOARCH, TargetTriple: opt.TargetTriple, ResolveSym: opt.ResolveSym,
		Sigs: sigs, AnnotateSource: opt.AnnotateSource, X87Mode: opt.X87Mode, goPackage: &pkg}
	module, err := TranslateModuleInContext(ctx, projected, options)
	if err != nil {
		return nil, err
	}
	if original.Arch == ArchARM {
		for name := range tailSigs {
			if err := proveSDKARMTailDefinitions(module.NamedFunction(name)); err != nil {
				module.Dispose()
				return nil, err
			}
		}
	}
	if err := promoteSDKTailFrame(module); err != nil {
		module.Dispose()
		return nil, fmt.Errorf("promote SDK %s tail registers and frame slots: %w", opt.GOARCH, err)
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

// Frame slots contain target-sized pointers. Give LLVM its actual target layout
// before scalarizing the frame and promoting virtual registers into SSA.
func promoteSDKTailFrame(module llvm.Module) error {
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
func projectSDKABI0Tail(original *File, helpers map[string]bool) (*File, error) {
	file := x86DirectTailSnapshot(original)
	for i := range file.Funcs {
		fn := &file.Funcs[i]
		if helpers[fn.Sym] {
			fn.Instrs[0].Raw = strings.Replace(fn.Instrs[0].Raw, fn.Sym+"(SB)", fn.Sym+"<>(SB)", 1)
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
				if !sdkABI0TailEdge(file.Arch, *ins) || offset != 0 ||
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
