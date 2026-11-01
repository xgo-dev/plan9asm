package plan9asm

import (
	"bytes"
	"context"
	"encoding/json"
	"go/ast"
	"go/types"
	"path/filepath"
	"reflect"
	"strings"
)

type arm64ScratchBinding struct {
	source     *GoARM64ScratchSource
	context    context.Context
	file       *File
	target     string
	sigs       map[string][]byte
	symbols    map[string]string
	closed     map[string]bool
	calls      map[string]string
	calleeSigs map[string][]byte
}

// GoARM64ScratchBindingNeeded is only a capture scheduling predicate. It does
// not certify a callee or authorize its memory/frame/ABI effects.
func GoARM64ScratchBindingNeeded(file *File) bool {
	if file == nil || file.Arch != ArchARM64 {
		return false
	}
	for _, function := range file.Funcs {
		if function.FrameSize < 32752 {
			continue
		}
		for _, instruction := range function.Instrs {
			if (instruction.Op == "CALL" || instruction.Op == "BL") && len(instruction.Args) == 1 &&
				instruction.Args[0].Kind == OpSym && strings.HasSuffix(instruction.Args[0].Sym, "(SB)") &&
				!strings.Contains(instruction.Args[0].Sym, "<") {
				return true
			}
		}
	}
	return false
}

func arm64ScratchFileSnapshot(file *File) *File {
	copy := *file
	copy.Funcs = make([]Func, len(file.Funcs))
	for i, function := range file.Funcs {
		copy.Funcs[i] = arm64PrivateTailSnapshot(function)
	}
	copy.Data = append([]DataStmt(nil), file.Data...)
	for i := range copy.Data {
		copy.Data[i].Payload = append([]byte(nil), file.Data[i].Payload...)
	}
	copy.Globl = append([]GloblStmt(nil), file.Globl...)
	copy.UnlinkedPrelude = append([]string(nil), file.UnlinkedPrelude...)
	return &copy
}

func arm64ScratchPublicSignature(sig FuncSig) []byte {
	data, _ := json.Marshal(sig)
	return data
}

// BindScratchClosure preserves actual declarations and whole original source.
// The producer cannot be manufactured with a manual FuncSig or JSON proof.
func (source *GoARM64ScratchSource) BindScratchClosure(ctx context.Context, file *File, options Options) (Options, error) {
	if err := source.Verify(ctx); err != nil {
		return Options{}, err
	}
	if file == nil || file.Arch != ArchARM64 || options.Goarch != "arm64" || options.ResolveSym == nil ||
		!reflect.DeepEqual(arm64ScratchFileSnapshot(file), arm64ScratchFileSnapshot(source.file)) {
		return Options{}, arm64ScratchContext("complete original source differs from actual selection")
	}
	targets := map[string]string{
		"aarch64-unknown-linux-gnu": "linux/arm64",
		"arm64-apple-darwin":        "darwin/arm64",
		"aarch64-apple-darwin":      "darwin/arm64",
		"arm64-apple-macosx":        "darwin/arm64",
		"aarch64-pc-windows-msvc":   "windows/arm64",
	}
	if targets[options.TargetTriple] != source.request.Target || options.WASMABI != WASMABIDirect || len(options.X86TailGroups) != 0 {
		return Options{}, arm64ScratchContext("consumer target differs from the native object")
	}
	binding := &arm64ScratchBinding{source: source, context: ctx, file: arm64ScratchFileSnapshot(file),
		target: options.TargetTriple, sigs: make(map[string][]byte), symbols: make(map[string]string), closed: make(map[string]bool), calls: make(map[string]string), calleeSigs: make(map[string][]byte)}
	calleeLayouts := make(map[string]FuncSig)
	for _, function := range file.Funcs {
		if strings.Contains(function.Sym, "<") || !strings.HasPrefix(function.Sym, "·") {
			return Options{}, arm64ScratchContext("initial binding requires ordinary same-package source definitions")
		}
		name := options.ResolveSym(function.Sym)
		if name == "" || binding.sigs[name] != nil {
			return Options{}, arm64ScratchContext("empty or colliding LLVM declaration identity")
		}
		object, ok := source.actual.Types.Scope().Lookup(strings.TrimPrefix(function.Sym, "·")).(*types.Func)
		if !ok || !arm64ScratchBodyless(source.actual.Syntax, object.Name()) {
			return Options{}, arm64ScratchContext("source has no actual bodyless declaration")
		}
		expected, err := DeriveGoFuncABI0Signature(name, object, "arm64", types.SizesFor("gc", "arm64"))
		actual, present := options.Sigs[name]
		if err != nil || !present || !bytes.Equal(arm64ScratchPublicSignature(expected), arm64ScratchPublicSignature(actual)) || binding.symbols[function.Sym] != "" {
			return Options{}, arm64ScratchContext("typed source/LLVM declaration changed")
		}
		binding.sigs[name], binding.symbols[function.Sym] = arm64ScratchPublicSignature(actual), name
	}
	for _, function := range file.Funcs {
		for _, instruction := range function.Instrs {
			if (instruction.Op != "CALL" && instruction.Op != "BL") || len(instruction.Args) != 1 || instruction.Args[0].Kind != OpSym {
				continue
			}
			symbol := strings.TrimSuffix(instruction.Args[0].Sym, "(SB)")
			if strings.Contains(symbol, "<") {
				continue
			}
			canonical := strings.ReplaceAll(symbol, "·", ".")
			if strings.HasPrefix(canonical, ".") {
				canonical = source.actual.Path + canonical
			}
			if captured, closed := source.closed[canonical]; closed {
				name := options.ResolveSym(symbol)
				actual := captured
				actual.Name = name
				calleeLayouts[name] = actual
				binding.calleeSigs[name] = arm64ScratchPublicSignature(actual)
				binding.closed[symbol] = true
				binding.calls[symbol] = name
			}
		}
	}
	// Deep-copy public slices without stripping existing private declaration
	// witnesses. The new pointer is never present in the stored expected layout.
	bound := make(map[string]FuncSig, len(options.Sigs))
	for name, signature := range options.Sigs {
		signature.Args = append([]LLVMType(nil), signature.Args...)
		signature.ArgRegs = append([]Reg(nil), signature.ArgRegs...)
		signature.Frame.Params = arm64CopyFPSlots(signature.Frame.Params)
		signature.Frame.Results = arm64CopyFPSlots(signature.Frame.Results)
		if _, present := binding.sigs[name]; present {
			signature.arm64NativeScratch = binding
		}
		bound[name] = signature
	}
	for name, signature := range calleeLayouts {
		if _, root := binding.sigs[name]; root {
			continue
		}
		signature.arm64NativeScratch = binding
		bound[name] = signature
	}
	options.Sigs = bound
	if err := source.Verify(ctx); err != nil {
		return Options{}, err
	}
	return options, nil
}

func (source *GoARM64ScratchSource) actualCalleeSignature(ctx context.Context, symbol, resolved string) (FuncSig, error) {
	path := ""
	for candidate, pkg := range source.packages {
		if strings.HasPrefix(symbol, candidate+".") && len(candidate) > len(path) &&
			(candidate == source.actual.Path || pkg.Standard && pkg.Goroot && goAssemblyPathWithinRoot(filepath.Join(source.settings["GOROOT"], "src"), pkg.Dir)) {
			path = candidate
		}
	}
	if path == "" {
		return FuncSig{}, arm64ScratchContext("native callee has no actual same-package/SDK declaration role")
	}
	pkg, typed := source.typed[path]
	if !typed {
		if err := source.typecheck(ctx, GoPackage{}, source.packages[path]); err != nil {
			return FuncSig{}, err
		}
		pkg = source.typed[path]
	}
	name := strings.TrimPrefix(symbol, path+".")
	declaration, ok := pkg.Types.Scope().Lookup(name).(*types.Func)
	if !ok || !arm64ScratchBodyless(pkg.Syntax, name) {
		return FuncSig{}, arm64ScratchContext("native callee lacks its actual selected bodyless declaration")
	}
	return DeriveGoFuncABI0Signature(resolved, declaration, "arm64", types.SizesFor("gc", "arm64"))
}

func arm64ScratchBodyless(files []*ast.File, name string) bool {
	count := 0
	for _, file := range files {
		for _, declaration := range file.Decls {
			if function, ok := declaration.(*ast.FuncDecl); ok && function.Name != nil && function.Name.Name == name && function.Recv == nil {
				if function.Body != nil {
					return false
				}
				count++
			}
		}
	}
	return count == 1
}

func arm64ScratchNOSPLIT(function Func) bool {
	if len(function.Instrs) == 0 || function.Instrs[0].Op != OpTEXT {
		return false
	}
	_, rest := splitOpcode(function.Instrs[0].Raw)
	parts := strings.Split(rest, ",")
	if len(parts) != 3 {
		return false
	}
	flags := globlFlagName.ReplaceAllStringFunc(parts[1], func(name string) string {
		if value, ok := goTextFlagValues[name]; ok {
			return value
		}
		return name
	})
	value, valid := parseImmExpr(strings.TrimSpace(flags))
	return valid && value&4 != 0 && value & ^uint64(4|512) == 0
}

func (source *GoARM64ScratchSource) closedNativeCallee(ctx context.Context, symbol string, visiting map[string]bool, depth int) (bool, error) {
	return source.closedNativeCalleeWithResults(ctx, symbol, visiting, depth, make(map[string]FuncSig))
}

func (source *GoARM64ScratchSource) closedNativeCalleeWithResults(ctx context.Context, symbol string, visiting map[string]bool, depth int, results map[string]FuncSig) (bool, error) {
	if depth >= 32 || len(visiting) >= 64 || visiting[symbol] {
		return false, nil
	}
	function, present := source.functions[symbol]
	if !present {
		var selected *arm64ScratchPackage
		for path, pkg := range source.packages {
			if strings.HasPrefix(symbol, path+".") && (path == source.actual.Path || pkg.Standard && pkg.Goroot &&
				goAssemblyPathWithinRoot(filepath.Join(source.settings["GOROOT"], "src"), pkg.Dir)) {
				copy := pkg
				selected = &copy
			}
		}
		if selected == nil {
			return false, nil
		}
		// Full selected assembly inventory is hashed even when only one source
		// defines this target. No native module/package alias is guessed.
		found := ""
		for _, name := range selected.SFiles {
			data, err := source.read(filepath.Join(selected.Dir, name))
			if err != nil {
				return false, err
			}
			for _, line := range strings.Split(string(data), "\n") {
				fields := strings.Fields(line)
				if len(fields) < 2 || fields[0] != "TEXT" {
					continue
				}
				candidate := strings.TrimSuffix(strings.TrimSuffix(fields[1], ","), "(SB)")
				candidate = goStripABISuffix(strings.ReplaceAll(candidate, "·", "."))
				if strings.HasPrefix(candidate, ".") {
					candidate = selected.ImportPath + candidate
				}
				if candidate == symbol {
					if found != "" {
						return false, arm64ScratchContext("ambiguous actual SDK assembly target")
					}
					found = name
				}
			}
		}
		if found == "" {
			return false, nil
		}
		if err := source.captureOriginalAssembly(ctx, *selected, found); err != nil {
			return false, err
		}
		if err := source.captureNativePackage(ctx, *selected); err != nil {
			return false, err
		}
		function, present = source.functions[symbol]
	}
	if !present || !arm64ScratchNOSPLIT(function) {
		return false, nil
	}
	var sdkInputs uint64
	var sdkLayout FuncSig
	var samePackageLayout FuncSig
	sdkBody := !strings.HasPrefix(symbol, source.actual.Path+".")
	if sdkBody {
		// Opaque SDK code does not pass through this file's ordinary lowerer
		// availability proof. Its original entry must independently close all
		// machine inputs using the actual declaration and wrapper transport.
		layout, err := source.actualCalleeSignature(ctx, symbol, symbol)
		if err != nil {
			return false, err
		}
		var valid bool
		sdkInputs, valid = arm64ScratchSDKTuple(function, layout)
		if !valid || source.abis[symbol] != "ABIInternal" {
			return false, nil
		}
		sdkLayout = layout
	} else {
		var err error
		samePackageLayout, err = source.actualCalleeSignature(ctx, symbol, symbol)
		if err != nil {
			return false, err
		}
		if source.abis[symbol] != "ABI0" {
			return false, nil
		}
	}
	bodies := source.native[symbol]
	if len(bodies) < 2 {
		return false, nil
	} // actual uncached assembler AND actual archive member
	visiting[symbol] = true
	defer delete(visiting, symbol)
	calls := make(map[string]FuncSig)
	for _, body := range bodies {
		for _, target := range body.calls {
			target = source.originalObjectCallTarget(target)
			if target == symbol && source.originalObjectGenerated(body.source) {
				continue // The exact wrapper's own source body is checked below.
			}
			closed, err := source.closedNativeCalleeWithResults(ctx, target, visiting, depth+1, results)
			if err != nil || !closed {
				return false, err
			}
			if layout, initialized := results[target]; initialized {
				calls[target] = layout
				if strings.HasPrefix(target, source.actual.Path+".") {
					calls["."+strings.TrimPrefix(target, source.actual.Path+".")] = layout
				}
			}
		}
	}
	actualAssembly, originalMatched := []uint32(nil), false
	for _, body := range bodies {
		if !arm64ScratchNativeDoesNotAccess(body) {
			return false, nil
		}
		if !source.originalObjectGenerated(body.source) {
			if sdkBody && !arm64ScratchSDKBodyInputs(body, sdkInputs) {
				return false, nil
			}
			if !sdkBody && !arm64ScratchSamePackageInputsWithCalls(function, samePackageLayout, body, calls) {
				return false, nil
			}
			if _, captured := source.originalObjectSource(body.source); !captured {
				return false, nil
			}
			if actualAssembly == nil {
				actualAssembly = body.code
			} else if reflect.DeepEqual(actualAssembly, body.code) {
				originalMatched = true
			} else {
				return false, nil
			}
		}
	}
	if originalMatched && !sdkBody && arm64ScratchNumericCallLayout(samePackageLayout) &&
		arm64ScratchSourceInputs(function, samePackageLayout, calls, true) {
		results[symbol] = samePackageLayout
	}
	if originalMatched && sdkBody && source.actualABI0Wrapper(symbol, sdkLayout) {
		// The independent SDK tuple contract accepts only a void result.
		// Its real wrapper supplies inputs, never initialized result bytes.
		results[symbol] = sdkLayout
	}
	return originalMatched, nil
}

func verifyARM64ScratchBindings(file *File, options Options) (map[string]*arm64ScratchBinding, error) {
	bindings := make(map[string]*arm64ScratchBinding)
	seen := make(map[*arm64ScratchBinding]bool)
	for _, signature := range options.Sigs {
		binding := signature.arm64NativeScratch
		if binding == nil || seen[binding] {
			continue
		}
		seen[binding] = true
		if err := binding.source.Verify(binding.context); err != nil {
			return nil, err
		}
		if file == nil || file.Arch != ArchARM64 || options.Goarch != "arm64" || options.TargetTriple != binding.target ||
			options.ResolveSym == nil || !reflect.DeepEqual(arm64ScratchFileSnapshot(file), binding.file) {
			return nil, arm64ScratchContext("consumer changed whole source or target")
		}
		for symbol, name := range binding.symbols {
			actual, present := options.Sigs[name]
			if !present || actual.arm64NativeScratch != binding || options.ResolveSym(symbol) != name ||
				!bytes.Equal(arm64ScratchPublicSignature(actual), binding.sigs[name]) {
				return nil, arm64ScratchContext("consumer changed a declaration or symbol")
			}
		}
		for symbol, name := range binding.calls {
			if options.ResolveSym(symbol) != name {
				return nil, arm64ScratchContext("consumer changed a native call target")
			}
		}
		for name, expected := range binding.calleeSigs {
			actual, present := options.Sigs[name]
			if !present || actual.arm64NativeScratch != binding || !bytes.Equal(arm64ScratchPublicSignature(actual), expected) {
				return nil, arm64ScratchContext("consumer changed an actual native callee ABI0 tuple")
			}
		}
		for symbol := range binding.closed {
			bindings[symbol] = binding
		}
	}
	return bindings, nil
}

func (binding *arm64ScratchBinding) hasCall(symbol string) bool {
	if binding == nil || binding.source == nil {
		return false
	}
	binding.source.mu.Lock()
	defer binding.source.mu.Unlock()
	return binding.source.ready && binding.closed[symbol] && binding.context.Err() == nil
}
