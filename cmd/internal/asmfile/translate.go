package asmfile

import (
	"fmt"
	"go/ast"
	"go/types"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/xgo-dev/llvm"
	"github.com/xgo-dev/plan9asm"
	"github.com/xgo-dev/plan9asm/internal/x86"
)

type FunctionInfo struct {
	Symbol   string   `json:"symbol"`
	Resolved string   `json:"resolved"`
	Args     []string `json:"args"`
	Ret      string   `json:"ret"`
}

func TranslatePackageFile(pkg plan9asm.GoPackage, sizes types.Sizes, asmPath, goos, goarch, triple string, annotate bool) (llvm.Module, []FunctionInfo, error) {
	src, err := os.ReadFile(asmPath)
	if err != nil {
		return llvm.Module{}, nil, err
	}
	arch, err := Architecture(goarch)
	if err != nil {
		return llvm.Module{}, nil, err
	}
	file, expanded, err := ParseInput(pkg, src, asmPath, goos, goarch, arch)
	if err != nil {
		return llvm.Module{}, nil, err
	}
	if file == nil {
		mod := EmptyModule(triple)
		return mod, []FunctionInfo{}, nil
	}

	resolve := resolveSymFunc(pkg.Path)
	if goarch == "wasm" {
		wasmABI := plan9asm.WASMABIDirect
		if goos == "js" || goos == "wasip1" {
			wasmABI = plan9asm.WASMABIGo
		}
		if expanded != nil {
			src = expanded
		}
		tr, err := plan9asm.TranslateGoModule(pkg, src, plan9asm.GoModuleOptions{
			SourcePreprocessed: expanded != nil,
			FileName:           asmPath,
			GOOS:               goos,
			GOARCH:             goarch,
			Sizes:              sizes,
			TargetTriple:       triple,
			WASMABI:            wasmABI,
			AnnotateSource:     annotate,
			ResolveSym:         resolve,
		})
		if err != nil {
			return llvm.Module{}, nil, err
		}

		fns := make([]FunctionInfo, 0, len(tr.Functions))
		for _, fn := range tr.Functions {
			sig := tr.Signatures[fn.ResolvedSymbol]
			args := make([]string, len(sig.Args))
			for i, arg := range sig.Args {
				args[i] = string(arg)
			}
			ret := string(sig.Ret)
			if ret == "" {
				ret = string(plan9asm.Void)
			}
			fns = append(fns, FunctionInfo{
				Symbol: fn.TextSymbol, Resolved: fn.ResolvedSymbol,
				Args: args, Ret: ret,
			})
		}
		return tr.Module, fns, nil
	}
	sigs, err := sigsForAsmFile(pkg, sizes, file, resolve, goarch)
	if err != nil {
		return llvm.Module{}, nil, err
	}
	mod, err := plan9asm.TranslateModule(file, plan9asm.Options{
		TargetTriple:   triple,
		ResolveSym:     resolve,
		Sigs:           sigs,
		Goarch:         goarch,
		AnnotateSource: annotate,
	})
	if err != nil {
		return llvm.Module{}, nil, err
	}
	fns := collectFunctionInfo(file, sigs, resolve)
	return mod, fns, nil
}

func collectFunctionInfo(file *plan9asm.File, sigs map[string]plan9asm.FuncSig, resolve func(string) string) []FunctionInfo {
	seen := map[string]bool{}
	out := make([]FunctionInfo, 0, len(file.Funcs))
	for _, fn := range file.Funcs {
		resolved := resolve(stripABISuffix(fn.Sym))
		if resolved == "" || seen[resolved] {
			continue
		}
		seen[resolved] = true
		sig := sigs[resolved]
		args := make([]string, len(sig.Args))
		for i, a := range sig.Args {
			args[i] = string(a)
		}
		ret := string(sig.Ret)
		if ret == "" {
			ret = string(plan9asm.Void)
		}
		out = append(out, FunctionInfo{
			Symbol:   fn.Sym,
			Resolved: resolved,
			Args:     args,
			Ret:      ret,
		})
	}
	return out
}

func Architecture(goarch string) (plan9asm.Arch, error) {
	switch goarch {
	case "amd64", "386":
		return plan9asm.ArchAMD64, nil
	case "arm":
		return plan9asm.ArchARM, nil
	case "arm64":
		return plan9asm.ArchARM64, nil
	case "wasm":
		return plan9asm.ArchWASM, nil
	default:
		return "", fmt.Errorf("unsupported -goarch %q (expect amd64/arm64/arm/386/wasm)", goarch)
	}
}

func resolveSymFunc(pkgPath string) func(sym string) string {
	return func(sym string) string {
		sym = stripABISuffix(sym)
		hadLocal := strings.HasSuffix(sym, "<>")
		sym = strings.TrimSuffix(sym, "<>")
		if strings.HasPrefix(sym, "·") {
			name := pkgPath + "." + strings.TrimPrefix(sym, "·")
			if hadLocal {
				return name + "$local"
			}
			return name
		}
		sym = strings.ReplaceAll(sym, "∕", "/")
		sym = strings.ReplaceAll(sym, "·", ".")
		if hadLocal {
			if !strings.Contains(sym, "/") && !strings.Contains(sym, ".") {
				return pkgPath + "." + sym + "$local"
			}
			return sym + "$local"
		}
		return sym
	}
}

var abiSuffixRe = regexp.MustCompile(`<ABI[^>]*>$`)

func stripABISuffix(sym string) string {
	return abiSuffixRe.ReplaceAllString(sym, "")
}

func sigsForAsmFile(pkg plan9asm.GoPackage, sizes types.Sizes, file *plan9asm.File, resolve func(string) string, goarch string) (map[string]plan9asm.FuncSig, error) {
	sigs := map[string]plan9asm.FuncSig{}
	if pkg.Types == nil || pkg.Types.Scope() == nil {
		for _, fn := range file.Funcs {
			fs := fallbackSigForAsmFunc(fn, resolve(stripABISuffix(fn.Sym)), goarch)
			if goarch == "wasm" && strings.HasSuffix(fn.Sym, "<>") {
				var err error
				fs, err = plan9asm.InferWASMAssemblyFuncSig(fn, fs.Name)
				if err != nil {
					return nil, err
				}
			}
			sigs[fs.Name] = fs
		}
		return sigs, nil
	}

	sz := sizes
	if sz == nil {
		sz = types.SizesFor("gc", goarch)
	}
	if sz == nil {
		return nil, fmt.Errorf("missing type sizes for %q", goarch)
	}

	scope := pkg.Types.Scope()
	linknames := linknameRemoteToLocal(pkg.Syntax)
	declaredSigs := map[string]bool{}

	for _, fn := range file.Funcs {
		sym := stripABISuffix(fn.Sym)
		resolved := resolve(sym)
		if resolved == "" {
			continue
		}
		fs, ok, err := tryDeclSig(scope, asmDeclLookupSym(pkg, sym), resolved, linknames, goarch, sz)
		if err != nil {
			return nil, err
		}
		if !ok {
			fs = fallbackSigForAsmFunc(fn, resolved, goarch)
		} else {
			declaredSigs[resolved] = true
		}
		sigs[resolved] = fs
	}
	if goarch == "wasm" {
		for _, fn := range file.Funcs {
			if !strings.HasSuffix(fn.Sym, "<>") {
				continue
			}
			resolved := resolve(stripABISuffix(fn.Sym))
			fs, err := plan9asm.InferWASMAssemblyFuncSig(fn, resolved)
			if err != nil {
				return nil, err
			}
			sigs[resolved] = fs
		}
	}

	addTargetSig := func(sym string, caller plan9asm.FuncSig, tail bool) {
		if sym == "" {
			return
		}
		sym = stripABISuffix(sym)
		resolved := resolve(sym)
		if resolved == "" {
			return
		}
		if existing, ok := sigs[resolved]; ok {
			// A local assembly helper may have no Go declaration and no FP result
			// slots even though every entry reaches it by tail call. Preserve its
			// inferred register/frame inputs, but make its LLVM return and matching
			// result slots agree with the declared caller. Local helpers share the
			// caller's physical frame, so a byte result may otherwise remain an i32
			// fallback slot underneath an i1 function signature.
			if tail && caller.Name != "" && !declaredSigs[resolved] {
				existing.Ret = caller.Ret
				if len(existing.Frame.Results) == len(caller.Frame.Results) {
					for i := range existing.Frame.Results {
						for _, callerResult := range caller.Frame.Results {
							if existing.Frame.Results[i].Offset == callerResult.Offset {
								existing.Frame.Results[i].Type = callerResult.Type
								break
							}
						}
					}
				}
				sigs[resolved] = existing
			}
			return
		}
		fs, ok, err := tryDeclSig(scope, asmDeclLookupSym(pkg, sym), resolved, linknames, goarch, sz)
		if err == nil && ok {
			sigs[resolved] = fs
			declaredSigs[resolved] = true
			return
		}
		if tail && caller.Name != "" {
			copySig := caller
			copySig.Name = resolved
			sigs[resolved] = copySig
			return
		}
		sigs[resolved] = plan9asm.FuncSig{Name: resolved, Ret: plan9asm.I64}
	}

	for _, fn := range file.Funcs {
		callerName := resolve(stripABISuffix(fn.Sym))
		caller := sigs[callerName]
		for _, ins := range fn.Instrs {
			if goarch == "386" {
				if sym := x86.AddressedFunctionCandidate(ins); sym != "" {
					sym = stripABISuffix(sym)
					name := resolve(sym)
					if _, exists := sigs[name]; !exists {
						fs, ok, err := tryDeclSig(scope, asmDeclLookupSym(pkg, sym), name, linknames, goarch, sz)
						if err != nil {
							return nil, err
						}
						if ok {
							sigs[name] = fs
							declaredSigs[name] = true
						}
					}
				}
			}
			op := strings.ToUpper(string(ins.Op))
			tail := op == "JMP" || op == "B"
			if !(tail || op == "CALL" || op == "BL") {
				continue
			}
			if len(ins.Args) != 1 || ins.Args[0].Kind != plan9asm.OpSym {
				continue
			}
			s := strings.TrimSpace(ins.Args[0].Sym)
			if !strings.HasSuffix(s, "(SB)") {
				continue
			}
			s = strings.TrimSuffix(s, "(SB)")
			base, off := splitSymPlusOff(s)
			if base == "" || off != 0 {
				continue
			}
			addTargetSig(base, caller, tail)

			// Entry stubs such as _rt0_386 have no Go declaration or FP
			// result slot, so their fallback signature conservatively assumes a
			// word return. A tail jump to a declared void function proves that
			// the stub itself does not return a value. Reconcile the caller here
			// instead of weakening the lowerer's return-type checks globally.
			targetName := resolve(stripABISuffix(base))
			target, targetOK := sigs[targetName]
			if tail && caller.Name != "" && !declaredSigs[callerName] &&
				len(caller.Frame.Results) == 0 && targetOK &&
				declaredSigs[targetName] && target.Ret == plan9asm.Void {
				caller.Ret = plan9asm.Void
				sigs[callerName] = caller
			}
		}
	}

	return sigs, nil
}

func asmDeclLookupSym(pkg plan9asm.GoPackage, sym string) string {
	if pkg.Types == nil {
		return sym
	}
	prefix := pkg.Types.Name() + "·"
	if strings.HasPrefix(sym, prefix) {
		return "·" + strings.TrimPrefix(sym, prefix)
	}
	return sym
}

func fallbackSigForAsmFunc(fn plan9asm.Func, resolved, goarch string) plan9asm.FuncSig {
	paramOff := map[int64]struct{}{}
	retOff := map[int64]struct{}{}

	for _, ins := range fn.Instrs {
		op := strings.ToUpper(string(ins.Op))
		for i, a := range ins.Args {
			if a.Kind != plan9asm.OpFP {
				continue
			}
			if isLikelyResultSlot(op, i, len(ins.Args), a.FPName) {
				retOff[a.FPOffset] = struct{}{}
			} else {
				paramOff[a.FPOffset] = struct{}{}
			}
		}
	}

	paramList := sortOffsets(paramOff)
	retList := sortOffsets(retOff)
	word := plan9asm.I64
	if goarch == "386" || goarch == "arm" {
		word = plan9asm.I32
	}
	params := make([]plan9asm.FrameSlot, 0, len(paramList))
	for i, off := range paramList {
		params = append(params, plan9asm.FrameSlot{Offset: off, Type: word, Index: i, Field: -1})
	}
	results := make([]plan9asm.FrameSlot, 0, len(retList))
	for i, off := range retList {
		results = append(results, plan9asm.FrameSlot{Offset: off, Type: word, Index: i, Field: -1})
	}

	args := make([]plan9asm.LLVMType, len(params))
	for i := range args {
		args[i] = word
	}
	ret := plan9asm.Void
	switch len(results) {
	case 0:
		ret = word
	case 1:
		ret = word
	default:
		parts := make([]string, 0, len(results))
		for range results {
			parts = append(parts, string(word))
		}
		ret = plan9asm.LLVMType("{ " + strings.Join(parts, ", ") + " }")
	}
	return plan9asm.FuncSig{
		Name: resolved,
		Args: args,
		Ret:  ret,
		Frame: plan9asm.FrameLayout{
			Params:  params,
			Results: results,
		},
	}
}

func isLikelyResultSlot(op string, argIndex int, argCount int, fpName string) bool {
	name := strings.ToLower(fpName)
	if strings.HasPrefix(name, "ret") {
		return true
	}
	if argCount > 0 && argIndex == argCount-1 {
		switch {
		case strings.HasPrefix(op, "MOV"), strings.HasPrefix(op, "VMOV"), strings.HasPrefix(op, "FMOV"):
			return true
		}
	}
	return false
}

func sortOffsets(m map[int64]struct{}) []int64 {
	out := make([]int64, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func tryDeclSig(scope *types.Scope, sym, resolved string, linknames map[string]string, goarch string, sz types.Sizes) (plan9asm.FuncSig, bool, error) {
	declName := strings.TrimPrefix(sym, "·")
	if strings.ContainsRune(declName, '·') {
		key := strings.ReplaceAll(sym, "∕", "/")
		key = strings.ReplaceAll(key, "·", ".")
		if local, ok := linknames[key]; ok {
			declName = local
		} else {
			return plan9asm.FuncSig{}, false, nil
		}
	}
	obj := scope.Lookup(declName)
	if obj == nil {
		return plan9asm.FuncSig{}, false, nil
	}
	fn, ok := obj.(*types.Func)
	if !ok {
		return plan9asm.FuncSig{}, false, nil
	}
	sig := fn.Type().(*types.Signature)
	if sig.Recv() != nil || sig.Variadic() {
		return plan9asm.FuncSig{}, false, nil
	}

	args, frameParams, nextOff, err := llvmArgsAndFrameSlotsForTuple(sig.Params(), goarch, sz, 0, false)
	if err != nil {
		return plan9asm.FuncSig{}, false, fmt.Errorf("%s: %w", fn.FullName(), err)
	}
	nextOff = alignOff(nextOff, int64(wordSize(goarch)))
	retTys, frameResults, _, err := llvmArgsAndFrameSlotsForTuple(sig.Results(), goarch, sz, nextOff, true)
	if err != nil {
		return plan9asm.FuncSig{}, false, fmt.Errorf("%s: %w", fn.FullName(), err)
	}
	ret := tupleRetType(retTys)
	return plan9asm.FuncSig{
		Name: resolved,
		Args: args,
		Ret:  ret,
		Frame: plan9asm.FrameLayout{
			Params:  frameParams,
			Results: frameResults,
		},
	}, true, nil
}

func tupleRetType(ts []plan9asm.LLVMType) plan9asm.LLVMType {
	switch len(ts) {
	case 0:
		return plan9asm.Void
	case 1:
		return ts[0]
	default:
		parts := make([]string, 0, len(ts))
		for _, t := range ts {
			parts = append(parts, string(t))
		}
		return plan9asm.LLVMType("{ " + strings.Join(parts, ", ") + " }")
	}
}

func splitSymPlusOff(s string) (base string, off int64) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", 0
	}
	sep := strings.LastIndexAny(s, "+-")
	if sep <= 0 || sep == len(s)-1 {
		return s, 0
	}
	n, err := strconv.ParseInt(strings.TrimSpace(s[sep:]), 0, 64)
	if err != nil {
		return s, 0
	}
	return strings.TrimSpace(s[:sep]), n
}

func linknameRemoteToLocal(files []*ast.File) map[string]string {
	m := map[string]string{}
	for _, f := range files {
		if f == nil {
			continue
		}
		for _, cg := range f.Comments {
			if cg == nil {
				continue
			}
			for _, c := range cg.List {
				if c == nil {
					continue
				}
				text := strings.TrimSpace(strings.TrimPrefix(c.Text, "//"))
				if !strings.HasPrefix(text, "go:linkname ") {
					continue
				}
				parts := strings.Fields(text)
				if len(parts) < 3 {
					continue
				}
				local := parts[1]
				remote := strings.ReplaceAll(parts[2], "∕", "/")
				m[remote] = local
			}
		}
	}
	return m
}

func llvmArgsAndFrameSlotsForTuple(tup *types.Tuple, goarch string, sz types.Sizes, startOff int64, flattenAgg bool) (args []plan9asm.LLVMType, slots []plan9asm.FrameSlot, nextOff int64, err error) {
	if tup == nil || tup.Len() == 0 {
		return nil, nil, startOff, nil
	}

	word := int64(wordSize(goarch))
	wordTy := plan9asm.I64
	if word == 4 {
		wordTy = plan9asm.LLVMType("i32")
	}
	align := func(off, a int64) int64 {
		if a <= 1 {
			return off
		}
		m := off % a
		if m == 0 {
			return off
		}
		return off + (a - m)
	}

	off := startOff
	argIdx := 0
	for i := 0; i < tup.Len(); i++ {
		t := tup.At(i).Type()
		off = align(off, int64(sz.Alignof(t)))
		if sz.Sizeof(t) == 0 {
			// Zero-sized marker parameters (for example runtime.goexit's
			// neverCallThisFunction) consume neither an LLVM argument nor a
			// physical Plan 9 frame slot.
			continue
		}

		switch u := unaliasType(t).(type) {
		case *types.Basic:
			if u.Kind() == types.String {
				if flattenAgg {
					args = append(args, plan9asm.Ptr, wordTy)
					slots = append(slots,
						plan9asm.FrameSlot{Offset: off + 0*word, Type: plan9asm.Ptr, Index: argIdx + 0, Field: -1},
						plan9asm.FrameSlot{Offset: off + 1*word, Type: wordTy, Index: argIdx + 1, Field: -1},
					)
					argIdx += 2
					off += int64(sz.Sizeof(t))
					continue
				}
				ty, e := llvmTypeForGo(t, goarch)
				if e != nil {
					return nil, nil, 0, e
				}
				args = append(args, ty)
				slots = append(slots,
					plan9asm.FrameSlot{Offset: off + 0*word, Type: plan9asm.Ptr, Index: argIdx, Field: 0},
					plan9asm.FrameSlot{Offset: off + 1*word, Type: wordTy, Index: argIdx, Field: 1},
				)
				argIdx++
				off += int64(sz.Sizeof(t))
				continue
			}
		case *types.Slice:
			if flattenAgg {
				args = append(args, plan9asm.Ptr, wordTy, wordTy)
				slots = append(slots,
					plan9asm.FrameSlot{Offset: off + 0*word, Type: plan9asm.Ptr, Index: argIdx + 0, Field: -1},
					plan9asm.FrameSlot{Offset: off + 1*word, Type: wordTy, Index: argIdx + 1, Field: -1},
					plan9asm.FrameSlot{Offset: off + 2*word, Type: wordTy, Index: argIdx + 2, Field: -1},
				)
				argIdx += 3
				off += int64(sz.Sizeof(t))
				continue
			}
			ty, e := llvmTypeForGo(t, goarch)
			if e != nil {
				return nil, nil, 0, e
			}
			args = append(args, ty)
			slots = append(slots,
				plan9asm.FrameSlot{Offset: off + 0*word, Type: plan9asm.Ptr, Index: argIdx, Field: 0},
				plan9asm.FrameSlot{Offset: off + 1*word, Type: wordTy, Index: argIdx, Field: 1},
				plan9asm.FrameSlot{Offset: off + 2*word, Type: wordTy, Index: argIdx, Field: 2},
			)
			argIdx++
			off += int64(sz.Sizeof(t))
			continue
		case *types.Interface:
			// An interface value is its runtime type/itab pointer followed by
			// its data pointer. Keep the two physical FP slots visible even
			// when the LLVM function signature uses one aggregate argument.
			if flattenAgg {
				args = append(args, plan9asm.Ptr, plan9asm.Ptr)
				slots = append(slots,
					plan9asm.FrameSlot{Offset: off + 0*word, Type: plan9asm.Ptr, Index: argIdx + 0, Field: -1},
					plan9asm.FrameSlot{Offset: off + 1*word, Type: plan9asm.Ptr, Index: argIdx + 1, Field: -1},
				)
				argIdx += 2
				off += int64(sz.Sizeof(t))
				continue
			}
			args = append(args, plan9asm.LLVMType("{ ptr, ptr }"))
			slots = append(slots,
				plan9asm.FrameSlot{Offset: off + 0*word, Type: plan9asm.Ptr, Index: argIdx, Field: 0},
				plan9asm.FrameSlot{Offset: off + 1*word, Type: plan9asm.Ptr, Index: argIdx, Field: 1},
			)
			argIdx++
			off += int64(sz.Sizeof(t))
			continue
		}

		ty, e := llvmTypeForGo(t, goarch)
		if e != nil {
			return nil, nil, 0, e
		}
		args = append(args, ty)
		slots = append(slots, plan9asm.FrameSlot{Offset: off, Type: ty, Index: argIdx, Field: -1})
		argIdx++
		off += int64(sz.Sizeof(t))
	}
	return args, slots, off, nil
}

func llvmTypeForGo(t types.Type, goarch string) (plan9asm.LLVMType, error) {
	switch tt := unaliasType(t).(type) {
	case *types.Basic:
		switch tt.Kind() {
		case types.Bool:
			return plan9asm.I1, nil
		case types.UnsafePointer:
			return plan9asm.Ptr, nil
		case types.Int8, types.Uint8:
			return plan9asm.I8, nil
		case types.Int16, types.Uint16:
			return plan9asm.I16, nil
		case types.Int32, types.Uint32:
			return plan9asm.I32, nil
		case types.Int64, types.Uint64:
			return plan9asm.I64, nil
		case types.Int, types.Uint, types.Uintptr:
			if wordSize(goarch) == 8 {
				return plan9asm.I64, nil
			}
			return plan9asm.I32, nil
		case types.Float32:
			return plan9asm.LLVMType("float"), nil
		case types.Float64:
			return plan9asm.LLVMType("double"), nil
		case types.String:
			if wordSize(goarch) == 8 {
				return plan9asm.LLVMType("{ ptr, i64 }"), nil
			}
			return plan9asm.LLVMType("{ ptr, i32 }"), nil
		default:
			return "", fmt.Errorf("unsupported basic type %s", tt.String())
		}
	case *types.Pointer:
		return plan9asm.Ptr, nil
	case *types.Signature, *types.Map, *types.Chan:
		// Go function values, maps, and channels occupy one pointer-sized word
		// in an assembly frame. The pointee/runtime descriptor is intentionally
		// opaque to the instruction translator.
		return plan9asm.Ptr, nil
	case *types.Interface:
		return plan9asm.LLVMType("{ ptr, ptr }"), nil
	case *types.Slice:
		if wordSize(goarch) == 8 {
			return plan9asm.LLVMType("{ ptr, i64, i64 }"), nil
		}
		return plan9asm.LLVMType("{ ptr, i32, i32 }"), nil
	case *types.Named:
		return llvmTypeForGo(tt.Underlying(), goarch)
	default:
		return "", fmt.Errorf("unsupported type %s", t.String())
	}
}

func wordSize(goarch string) int {
	switch goarch {
	case "amd64", "arm64", "loong64", "mips64", "mips64le", "ppc64", "ppc64le", "riscv64", "s390x", "wasm":
		return 8
	default:
		return 4
	}
}

func alignOff(off, a int64) int64 {
	if a <= 1 {
		return off
	}
	m := off % a
	if m == 0 {
		return off
	}
	return off + (a - m)
}
