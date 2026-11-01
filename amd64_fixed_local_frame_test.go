package plan9asm

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/llvm"
)

func fixedLocalFrameFixture(t *testing.T, operation string) (GoPackage, GoAMD64FrameCaptureRequest, *File, Options) {
	t.Helper()
	_, request := goAMD64FrameSourceFixture(t)
	source, _, _ := x86PrivateAlignedFrameAuditFixture(t, operation)
	declaration := []byte("package framefixture\nfunc Value(a, b, c, d uint64) uint64\n")
	for name, data := range map[string][]byte{
		"value.go": declaration, "value_amd64.s": []byte(source),
	} {
		if err := os.WriteFile(filepath.Join(request.Directory, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	fset := token.NewFileSet()
	syntax, err := parser.ParseFile(fset, "value.go", declaration, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	sizes := types.SizesFor("gc", "amd64")
	typed, err := (&types.Config{Sizes: sizes}).Check("example.invalid/framefixture", fset, []*ast.File{syntax}, nil)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := DeriveGoFuncABI0Signature(typed.Path()+".Value", typed.Scope().Lookup("Value").(*types.Func), "amd64", sizes)
	if err != nil {
		t.Fatal(err)
	}
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	resolve := func(symbol string) string { return strings.Replace(symbol, "·", typed.Path()+".", 1) }
	pkg := GoPackage{Path: typed.Path(), Types: typed, Syntax: []*ast.File{syntax}}
	return pkg, request, file, Options{
		Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu", ResolveSym: resolve,
		Sigs: map[string]FuncSig{sig.Name: sig},
	}
}

func TestGoAMD64FixedLocalFrameSevenOriginalNativeOperations(t *testing.T) {
	for _, operation := range []string{
		"PADDB 16(SP),X0", "PADDW 16(SP),X0", "PADDL 16(SP),X0", "PADDQ 16(SP),X0",
		"PMADDWL 16(SP),X0", "CMPPS 16(SP),X0,$0", "CMPPD 16(SP),X0,$0",
	} {
		t.Run(strings.Fields(operation)[0], func(t *testing.T) {
			pkg, request, file, options := fixedLocalFrameFixture(t, operation)
			source := requireGoAMD64FrameCapture(t, pkg, request)
			observed := source.functions[pkg.Path+".Value"]
			if observed.locals != 168 || observed.args != 40 || len(observed.code) == 0 {
				t.Fatalf("missing actual original Go frame/object: %+v", observed)
			}
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			options, err := source.BindFixedLocal(ctx, pkg, file, options)
			if err != nil {
				t.Fatal(err)
			}
			fixedLocalAPIs(t, pkg, file, options, func(t *testing.T, ir string, err error) {
				if err != nil {
					t.Fatalf("original numeric frame needs sealed native backing: %v", err)
				}
				for _, required := range []string{"fixed_local_native", "align 8", "asm sideeffect"} {
					if !strings.Contains(ir, required) {
						t.Fatalf("missing actual native storage/opcode %q", required)
					}
				}
			})
		})
	}
}

func TestGoAMD64FixedLocalFrameActualTargetObjectsPreserveProducerBoundary(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range []string{"linux/amd64", "darwin/amd64", "windows/amd64", "linux/386", "windows/386"} {
		t.Run(target, func(t *testing.T) {
			pkg, request, file, options := fixedLocalFrameFixture(t, "PADDQ 16(SP),X0")
			request.Target = target
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			source, err := CaptureGoAMD64FrameSource(ctx, pkg, request)
			if strings.HasSuffix(target, "/386") || target == "windows/amd64" && err != nil {
				if !errors.Is(err, ErrProbeNeedsContext) || source != nil ||
					target == "windows/amd64" && !strings.Contains(err.Error(), "SSEHUNWINDINFO") {
					t.Fatalf("unclosed physical target unexpectedly obtained authority: %v", err)
				}
				t.Logf("existing actual observer boundary remains Context, not a positive fixed-local object: %v", err)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := source.Close(); err != nil {
					t.Error(err)
				}
			})
			if target == "darwin/amd64" {
				options.TargetTriple = "x86_64-apple-darwin"
			}
			if target == "windows/amd64" {
				options.TargetTriple = "x86_64-pc-windows-msvc"
			}
			bound, err := source.BindFixedLocal(ctx, pkg, file, options)
			if err != nil {
				t.Fatal(err)
			}
			fixedLocalAPIs(t, pkg, file, bound, func(t *testing.T, ir string, err error) {
				if err != nil {
					t.Fatal(err)
				}
				compileLLVMToObject(t, llc, options.TargetTriple, "fixed-local.ll", "fixed-local.o", ir)
				compileLLVMToObject(t, llc, options.TargetTriple, "fixed-local-opt.ll", "fixed-local-opt.o", x86MulDivRoundOptimize(t, ir))
			})
		})
	}
}

func TestGoAMD64FixedLocalFrameScalarMemoryWidthsHaveExactCertificates(t *testing.T) {
	for _, form := range []struct {
		opcode string
		width  int64
	}{{"MOVB", 1}, {"MOVW", 2}, {"MOVL", 4}, {"MOVQ", 8}} {
		t.Run(form.opcode, func(t *testing.T) {
			pkg, request, file, options := fixedLocalFrameFixture(t, "PADDQ 16(SP),X0")
			var source, stores strings.Builder
			for _, ins := range file.Funcs[0].Instrs {
				source.WriteString(ins.Raw + "\n")
			}
			for offset := int64(16); offset < 32; offset += form.width {
				fmt.Fprintf(&stores, "%s $1,%d(SP)\n", form.opcode, offset)
			}
			fmt.Fprintf(&stores, "%s 16(SP),DX\n", form.opcode)
			original := strings.Replace(source.String(), "MOVQ AX,16(SP)\nMOVQ CX,24(SP)\n", stores.String(), 1)
			requireX86GoAssemblerResult(t, "amd64", original, true)
			if err := os.WriteFile(filepath.Join(request.Directory, request.AssemblyFile), []byte(original), 0600); err != nil {
				t.Fatal(err)
			}
			file, err := Parse(ArchAMD64, original)
			if err != nil {
				t.Fatal(err)
			}
			observed := requireGoAMD64FrameCapture(t, pkg, request)
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			bound, err := observed.BindFixedLocal(ctx, pkg, file, options)
			if err != nil {
				t.Fatal(err)
			}
			normalized, err := normalizeX86RawFile(file, "amd64", bound)
			if err != nil {
				t.Fatal(err)
			}
			read, write := false, false
			for _, ins := range normalized.Funcs[0].Instrs {
				if string(ins.Op) != form.opcode {
					continue
				}
				for _, access := range ins.x86FixedLocalMemory {
					if access.width != form.width {
						t.Fatalf("scalar byte envelope changed: %+v", access)
					}
					read = read || !access.write
					write = write || access.write
				}
			}
			if !read || !write {
				t.Fatal("missing independently proved scalar read/write")
			}
			fixedLocalAPIs(t, pkg, file, bound, func(t *testing.T, ir string, err error) {
				if err != nil || ir == "" {
					t.Fatalf("actual scalar memory width failed consumer: %v", err)
				}
			})
		})
	}
}

func fixedLocalAPIs(t *testing.T, pkg GoPackage, file *File, options Options, check func(*testing.T, string, error)) {
	t.Helper()
	for _, api := range []string{"Translate", "Module", "GoModule"} {
		t.Run(api, func(t *testing.T) {
			fixedLocalAPI(t, pkg, file, options, api, check)
		})
	}
}

// Each API consumes its own complete actual source observation. Neither the
// compiler cache nor a previous API's options can extend or revive that lease.
func fixedLocalFreshAPIs(t *testing.T, pkg GoPackage, request GoAMD64FrameCaptureRequest, options Options, apis []string, check func(*testing.T, string, error)) {
	t.Helper()
	seen := make(map[string]bool)
	if len(apis) == 0 {
		t.Fatal("missing fixed-local API inventory")
	}
	for _, api := range apis {
		if (api != "Translate" && api != "Module" && api != "GoModule") || seen[api] {
			t.Fatal("unknown or duplicated fixed-local API", api)
		}
		seen[api] = true
	}
	for _, api := range apis {
		t.Run(api, func(t *testing.T) {
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			source, err := CaptureGoAMD64FrameSource(ctx, pkg, request)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := source.Close(); err != nil {
					t.Error(err)
				}
			}()
			original, err := os.ReadFile(filepath.Join(request.Directory, request.AssemblyFile))
			if err != nil {
				t.Fatal(err)
			}
			// Bind consumes the exact producer's complete CPP output, including
			// suffix formatting. The original file remains an immutable input.
			expanded, err := source.preprocess(request.AssemblyFile, original)
			if err != nil {
				t.Fatal(err)
			}
			file, err := Parse(ArchAMD64, expanded)
			if err != nil {
				t.Fatal(err)
			}
			bound, err := source.BindFixedLocal(ctx, pkg, file, options)
			if err != nil {
				t.Fatal(err)
			}
			if len(source.functions) != len(file.Funcs) {
				t.Fatal("incomplete actual original Go object inventory")
			}
			fixedLocalAPI(t, pkg, file, bound, api, check, expanded)
		})
	}
}

func fixedLocalAPI(t *testing.T, pkg GoPackage, file *File, options Options, api string, check func(*testing.T, string, error), assembly ...string) {
	t.Helper()
	if len(assembly) > 1 || len(assembly) == 1 && assembly[0] == "" {
		t.Fatal("expected at most one complete nonempty assembly source")
	}
	switch api {
	case "Translate":
		ir, err := Translate(file, options)
		check(t, ir, err)
	case "Module":
		ctx := llvm.NewContext()
		defer ctx.Dispose()
		module, err := TranslateModuleInContext(ctx, file, options)
		ir := ""
		if !module.IsNil() {
			defer module.Dispose()
			ir = module.String()
		}
		check(t, ir, err)
	case "GoModule":
		var source strings.Builder
		// The fresh owner supplies its exact preprocessed source, retaining
		// DATA/GLOBL as well as every TEXT body in this independent API.
		if len(assembly) == 1 {
			source.WriteString(assembly[0])
		} else {
			for _, fn := range file.Funcs {
				for _, ins := range fn.Instrs {
					source.WriteString(ins.Raw + "\n")
				}
			}
		}
		goos := "linux"
		if strings.Contains(options.TargetTriple, "apple") {
			goos = "darwin"
		}
		if strings.Contains(options.TargetTriple, "windows") {
			goos = "windows"
		}
		translation, err := TranslateGoModule(pkg, []byte(source.String()), GoModuleOptions{
			GOOS: goos, GOARCH: options.Goarch,
			TargetTriple: options.TargetTriple, Sizes: types.SizesFor("gc", options.Goarch), WASMABI: options.WASMABI,
			ResolveSym: options.ResolveSym,
			ManualSig:  func(name string) (FuncSig, bool) { sig, found := options.Sigs[name]; return sig, found },
		})
		ir := ""
		if translation != nil && !translation.Module.IsNil() {
			defer translation.Module.Dispose()
			ir = translation.Module.String()
		}
		check(t, ir, err)
	default:
		t.Fatal("unknown fixed-local API", api)
	}
}

func fixedLocalRequireContext(t *testing.T, ir string, err error) {
	t.Helper()
	if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
		t.Fatalf("unbound frame/effect produced IR: %v %s", err, ir)
	}
}

func TestGoAMD64FixedLocalFrameThreeAPIsCannotForgeOrMutateBinding(t *testing.T) {
	pkg, request, file, options := fixedLocalFrameFixture(t, "PADDQ 16(SP),X0")
	fixedLocalAPIs(t, pkg, file, options, fixedLocalRequireContext)
	source := requireGoAMD64FrameCapture(t, pkg, request)
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	bound, err := source.BindFixedLocal(ctx, pkg, file, options)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []string{"JSON", "signature", "slot", "attrs", "target", "arch", "resolver", "source", "missing function", "ABI"} {
		t.Run(mutation, func(t *testing.T) {
			changed := bound
			changed.Sigs, err = cloneFixedLocalSigs(bound.Sigs)
			if err != nil {
				t.Fatal(err)
			}
			for name, sig := range changed.Sigs {
				sig.x86FixedLocal = bound.Sigs[name].x86FixedLocal
				changed.Sigs[name] = sig
			}
			changedFile := *file
			changedFile.Funcs = append([]Func(nil), file.Funcs...)
			sig := changed.Sigs[pkg.Path+".Value"]
			switch mutation {
			case "JSON":
				changed.Sigs, err = cloneFixedLocalSigs(bound.Sigs)
				if err != nil {
					t.Fatal(err)
				}
			case "signature":
				sig.Args[0] = I32
			case "slot":
				sig.Frame.Params[0].Offset++
			case "attrs":
				sig.Attrs = "nounwind"
			case "target":
				changed.TargetTriple = "x86_64-apple-darwin"
			case "arch":
				changed.Goarch = "386"
			case "resolver":
				changed.ResolveSym = func(string) string { return "foreign.Value" }
			case "ABI":
				changed.WASMABI = WASMABIGo
			case "source":
				changedFile.Funcs[0].FrameSize += 8
				changedFile.Funcs[0].Instrs = append([]Instr(nil), file.Funcs[0].Instrs...)
				changedFile.Funcs[0].Instrs[0].Raw = strings.Replace(changedFile.Funcs[0].Instrs[0].Raw, "$160-40", "$168-40", 1)
			case "missing function":
				changedFile.Funcs = nil
			}
			if mutation != "JSON" {
				changed.Sigs[pkg.Path+".Value"] = sig
			}
			check := fixedLocalRequireContext
			if mutation == "missing function" {
				check = func(t *testing.T, ir string, err error) {
					if err == nil || ir != "" {
						t.Fatalf("missing entire source produced a module: %v", err)
					}
				}
			}
			fixedLocalAPIs(t, pkg, &changedFile, changed, check)
		})
	}
	// Mutating the original input does not mutate the returned signature nor
	// the separately cloned sealed expected declaration.
	input := options.Sigs[pkg.Path+".Value"]
	input.Args[0] = I32
	options.Sigs[pkg.Path+".Value"] = input
	if _, err := Translate(file, bound); err != nil {
		t.Fatalf("caller-owned Options changed the immutable binding: %v", err)
	}
	// Tail groups exist only in Options, not in GoModuleOptions. Exercise the
	// actual two consumers that can receive this request, not a fake transport.
	changed := bound
	changed.X86TailGroups = []X86TailGroup{{Root: "·Value", Helpers: []string{"·Value"}}}
	ir, err := Translate(file, changed)
	fixedLocalRequireContext(t, ir, err)
	llvmContext := llvm.NewContext()
	defer llvmContext.Dispose()
	module, err := TranslateModuleInContext(llvmContext, file, changed)
	if !module.IsNil() {
		defer module.Dispose()
		t.Fatal("unbound continuation request produced a module")
	}
	fixedLocalRequireContext(t, "", err)
}

func TestGoAMD64FixedLocalFrameBindResolverMayRevokeWithoutLockingDeadlock(t *testing.T) {
	if os.Getenv("PLAN9ASM_FIXED_LOCAL_REENTRANCY_CHILD") != "1" {
		stage, cancelStage := runtimeOracleStageContext(t)
		defer cancelStage()
		ctx, cancel := context.WithTimeout(stage, 30*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestGoAMD64FixedLocalFrameBindResolverMayRevokeWithoutLockingDeadlock$", "-test.timeout=1m")
		command.Env = append(os.Environ(), "PLAN9ASM_FIXED_LOCAL_REENTRANCY_CHILD=1")
		if output, err := runtimeOracleCombinedOutput(ctx, command); err != nil {
			t.Fatalf("bounded actual bind resolver/Close child failed or deadlocked: %v\n%s", err, output)
		}
		return
	}
	pkg, request, file, options := fixedLocalFrameFixture(t, "PADDQ 16(SP),X0")
	source := requireGoAMD64FrameCapture(t, pkg, request)
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	resolve := options.ResolveSym
	options.ResolveSym = func(symbol string) string {
		if err := source.Close(); err != nil {
			t.Fatal(err)
		}
		return resolve(symbol)
	}
	if _, err := source.BindFixedLocal(ctx, pkg, file, options); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("callback-revoked observation obtained a binding: %v", err)
	}
}

func TestGoAMD64FixedLocalFrameTruncatedConstantCannotAuthorizePointerArithmetic(t *testing.T) {
	for _, move := range []string{"MOVL", "MOVW", "MOVB"} {
		t.Run(move, func(t *testing.T) {
			pkg, request, file, options := fixedLocalFrameFixture(t, "PADDQ 16(SP),X0")
			var original strings.Builder
			for _, ins := range file.Funcs[0].Instrs {
				original.WriteString(ins.Raw + "\n")
			}
			changed := strings.Replace(original.String(), "MOVQ $31,R9\nNOTQ R9\nANDQ R9,SP", "MOVQ $-16,AX\n"+move+" AX,BX\nANDQ BX,SP", 1)
			requireX86GoAssemblerResult(t, "amd64", changed, true)
			if err := os.WriteFile(filepath.Join(request.Directory, request.AssemblyFile), []byte(changed), 0600); err != nil {
				t.Fatal(err)
			}
			file, err := Parse(ArchAMD64, changed)
			if err != nil {
				t.Fatal(err)
			}
			source := requireGoAMD64FrameCapture(t, pkg, request)
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			if _, err := source.BindFixedLocal(ctx, pkg, file, options); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("actual Go accepted %s narrow constant acquired full-width pointer authority: %v", move, err)
			}
		})
	}
}

func TestGoAMD64FixedLocalFrameClosedExpiredAndChangedSourceRevokes(t *testing.T) {
	for _, mutation := range []string{"close", "cancel", "file", "object", "listing", "export", "post-consumer"} {
		t.Run(mutation, func(t *testing.T) {
			pkg, request, file, options := fixedLocalFrameFixture(t, "PADDQ 16(SP),X0")
			source := requireGoAMD64FrameCapture(t, pkg, request)
			stage, finish := runtimeOracleStageContext(t)
			defer finish()
			ctx, cancel := context.WithCancel(stage)
			defer cancel()
			bound, err := source.BindFixedLocal(ctx, pkg, file, options)
			if err != nil {
				t.Fatal(err)
			}
			var path string
			switch mutation {
			case "close":
				if err := source.Close(); err != nil {
					t.Fatal(err)
				}
			case "cancel":
				cancel()
			case "file":
				path = filepath.Join(request.Directory, "value.go")
			case "object":
				path = filepath.Join(source.owned, request.AssemblyFile+".o")
			case "listing":
				path = filepath.Join(source.owned, request.AssemblyFile+".o.listing")
			case "export":
				path = source.selection.Export
			case "post-consumer":
				calls := 0
				bound.ResolveSym = func(symbol string) string {
					calls++
					if calls == 1 {
						if err := os.WriteFile(filepath.Join(request.Directory, "value.go"), []byte("package changed\n"), 0600); err != nil {
							t.Fatal(err)
						}
					}
					return options.ResolveSym(symbol)
				}
			}
			if path != "" {
				if err := os.WriteFile(path, []byte("mutation"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			fixedLocalAPIs(t, pkg, file, bound, fixedLocalRequireContext)
			if mutation != "post-consumer" && source.ready {
				t.Fatal("failed observer verification did not permanently revoke the binding")
			}
		})
	}
}

func TestGoAMD64FixedLocalFrameResolverCannotChangeParsedSourceAfterValidation(t *testing.T) {
	for _, api := range []string{"Translate", "Module", "GoModule"} {
		t.Run(api, func(t *testing.T) {
			pkg, request, file, options := fixedLocalFrameFixture(t, "PADDQ 16(SP),X0")
			source := requireGoAMD64FrameCapture(t, pkg, request)
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			bound, err := source.BindFixedLocal(ctx, pkg, file, options)
			if err != nil {
				t.Fatal(err)
			}
			resolve := bound.ResolveSym
			bound.ResolveSym = func(symbol string) string {
				for index := range file.Funcs[0].Instrs {
					ins := &file.Funcs[0].Instrs[index]
					if ins.Op == "PADDQ" {
						ins.Op = "PADDB"
						ins.Raw = strings.Replace(ins.Raw, "PADDQ", "PADDB", 1)
					}
				}
				return resolve(symbol)
			}
			if api == "Translate" {
				ir, err := Translate(file, bound)
				fixedLocalRequireContext(t, ir, err)
				return
			}
			if api == "Module" {
				llvmContext := llvm.NewContext()
				defer llvmContext.Dispose()
				module, err := TranslateModuleInContext(llvmContext, file, bound)
				if !module.IsNil() {
					defer module.Dispose()
					t.Fatal("resolver-mutated original source produced a module")
				}
				fixedLocalRequireContext(t, "", err)
				return
			}
			// GoModule reparses the original bytes into its own private file;
			// this public-file mutation cannot change that source. Its resolver
			// is frozen before consumer normalization, so the original opcode
			// must remain independently bound rather than silently substituted.
			original := strings.Builder{}
			for _, ins := range file.Funcs[0].Instrs {
				original.WriteString(ins.Raw + "\n")
			}
			translation, err := TranslateGoModule(pkg, []byte(original.String()), GoModuleOptions{
				GOOS: "linux", GOARCH: "amd64", TargetTriple: bound.TargetTriple,
				Sizes: types.SizesFor("gc", "amd64"), ResolveSym: bound.ResolveSym,
				ManualSig: func(name string) (FuncSig, bool) { sig, found := bound.Sigs[name]; return sig, found },
			})
			if translation != nil && !translation.Module.IsNil() {
				defer translation.Module.Dispose()
			}
			if err != nil || translation == nil || !strings.Contains(translation.Module.String(), "paddq") {
				t.Fatalf("GoModule did not preserve its independent original source: %v", err)
			}
		})
	}
}

func TestGoAMD64FixedLocalFrameProofFullByteWidthAddressAndControlNegatives(t *testing.T) {
	base, sig, _ := x86PrivateAlignedFrameAuditFixture(t, "PADDQ 16(SP),X0")
	mutations := map[string]string{
		"alignment":                strings.Replace(base, "ADDQ $32,SP", "ADDQ $33,SP", 1),
		"read extent":              strings.Replace(base, "PADDQ 16(SP)", "PADDQ 152(SP)", 1),
		"write extent":             strings.Replace(base, "MOVQ AX,16(SP)", "MOVQ AX,160(SP)", 1),
		"unknown pointer":          strings.Replace(base, "PADDQ 16(SP)", "PADDQ 16(SI)", 1),
		"indexed pointer":          strings.Replace(base, "PADDQ 16(SP)", "PADDQ 16(SP)(AX*1)", 1),
		"segment":                  strings.Replace(base, "PADDQ 16(SP)", "PADDQ 16(FS)", 1),
		"pointer result":           strings.Replace(base, "MOVQ AX,ret+32(FP)", "MOVQ R11,ret+32(FP)", 1),
		"pointer flags":            strings.Replace(base, "MOVQ AX,ret+32(FP)", "CMPQ R11,AX\nMOVQ AX,ret+32(FP)", 1),
		"pointer truncated":        strings.Replace(base, "MOVQ SP,R11", "MOVL SP,R11", 1),
		"missing restore":          strings.Replace(base, "MOVQ R11,SP", "MOVQ $0,R10", 1),
		"pointer cell clobber":     strings.Replace(base, "MOVQ 96(SP),R11", "MOVB $1,96(SP)\nMOVQ 96(SP),R11", 1),
		"pointer bytes as numeric": strings.Replace(base, "PADDQ 16(SP)", "PADDQ 96(SP)", 1),
		"unknown call":             strings.Replace(base, "PADDQ", "CALL ·Other(SB)\nPADDQ", 1),
		"unknown dead effect":      base + "SYSCALL\n",
		"result width":             strings.Replace(base, "MOVQ AX,ret+32(FP)", "MOVL AX,ret+32(FP)", 1),
		"local spill escape":       strings.Replace(base, "MOVQ AX,ret+32(FP)", "MOVQ R11,·global(SB)\nMOVQ AX,ret+32(FP)", 1),
		"unknown flags branch":     strings.Replace(base, "MOVQ AX,16(SP)", "JEQ done\nMOVQ AX,16(SP)", 1) + "done:\nRET\n",
		"FP after SP change":       strings.Replace(base, "MOVQ AX,16(SP)", "MOVQ a+0(FP),AX\nMOVQ AX,16(SP)", 1),
		"high legacy vector bank":  strings.ReplaceAll(base, "X0", "X16"),
	}
	for byteIndex := 0; byteIndex < 16; byteIndex++ {
		var stores strings.Builder
		for index := 0; index < 16; index++ {
			if index != byteIndex {
				fmt.Fprintf(&stores, "MOVB $1,%d(SP)\n", 16+index)
			}
		}
		mutated := strings.Replace(base, "MOVQ AX,16(SP)\nMOVQ CX,24(SP)\n", stores.String(), 1)
		mutations[fmt.Sprintf("missing byte %02d", byteIndex)] = mutated
	}
	for name, source := range mutations {
		t.Run(name, func(t *testing.T) {
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := proveX86FixedLocal(file.Funcs[0], sig); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("unproved source admitted: %v", err)
			}
		})
	}
}

func TestGoAMD64FixedLocalFrameAllPathInitializationAndResourceBounds(t *testing.T) {
	base, sig, _ := x86PrivateAlignedFrameAuditFixture(t, "PADDQ 16(SP),X0")
	branch := strings.Replace(base, "MOVQ CX,24(SP)", "MOVQ CX,24(SP)\nCMPQ AX,CX\nJEQ joined\nMOVQ CX,24(SP)\njoined:", 1)
	requireX86GoAssemblerResult(t, "amd64", branch, true)
	file, err := Parse(ArchAMD64, branch)
	if err != nil {
		t.Fatal(err)
	}
	proved, err := proveX86FixedLocal(file.Funcs[0], sig)
	if err != nil {
		t.Fatal(err)
	}
	for _, ins := range proved.Instrs {
		if ins.Op != "PADDQ" {
			continue
		}
		access := ins.x86FixedLocalMemory[0]
		if access.offset != [8]int64{48, 40, 32, 24, 48, 40, 32, 24} {
			t.Fatalf("missing all original SP residue accesses: %v", access.offset)
		}
	}
	for name, source := range map[string]string{
		"one predecessor uninitialized": strings.Replace(branch, "MOVQ CX,24(SP)\nCMPQ", "CMPQ", 1),
		"stale pointer flags":           strings.Replace(branch, "CMPQ AX,CX", "ADDQ $0,SP", 1),
		"loop loses flags":              strings.Replace(branch, "JEQ joined", "before:\nJEQ joined\nIMULQ $3,AX\nJMP before", 1),
		"different address join":        strings.Replace(branch, "JEQ joined\nMOVQ CX,24(SP)", "JEQ joined\nADDQ $8,SP\nMOVQ CX,24(SP)", 1),
		"fallthrough":                   strings.TrimSuffix(base, "RET\n"),
	} {
		t.Run(name, func(t *testing.T) {
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := proveX86FixedLocal(file.Funcs[0], sig); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("unproved CFG gained backing: %v", err)
			}
		})
	}
	tooLarge := file.Funcs[0]
	tooLarge.FrameSize = 1 << 20
	if _, err := proveX86FixedLocal(tooLarge, sig); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("oversized physical frame was admitted")
	}
	// A long straight block no longer retains one state per instruction.
	// Exercise the unchanged storage cap with actual control-flow boundaries.
	tooLarge, largeSig := fixedLocalRetainedStateBudgetFixture(t)
	if _, err := proveX86FixedLocal(tooLarge, largeSig); !errors.Is(err, ErrProbeNeedsContext) ||
		!strings.Contains(err.Error(), "state storage budget") {
		t.Fatal("retained frame-state storage budget was ignored", err)
	}
}

func TestGoAMD64FixedLocalFrameResidueDependentAliasesCannotRelocate(t *testing.T) {
	base, sig, _ := x86PrivateAlignedFrameAuditFixture(t, "PADDQ 16(SP),X0")
	// Both address origins belong to the same local frame, and every byte is
	// initialized for every residue. Nevertheless this write overlaps the
	// source's low word, high word or neither depending on original SP mod 32.
	// A new physical alloca cannot silently choose one of these observations.
	source := strings.Replace(base, "MOVQ BX,56(SP)", "MOVQ BX,56(SP)\nMOVQ $1,48(R11)", 1)
	requireX86GoAssemblerResult(t, "amd64", source, true)
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := proveX86FixedLocal(file.Funcs[0], sig); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("residue-dependent initialized aliases were relocated: %v", err)
	}
	// Independent little-endian byte-memory mathematics, not the production
	// address/state/certificate implementation, exposes the actual data change.
	want := [4][2]uint64{{6, 10}, {7, 8}, {7, 10}, {7, 10}}
	for residue := 0; residue < 4; residue++ {
		var memory [256]byte
		sp := 32 + residue*8
		aligned := sp&^31 + 32
		for index, value := range []uint64{2, 3} {
			binary.LittleEndian.PutUint64(memory[aligned+16+index*8:], value)
		}
		for index, value := range []uint64{5, 7} {
			binary.LittleEndian.PutUint64(memory[aligned+48+index*8:], value)
		}
		binary.LittleEndian.PutUint64(memory[sp+48:], 1)
		got := [2]uint64{}
		for index := range got {
			got[index] = binary.LittleEndian.Uint64(memory[aligned+16+index*8:]) +
				binary.LittleEndian.Uint64(memory[aligned+48+index*8:])
		}
		if got != want[residue] {
			t.Fatalf("independent original residue %d data: got %v want %v", residue, got, want[residue])
		}
	}
}

func TestGoAMD64FixedLocalFrameCertificatesArePrivateExactAndRevocable(t *testing.T) {
	pkg, request, file, options := fixedLocalFrameFixture(t, "PADDQ 16(SP),X0")
	source := requireGoAMD64FrameCapture(t, pkg, request)
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	bound, err := source.BindFixedLocal(ctx, pkg, file, options)
	if err != nil {
		t.Fatal(err)
	}
	normalized, err := normalizeX86RawFile(file, "amd64", bound)
	if err != nil {
		t.Fatal(err)
	}
	fn := normalized.Funcs[0]
	lower := &amd64Ctx{fixedLocal: fn.x86FixedLocal}
	for _, ins := range fn.Instrs {
		for index, access := range ins.x86FixedLocalMemory {
			if !lower.fixedLocalMemoryCertified(ins, index) {
				t.Fatal("missing independently replayed original access")
			}
			for residue, offset := range access.offset {
				if offset < 0 || offset+access.width > 160 {
					t.Fatalf("invalid residue %d certified extent", residue)
				}
			}
			for _, mutation := range []string{"op", "args", "width", "owner", "JSON", "address size"} {
				changed := ins
				changed.Args = append([]Operand(nil), ins.Args...)
				changed.x86FixedLocalMemory = make(map[int]x86FixedLocalAccess)
				for key, value := range ins.x86FixedLocalMemory {
					changed.x86FixedLocalMemory[key] = value
				}
				switch mutation {
				case "op":
					changed.Op = "UNDEF"
				case "args":
					changed.Args[index].Mem.Off++
				case "width":
					value := changed.x86FixedLocalMemory[index]
					value.width++
					changed.x86FixedLocalMemory[index] = value
				case "owner":
					value := changed.x86FixedLocalMemory[index]
					value.owner = &x86FixedLocalProof{}
					changed.x86FixedLocalMemory[index] = value
				case "JSON":
					data, _ := json.Marshal(ins)
					changed = Instr{}
					if err := json.Unmarshal(data, &changed); err != nil {
						t.Fatal(err)
					}
				case "address size":
					changed.x86AddressBits = 32
				}
				if lower.fixedLocalMemoryCertified(changed, index) {
					t.Fatalf("%s preserved a stale native access certificate", mutation)
				}
			}
		}
	}
}
