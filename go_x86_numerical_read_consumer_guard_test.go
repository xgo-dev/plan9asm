//go:build go1.27

package plan9asm

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestGoX86NumericalSBReadGoWrapperSealedFunctionMetadata(t *testing.T) {
	pkg, _, _, create := numericalConsumerFactory(t, "amd64")
	source, options := create(t)
	resolve := options.ResolveSym
	metadataCallback := false
	stateful := func(symbol string) string {
		if symbol == "·Feature" {
			// A caller may change only one answer and restore all later
			// answers. Select the direct wrapper metadata call, not the
			// nested declaration or pre/post guard consumers.
			pc, _, _, ok := runtime.Caller(1)
			if ok && strings.HasSuffix(runtime.FuncForPC(pc).Name(), ".translateGoModuleInContext") {
				metadataCallback = true
				return "foreign.Feature"
			}
		}
		return resolve(symbol)
	}
	result, err := TranslateGoModule(pkg, numericalWrapperOriginal(t, source), GoModuleOptions{
		FileName: source.request.AssemblyFile, GOOS: "linux", GOARCH: "amd64",
		TargetTriple: options.TargetTriple, NumericalReads: options.NumericalReads, ResolveSym: stateful,
	})
	if err != nil {
		// A guard that rejects the changed callback is also valid; it must
		// return no module or partially inconsistent metadata.
		if result != nil || !errors.Is(err, ErrProbeNeedsContext) || !metadataCallback {
			t.Fatal("wrapper failed outside the actual metadata TOCTOU", metadataCallback, err)
		}
		return
	}
	if result == nil || result.Module.IsNil() {
		t.Fatal("successful wrapper lost its real translated module")
	}
	defer result.Module.Dispose()
	want := pkg.Path + ".Feature"
	if len(result.Functions) != 1 || result.Functions[0].ResolvedSymbol != want ||
		result.Module.NamedFunction(want).IsNil() || len(result.Signatures) != 1 || result.Signatures[want].Name != want {
		t.Fatal("wrapper module, signatures and function metadata disagree", metadataCallback, result.Functions, result.Signatures)
	}
}

func TestGoX86NumericalSBReadGoWrapperCompleteProfileGuards(t *testing.T) {
	pkg, _, _, create := numericalConsumerFactory(t, "amd64")
	for _, test := range []struct {
		name   string
		mutate func(*GoModuleOptions)
	}{
		{"GOOS", func(o *GoModuleOptions) { o.GOOS = "darwin" }},
		{"GOARCH", func(o *GoModuleOptions) { o.GOARCH = "386" }},
		{"target", func(o *GoModuleOptions) { o.TargetTriple = "x86_64-apple-darwin" }},
		{"value sizes", func(o *GoModuleOptions) { o.Sizes = types.SizesFor("gc", "amd64") }},
		{"frame sizes", func(o *GoModuleOptions) { o.FrameSizes = types.SizesFor("gc", "amd64") }},
		{"foreign source path", func(o *GoModuleOptions) { o.FileName = filepath.Join(t.TempDir(), o.FileName) }},
		{"WASM", func(o *GoModuleOptions) { o.WASMABI = WASMABIGo }},
		{"x87", func(o *GoModuleOptions) { o.X87Mode = X87Software }},
		{"annotation", func(o *GoModuleOptions) { o.AnnotateSource = true }},
		{"resolver", func(o *GoModuleOptions) { o.ResolveSym = nil }},
		{"filter", func(o *GoModuleOptions) { o.KeepFunc = func(string, string) bool { return true } }},
		{"ARM64 carriers", func(o *GoModuleOptions) { o.ARM64ClosureABIs = map[string]ARM64ClosureABI{"foreign": {}} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			source, options := create(t)
			opt := GoModuleOptions{FileName: source.request.AssemblyFile, GOOS: "linux", GOARCH: "amd64",
				TargetTriple: options.TargetTriple, NumericalReads: options.NumericalReads, ResolveSym: options.ResolveSym}
			test.mutate(&opt)
			result, err := TranslateGoModule(pkg, numericalWrapperOriginal(t, source), opt)
			if result != nil {
				result.Module.Dispose()
			}
			if result != nil || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("different wrapper profile/source role published translated output", err)
			}
			if !errors.Is(source.Verify(options.NumericalReads.context), ErrProbeNeedsContext) {
				t.Fatal("wrapper profile failure did not permanently revoke the source")
			}
		})
	}
}

func TestGoX86NumericalSBReadGoWrapperOriginalBytesPostGuard(t *testing.T) {
	pkg, _, _, create := numericalConsumerFactory(t, "386")
	source, options := create(t)
	input := numericalWrapperOriginal(t, source)
	resolve := options.ResolveSym
	mutated := false
	callback := func(symbol string) string {
		pc, _, _, ok := runtime.Caller(1)
		if ok && strings.HasSuffix(runtime.FuncForPC(pc).Name(), ".addDeclaredFuncSigs") && !mutated {
			// Alter caller-owned bytes only after parsing, not the frozen
			// object/source producer or the callback's returned symbol.
			input[len(input)-1] ^= 1
			mutated = true
		}
		return resolve(symbol)
	}
	result, err := TranslateGoModule(pkg, input, GoModuleOptions{
		FileName: source.request.AssemblyFile, GOOS: "linux", GOARCH: "386",
		TargetTriple: options.TargetTriple, NumericalReads: options.NumericalReads, ResolveSym: callback,
	})
	if result != nil {
		result.Module.Dispose()
	}
	if !mutated || result != nil || !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("wrapper caller-owned source bytes escaped the final guard", mutated, err)
	}
	if !errors.Is(source.Verify(options.NumericalReads.context), ErrProbeNeedsContext) {
		t.Fatal("wrapper byte mutation did not permanently revoke the source")
	}
}

func numericalWrapperOriginal(t *testing.T, source *GoX86NumericalReadSource) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(source.request.Directory, source.request.AssemblyFile))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestGoX86NumericalSBReadGoWrapperExactOriginalBytesAndLifetime(t *testing.T) {
	pkg, _, _, create := numericalConsumerFactory(t, "amd64")
	for _, name := range []string{"same parse different bytes", "raw rewrite", "copied token", "foreign source", "revoked source"} {
		t.Run(name, func(t *testing.T) {
			source, options := create(t)
			input := numericalWrapperOriginal(t, source)
			binding := options.NumericalReads
			switch name {
			case "same parse different bytes":
				changed := append(append([]byte(nil), input...), []byte("// not selected original bytes\n")...)
				a, aErr := Parse(ArchAMD64, string(input))
				b, bErr := Parse(ArchAMD64, string(changed))
				aHash, _ := x86CallerSourceFingerprint(a)
				bHash, _ := x86CallerSourceFingerprint(b)
				if aErr != nil || bErr != nil || aHash != bHash {
					t.Fatal("different-bytes/same-parse fixture precondition failed", aErr, bErr)
				}
				input = changed
			case "raw rewrite":
				input = []byte(strings.Replace(string(input), "CMPB", "MOVB", 1))
			case "copied token":
				copied := *binding
				binding = &copied
			case "foreign source":
				foreign, _ := create(t)
				binding.source = foreign
			case "revoked source":
				if err := source.Close(); err != nil {
					t.Fatal(err)
				}
			}
			result, err := TranslateGoModule(pkg, input, GoModuleOptions{
				FileName: source.request.AssemblyFile, GOOS: "linux", GOARCH: "amd64",
				TargetTriple: options.TargetTriple, NumericalReads: binding, ResolveSym: options.ResolveSym,
			})
			if result != nil {
				result.Module.Dispose()
			}
			if result != nil || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("foreign/raw/lifetime input published a Go module", err)
			}
		})
	}
}

func TestGoX86NumericalSBReadGoWrapperHeaderTOCTOU(t *testing.T) {
	pkg, _, _, create := numericalConsumerFactory(t, "amd64")
	first, _ := create(t)
	dir := first.request.Directory
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	header := filepath.Join(dir, "textflag.h")
	if err := os.WriteFile(header, []byte("#define NOSPLIT 4\n"), 0600); err != nil {
		t.Fatal(err)
	}
	source, options := create(t)
	resolve := options.ResolveSym
	mutated := false
	callback := func(symbol string) string {
		pc, _, _, ok := runtime.Caller(1)
		if ok && strings.HasSuffix(runtime.FuncForPC(pc).Name(), ".addDeclaredFuncSigs") && !mutated {
			if err := os.WriteFile(header, []byte("#define NOSPLIT 4\n// changed sealed header bytes\n"), 0600); err != nil {
				t.Fatal(err)
			}
			mutated = true
		}
		return resolve(symbol)
	}
	result, err := TranslateGoModule(pkg, numericalWrapperOriginal(t, source), GoModuleOptions{
		FileName: source.request.AssemblyFile, GOOS: "linux", GOARCH: "amd64",
		TargetTriple: options.TargetTriple, NumericalReads: options.NumericalReads, ResolveSym: callback,
	})
	if result != nil {
		result.Module.Dispose()
	}
	if !mutated || result != nil || !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("changed actual owned header published a Go module", mutated, err)
	}
	if err := os.WriteFile(header, []byte("#define NOSPLIT 4\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(source.Verify(options.NumericalReads.context), ErrProbeNeedsContext) {
		t.Fatal("header restoration could revive a revoked source")
	}
}

func numericalConsumerFactory(t *testing.T, arch string) (GoPackage, *File, Options, func(*testing.T) (*GoX86NumericalReadSource, Options)) {
	t.Helper()
	pkg, request, file, options := numericalSBFixture(t, arch)
	ctx, cancel := runtimeOracleProofContext(t)
	t.Cleanup(cancel)
	owner, err := CaptureGoNumericalStorageOwner(ctx, GoNumericalStorageCaptureRequest{
		GoBinary: request.GoBinary, Directory: filepath.Join(filepath.Dir(filepath.Dir(request.GoBinary)), "src", "internal", "cpu"),
		PackagePath: "internal/cpu", Target: request.Target, Environment: request.Environment, SDKCPU: true,
		Variables: []GoNumericalStorageReference{{PackagePath: "internal/cpu", Name: "X86"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(owner.Close)
	create := func(t *testing.T) (*GoX86NumericalReadSource, Options) {
		t.Helper()
		source, err := CaptureGoX86NumericalReadSource(ctx, GoX86NumericalReadCaptureRequest{
			GoBinary: request.GoBinary, Directory: request.Directory, PackagePath: pkg.Path,
			AssemblyFile: request.AssemblyFile, Target: request.Target, Environment: request.Environment,
			Owners: []*GoNumericalStorageOwner{owner},
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := source.Close(); err != nil {
				t.Error(err)
			}
		})
		bound, err := source.BindNumericalReads(ctx, pkg, file, options)
		if err != nil {
			t.Fatal("actual source/object/owner binding precondition", err)
		}
		return source, bound
	}
	return pkg, file, options, create
}

func TestGoX86NumericalSBReadConsumerCompleteOptionAndSignatureGuards(t *testing.T) {
	_, file, _, create := numericalConsumerFactory(t, "amd64")
	for _, test := range []struct {
		name   string
		mutate func(*Options)
	}{
		{"target", func(o *Options) { o.TargetTriple = "x86_64-apple-darwin" }},
		{"arch", func(o *Options) { o.Goarch = "386" }},
		{"wasm", func(o *Options) { o.WASMABI = WASMABIGo }},
		{"x87", func(o *Options) { o.X87Mode = X87Software }},
		{"annotation", func(o *Options) { o.AnnotateSource = true }},
		{"tail groups", func(o *Options) { o.X86TailGroups = []X86TailGroup{{}} }},
		{"missing resolver", func(o *Options) { o.ResolveSym = nil }},
		{"foreign resolver", func(o *Options) { o.ResolveSym = func(s string) string { return s } }},
		{"missing signatures", func(o *Options) { o.Sigs = nil }},
		{"additional signature", func(o *Options) { o.Sigs["foreign"] = FuncSig{Name: "foreign", Ret: Void} }},
		{"result type", func(o *Options) {
			for name, sig := range o.Sigs {
				sig.Ret = I32
				o.Sigs[name] = sig
			}
		}},
		{"result slot", func(o *Options) {
			for name, sig := range o.Sigs {
				sig.Frame.Results[0].Offset++
				o.Sigs[name] = sig
			}
		}},
		{"private caller identity", func(o *Options) {
			for name, sig := range o.Sigs {
				sig.x86CallerRegions = &x86GoCallerRegionProof{}
				o.Sigs[name] = sig
			}
		}},
		{"private local identity", func(o *Options) {
			for name, sig := range o.Sigs {
				sig.x86FixedLocal = &x86FixedLocalBinding{}
				o.Sigs[name] = sig
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			source, options := create(t)
			test.mutate(&options)
			if err := verifyNumericalReadInputs(file, options); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("changed consumer shape retained a live read binding", err)
			}
			if !errors.Is(source.Verify(options.NumericalReads.context), ErrProbeNeedsContext) {
				t.Fatal("failed consumer guard did not permanently revoke its source")
			}
		})
	}
}

func TestGoX86NumericalSBReadConsumerResolverMutationGuard(t *testing.T) {
	pkg, file, originalOptions, create := numericalConsumerFactory(t, "386")
	for _, mutation := range []string{"source", "AST", "resolver", "signature"} {
		t.Run(mutation, func(t *testing.T) {
			_, options := create(t)
			resolve := options.ResolveSym
			called := false
			options.ResolveSym = func(symbol string) string {
				if !called {
					called = true
					switch mutation {
					case "source":
						file.Funcs[0].Instrs[2].Args[1].Imm++
						t.Cleanup(func() { file.Funcs[0].Instrs[2].Args[1].Imm-- })
					case "AST":
						pkg.Syntax[0].Name.Name += "changed"
						t.Cleanup(func() { pkg.Syntax[0].Name.Name = "numericalfixture" })
					case "resolver":
						options.ResolveSym = originalOptions.ResolveSym
						return "foreign"
					case "signature":
						for name, sig := range options.Sigs {
							sig.Attrs = "#77"
							options.Sigs[name] = sig
						}
					}
				}
				return resolve(symbol)
			}
			if ir, err := Translate(file, options); ir != "" || !errors.Is(err, ErrProbeNeedsContext) || !called {
				t.Fatal("resolver TOCTOU published translated output", called, err)
			}
		})
	}
}

func TestGoX86NumericalSBReadBindingDeclarationIdentityAndWrapperGuards(t *testing.T) {
	pkg, _, _, create := numericalConsumerFactory(t, "amd64")
	t.Run("private types identity", func(t *testing.T) {
		_, options := create(t)
		binding := options.NumericalReads
		fset := token.NewFileSet()
		syntax, err := parser.ParseFile(fset, "value.go", "package numericalfixture\nfunc Feature() byte\n", parser.ParseComments)
		if err != nil {
			t.Fatal(err)
		}
		replacement, err := (&types.Config{Sizes: types.SizesFor("gc", "amd64")}).Check(pkg.Path, fset, []*ast.File{syntax}, nil)
		if err != nil {
			t.Fatal(err)
		}
		binding.packageInput.Types = replacement
		if !errors.Is(binding.verify(), ErrProbeNeedsContext) {
			t.Fatal("same-shaped foreign private type package replaced the live declaration owner")
		}
	})
	for _, mutation := range []string{"missing syntax", "changed syntax", "source selection", "manual signature"} {
		t.Run(mutation, func(t *testing.T) {
			_, options := create(t)
			binding := options.NumericalReads
			wrapperPkg := pkg
			opt := GoModuleOptions{FileName: binding.source.request.AssemblyFile, GOOS: "linux", GOARCH: "amd64",
				TargetTriple: options.TargetTriple, NumericalReads: binding, ResolveSym: options.ResolveSym}
			switch mutation {
			case "missing syntax":
				wrapperPkg.Syntax = nil
			case "changed syntax":
				fset := token.NewFileSet()
				changed, err := parser.ParseFile(fset, "value.go", "package other\nfunc Feature() byte\n", parser.ParseComments)
				if err != nil {
					t.Fatal(err)
				}
				wrapperPkg.Syntax = []*ast.File{changed}
			case "source selection":
				wrapperPkg.SourceSelection = &GoSourceSelection{}
			case "manual signature":
				opt.ManualSig = func(name string) (FuncSig, bool) { return options.Sigs[name], true }
			}
			if err := verifyGoNumericalReadInputs(binding, wrapperPkg, opt); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("unbound Go wrapper declaration/source role survived the precondition", mutation, err)
			}
			if !errors.Is(binding.source.Verify(binding.context), ErrProbeNeedsContext) {
				t.Fatal("failed wrapper guard did not permanently revoke its source")
			}
		})
	}
}

func TestGoX86NumericalSBReadNormalizedOrdinalAndCertificateGuards(t *testing.T) {
	_, file, _, create := numericalConsumerFactory(t, "386")
	for _, mutation := range []string{"removed", "duplicate", "operand", "ordinal", "function", "foreign binding", "data collision"} {
		t.Run(mutation, func(t *testing.T) {
			_, options := create(t)
			frozen, bound, err := freezeNumericalReadInputs(file, options)
			if err != nil {
				t.Fatal(err)
			}
			fn := &frozen.Funcs[0]
			read := &fn.Instrs[2]
			if read.x86NumericalRead == nil {
				t.Fatal("actual original CMP read ordinal changed")
			}
			switch mutation {
			case "removed":
				read.x86NumericalRead = nil
			case "duplicate":
				fn.Instrs = append(fn.Instrs, *read)
			case "operand":
				read.Args[0].Sym = strings.Replace(read.Args[0].Sym, "+64", "+65", 1)
			case "ordinal":
				fn.Instrs[1], fn.Instrs[2] = fn.Instrs[2], fn.Instrs[1]
			case "function":
				fn.Sym = "·Foreign"
			case "foreign binding":
				copyBinding := *bound.NumericalReads
				read.x86NumericalRead.binding = &copyBinding
			case "data collision":
				frozen.Globl = append(frozen.Globl, GloblStmt{})
			}
			if !errors.Is(verifyNormalizedNumericalReads(frozen, bound), ErrProbeNeedsContext) {
				t.Fatal("normalized native read identity changed without rejection")
			}
		})
	}
}
