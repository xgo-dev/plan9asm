package plan9asm

import (
	"context"
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

	"github.com/xgo-dev/llvm"
	"github.com/xgo-dev/plan9asm/internal/goasmcmd"
)

const arm64ScratchSelectedSource = `TEXT ·Scratch(SB),0,$32904-16
MOVD n+0(FP),R1
MOVD R1,8(RSP)
CALL ·Value(SB)
MOVD 16(RSP),R2
MOVD R2,ret+8(FP)
RET
TEXT ·Value(SB),4,$0-16
MOVD n+0(FP),R1
ADD $3,R1
MOVD R1,ret+8(FP)
RET
`

func arm64ScratchActualSourceFixture(t *testing.T, goos string) (GoPackage, GoARM64ScratchCaptureRequest) {
	return arm64ScratchActualSourceFixtureWithAssembly(t, goos, arm64ScratchSelectedSource)
}

func arm64ScratchActualSourceFixtureWithAssembly(t *testing.T, goos, assembly string) (GoPackage, GoARM64ScratchCaptureRequest) {
	return arm64ScratchActualSourceFixtureWithPackage(t, goos, assembly, "example.invalid/scratchfixture")
}

func arm64ScratchActualSourceFixtureWithPackage(t *testing.T, goos, assembly, packagePath string, extraDeclarations ...string) (GoPackage, GoARM64ScratchCaptureRequest) {
	t.Helper()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	declarations := "package scratchfixture\nfunc Scratch(n uint64) uint64\nfunc Value(n uint64) uint64\n" + strings.Join(extraDeclarations, "\n")
	for name, data := range map[string]string{
		"go.mod":   "module " + packagePath + "\n\ngo 1.20\n",
		"value.go": declarations, "value_arm64.s": assembly,
	} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	fset := token.NewFileSet()
	syntax, err := parser.ParseFile(fset, filepath.Join(directory, "value.go"), declarations, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	typed, err := (&types.Config{Sizes: types.SizesFor("gc", "arm64")}).Check(
		packagePath, fset, []*ast.File{syntax}, nil)
	if err != nil {
		t.Fatal(err)
	}
	binary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	binary, err = filepath.Abs(binary)
	if err != nil {
		t.Fatal(err)
	}
	binary, err = filepath.EvalSymlinks(binary)
	if err != nil {
		t.Fatal(err)
	}
	environment := append(os.Environ(), "GOOS="+goos, "GOARCH=arm64", "CGO_ENABLED=0",
		"GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local", "GOFLAGS=", "GOEXPERIMENT=", "GOPACKAGESDRIVER=off")
	for _, key := range []string{"GOPATH", "GOMODCACHE", "GOCACHE", "TMPDIR", "GOTMPDIR"} {
		if !filepath.IsAbs(os.Getenv(key)) {
			environment = append(environment, key+"="+t.TempDir())
		}
	}
	return GoPackage{Path: typed.Path(), Types: typed, Syntax: []*ast.File{syntax}}, GoARM64ScratchCaptureRequest{
		GoBinary: binary, Directory: directory, AssemblyFile: "value_arm64.s", Target: goos + "/arm64", Environment: environment,
	}
}

func arm64ScratchActualBoundSource(t *testing.T, goos, target string) (context.Context, GoPackage, *File, Options, *GoARM64ScratchSource) {
	return arm64ScratchActualBoundSourceWithAssembly(t, goos, target, arm64ScratchSelectedSource)
}

func arm64ScratchActualBoundSourceWithAssembly(t *testing.T, goos, target, assembly string) (context.Context, GoPackage, *File, Options, *GoARM64ScratchSource) {
	return arm64ScratchActualBoundSourceWithPackage(t, goos, target, assembly, "example.invalid/scratchfixture")
}

func arm64ScratchActualBoundSourceWithPackage(t *testing.T, goos, target, assembly, packagePath string, extraDeclarations ...string) (context.Context, GoPackage, *File, Options, *GoARM64ScratchSource) {
	t.Helper()
	pkg, request := arm64ScratchActualSourceFixtureWithPackage(t, goos, assembly, packagePath, extraDeclarations...)
	ctx, cancel := runtimeOracleStageContext(t)
	t.Cleanup(cancel)
	source, err := CaptureGoARM64ScratchSource(ctx, pkg, request)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := source.Close(); err != nil {
			t.Error(err)
		}
	})
	file, err := Parse(ArchARM64, assembly)
	if err != nil {
		t.Fatal(err)
	}
	resolve := func(symbol string) string { return strings.TrimPrefix(strings.TrimSuffix(symbol, "(SB)"), "·") }
	sigs, err := goSigsForAsmFile(pkg, file, resolve, "arm64", nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	options, err := source.BindScratchClosure(ctx, file, Options{
		Goarch: "arm64", TargetTriple: target, ResolveSym: resolve, Sigs: sigs,
	})
	if err != nil {
		t.Fatal(err)
	}
	return ctx, pkg, file, options, source
}

func TestARM64NativeScratchTransitiveAndPostCallOriginRemainContext(t *testing.T) {
	for _, test := range []struct {
		name, body string
	}{
		{"callee-entry-read", "MOVD R27,R1"},
		{"callee-partial-definition", "MOVK $1,R27\nMOVD R27,R1"},
		{"callee-one-branch", "CBZ R1,read\nMOVD $1,R27\nread:\nMOVD R27,R1"},
		{"transitive-cycle", "CALL ·Value(SB)"},
	} {
		t.Run(test.name, func(t *testing.T) {
			assembly := strings.Replace(arm64ScratchSelectedSource, "ADD $3,R1", test.body, 1)
			_, pkg, file, options, source := arm64ScratchActualBoundSourceWithAssembly(t, "linux", "aarch64-unknown-linux-gnu", assembly)
			if _, closed := source.closed[pkg.Path+".Value"]; closed {
				t.Fatal("unsafe native transitive component acquired a scratch-origin fact")
			}
			for _, api := range []string{"text", "module"} {
				if _, err := arm64ScratchSourceAPI(t, pkg, file, options, api); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("callee input/recursive origin escaped through %s: %v", api, err)
				}
			}
		})
	}
	assembly := strings.Replace(arm64ScratchSelectedSource, "MOVD 16(RSP),R2", "MOVD R27,R2", 1)
	_, pkg, file, options, _ := arm64ScratchActualBoundSourceWithAssembly(t, "linux", "aarch64-unknown-linux-gnu", assembly)
	for _, api := range []string{"text", "module"} {
		t.Run("caller-origin-killed/"+api, func(t *testing.T) {
			if _, err := arm64ScratchSourceAPI(t, pkg, file, options, api); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("callee closure propagated its R27 address/value back to caller: %v", err)
			}
		})
	}
}

func arm64ScratchSourceAPI(t *testing.T, pkg GoPackage, file *File, options Options, api string) (string, error) {
	return arm64ScratchSourceAPIWithAssembly(t, pkg, file, options, api, arm64ScratchSelectedSource)
}

func arm64ScratchSourceAPIWithAssembly(t *testing.T, pkg GoPackage, file *File, options Options, api, assembly string) (string, error) {
	t.Helper()
	if api == "text" {
		return Translate(file, options)
	}
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	var module llvm.Module
	var err error
	if api == "module" {
		module, err = TranslateModuleInContext(ctx, file, options)
	} else {
		translation, translateErr := translateGoModuleInContext(ctx, pkg, []byte(assembly), GoModuleOptions{
			GOARCH: options.Goarch, TargetTriple: options.TargetTriple, ResolveSym: options.ResolveSym,
			ManualSig: func(name string) (FuncSig, bool) { signature, present := options.Sigs[name]; return signature, present },
		})
		err = translateErr
		if translation != nil {
			module = translation.Module
		}
	}
	if !module.IsNil() {
		defer module.Dispose()
	}
	if err != nil {
		return "", err
	}
	return module.String(), nil
}

func TestARM64NativeScratchSourceThreeAPIActualObjects(t *testing.T) {
	llc, _, _ := findLlcAndClang(t)
	for _, target := range []struct{ goos, triple string }{
		{"linux", "aarch64-unknown-linux-gnu"},
		{"darwin", "arm64-apple-darwin"},
		{"darwin", "arm64-apple-macosx"},
		{"windows", "aarch64-pc-windows-msvc"},
	} {
		t.Run(target.goos, func(t *testing.T) {
			_, pkg, file, options, _ := arm64ScratchActualBoundSource(t, target.goos, target.triple)
			for _, api := range []string{"text", "module", "GoModule"} {
				t.Run(api, func(t *testing.T) {
					ir, err := arm64ScratchSourceAPI(t, pkg, file, options, api)
					if err != nil {
						t.Fatal(err)
					}
					compileLLVMToObject(t, llc, target.triple, "scratch.ll", "scratch.o", ir)
				})
			}
		})
	}
}

func TestARM64NativeScratchSourceLabelAliases(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range []struct{ goos, triple string }{
		{"linux", "aarch64-unknown-linux-gnu"},
		{"darwin", "arm64-apple-darwin"},
		{"windows", "aarch64-pc-windows-msvc"},
	} {
		t.Run(target.goos, func(t *testing.T) {
			for _, test := range []struct{ name, labels string }{
				{"inline", "first: next:"},
				{"internal_names", "reg_R0: anon_1:"},
			} {
				t.Run(test.name, func(t *testing.T) {
					assembly := strings.Replace(arm64ScratchSelectedSource,
						"ADD $3,R1", test.labels+" ADD $3,R1", 1)
					_, pkg, file, options, source := arm64ScratchActualBoundSourceWithAssembly(
						t, target.goos, target.triple, assembly)
					// The factory assembled the unchanged source and captured both
					// its native object and package archive. Empty source aliases
					// must preserve fallthrough, not invent inputs or a return.
					if _, closed := source.closed[pkg.Path+".Value"]; !closed {
						t.Fatal("Go-accepted source label aliases broke native scratch closure")
					}
					for _, api := range []string{"text", "module", "GoModule"} {
						t.Run(api, func(t *testing.T) {
							ir, err := arm64ScratchSourceAPIWithAssembly(t, pkg, file, options, api, assembly)
							if err != nil {
								t.Fatal(err)
							}
							compileLLVMToObject(t, llc, target.triple, "aliases.ll", "aliases.o", ir)
						})
					}
				})
			}
		})
	}
}

func TestARM64NativeScratchCanonicalCPPSourceIdentity(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range []struct{ goos, triple string }{
		{"linux", "aarch64-unknown-linux-gnu"},
		{"darwin", "arm64-apple-darwin"},
		{"windows", "aarch64-pc-windows-msvc"},
	} {
		t.Run(target.goos, func(t *testing.T) {
			// The native producer and profile consumer must use the same CPP
			// frontend. Keep exact source/file equality; do not erase Raw or
			// relax the binding to compare only opcode/operand summaries.
			original := strings.ReplaceAll(arm64ScratchSelectedSource, ",", ", ")
			expanded, err := PreprocessAssemblySource(original, AssemblyPreprocessOptions{FileName: "value_arm64.s"})
			if err != nil {
				t.Fatal(err)
			}
			pkg, request := arm64ScratchActualSourceFixtureWithAssembly(t, target.goos, original)
			ctx, cancel := runtimeOracleStageContext(t)
			t.Cleanup(cancel)
			source, err := CaptureGoARM64ScratchSource(ctx, pkg, request)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := source.Close(); err != nil {
					t.Error(err)
				}
			})
			file, err := Parse(ArchARM64, expanded)
			if err != nil {
				t.Fatal(err)
			}
			resolve := func(symbol string) string {
				return strings.TrimPrefix(strings.TrimSuffix(symbol, "(SB)"), "·")
			}
			sigs, err := goSigsForAsmFile(pkg, file, resolve, "arm64", nil, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			options, err := source.BindScratchClosure(ctx, file, Options{
				Goarch: "arm64", TargetTriple: target.triple, ResolveSym: resolve, Sigs: sigs,
			})
			if err != nil {
				t.Fatalf("unchanged original CPP selection: %v", err)
			}
			for _, api := range []string{"text", "module"} {
				t.Run(api, func(t *testing.T) {
					ir, err := arm64ScratchSourceAPI(t, pkg, file, options, api)
					if err != nil {
						t.Fatal(err)
					}
					compileLLVMToObject(t, llc, target.triple, "identity.ll", "identity.o", ir)
				})
			}
		})
	}
}

func TestARM64NativeScratchActualSDKBodyInputContract(t *testing.T) {
	assembly := strings.Replace(arm64ScratchSelectedSource, "TEXT ·Value(SB),4,$0-16\nMOVD n+0(FP),R1\nADD $3,R1", `TEXT ·Value(SB),4,$40-16
MOVD $0,R1
MOVD R1,8(RSP)
MOVD R1,16(RSP)
MOVD R1,24(RSP)
CALL runtime·memmove(SB)
MOVD $11,R1`, 1)
	pkg, request := arm64ScratchActualSourceFixtureWithAssembly(t, "linux", assembly)
	filename := filepath.Join(request.Directory, "value.go")
	declarations, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	declarations = []byte(strings.Replace(string(declarations), "package scratchfixture\n", "package scratchfixture\nimport _ \"runtime\"\n", 1))
	if err := os.WriteFile(filename, declarations, 0600); err != nil {
		t.Fatal(err)
	}
	// The capture re-typechecks these actual complete selected files and the
	// same-mode runtime export. Supplied ordinary function types cannot claim
	// any SDK body, wrapper, hidden entry or source permission by themselves.
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	source, err := CaptureGoARM64ScratchSource(ctx, pkg, request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := source.Close(); err != nil {
			t.Error(err)
		}
	}()
	for index, body := range source.native["runtime.memmove"] {
		t.Logf("actual SDK native member %d source=%s; complete original words=%08x; calls=%v; relocations=%+v",
			index, body.source, body.code, body.calls, body.relocs)
	}
	if _, closed := source.closed["runtime.memmove"]; !closed {
		t.Fatal("actual no-hidden-entry SDK body and actual ABI0 wrapper tuple did not close")
	}
	file, err := Parse(ArchARM64, assembly)
	if err != nil {
		t.Fatal(err)
	}
	resolve := func(symbol string) string { return strings.TrimPrefix(strings.TrimSuffix(symbol, "(SB)"), "·") }
	sigs, err := goSigsForAsmFile(pkg, file, resolve, "arm64", nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	options, err := source.BindScratchClosure(ctx, file, Options{Goarch: "arm64", TargetTriple: "aarch64-unknown-linux-gnu", ResolveSym: resolve, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	llc, _, _ := findLlcAndClang(t)
	for _, api := range []string{"text", "module", "GoModule"} {
		t.Run(api, func(t *testing.T) {
			var ir string
			var err error
			if api == "GoModule" {
				context := llvm.NewContext()
				defer context.Dispose()
				result, translateErr := translateGoModuleInContext(context, pkg, []byte(assembly), GoModuleOptions{
					GOARCH: options.Goarch, TargetTriple: options.TargetTriple, ResolveSym: options.ResolveSym,
					ManualSig: func(name string) (FuncSig, bool) { signature, present := options.Sigs[name]; return signature, present },
				})
				err = translateErr
				if result != nil && !result.Module.IsNil() {
					defer result.Module.Dispose()
					ir = result.Module.String()
				}
			} else {
				ir, err = arm64ScratchSourceAPI(t, pkg, file, options, api)
			}
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, options.TargetTriple, "actual-sdk.ll", "actual-sdk.o", ir)
		})
	}
}

func TestARM64NativeScratchSourcePublicInputsCannotForge(t *testing.T) {
	_, pkg, file, options, _ := arm64ScratchActualBoundSource(t, "linux", "aarch64-unknown-linux-gnu")
	for _, mutation := range []string{"without-token", "JSON", "result-tuple", "callee-tuple", "target", "resolver", "whole-source", "KeepFunc"} {
		for _, api := range []string{"text", "module", "GoModule"} {
			t.Run(mutation+"/"+api, func(t *testing.T) {
				changed := options
				changed.Sigs = make(map[string]FuncSig)
				for name, signature := range options.Sigs {
					changed.Sigs[name] = signature
					if mutation == "without-token" {
						signature.arm64NativeScratch = nil
						changed.Sigs[name] = signature
					}
				}
				input := arm64ScratchFileSnapshot(file)
				switch mutation {
				case "JSON":
					data, err := json.Marshal(changed.Sigs)
					if err != nil {
						t.Fatal(err)
					}
					if err := json.Unmarshal(data, &changed.Sigs); err != nil {
						t.Fatal(err)
					}
				case "result-tuple", "callee-tuple":
					name := "Scratch"
					if mutation == "callee-tuple" {
						name = "Value"
					}
					signature := changed.Sigs[name]
					signature.Ret = I32
					changed.Sigs[name] = signature
				case "target":
					changed.TargetTriple = "arm64-apple-darwin"
				case "resolver":
					changed.ResolveSym = func(name string) string { return "changed." + options.ResolveSym(name) }
					renamed := make(map[string]FuncSig)
					for name, signature := range changed.Sigs {
						signature.Name = "changed." + name
						renamed[signature.Name] = signature
					}
					changed.Sigs = renamed
				case "whole-source":
					input.Funcs[1].Instrs[2].Raw = "changed actual source"
				case "KeepFunc":
					input.Funcs = input.Funcs[:1]
				}
				if api == "GoModule" && (mutation == "whole-source" || mutation == "KeepFunc") {
					// This API reparses its bytes, not the separately mutated File.
					// Exercise its actual whole-source boundary explicitly below.
					ctx := llvm.NewContext()
					defer ctx.Dispose()
					opt := GoModuleOptions{GOARCH: changed.Goarch, TargetTriple: changed.TargetTriple, ResolveSym: changed.ResolveSym,
						ManualSig: func(name string) (FuncSig, bool) { signature, present := changed.Sigs[name]; return signature, present }}
					source := arm64ScratchSelectedSource
					if mutation == "whole-source" {
						source = strings.Replace(source, "ADD $3", "ADD $4", 1)
					} else {
						opt.KeepFunc = func(symbol, _ string) bool { return symbol == "·Scratch" }
					}
					result, err := translateGoModuleInContext(ctx, pkg, []byte(source), opt)
					if result != nil && !result.Module.IsNil() {
						result.Module.Dispose()
					}
					if !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatalf("mutated whole selected source acquired a scratch certificate: %v", err)
					}
					return
				}
				_, err := arm64ScratchSourceAPI(t, pkg, input, changed, api)
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("%s acquired native scratch permission: %v", mutation, err)
				}
			})
		}
	}
}

func TestARM64NativeScratchBinderLLVMIdentityCannotCollapse(t *testing.T) {
	ctx, _, file, options, source := arm64ScratchActualBoundSource(t, "linux", "aarch64-unknown-linux-gnu")
	for _, resolved := range []string{"", "same"} {
		t.Run("name="+resolved, func(t *testing.T) {
			changed := options
			changed.ResolveSym = func(string) string { return resolved }
			signature := options.Sigs["Scratch"]
			signature.Name = resolved
			changed.Sigs = map[string]FuncSig{resolved: signature}
			if _, err := source.BindScratchClosure(ctx, file, changed); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("collapsed declaration namespace acquired a binding: %v", err)
			}
		})
	}
}

func TestARM64NativeScratchSourceLateInputMutationAndClose(t *testing.T) {
	for _, input := range []string{"value.go", "value_arm64.s", "go.mod", "native-object", "new-selected-Go", "closed"} {
		t.Run(input, func(t *testing.T) {
			ctx, _, file, options, source := arm64ScratchActualBoundSource(t, "linux", "aarch64-unknown-linux-gnu")
			if input == "closed" {
				if err := source.Close(); err != nil {
					t.Fatal(err)
				}
			} else {
				name := filepath.Join(source.request.Directory, input)
				if input == "native-object" {
					name = filepath.Join(source.owned, "original-0.o")
				}
				contents := "changed selected input"
				if input == "new-selected-Go" {
					name = filepath.Join(source.request.Directory, "new.go")
					contents = "package scratchfixture\nconst NewlySelected = 1\n"
				}
				if err := os.WriteFile(name, []byte(contents), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := source.Verify(ctx); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("late input mutation retained a live source token: %v", err)
			}
			if _, err := Translate(file, options); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("late input mutation produced LLVM output: %v", err)
			}
		})
	}
}

func TestARM64NativeScratchSourceCaptureRequiresActualRoles(t *testing.T) {
	pkg, request := arm64ScratchActualSourceFixture(t, "linux")
	for _, test := range []struct {
		name string
		ctx  context.Context
		edit func(*GoPackage, *GoARM64ScratchCaptureRequest)
	}{
		{"unbounded", context.Background(), func(*GoPackage, *GoARM64ScratchCaptureRequest) {}},
		{"foreign-package", nil, func(pkg *GoPackage, _ *GoARM64ScratchCaptureRequest) { pkg.Path = "foreign.invalid" }},
		{"unselected-file", nil, func(_ *GoPackage, request *GoARM64ScratchCaptureRequest) { request.AssemblyFile = "other_arm64.s" }},
		{"custom-driver", nil, func(_ *GoPackage, request *GoARM64ScratchCaptureRequest) {
			request.Environment = append(request.Environment, "GOPACKAGESDRIVER=invented")
		}},
		{"unknown-target", nil, func(_ *GoPackage, request *GoARM64ScratchCaptureRequest) { request.Target = "linux/amd64" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			claimed, changed := pkg, request
			test.edit(&claimed, &changed)
			ctx := test.ctx
			if ctx == nil {
				var cancel context.CancelFunc
				ctx, cancel = runtimeOracleStageContext(t)
				defer cancel()
			}
			source, err := CaptureGoARM64ScratchSource(ctx, claimed, changed)
			if source != nil {
				defer source.Close()
			}
			if !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal(fmt.Sprintf("actual input role %s acquired permission: %v", test.name, err))
			}
		})
	}
}

func TestARM64NativeScratchOriginalSelectionFreshExportIdentity(t *testing.T) {
	_, request := arm64ScratchActualSourceFixture(t, "linux")
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	var identities [][]byte
	for observation := 0; observation < 2; observation++ {
		output, err := goasmcmd.Run(ctx, request.Directory, request.Environment, request.GoBinary,
			"list", "-deps", "-export", "-compiled", "-mod=readonly", "-json", ".")
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("actual stock Go selection observation %d:\n%s", observation, output)
		identity, err := arm64ScratchSelectionIdentity(output)
		if err != nil {
			t.Fatal(err)
		}
		identities = append(identities, identity)
	}
	if string(identities[0]) != string(identities[1]) {
		t.Fatal("actual original source/export identity changed across fresh export")
	}
}

func TestARM64NativeScratchSelectionOnlyCacheStateIsTransient(t *testing.T) {
	const observation = `{"Dir":"/source","ImportPath":"example.invalid/pkg","Export":"/export","BuildID":"actual","CompiledGoFiles":["value.go"],"Module":{"Path":"example.invalid/pkg","GoMod":"/source/go.mod","GoVersion":"1.20"},"ImportMap":{"other":"real/other"},"Stale":true,"StaleReason":"build ID mismatch","FutureField":{"Role":"original"}}`
	expected, err := arm64ScratchSelectionIdentity([]byte(observation))
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"Stale", "StaleReason", "Dir", "ImportPath", "Export", "BuildID", "CompiledGoFiles", "Module", "ImportMap", "FutureField"} {
		t.Run(field, func(t *testing.T) {
			var record map[string]json.RawMessage
			if err := json.Unmarshal([]byte(observation), &record); err != nil {
				t.Fatal(err)
			}
			record[field] = json.RawMessage(`"changed"`)
			changed, err := json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			actual, err := arm64ScratchSelectionIdentity(changed)
			if err != nil {
				t.Fatal(err)
			}
			if equal := string(actual) == string(expected); equal != (field == "Stale" || field == "StaleReason") {
				t.Fatalf("selection field %s identity equality=%v", field, equal)
			}
		})
	}
}

func TestARM64NativeScratchSourceSharedBudgetIsObservationNotPermission(t *testing.T) {
	name := filepath.Join(t.TempDir(), "input")
	if err := os.WriteFile(name, []byte{1, 2}, 0600); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name  string
		bytes int64
		count int
	}{
		{"bytes", 256<<20 - 1, 0},
		{"count", 0, 8192},
	} {
		t.Run(test.name, func(t *testing.T) {
			source := &GoARM64ScratchSource{inputs: make(map[string][32]byte), bytes: test.bytes}
			for i := 0; i < test.count; i++ {
				source.inputs[fmt.Sprint(i)] = [32]byte{}
			}
			if _, err := source.read(name); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("exhausted shared capture budget was ignored: %v", err)
			}
			if source.ready {
				t.Fatal("resource ledger manufactured a source capability")
			}
		})
	}
}
