package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/constant"
	"go/types"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm"
	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

// These stubs have zero declared parameters, but their physical callers have
// arbitrary signatures. A successful Go object is not an ordinary LLVM entry
// contract. Keep both original TEXT bodies and the missing-context failures.
func TestReflectDynamicStubNativeObjectsRetainContext(t *testing.T) {
	for _, goarch := range []string{"386", "amd64", "arm"} {
		t.Run(goarch, func(t *testing.T) {
			pkgs, err := loadPkgs("linux", goarch, []string{"reflect"}, nil, "", true, false)
			if err != nil || len(pkgs) != 1 {
				t.Fatalf("actual reflect package: count=%d err=%v", len(pkgs), err)
			}
			pkg := pkgs[0]
			sourcePath := filepath.Join(filepath.Dir(pkg.GoFiles[0]), "asm_"+goarch+".s")
			source, err := readAsmSource(sourcePath, asmSourceRoot(pkg, sourcePath))
			if err != nil {
				t.Fatal(err)
			}
			imports := make(map[string]*types.Package, len(pkg.Imports))
			for path, dependency := range pkg.Imports {
				imports[path] = dependency.Types
			}
			source = plan9asm.ExpandGoAssemblySource(plan9asm.GoPackage{
				Path: pkg.PkgPath, Types: pkg.Types, Imports: imports,
			}, source, goarch)
			arch, err := toPlan9Arch(goarch)
			if err != nil {
				t.Fatal(err)
			}
			file, err := plan9asm.ParseWithDefines(arch, string(source), plan9asm.GoAssemblerDefines("linux", goarch))
			if err != nil {
				t.Fatal(err)
			}
			resolve := resolveSymFunc(pkg.PkgPath)
			sigs, argSizes, err := sigsForAsmFile(pkg, file, resolve, goarch)
			if err != nil {
				t.Fatal(err)
			}
			listing, actualHeader := reflectDynamicStubGoObject(t, pkg.Types, sourcePath, goarch)
			if goarch == "amd64" {
				selected := plan9asm.GoPackage{Path: pkg.PkgPath, Types: pkg.Types, Imports: imports}
				canonical, err := parseCompleteCLIAssembly(arch, string(source),
					plan9asm.GoAssemblerDefines("linux", goarch), goarch, &selected)
				if err != nil {
					t.Fatal("selected generated header did not reach complete CPP", err)
				}
				expanded, err := plan9asm.PreprocessAssemblySource(string(source), plan9asm.AssemblyPreprocessOptions{
					Defines: plan9asm.GoAssemblerDefines("linux", goarch),
					ReadInclude: func(_ string, name string) (string, []byte, error) {
						if name != "go_asm.h" {
							return "", nil, fmt.Errorf("unexpected remaining SDK include %q", name)
						}
						return "actual/go_asm.h", actualHeader, nil
					},
				})
				if err != nil {
					t.Fatal(err)
				}
				original, err := plan9asm.Parse(arch, expanded)
				if err != nil || !reflect.DeepEqual(canonical, original) {
					t.Fatal("selected CPP differs from the real compiler-generated header", err)
				}
			}
			unknown := pkg.Imports["internal/abi"].Types.Scope().Lookup("ArgsSizeUnknown").(*types.Const)
			unknownSize, ok := constant.Int64Val(unknown.Val())
			if !ok {
				t.Fatal("actual Go ArgsSizeUnknown is not an int64 constant")
			}
			for _, name := range []string{"makeFuncStub", "methodValueCall"} {
				t.Run(name, func(t *testing.T) {
					decl, ok := pkg.Types.Scope().Lookup(name).(*types.Func)
					if !ok {
						t.Fatalf("actual reflect declaration %s not found", name)
					}
					declSig := decl.Type().(*types.Signature)
					if declSig.Params().Len() != 0 || declSig.Results().Len() != 0 {
						t.Fatalf("%s no longer has the source zero-argument declaration", name)
					}
					resolved := pkg.PkgPath + "." + name
					fs, ok := sigs[resolved]
					argSize, declared := argSizes[resolved]
					if !ok || !declared || len(fs.Args) != 0 || fs.Ret != plan9asm.Void || len(fs.Frame.Params) != 0 || len(fs.Frame.Results) != 0 || argSize != 0 {
						t.Fatalf("invented explicit Go arguments/frame for %s: %+v", resolved, fs)
					}
					var function *plan9asm.Func
					for index := range file.Funcs {
						if resolve(file.Funcs[index].Sym) == resolved {
							function = &file.Funcs[index]
						}
					}
					if function == nil || function.FrameSize <= 0 || hasExplicitTextArgSize(*function) {
						t.Fatalf("original %s TEXT lost its local/dynamic-argument frame", resolved)
					}
					reflectDynamicStubCheckArgsSize(t, listing, resolved, unknownSize)
					original := &plan9asm.File{Arch: arch, Funcs: []plan9asm.Func{*function}}
					ir, err := plan9asm.Translate(original, plan9asm.Options{
						Goarch: goarch, TargetTriple: targetTriple("linux", goarch),
						ResolveSym: resolve, Sigs: sigs,
					})
					if !errors.Is(err, plan9asm.ErrProbeNeedsContext) || !strings.Contains(err.Error(), "bound typed frame storage") || ir != "" {
						t.Fatalf("dynamic caller frame must not become a zero/ordinary FP slot: emitted IR bytes=%d err=%v", len(ir), err)
					}
					t.Logf("%s actual Go declaration=func(); native TEXT args=ArgsSizeUnknown; original LLVM translation remains FAILED: %v", resolved, err)
				})
			}
			cfg, err := resolveCompileConfig(true, "", true, 2)
			if err != nil {
				t.Fatal(err)
			}
			out := filepath.Join(t.TempDir(), "reflect.ll")
			err = compileOne(pkg, arch, "linux", goarch, targetTriple("linux", goarch),
				asmTask{PkgPath: pkg.PkgPath, AsmFile: sourcePath, OutLL: out}, false, cfg)
			var sourceNA *asmABINotApplicableError
			if !errors.Is(err, plan9asm.ErrProbeNeedsContext) || errors.As(err, &sourceNA) {
				t.Fatalf("whole original reflect source must retain its real translation failure, not source N/A: %v", err)
			}
			if !strings.Contains(err.Error(), "empty Go declaration does not bind a dynamic caller frame") ||
				!strings.Contains(err.Error(), "TEXT argument size is unspecified") {
				t.Fatalf("actual-source failure lost its dynamic-entry diagnostic: %v", err)
			}
			for _, artifact := range []string{out, strings.TrimSuffix(out, ".ll") + ".o"} {
				if _, err := os.Stat(artifact); !os.IsNotExist(err) {
					t.Fatalf("failed whole-source translation published an artifact: %v", err)
				}
			}
			repoRoot, err := filepath.Abs("../..")
			if err != nil {
				t.Fatal(err)
			}
			report, _, err := runOneTarget(targetSpec{Goos: "linux", Goarch: goarch},
				[]string{"reflect"}, nil, nil, "", t.TempDir(),
				false, 0, true, false, true, repoRoot, cfg)
			if err != nil || report.TotalAsm != 1 || report.Success != 0 || report.NotApplicable != 0 || report.Failed != 1 ||
				len(report.AsmFiles) != 1 || report.AsmFiles[0] != sourcePath || len(report.Fails) != 1 ||
				!strings.Contains(report.Fails[0].Err, "bound typed frame storage") ||
				!strings.Contains(report.Fails[0].Err, "empty Go declaration does not bind a dynamic caller frame") ||
				len(report.UnsupportedOps) != 0 {
				t.Fatalf("original dynamic-entry failure must remain a failed file: report=%+v err=%v", report, err)
			}
			t.Logf("actual whole-file report linux/%s: total=1 success=0 failed=1 source-N/A=0; error=%s", goarch, report.Fails[0].Err)
		})
	}
}

func reflectDynamicStubGoObject(t *testing.T, pkg *types.Package, source, goarch string) (string, []byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	binary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	env := append(os.Environ(), "GOOS=linux", "GOARCH="+goarch, "CGO_ENABLED=0", "GOTOOLCHAIN=local")
	run := func(args ...string) []byte {
		t.Helper()
		out, stderr, err := gotoolprofile.RunBounded(ctx, "", env, binary, args...)
		if err != nil {
			t.Fatalf("actual Go %v: %v\n%s\n%s", args, err, out, stderr)
		}
		return append(out, stderr...)
	}
	var importcfg strings.Builder
	var files []string
	decoder := json.NewDecoder(strings.NewReader(string(run("list", "-deps", "-export", "-json", "reflect"))))
	for {
		var selected struct {
			ImportPath, Dir, Export string
			GoFiles, SFiles         []string
		}
		if err := decoder.Decode(&selected); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		// unsafe is intrinsic compiler input, not an export archive. This is
		// the same omission as Go's generated importcfg, not an assembly skip.
		if selected.ImportPath == "unsafe" && selected.Export == "" {
			continue
		}
		if selected.Export == "" {
			t.Fatalf("actual Go export missing for %s", selected.ImportPath)
		}
		fmt.Fprintf(&importcfg, "packagefile %s=%s\n", selected.ImportPath, selected.Export)
		if selected.ImportPath == "reflect" {
			selectedSource, err := reflectDynamicStubAssemblySelected(selected.Dir, selected.SFiles, source)
			if err != nil || !selectedSource {
				t.Fatalf("actual Go linux/%s did not select %s: %v", goarch, source, err)
			}
			for _, name := range selected.GoFiles {
				files = append(files, filepath.Join(selected.Dir, name))
			}
		}
	}
	if len(files) == 0 {
		t.Fatal("actual Go selected no reflect source")
	}
	dir := t.TempDir()
	config := filepath.Join(dir, "importcfg")
	if err := os.WriteFile(config, []byte(importcfg.String()), 0600); err != nil {
		t.Fatal(err)
	}
	header := filepath.Join(dir, "go_asm.h")
	typedHeader, err := plan9asm.GoAssemblyHeader(plan9asm.GoPackage{Path: "reflect", Types: pkg}, goarch)
	if err != nil {
		t.Fatal(err)
	}
	// Bootstrap symabis with the complete selected typed header, never an
	// empty placeholder. Compilation then overwrites it with real -asmhdr;
	// compare every definition before using that real header for the object.
	if err := os.WriteFile(header, typedHeader, 0600); err != nil {
		t.Fatal(err)
	}
	root := strings.TrimSpace(string(run("env", "GOROOT")))
	symabis := filepath.Join(dir, "symabis")
	run("tool", "asm", "-gensymabis", "-p", "reflect", "-I", filepath.Join(root, "pkg", "include"),
		"-I", dir, "-o", symabis, source)
	nativeABIs, err := os.ReadFile(symabis)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"makeFuncStub", "methodValueCall"} {
		if !strings.Contains(string(nativeABIs), "def reflect."+name+" ABI0\n") {
			t.Fatalf("real selected assembly did not define %s with ABI0: %s", name, nativeABIs)
		}
	}
	args := []string{"tool", "compile", "-std", "-p", "reflect", "-importcfg", config,
		"-symabis", symabis, "-asmhdr", header, "-o", filepath.Join(dir, "header.o")}
	run(append(args, files...)...)
	actualHeader, err := os.ReadFile(header)
	if err != nil {
		t.Fatal(err)
	}
	actualDefinitions, err := gotoolprofile.HeaderDefinitions(actualHeader)
	if err != nil {
		t.Fatal(err)
	}
	typedDefinitions, err := gotoolprofile.HeaderDefinitions(typedHeader)
	if err != nil || !reflect.DeepEqual(actualDefinitions, typedDefinitions) {
		t.Fatalf("actual Go -asmhdr and selected typed reflect layouts differ: %v", err)
	}
	object := filepath.Join(dir, "reflect.o")
	listing := run("tool", "asm", "-S", "-p", "reflect", "-I", filepath.Join(root, "pkg", "include"),
		"-I", dir, "-o", object, source)
	info, err := os.Stat(object)
	if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
		t.Fatalf("actual Go assembler produced no nonempty object: %v", err)
	}
	t.Logf("actual Go linux/%s object=%d bytes; original source sha256=%s; real generated header sha256=%s\n%s\n%s",
		goarch, info.Size(), mustReflectContractFileSHA(t, source), featureBytesSHA256(actualHeader), nativeABIs, listing)
	return string(listing), actualHeader
}

func reflectDynamicStubCheckArgsSize(t *testing.T, listing, symbol string, unknown int64) {
	t.Helper()
	for _, line := range strings.Split(listing, "\n") {
		if !strings.HasPrefix(line, symbol+" STEXT ") {
			continue
		}
		for _, field := range strings.Fields(line) {
			if !strings.HasPrefix(field, "args=") {
				continue
			}
			bits, err := strconv.ParseUint(strings.TrimPrefix(field, "args="), 0, 64)
			if err != nil || int64(int32(bits)) != unknown {
				t.Fatalf("native %s args is not actual Go ArgsSizeUnknown=%d: %s", symbol, unknown, line)
			}
			return
		}
	}
	t.Fatalf("native %s ArgsSizeUnknown metadata is absent", symbol)
}

func mustReflectContractFileSHA(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return featureBytesSHA256(data)
}
