//go:build go1.27

package plan9asm

import (
	"encoding/json"
	"errors"
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

func numericalSBFixture(t testing.TB, arch string) (GoPackage, GoAMD64FrameCaptureRequest, *File, Options) {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	goSource := []byte("package numericalfixture\nfunc Feature() byte\n")
	assembly := `#include "textflag.h"
TEXT ·Feature(SB),NOSPLIT,$0-1
MOVL $0,AX
CMPB internal∕cpu·X86+64(SB),$1
SETEQ AL
PINSRD $0,AX,X0
PEXTRD $0,X0,AX
MOVB AL,ret+0(FP)
RET
`
	for name, data := range map[string][]byte{
		"go.mod":               []byte("module example.invalid/numericalfixture\ngo 1.27\n"),
		"value.go":             goSource,
		"value_" + arch + ".s": []byte(assembly),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	fset := token.NewFileSet()
	syntax, err := parser.ParseFile(fset, filepath.Join(dir, "value.go"), goSource, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	typed, err := (&types.Config{Sizes: types.SizesFor("gc", arch)}).Check("example.invalid/numericalfixture", fset, []*ast.File{syntax}, nil)
	if err != nil {
		t.Fatal(err)
	}
	binary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	binary, err = filepath.EvalSymlinks(binary)
	if err != nil {
		t.Fatal(err)
	}
	env := make(map[string]string)
	for _, pair := range os.Environ() {
		key, value, _ := strings.Cut(pair, "=")
		env[key] = value
	}
	for _, key := range []string{"GOCACHE", "GOMODCACHE", "GOPATH", "TMPDIR", "GOTMPDIR"} {
		if !filepath.IsAbs(env[key]) {
			env[key] = t.TempDir()
		}
		env[key], err = filepath.EvalSymlinks(env[key])
		if err != nil {
			t.Fatal(err)
		}
	}
	for key, value := range map[string]string{
		"GOOS": "linux", "GOARCH": arch, "GOAMD64": "v1", "GO386": "sse2",
		"GOFLAGS": "", "GOEXPERIMENT": "", "GOTOOLCHAIN": "local", "GOENV": "off",
		"GOWORK": "off", "CGO_ENABLED": "0", "GOPROXY": "off",
	} {
		env[key] = value
	}
	var environment []string
	for key, value := range env {
		environment = append(environment, key+"="+value)
	}
	request := GoAMD64FrameCaptureRequest{GoBinary: binary, Directory: dir, AssemblyFile: "value_" + arch + ".s", Target: "linux/" + arch, Environment: environment}
	file, err := Parse(ArchAMD64, strings.Replace(assembly, "#include \"textflag.h\"", "#define NOSPLIT 4", 1))
	if err != nil {
		t.Fatal(err)
	}
	declaration := typed.Scope().Lookup("Feature").(*types.Func)
	sig, err := DeriveGoFuncABI0Signature(typed.Path()+".Feature", declaration, arch, types.SizesFor("gc", arch))
	if err != nil {
		t.Fatal(err)
	}
	triple := "x86_64-unknown-linux-gnu"
	if arch == "386" {
		triple = "i386-unknown-linux-gnu"
	}
	opt := Options{Goarch: arch, TargetTriple: triple, ResolveSym: func(sym string) string {
		if strings.HasPrefix(sym, "·") {
			return typed.Path() + "." + strings.TrimPrefix(sym, "·")
		}
		return strings.ReplaceAll(strings.ReplaceAll(sym, "∕", "/"), "·", ".")
	}, Sigs: map[string]FuncSig{sig.Name: sig}}
	return GoPackage{Path: typed.Path(), Types: typed, Syntax: []*ast.File{syntax}}, request, file, opt
}

func TestGoX86NumericalSBReadActualSealedSDKJoin(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			_, original, _, _ := numericalSBFixture(t, arch)
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			owner, err := CaptureGoNumericalStorageOwner(ctx, GoNumericalStorageCaptureRequest{
				GoBinary: original.GoBinary, Directory: filepath.Join(filepath.Dir(filepath.Dir(original.GoBinary)), "src", "internal", "cpu"),
				PackagePath: "internal/cpu", Target: original.Target, Environment: original.Environment, SDKCPU: true,
				Variables: []GoNumericalStorageReference{{PackagePath: "internal/cpu", Name: "X86"}},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer owner.Close()
			source, err := CaptureGoX86NumericalReadSource(ctx, GoX86NumericalReadCaptureRequest{
				GoBinary: original.GoBinary, Directory: original.Directory, PackagePath: "example.invalid/numericalfixture",
				AssemblyFile: original.AssemblyFile, Target: original.Target, Environment: original.Environment,
				Owners: []*GoNumericalStorageOwner{owner},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := source.Close(); err != nil {
					t.Error(err)
				}
			}()
			if len(source.reads) != 1 {
				t.Fatalf("wrong actual numerical reads: %d", len(source.reads))
			}
			read := source.reads[0]
			add := int64(64)
			if arch == "amd64" {
				add = 63
			}
			if read.offset != 64 || read.width != 1 || read.relocation.Add != add || read.variable.NativeName != "internal/cpu.X86" {
				t.Fatalf("whole native CMP trailing-immediate/source offset join differs: %+v", read)
			}
			data, err := source.Readback(ctx)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("actual %s read sealed; source64/read1 nativeAdd%d reportBytes%d", arch, add, len(data))
			retainNumericalRead(t, source, "cpu")
			var restored GoX86NumericalReadSource
			if err := json.Unmarshal([]byte("{}"), &restored); err != nil || !errors.Is(restored.Verify(ctx), ErrProbeNeedsContext) {
				t.Fatal("JSON recreated source permission")
			}
			owner.Close()
			if !errors.Is(source.Verify(ctx), ErrProbeNeedsContext) {
				t.Fatal("closed numerical owner retained source join")
			}
		})
	}
}

func retainNumericalRead(t *testing.T, source *GoX86NumericalReadSource, role string) {
	t.Helper()
	if artifact := os.Getenv("PLAN9ASM_STATIC_STORAGE_ARTIFACT_DIR"); artifact != "" {
		folder := filepath.Join(artifact, strings.ReplaceAll(source.request.Target, "/", "-"), "numerical-read-"+role)
		if err := os.MkdirAll(folder, 0700); err != nil {
			t.Fatal(err)
		}
		for name, data := range map[string][]byte{
			"sealed-report.json":   source.report,
			"archive-original.a":   source.native.Archive,
			"object-original.o":    source.native.OriginalObject,
			"object-expanded.o":    source.native.ExpandedObject,
			"listing-original.txt": source.native.OriginalListing,
			"listing-expanded.txt": source.native.ExpandedListing,
			"source-expanded.s":    []byte(source.cpp.Output),
		} {
			if err := os.WriteFile(filepath.Join(folder, name), data, 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestGoX86NumericalSBReadActualSDKBlankAndExtentNegatives(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			_, original, _, _ := numericalSBFixture(t, arch)
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			owner, err := CaptureGoNumericalStorageOwner(ctx, GoNumericalStorageCaptureRequest{
				GoBinary: original.GoBinary, Directory: filepath.Join(filepath.Dir(filepath.Dir(original.GoBinary)), "src", "internal", "cpu"),
				PackagePath: "internal/cpu", Target: original.Target, Environment: original.Environment, SDKCPU: true,
				Variables: []GoNumericalStorageReference{{PackagePath: "internal/cpu", Name: "X86"}},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer owner.Close()
			for _, test := range []struct{ name, instruction string }{
				{"leading CacheLinePad", "MOVB internal∕cpu·X86+63(SB),AL"},
				{"cross numerical span", "MOVW internal∕cpu·X86+99(SB),AX"},
				{"trailing CacheLinePad", "MOVB internal∕cpu·X86+100(SB),AL"},
				{"outside native extent", "MOVB internal∕cpu·X86+164(SB),AL"},
			} {
				t.Run(test.name, func(t *testing.T) {
					assembly := "#include \"textflag.h\"\nTEXT ·Feature(SB),NOSPLIT,$0-1\n" + test.instruction + "\nMOVB AL,ret+0(FP)\nRET\n"
					if err := os.WriteFile(filepath.Join(original.Directory, original.AssemblyFile), []byte(assembly), 0600); err != nil {
						t.Fatal(err)
					}
					actual, err := goasmcmd.Run(ctx, original.Directory, original.Environment, original.GoBinary,
						"list", "-json", "-compiled", "-export", "-mod=readonly", ".")
					if err != nil {
						t.Fatalf("actual original Go accepted negative precondition failed: %v\n%s", err, actual)
					}
					source, err := CaptureGoX86NumericalReadSource(ctx, GoX86NumericalReadCaptureRequest{
						GoBinary: original.GoBinary, Directory: original.Directory, PackagePath: "example.invalid/numericalfixture",
						AssemblyFile: original.AssemblyFile, Target: original.Target, Environment: original.Environment,
						Owners: []*GoNumericalStorageOwner{owner},
					})
					if source != nil {
						source.Close()
						t.Fatal("blank/cross-span/out-of-extent CPU bytes obtained a read join")
					}
					if !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("negative did not produce exact Context", err)
					}
				})
			}
		})
	}
}

func TestGoX86NumericalSBReadOriginalContext(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			_, request, file, opt := numericalSBFixture(t, arch)
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			selection, err := goasmcmd.Run(ctx, request.Directory, request.Environment, request.GoBinary, "list", "-json", "-compiled", "-export", "-mod=readonly", ".")
			if err != nil {
				t.Fatalf("actual original Go export failed: %v\n%s", err, selection)
			}
			listing, err := goasmcmd.Run(ctx, request.Directory, request.Environment, request.GoBinary, "tool", "asm", "-S", "-p", "example.invalid/numericalfixture", "-I", filepath.Join(filepath.Dir(filepath.Dir(request.GoBinary)), "pkg", "include"), "-o", filepath.Join(t.TempDir(), "original.o"), request.AssemblyFile)
			if err != nil {
				t.Fatalf("actual original Go asm failed: %v\n%s", err, listing)
			}
			t.Logf("actual %s original Go export succeeded; source64/read1 listing:\n%s", arch, listing)
			for _, api := range []string{"text", "module", "context"} {
				t.Run(api, func(t *testing.T) {
					var err error
					if api == "text" {
						_, err = Translate(file, opt)
					} else if api == "module" {
						mod, failure := TranslateModule(file, opt)
						err = failure
						if !mod.IsNil() {
							mod.Dispose()
						}
					} else {
						llvmContext := llvm.NewContext()
						mod, failure := TranslateModuleInContext(llvmContext, file, opt)
						err = failure
						if !mod.IsNil() {
							mod.Dispose()
						}
						llvmContext.Dispose()
					}
					if os.Getenv("PLAN9ASM_NUMERICAL_SB_EXPECT_ACCEPT") == "1" {
						if err != nil {
							t.Fatalf("actual-Go accepted numerical SB read not closed: %v", err)
						}
					} else if !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatalf("declaration-only SB read acquired authority: %v", err)
					}
				})
			}
		})
	}
}
