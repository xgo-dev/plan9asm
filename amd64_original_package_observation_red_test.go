package plan9asm

import (
	"bytes"
	"encoding/json"
	"errors"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
	"github.com/xgo-dev/plan9asm/internal/goasmcmd"
)

// Ordinary bodies and SDK imports may accompany a sealed object observation,
// but only bodyless assembly declarations enter its function/layout map.
// Observation remains separate from fixed-local/caller/native-memory permission.
type originalPackageObservationVariant struct {
	name        string
	directory   string
	declaration string
	data        bool
}

var originalPackageObservationVariants = []originalPackageObservationVariant{
	{name: "nested", directory: "internal/kernel"},
	{name: "bodyful", declaration: "func Reference(a uint64) uint64 { return a + 1 }\n"},
	{name: "import", declaration: "import _ \"math/bits\"\n"},
	{name: "data", data: true},
}

type originalPackageObservationSelected struct {
	Dir, ImportPath, Export                   string
	GoFiles, CompiledGoFiles, SFiles, Imports []string
	ImportMap                                 map[string]string
	Module                                    *struct {
		Path, Version, Dir, GoMod, GoVersion string
		Main                                 bool
	}
}

func originalPackageObservationFixture(t *testing.T, variant originalPackageObservationVariant) (GoPackage, GoAMD64FrameCaptureRequest) {
	t.Helper()
	_, request := goAMD64FrameSourceFixture(t)
	root := request.Directory
	const module = "example.invalid/framefixture"
	directory := root
	packagePath := module
	if variant.directory != "" {
		directory = filepath.Join(root, filepath.FromSlash(variant.directory))
		packagePath += "/" + variant.directory
		if err := os.MkdirAll(directory, 0700); err != nil {
			t.Fatal(err)
		}
	}
	declaration := "package framefixture\n" + variant.declaration + "func Value(a uint64) uint64\n"
	files := map[string]string{
		"value.go": declaration,
		"value_amd64.s": "#include \"textflag.h\"\nTEXT ·Value(SB),NOSPLIT,$160-16\n" +
			"MOVQ a+0(FP),AX\nMOVQ AX,16(SP)\nMOVQ 16(SP),AX\nMOVQ AX,ret+8(FP)\nRET\n",
	}
	if variant.data {
		files["data_amd64.s"] = "#include \"textflag.h\"\nDATA ·constant<>+0(SB)/8,$1\n" +
			"GLOBL ·constant<>(SB),RODATA|NOPTR,$8\n"
	}
	for name, source := range files {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
	}
	request.Directory = directory
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	env := append([]string(nil), request.Environment...)
	env = append(env, "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0", "GOFLAGS=", "GOWORK=off", "GOTOOLCHAIN=local", "GOENV=off")
	data, err := goasmcmd.Run(ctx, directory, env, request.GoBinary,
		"list", "-deps", "-compiled", "-export", "-mod=readonly", "-json", ".")
	if err != nil {
		t.Fatalf("first-party original Go export failed: %v; %s", err, data)
	}
	t.Logf("actual original Go selected/export graph (%s):\n%s", variant.name, data)
	exports := make(map[string]string)
	var selected *originalPackageObservationSelected
	decoder := json.NewDecoder(bytes.NewReader(data))
	for {
		var pkg originalPackageObservationSelected
		if err := decoder.Decode(&pkg); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		if pkg.Export != "" {
			if _, duplicate := exports[pkg.ImportPath]; duplicate {
				t.Fatalf("duplicate actual export: %s", pkg.ImportPath)
			}
			exports[pkg.ImportPath] = pkg.Export
		}
		if pkg.ImportPath == packagePath {
			if selected != nil {
				t.Fatal("duplicate actual original package selection")
			}
			copy := pkg
			selected = &copy
		}
	}
	if selected == nil || selected.Module == nil || !selected.Module.Main ||
		selected.Module.Path != module || selected.Module.Version != "" ||
		len(selected.CompiledGoFiles) == 0 || len(selected.SFiles) == 0 || selected.Export == "" {
		t.Fatalf("incomplete actual original main-package export: %+v", selected)
	}
	actualDir, err := filepath.EvalSymlinks(selected.Dir)
	if err != nil {
		t.Fatal(err)
	}
	wantedDir, err := filepath.EvalSymlinks(directory)
	if err != nil || actualDir != wantedDir {
		t.Fatalf("actual package physical root differs: %s, %s, %v", actualDir, wantedDir, err)
	}
	if variant.data && len(selected.SFiles) != 2 {
		t.Fatalf("original Go omitted the DATA-only sibling: %v", selected.SFiles)
	}
	if variant.name == "import" && exports["math/bits"] == "" {
		t.Fatal("actual standard-library dependency export was not observed")
	}
	fset := token.NewFileSet()
	var syntax []*ast.File
	for _, name := range selected.CompiledGoFiles {
		if !filepath.IsAbs(name) {
			name = filepath.Join(selected.Dir, name)
		}
		file, err := parser.ParseFile(fset, name, nil, parser.ParseComments)
		if err != nil {
			t.Fatal(err)
		}
		syntax = append(syntax, file)
	}
	actualImporter := importer.ForCompiler(fset, "gc", func(path string) (io.ReadCloser, error) {
		if actual, mapped := selected.ImportMap[path]; mapped {
			path = actual
		}
		filename := exports[path]
		if filename == "" {
			t.Fatalf("missing actual selected export for %s", path)
		}
		return os.Open(filename)
	})
	typed, err := (&types.Config{Importer: actualImporter, Sizes: types.SizesFor("gc", "amd64"),
		GoVersion: "go" + selected.Module.GoVersion}).Check(packagePath, fset, syntax, nil)
	if err != nil {
		t.Fatal(err)
	}
	return GoPackage{Path: packagePath, Types: typed, Syntax: syntax}, request
}

func TestGoAMD64OriginalPackageObservationKeepsAuthorityBoundaries(t *testing.T) {
	for _, variant := range originalPackageObservationVariants {
		t.Run(variant.name, func(t *testing.T) {
			pkg, request := originalPackageObservationFixture(t, variant)
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			observed, err := CaptureGoAMD64FrameSource(ctx, pkg, request)
			if observed != nil {
				defer func() {
					if err := observed.Close(); err != nil {
						t.Error(err)
					}
				}()
			}
			if variant.name == "bodyful" || variant.name == "import" {
				if err != nil || observed == nil {
					t.Fatalf("ordinary original source lost its sealed observation: %v", err)
				}
				if len(observed.functions) != 1 || len(observed.declarations) != 1 ||
					observed.functions[pkg.Path+".Value"].locals != 168 {
					t.Fatal("ordinary Go declaration manufactured an assembly frame observation")
				}
				if err := observed.Verify(ctx); err != nil {
					t.Fatal(err)
				}
				// Even a live real-object observation supplies no aligned native
				// stack storage to any translator without its separate Binder.
				const assembly = "TEXT ·Value(SB),4,$160-16\nPXOR X0,X0\nMOVOU X0,16(SP)\nPADDQ 16(SP),X0\nMOVQ $1,ret+8(FP)\nRET\n"
				goAssemblerOracleOutput(t, "amd64", assembly, "", true)
				file, err := Parse(ArchAMD64, assembly)
				if err != nil {
					t.Fatal(err)
				}
				resolve := func(symbol string) string { return strings.Replace(symbol, "·", pkg.Path+".", 1) }
				sig := observed.functions[pkg.Path+".Value"].signature
				opt := Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu", ResolveSym: resolve,
					Sigs: map[string]FuncSig{sig.Name: sig}}
				if _, err := Translate(file, opt); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("ordinary observation granted native memory to text API: %v", err)
				}
				context := llvm.NewContext()
				defer context.Dispose()
				module, err := TranslateModuleInContext(context, file, opt)
				if !module.IsNil() {
					defer module.Dispose()
				}
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("ordinary observation granted native memory to module API: %v", err)
				}
				translated, err := translateGoModuleInContext(context, pkg, []byte(assembly), GoModuleOptions{
					GOOS: "linux", GOARCH: "amd64", TargetTriple: opt.TargetTriple, ResolveSym: resolve})
				if translated != nil && !translated.Module.IsNil() {
					defer translated.Module.Dispose()
				}
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("ordinary observation granted native memory to typed Go API: %v", err)
				}
			} else if !errors.Is(err, ErrProbeNeedsContext) || observed != nil {
				t.Fatalf("unsupported original source role acquired an observation: %v", err)
			}
		})
	}
}
