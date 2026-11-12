//go:build go1.27

package plan9asm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

type numericalExecutionCase struct {
	name, instruction, predicate string
	register                     string
	source, gp                   int64
	signed, compare              bool
	reversed, immediate          bool
	high, cpu, dead              bool
	partnerHigh                  bool
}

// Widths and formats come from the independent complete Go encoder inventory,
// not the consumer's typed grammar. Every compare direction/predicate remains
// separately observable, as do partial/high-byte and zero-extending writes.
func numericalExecutionCases(arch string) []numericalExecutionCase {
	var cases []numericalExecutionCase
	for _, row := range numericalSBOracleRows {
		if arch == "386" && row.rejected386 {
			continue
		}
		if strings.HasPrefix(row.op, "CMP") {
			for _, predicate := range []string{"LT", "CS", "EQ"} {
				for _, partner := range []string{"$4294967295", "AX", "reversed"} {
					instruction := row.op + " ·Mutable+3(SB)," + partner
					if partner == "reversed" {
						instruction = row.op + " AX,·Mutable+3(SB)"
					}
					cases = append(cases, numericalExecutionCase{
						instruction: instruction, predicate: predicate, source: row.source, gp: row.gp,
						compare: true, reversed: partner == "reversed", immediate: partner[0] == '$',
					})
				}
			}
			continue
		}
		gp := row.gp
		if arch == "386" && row.op == "MOVLQZX" {
			gp = 4
		}
		signed := strings.HasSuffix(row.op, "SX") || row.op == "MOVSWW"
		cases = append(cases, numericalExecutionCase{instruction: row.op + " ·Mutable+3(SB),AX",
			source: row.source, gp: gp, signed: signed})
		if arch == "amd64" {
			cases = append(cases, numericalExecutionCase{instruction: row.op + " ·Mutable+3(SB),R8",
				register: "R8", source: row.source, gp: gp, signed: signed})
		}
	}
	for _, predicate := range []string{"LT", "CS", "EQ"} {
		cases = append(cases, numericalExecutionCase{instruction: "CMPB AH,·Mutable+3(SB)",
			predicate: predicate, source: 1, gp: 1, compare: true, reversed: true, partnerHigh: true})
	}
	cases = append(cases,
		numericalExecutionCase{instruction: "MOVB ·Mutable+3(SB),AH", source: 1, gp: 1, high: true},
		numericalExecutionCase{instruction: "MOVB internal∕cpu·X86+64(SB),AL", source: 1, gp: 1, cpu: true},
		numericalExecutionCase{instruction: "MOVB ·Mutable+3(SB),AL", source: 1, gp: 1, dead: true},
	)
	for index := range cases {
		cases[index].name = fmt.Sprintf("Read%02d", index)
	}
	return cases
}

func numericalExecutionFixture(t *testing.T, arch string) (GoPackage, *File, Options, []numericalExecutionCase) {
	t.Helper()
	_, profile, _, _ := numericalSBFixture(t, arch)
	ownerDirectory := profile.Directory
	if err := os.Remove(filepath.Join(ownerDirectory, profile.AssemblyFile)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ownerDirectory, "value.go"), []byte("package numericalfixture\nvar Mutable [32]byte\n"), 0600); err != nil {
		t.Fatal(err)
	}
	profile.Directory = filepath.Join(ownerDirectory, "consumer")
	if err := os.Mkdir(profile.Directory, 0700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := runtimeOracleProofContext(t)
	t.Cleanup(cancel)
	cases := numericalExecutionCases(arch)
	move, word, seed := "MOVQ", "uint64", "0x8877665544332211"
	if arch == "386" {
		move, word, seed = "MOVL", "uint32", "0x44332211"
	}
	var declarations, assembly strings.Builder
	declarations.WriteString("package consumer\nimport owner \"example.invalid/numericalfixture\"\nvar _ = owner.Mutable\n")
	assembly.WriteString("#include \"textflag.h\"\n")
	for _, test := range cases {
		instruction := strings.ReplaceAll(test.instruction, "·Mutable", "example·invalid∕numericalfixture·Mutable")
		register := test.register
		if register == "" {
			register = "AX"
		}
		fmt.Fprintf(&declarations, "func %s() %s\n", test.name, word)
		fmt.Fprintf(&assembly, "TEXT ·%s(SB),NOSPLIT,$0-%d\n%s $%s,%s\n%s\n",
			test.name, goWordSize(arch), move, seed, register, instruction)
		if register != "AX" {
			fmt.Fprintf(&assembly, "%s %s,AX\n", move, register)
		}
		if test.compare {
			fmt.Fprintf(&assembly, "SET%s CL\nMOVBLZX CL,AX\n", test.predicate)
		}
		if test.dead {
			assembly.WriteString("MOVL $7,AX\n")
		}
		fmt.Fprintf(&assembly, "%s AX,ret+0(FP)\nRET\n", move)
	}
	goSources := map[string]string{
		"value.go": declarations.String(),
		"other.go": "package consumer\nvar Sentinel = byte(0x5a)\n",
	}
	fset := token.NewFileSet()
	var syntax []*ast.File
	for _, name := range []string{"value.go", "other.go"} {
		filename := filepath.Join(profile.Directory, name)
		data := []byte(goSources[name])
		if err := os.WriteFile(filename, data, 0600); err != nil {
			t.Fatal(err)
		}
		file, err := parser.ParseFile(fset, filename, data, parser.ParseComments)
		if err != nil {
			t.Fatal(err)
		}
		syntax = append(syntax, file)
	}
	if err := os.WriteFile(filepath.Join(profile.Directory, profile.AssemblyFile), []byte(assembly.String()), 0600); err != nil {
		t.Fatal(err)
	}
	// All fixture bytes, including the consumer, exist before the owned module's
	// complete-source inventory is captured. Later work is read-only.
	var owners []*GoNumericalStorageOwner
	exports := make(map[string]string)
	for _, request := range []GoNumericalStorageCaptureRequest{
		{GoBinary: profile.GoBinary, Directory: ownerDirectory, PackagePath: "example.invalid/numericalfixture", Target: profile.Target,
			Environment: profile.Environment, Variables: []GoNumericalStorageReference{{PackagePath: "example.invalid/numericalfixture", Name: "Mutable"}}},
		{GoBinary: profile.GoBinary, Directory: filepath.Join(filepath.Dir(filepath.Dir(profile.GoBinary)), "src", "internal", "cpu"),
			PackagePath: "internal/cpu", Target: profile.Target, Environment: profile.Environment, SDKCPU: true,
			Variables: []GoNumericalStorageReference{{PackagePath: "internal/cpu", Name: "X86"}}},
	} {
		owner, err := CaptureGoNumericalStorageOwner(ctx, request)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(owner.Close)
		owners = append(owners, owner)
		observation, err := owner.observation.Readback(ctx)
		if err != nil {
			t.Fatal(err)
		}
		decoder := json.NewDecoder(bytes.NewReader(observation.RawSelection))
		for decoder.More() {
			var selected goAMD64FrameSelection
			if err := decoder.Decode(&selected); err != nil {
				t.Fatal(err)
			}
			if selected.Export != "" {
				exports[selected.ImportPath] = selected.Export
			}
		}
	}
	importer := importer.ForCompiler(fset, "gc", func(path string) (io.ReadCloser, error) {
		filename, found := exports[path]
		if !found {
			return nil, fmt.Errorf("actual selected owner export missing for %s", path)
		}
		return os.Open(filename)
	})
	typed, err := (&types.Config{Sizes: types.SizesFor("gc", arch), Importer: importer}).Check("example.invalid/numericalfixture/consumer", fset, syntax, nil)
	if err != nil {
		t.Fatal(err)
	}
	pkg := GoPackage{Path: typed.Path(), Types: typed, Syntax: syntax, Imports: make(map[string]*types.Package)}
	for _, dependency := range typed.Imports() {
		pkg.Imports[dependency.Path()] = dependency
	}
	file, err := Parse(ArchAMD64, strings.Replace(assembly.String(), "#include \"textflag.h\"", "#define NOSPLIT 4", 1))
	if err != nil {
		t.Fatal(err)
	}
	options := Options{Goarch: arch, TargetTriple: "x86_64-unknown-linux-gnu",
		Sigs: make(map[string]FuncSig), ResolveSym: func(symbol string) string { return numericalNativeName(symbol, pkg.Path) }}
	if arch == "386" {
		options.TargetTriple = "i386-unknown-linux-gnu"
	}
	for _, test := range cases {
		name := pkg.Path + "." + test.name
		sig, err := DeriveGoFuncABI0Signature(name, typed.Scope().Lookup(test.name).(*types.Func), arch, types.SizesFor("gc", arch))
		if err != nil {
			t.Fatal(err)
		}
		options.Sigs[name] = sig
	}
	source, err := CaptureGoX86NumericalReadSource(ctx, GoX86NumericalReadCaptureRequest{
		GoBinary: profile.GoBinary, Directory: profile.Directory, PackagePath: pkg.Path, AssemblyFile: profile.AssemblyFile,
		Target: profile.Target, Environment: profile.Environment, Owners: owners,
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
	if err != nil || len(source.reads) != len(cases) {
		t.Fatal("complete actual two-Go-file family did not bind", err, len(source.reads))
	}
	return pkg, file, bound, cases
}

func numericalFamilyTranslate(t *testing.T, api string, pkg GoPackage, file *File, options Options) string {
	t.Helper()
	if api == "text" {
		ir, err := Translate(file, options)
		if err != nil {
			t.Fatal(err)
		}
		return ir
	}
	context := llvm.NewContext()
	defer context.Dispose()
	var module llvm.Module
	var err error
	switch api {
	case "module":
		module, err = TranslateModule(file, options)
	case "context":
		module, err = TranslateModuleInContext(context, file, options)
	case "go-module":
		source := options.NumericalReads.source
		data, readErr := os.ReadFile(filepath.Join(source.request.Directory, source.request.AssemblyFile))
		if readErr != nil {
			t.Fatal(readErr)
		}
		goos, _, target := strings.Cut(source.request.Target, "/")
		if !target {
			t.Fatal("actual numerical source target has no OS/architecture", source.request.Target)
		}
		result, translateErr := translateGoModuleInContext(context, pkg, data, GoModuleOptions{
			GOARCH: options.Goarch, GOOS: goos, TargetTriple: options.TargetTriple,
			FileName: source.request.AssemblyFile, NumericalReads: options.NumericalReads, ResolveSym: options.ResolveSym,
		})
		err = translateErr
		if result != nil {
			module = result.Module
			for _, fn := range result.Functions {
				if _, found := result.Signatures[fn.ResolvedSymbol]; !found || module.NamedFunction(fn.ResolvedSymbol).IsNil() {
					module.Dispose()
					t.Fatal("Go wrapper function/signature/module identities disagree", fn)
				}
			}
		}
	default:
		t.Fatal("unknown numerical family API", api)
	}
	if err != nil {
		t.Fatal(err)
	}
	if module.IsNil() {
		t.Fatal("successful numerical family returned no module")
	}
	defer module.Dispose()
	return module.String()
}

func numericalLLVM22Axes(t *testing.T, ir, triple string, run func(*testing.T, string, string)) {
	t.Helper()
	llc, opt := findLLVM22Tool("llc"), findLLVM22Tool("opt")
	if llc == "" || opt == "" {
		t.Fatal("LLVM22 llc and opt required")
	}
	for _, passes := range []string{"none", "O2"} {
		t.Run("IR-"+passes, func(t *testing.T) {
			dir := t.TempDir()
			input := filepath.Join(dir, "input.ll")
			if err := os.WriteFile(input, []byte(ir), 0600); err != nil {
				t.Fatal(err)
			}
			if passes == "O2" {
				optimized := filepath.Join(dir, "optimized.ll")
				x86FloatCompareCaptureCommand(t, exec.Command(opt, "-passes=default<O2>", "-S", input, "-o", optimized))
				input = optimized
			}
			for _, backend := range []string{"-O0", "-O2"} {
				t.Run("backend"+backend, func(t *testing.T) {
					object := filepath.Join(t.TempDir(), "numerical.o")
					x86FloatCompareCaptureCommand(t, exec.Command(llc, backend, "-mtriple="+triple, "-filetype=obj", input, "-o", object))
					if info, err := os.Stat(object); err != nil || info.Size() == 0 {
						t.Fatal("LLVM22 produced no real object", err)
					}
					if run != nil {
						run(t, object, triple)
					}
				})
			}
		})
	}
}

func TestGoX86NumericalSBReadCompleteFamilyLLVM22Objects(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			pkg, file, options, cases := numericalExecutionFixture(t, arch)
			for _, api := range []string{"text", "module", "context", "go-module"} {
				t.Run(api, func(t *testing.T) {
					ir := numericalFamilyTranslate(t, api, pkg, file, options)
					if strings.Count(ir, "load volatile") != len(cases) || strings.Contains(ir, "constant [") {
						t.Fatal("complete numerical family lost mutable/dead reads")
					}
					numericalLLVM22Axes(t, ir, options.TargetTriple, nil)
				})
			}
		})
	}
}
