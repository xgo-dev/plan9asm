package plan9asm

import (
	"context"
	"errors"
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
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/llvm"
)

const importedTailDeclarations = `package tail
import "syscall"
func Forward(trap, a1, a2, a3 uintptr) (r1, r2 uintptr, err syscall.Errno)
func Forward6(trap, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err syscall.Errno)
`

func importedTailPackage(t *testing.T, arch string) GoPackage {
	return importedTailPackageSource(t, arch, importedTailDeclarations)
}

func importedTailPackageSource(t *testing.T, arch, source string) GoPackage {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "value.go", source, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	actualImports := importer.ForCompiler(fset, "gc", func(path string) (io.ReadCloser, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		command := exec.CommandContext(ctx, filepath.Join(runtime.GOROOT(), "bin", "go"), "list", "-p=1", "-export", "-f={{.Export}}", path)
		command.Env = append(os.Environ(), "GOROOT="+runtime.GOROOT(), "GOTOOLCHAIN=local", "GOENV=off", "GOWORK=off", "GOPROXY=off", "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+arch)
		output, err := command.Output()
		if err != nil {
			return nil, fmt.Errorf("actual target SDK export %s: %w", path, err)
		}
		return os.Open(strings.TrimSpace(string(output)))
	})
	typed, err := (&types.Config{Importer: actualImports, Sizes: types.SizesFor("gc", arch)}).Check("example.com/tail", fset, []*ast.File{file}, nil)
	if err != nil {
		t.Fatal(err)
	}
	imports := make(map[string]*types.Package)
	for _, dependency := range typed.Imports() {
		imports[dependency.Path()] = dependency
	}
	dependency, err := parser.ParseFile(fset, filepath.Join(runtime.GOROOT(), "src/syscall/syscall_linux.go"), nil, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	return GoPackage{Path: typed.Path(), Types: typed, Syntax: []*ast.File{file}, Imports: imports,
		ImportSyntax: map[string][]*ast.File{"syscall": {dependency}}}
}

func importedTailAssembly(arch, target string) string {
	width := 8
	if arch == "386" {
		width = 4
	}
	return fmt.Sprintf("TEXT ·Forward(SB),4,$0-%d\nJMP syscall·%s(SB)\nTEXT ·Forward6(SB),4,$0-%d\nJMP syscall·%s6(SB)\n", 7*width, target, 10*width, target)
}

func TestX86GoImportedTailOriginalGo(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, target := range []string{"Syscall", "RawSyscall"} {
			t.Run(arch+"/"+target, func(t *testing.T) {
				directory := t.TempDir()
				files := map[string]string{
					"go.mod":                 "module example.com/tail\n\ngo 1.20\n",
					"value.go":               importedTailDeclarations,
					"forward_" + arch + ".s": importedTailAssembly(arch, target),
					"cmd/main.go": `package main
import ("example.com/tail"; "syscall")
func main() {
  pid, _, errno := tail.Forward(syscall.SYS_GETPID,0,0,0)
  if errno != 0 || pid == 0 || pid != uintptr(syscall.Getpid()) { panic("pid") }
  result, _, errno := tail.Forward(^uintptr(0),0,0,0)
  if result != ^uintptr(0) || errno != syscall.ENOSYS { panic("errno") }
  pid, _, errno = tail.Forward6(syscall.SYS_GETPID,0,0,0,0,0,0)
  if errno != 0 || pid != uintptr(syscall.Getpid()) { panic("six") }
}
`,
				}
				for name, source := range files {
					path := filepath.Join(directory, name)
					if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
				defer cancel()
				command := exec.CommandContext(ctx, filepath.Join(runtime.GOROOT(), "bin", "go"), "build", "-p=1", "-mod=readonly", "-o", filepath.Join(directory, "original"), "./cmd")
				command.Dir = directory
				command.Env = append(os.Environ(), "GOROOT="+runtime.GOROOT(), "GOTOOLCHAIN=local", "GOENV=off", "GOWORK=off", "GOFLAGS=", "GOPROXY=off", "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+arch)
				if output, err := command.CombinedOutput(); err != nil {
					t.Fatalf("original full package/ELF link: %v\n%s", err, output)
				}
			})
		}
	}
}

func TestX86GoImportedTailPublicModule(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, target := range []string{"Syscall", "RawSyscall"} {
			t.Run(arch+"/"+target, func(t *testing.T) {
				triple, word := "x86_64-unknown-linux-gnu", "i64"
				if arch == "386" {
					triple, word = "i386-unknown-linux-gnu", "i32"
				}
				pkg := importedTailPackage(t, arch)
				tr, err := TranslateGoModule(pkg, []byte(importedTailAssembly(arch, target)), GoModuleOptions{GOOS: "linux", GOARCH: arch, TargetTriple: triple, ResolveSym: testResolveSym(pkg.Path)})
				if err != nil {
					t.Fatal("actual declared SDK tail:", err)
				}
				defer tr.Module.Dispose()
				ir := tr.Module.String()
				for _, entry := range []struct{ root, callee string }{{"Forward", target}, {"Forward6", target + "6"}} {
					function := tr.Module.NamedFunction(pkg.Path + "." + entry.root)
					calls := 0
					for _, block := range function.BasicBlocks() {
						for instruction := block.FirstInstruction(); !instruction.IsNil(); instruction = llvm.NextInstruction(instruction) {
							if instruction.InstructionOpcode() == llvm.Call {
								calls++
								if instruction.CalledValue().Name() != "syscall."+entry.callee || instruction.Type().String() != "{ "+word+", "+word+", "+word+" }" {
									t.Fatal("lost exact typed imported scalar tuple call", instruction.String())
								}
							}
						}
					}
					if calls != 1 {
						t.Fatalf("%s has %d calls, want its single exact imported tail", entry.root, calls)
					}
				}
				path := filepath.Join(t.TempDir(), "tail.ll")
				if err := os.WriteFile(path, []byte(ir), 0o600); err != nil {
					t.Fatal(err)
				}
				llc := findLLVM22Tool("llc")
				if llc == "" {
					t.Fatal("LLVM22 llc is required")
				}
				for _, level := range []string{"0", "2"} {
					ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
					command := exec.CommandContext(ctx, llc, "-O="+level, "-filetype=obj", path, "-o", path+level+".o")
					output, err := command.CombinedOutput()
					cancel()
					if err != nil {
						t.Fatalf("LLVM22 O%s object: %v\n%s", level, err, output)
					}
				}
			})
		}
	}
}

func TestX86GoImportedTailSignatureCollectionKeepsIndependentConsumers(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			pkg := importedTailPackageSource(t, arch, importedTailDeclarations+`
func Boolean(x bool) bool
func Numeric(x uint32) uint32
`)
			// One real imported numerical tail must not make unrelated assembly
			// aliases require imports during declaration collection. Their actual
			// consumers still validate the callee independently before translation.
			source := importedTailAssembly(arch, "Syscall") + `
TEXT ·Boolean(SB),4,$0
JMP outside·boolean(SB)
TEXT ·Numeric(SB),4,$0
JMP outside·numeric(SB)
`
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			sigs, err := goSigsForAsmFile(pkg, file, testResolveSym(pkg.Path), arch, nil, nil, nil)
			if err != nil {
				t.Fatal("unrelated alias stole declaration collection", err)
			}
			if !sigs["outside.boolean"].x86BorrowedBoolTail {
				t.Fatal("unresolved bool alias lost its copied-caller denial")
			}
			if _, found := sigs["syscall.Syscall"]; !found {
				t.Fatal("actual selected imported declaration was not collected")
			}
			triple := "x86_64-unknown-linux-gnu"
			if arch == "386" {
				triple = "i386-unknown-linux-gnu"
			}
			translated, err := TranslateGoModule(pkg, []byte(source), GoModuleOptions{
				GOOS: "linux", GOARCH: arch, TargetTriple: triple, ResolveSym: testResolveSym(pkg.Path)})
			if translated != nil {
				translated.Module.Dispose()
			}
			if translated != nil || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("unresolved alias acquired its caller's declaration", err)
			}
		})
	}
}

func TestX86GoImportedTailBoolInputCannotBypassSelectedImport(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			pkg := mustGoPackage(t, "tailinput", "package tailinput\nfunc Forward(flag bool) uint32\n")
			source := []byte("TEXT ·Forward(SB),4,$0\nJMP outside·target(SB)\n")
			file, err := Parse(ArchAMD64, string(source))
			if err != nil {
				t.Fatal(err)
			}
			resolve := testResolveSym(pkg.Path)
			sigs, err := goSigsForAsmFile(pkg, file, resolve, arch, nil, nil, nil)
			if err != nil {
				t.Fatal("source-only alias declaration collection", err)
			}
			if sigs["outside.target"].Ret != I32 || sigs["outside.target"].x86BorrowedBoolTail {
				t.Fatal("fixture must reach the numerical-result consumer")
			}
			triple := "x86_64-unknown-linux-gnu"
			if arch == "386" {
				triple = "i386-unknown-linux-gnu"
			}
			translated, err := TranslateGoModule(pkg, source, GoModuleOptions{
				GOOS: "linux", GOARCH: arch, TargetTriple: triple, ResolveSym: resolve})
			if translated != nil {
				translated.Module.Dispose()
			}
			if translated != nil || !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), "complete selected typed import") {
				t.Fatal("bool input bypassed the independent numerical tail declaration", err)
			}
		})
	}
}

func TestX86GoImportedTailResolverCannotEraseSourceBeforeCapture(t *testing.T) {
	for at := 1; at <= 12; at++ {
		t.Run(fmt.Sprint(at), func(t *testing.T) {
			file, err := Parse(ArchAMD64, "TEXT ·Forward(SB),4,$0\nJMP outside·target(SB)\n")
			if err != nil {
				t.Fatal(err)
			}
			pkg := mustGoPackage(t, "callbacktail", "package callbacktail\nfunc Forward()\n")
			resolve := testResolveSym(pkg.Path)
			sigs, err := goSigsForAsmFile(pkg, file, resolve, "amd64", nil, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			options := Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu", Sigs: sigs}
			options.ResolveSym = func(symbol string) string {
				calls++
				if calls == at {
					file.Funcs[0].Instrs[1] = Instr{Op: OpRET, Raw: "RET"}
				}
				return resolve(symbol)
			}
			prepared, err := PrepareX86DirectTailSource(file, options)
			if prepared != nil || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("resolver erased the undeclared terminal before source capture", calls, err)
			}
		})
	}
}

func TestX86GoImportedTailShapeGuards(t *testing.T) {
	for _, row := range []struct{ name, old, replacement string }{
		{"parameter", "trap, a1, a2, a3 uintptr", "trap, a1, a2, a3 uint32"},
		{"result", "r1, r2 uintptr", "r1, r2 uint32"},
		{"arity", "trap, a1, a2, a3 uintptr", "trap, a1, a2 uintptr"},
		{"native caller", "func Forward(", "//llgo:stdcall\nfunc Forward("},
		{"caller body", "err syscall.Errno)\nfunc Forward6", "err syscall.Errno) { return }\nfunc Forward6"},
	} {
		t.Run(row.name, func(t *testing.T) {
			pkg := importedTailPackageSource(t, "amd64", strings.Replace(importedTailDeclarations, row.old, row.replacement, 1))
			translated, err := TranslateGoModule(pkg, []byte(importedTailAssembly("amd64", "Syscall")), GoModuleOptions{
				GOOS: "linux", GOARCH: "amd64", TargetTriple: "x86_64-unknown-linux-gnu", ResolveSym: testResolveSym(pkg.Path)})
			if translated != nil {
				translated.Module.Dispose()
			}
			if err == nil {
				t.Fatal("nonidentical or native Go tail shape accepted")
			}
		})
	}
	for _, row := range []struct{ name, old, replacement string }{
		{"frame", "$0-56", "$8-56"},
		{"arguments small", "$0-56", "$0-48"},
		{"arguments large", "$0-56", "$0-64"},
		{"offset", "syscall·Syscall(SB)", "syscall·Syscall+1(SB)"},
		{"unknown", "syscall·Syscall(SB)", "syscall·Unknown(SB)"},
		{"side effect", "JMP syscall·Syscall(SB)", "ADDQ $1, AX\nJMP syscall·Syscall(SB)"},
		{"native target", "syscall·Syscall(SB)", "syscall·Syscall<ABIInternal>(SB)"},
	} {
		t.Run(row.name, func(t *testing.T) {
			pkg := importedTailPackage(t, "amd64")
			source := strings.Replace(importedTailAssembly("amd64", "Syscall"), row.old, row.replacement, 1)
			translated, err := TranslateGoModule(pkg, []byte(source), GoModuleOptions{
				GOOS: "linux", GOARCH: "amd64", TargetTriple: "x86_64-unknown-linux-gnu", ResolveSym: testResolveSym(pkg.Path)})
			if translated != nil {
				translated.Module.Dispose()
			}
			if err == nil {
				t.Fatal("unclosed source tail accepted")
			}
		})
	}
}

func TestX86GoImportedTailSourceGuards(t *testing.T) {
	for _, name := range []string{"missing syntax", "missing import", "wrong import identity", "native package", "native declaration", "renamed declaration", "manual target", "manual caller"} {
		t.Run(name, func(t *testing.T) {
			pkg := importedTailPackage(t, "amd64")
			options := GoModuleOptions{GOOS: "linux", GOARCH: "amd64", TargetTriple: "x86_64-unknown-linux-gnu", ResolveSym: testResolveSym(pkg.Path)}
			switch name {
			case "missing syntax":
				pkg.ImportSyntax = nil
			case "missing import":
				pkg.Imports = nil
			case "wrong import identity":
				pkg.Imports["syscall"] = types.NewPackage("syscall", "syscall")
			case "native package":
				defer pkg.Imports["syscall"].SetName(pkg.Imports["syscall"].Name())
				pkg.Imports["syscall"].SetName("C")
			case "native declaration", "renamed declaration":
				for _, node := range pkg.ImportSyntax["syscall"][0].Decls {
					if declaration, ok := node.(*ast.FuncDecl); ok && declaration.Name.Name == "Syscall" {
						text := "//llgo:cdecl"
						if name == "renamed declaration" {
							text = "//go:linkname Syscall C.foo"
						}
						declaration.Doc = &ast.CommentGroup{List: []*ast.Comment{{Text: text}}}
						// Parsed Go syntax records attached directives in both lists.
						pkg.ImportSyntax["syscall"][0].Comments = append(pkg.ImportSyntax["syscall"][0].Comments, declaration.Doc)
					}
				}
			case "manual target", "manual caller":
				options.ManualSig = func(symbol string) (FuncSig, bool) {
					wanted := "syscall.Syscall"
					if name == "manual caller" {
						wanted = pkg.Path + ".Forward"
					}
					return FuncSig{Name: symbol, Ret: I64}, symbol == wanted
				}
			}
			translated, err := TranslateGoModule(pkg, []byte(importedTailAssembly("amd64", "Syscall")), options)
			if translated != nil {
				translated.Module.Dispose()
			}
			if err == nil {
				t.Fatal("source role accepted", name)
			}
		})
	}
}

func TestX86GoImportedTailRawManualSignatures(t *testing.T) {
	pkg := importedTailPackage(t, "amd64")
	resolve := testResolveSym(pkg.Path)
	file, err := Parse(ArchAMD64, importedTailAssembly("amd64", "Syscall"))
	if err != nil {
		t.Fatal(err)
	}
	signatures, err := goSigsForAsmFile(pkg, file, resolve, "amd64", nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Translate(file, Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu", ResolveSym: resolve, Sigs: signatures})
	if !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("manual signatures supplied actual Go declaration source: %v", err)
	}
}

func TestX86GoImportedTailUnspecifiedTEXT(t *testing.T) {
	pkg := importedTailPackage(t, "amd64")
	source := strings.ReplaceAll(strings.ReplaceAll(importedTailAssembly("amd64", "Syscall"), "$0-56", "$0"), "$0-80", "$0")
	translated, err := TranslateGoModule(pkg, []byte(source), GoModuleOptions{
		GOOS: "linux", GOARCH: "amd64", TargetTriple: "x86_64-unknown-linux-gnu", ResolveSym: testResolveSym(pkg.Path)})
	if err != nil {
		t.Fatal("omitted TEXT metadata must obtain only its actual declared layout", err)
	}
	translated.Module.Dispose()
}

func TestX86GoImportedTailPreservesLocalGoTarget(t *testing.T) {
	for _, target := range []string{"·scalar", "example.com∕tail·scalar"} {
		t.Run(target, func(t *testing.T) {
			pkg := importedTailPackageSource(t, "amd64", `package tail
func Forward(x uintptr) uintptr
func scalar(x uintptr) uintptr { return x + 1 }
`)
			source := "TEXT ·Forward(SB),4,$0-16\nJMP " + target + "(SB)\n"
			translated, err := TranslateGoModule(pkg, []byte(source), GoModuleOptions{
				GOOS: "linux", GOARCH: "amd64", TargetTriple: "x86_64-unknown-linux-gnu", ResolveSym: testResolveSym(pkg.Path)})
			if err != nil {
				t.Fatal("existing same-package Go tail regressed", err)
			}
			defer translated.Module.Dispose()
			function := translated.Module.NamedFunction(pkg.Path + ".Forward")
			calls := 0
			for _, block := range function.BasicBlocks() {
				for instruction := block.FirstInstruction(); !instruction.IsNil(); instruction = llvm.NextInstruction(instruction) {
					if instruction.InstructionOpcode() == llvm.Call {
						calls++
						if instruction.CalledValue().Name() != pkg.Path+".scalar" || instruction.Type().String() != "i64" {
							t.Fatal("same-package tail lost its actual Go signature", instruction.String())
						}
					}
				}
			}
			if calls != 1 {
				t.Fatalf("same-package tail has %d calls, want one", calls)
			}
		})
	}
}

func TestX86GoImportedTailSelectedDeclarationConsistency(t *testing.T) {
	for _, role := range []string{"caller", "callee", "resolver mutation"} {
		t.Run(role, func(t *testing.T) {
			pkg := importedTailPackage(t, "amd64")
			resolve := testResolveSym(pkg.Path)
			wrongSource := "package syscall\nfunc Syscall() uintptr\nfunc Syscall6() uintptr\n"
			if role == "caller" {
				wrongSource = "package tail\nfunc Forward() uintptr\nfunc Forward6() uintptr\n"
			}
			wrong, err := parser.ParseFile(token.NewFileSet(), "changed.go", wrongSource, parser.ParseComments)
			if err != nil {
				t.Fatal(err)
			}
			mutate := func() {
				if role == "caller" {
					pkg.Syntax = []*ast.File{wrong}
				} else {
					pkg.ImportSyntax["syscall"] = []*ast.File{wrong}
				}
			}
			file, err := Parse(ArchAMD64, importedTailAssembly("amd64", "Syscall"))
			if err != nil {
				t.Fatal(err)
			}
			signatures, err := goSigsForAsmFile(pkg, file, resolve, "amd64", nil, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			options := Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu", ResolveSym: resolve, Sigs: signatures, goPackage: &pkg}
			if role == "resolver mutation" {
				file, err = PrepareX86DirectTailSource(file, options)
				if err != nil {
					t.Fatal("valid initial selected declarations", err)
				}
				options.ResolveSym = func(symbol string) string {
					mutate()
					return resolve(symbol)
				}
			} else {
				mutate()
			}
			_, err = Translate(file, options)
			if !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("selected declaration changed while typed objects stayed fixed: %v", err)
			}
		})
	}
}

func TestX86GoImportedTailTargetSizedDeclaration(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			pkg := importedTailPackageSource(t, arch, `package tail
import "unsafe"
func Forward(x *[unsafe.Sizeof(uintptr(0))]byte) uintptr
`)
			sizes := types.SizesFor("gc", arch)
			if _, err := goX86TailFunction(pkg, "Forward", true, sizes); err != nil {
				t.Fatal("target-sized actual declaration rejected", err)
			}
			wrong := "8"
			if arch == "amd64" {
				wrong = "4"
			}
			declaration, err := parser.ParseFile(token.NewFileSet(), "changed.go",
				"package tail\nfunc Forward(x *["+wrong+"]byte) uintptr\n", 0)
			if err != nil {
				t.Fatal(err)
			}
			pkg.Syntax = []*ast.File{declaration}
			if _, err := goX86TailFunction(pkg, "Forward", true, sizes); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("wrong target-sized array accepted: %v", err)
			}
		})
	}
}

func TestX86GoImportedTailBodyOnlyImport(t *testing.T) {
	pkg := importedTailPackageSource(t, "amd64", `package tail
import "strings"
//go:noinline
func scalar(x uintptr) uintptr {
	if strings.Contains("original", "missing") { return x + 1 }
	return x
}
`)
	// Go export packages may omit imports used only inside function bodies.
	// Keep the actual checked function and selected source, changing only this
	// optional dependency inventory to its valid export-data projection.
	pkg.Types.SetImports(nil)
	if _, err := goX86TailFunction(pkg, "scalar", false, types.SizesFor("gc", "amd64")); err != nil {
		t.Fatal("body-only import rejected an unchanged scalar declaration", err)
	}

	pkg = importedTailPackage(t, "amd64")
	pkg.Types.SetImports(nil)
	if _, err := goX86TailFunction(pkg, "Forward", true, types.SizesFor("gc", "amd64")); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("missing import actually used by the signature supplied a type: %v", err)
	}
}
