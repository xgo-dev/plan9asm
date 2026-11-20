package plan9asm

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestGoAssemblyHeaderCompileOracle(t *testing.T) {
	const source = `package header
const (
	Small = 42
	Large = 18446744073709551615
	Huge = 1234567890123456789012345678901234567890
	Truth = true
	Falsehood = false
	Quoted = "header\nvalue"
	Rune = 'é'
	Fraction = 1.25
	Imaginary = 1+2i
	_ = 17
)
type embedded struct { byteValue byte; wide uint64 }
type Mixed struct {
	first byte
	_ uint16
	embedded
	*Other
	view []byte
	text string
	callback func()
	last uint64
}
type Other struct { value uintptr }
type Alias = Mixed
type Named Mixed
type Array [2]uint64
type Generic[T any] struct { Value T }
type Concrete = Generic[uint64]
type ConcreteNamed Generic[uint64]
`
	testGoAssemblyHeaderCompileOracle(t, source)
}

func testGoAssemblyHeaderCompileOracle(t *testing.T, source string) {
	t.Helper()
	pkg := mustGoPackage(t, "oracle/header", source)
	for _, target := range []struct{ arch, goos string }{
		{"amd64", "linux"}, {"386", "linux"}, {"arm", "linux"}, {"arm64", "linux"}, {"wasm", "js"},
	} {
		t.Run(target.arch, func(t *testing.T) {
			dir := t.TempDir()
			goFile := filepath.Join(dir, "header.go")
			if err := os.WriteFile(goFile, []byte(source), 0600); err != nil {
				t.Fatal(err)
			}
			goHeader := filepath.Join(dir, "go_asm.h")
			command := exec.Command("go", "tool", "compile", "-p", pkg.Path, "-asmhdr", goHeader, "-o", filepath.Join(dir, "go.o"), goFile)
			command.Env = append(os.Environ(), "GOOS="+target.goos, "GOARCH="+target.arch)
			if out, err := command.CombinedOutput(); err != nil {
				t.Fatalf("actual Go compile -asmhdr: %v\n%s", err, out)
			}
			original, err := os.ReadFile(goHeader)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("actual Go header:\n%s", original)
			generated, err := GoAssemblyHeader(pkg, target.arch)
			if err != nil {
				t.Fatal(err)
			}
			definitions := func(header []byte) map[string]string {
				out := map[string]string{}
				for _, line := range strings.Split(string(header), "\n") {
					fields := strings.Fields(line)
					if len(fields) >= 3 && fields[0] == "#define" {
						name := fields[1]
						out[name] = strings.TrimSpace(strings.TrimPrefix(line, "#define "+name))
					}
				}
				return out
			}
			if want, got := definitions(original), definitions(generated); !reflect.DeepEqual(got, want) {
				t.Fatalf("generated definitions differ from actual Go:\ngot %v\nwant %v", got, want)
			}
			// Existence itself is source semantics: eagerly replacing operands
			// after ignoring this header cannot reproduce these conditionals.
			conditional := "#include \"go_asm.h\"\n#ifdef const_Huge\n#ifdef Alias__size\n#ifdef Concrete_Value\nGOOD\n#endif\n#endif\n#endif\n" +
				"#ifdef const_Fraction\nBAD_FLOAT\n#endif\n#ifdef Generic__size\nBAD_GENERIC\n#endif\n#ifdef GenericAlias__size\nBAD_ALIAS\n#endif\n"
			got, err := PreprocessAssemblySource(conditional, AssemblyPreprocessOptions{
				FileName: "generated.s", ReadInclude: func(parent, name string) (string, []byte, error) {
					return name, generated, nil
				},
			})
			if err != nil || strings.TrimSpace(got) != "GOOD" {
				t.Fatalf("generated header conditional semantics = %q, %v", got, err)
			}
		})
	}
}

func TestGoAssemblyHeaderMissingContext(t *testing.T) {
	for _, pkg := range []GoPackage{{}, {Types: nil, Path: "missing"}} {
		if _, err := GoAssemblyHeader(pkg, "arm64"); err == nil {
			t.Fatal("missing package types accepted")
		}
	}
	if _, err := GoAssemblyHeader(mustGoPackage(t, "oracle", "package oracle"), "unknown"); err == nil {
		t.Fatal("unknown target layout accepted")
	}
}
