package gotoolprofile

import (
	"reflect"
	"strings"
	"testing"
)

// The import is outside the header property closure, while the mutually
// referring generic declarations have no uninstantiated native properties.
// Retain an ordinary alias and constant so omitting every type cannot pass.
const nativeHeaderUninstantiatedRootsSource = `package header
import dep "example.invalid/dependency"
var unused = dep.New("initializer")
type Frame[R, S any] struct { ctx *State[R, S] }
type State[R, S any] struct { recv R; send S; inner[R] }
type inner[R any] struct { next chan R }
type Constrained[T interface { ~uint64 | ~string }] struct { Value T }
type Record struct { Value uint64; Tail byte }
type Alias = Record
const Count = 7
//go:noinline
//go:nosplit
func Holder() { _ = dep.New("body") }
`

func TestNativeHeaderUninstantiatedGenericRootsMatchActualCompiler(t *testing.T) {
	dependencies := map[string]string{
		"example.invalid/dependency": "package dependency\nfunc New(value string) string { return value }\n",
	}
	for _, target := range []string{"linux/386", "linux/amd64", "linux/arm", "linux/arm64", "js/wasm"} {
		t.Run(target, func(t *testing.T) {
			actual := compileNativeHeaderRulesWithImports(t, target, nativeHeaderUninstantiatedRootsSource, dependencies)
			if len(actual) != 7 || actual["Record__size"] == "" || actual["Alias__size"] == "" || actual["const_Count"] != "7" {
				t.Fatalf("actual compiler did not retain exactly the ordinary native properties: %v", actual)
			}
			for name := range actual {
				for _, generic := range []string{"Frame", "State", "inner", "Constrained"} {
					if strings.HasPrefix(name, generic+"_") {
						t.Fatalf("actual compiler emitted an uninstantiated generic property: %s", name)
					}
				}
			}
			t.Logf("ACTUAL_GO_UNINSTANTIATED_HEADER target=%s definitions=%v", target, actual)
			sources := map[string]string{"header.go": nativeHeaderUninstantiatedRootsSource}
			if err := PreflightNativeGeneratedHeaderSource("example.invalid/header", target, "go1.20", sources); err != nil {
				t.Fatalf("uninstantiated declaration forced unrelated native property queries: %v", err)
			}
			imports := map[string]string{"example.invalid/dependency": "example.invalid/dependency"}
			replayed, err := ReplayNativeGeneratedHeaderWithImportMap("example.invalid/header", target, "go1.20", sources, imports)
			if err != nil || !reflect.DeepEqual(actual, replayed) {
				t.Fatalf("complete native property projection differs: actual=%v replay=%v error=%v", actual, replayed, err)
			}
		})
	}
}

func TestNativeHeaderGenericRootsRetainConcreteAndForeignDependencies(t *testing.T) {
	for name, suffix := range map[string]string{
		"concrete alias":         "type Concrete = Frame[uint64, string]\n",
		"concrete field":         "type Concrete struct { Value Frame[uint64, string] }\n",
		"concrete named type":    "type Concrete Frame[uint64, string]\n",
		"concrete sizeof":        "const Width = u.Sizeof(Frame[uint64, string]{})\n",
		"foreign type":           "type Foreign dep.Record\n",
		"foreign field":          "type Foreign struct { Value dep.Record }\n",
		"foreign array constant": "type Foreign struct { Value [dep.Count]byte }\n",
		"foreign constant":       "const Foreign = dep.Count\n",
		"unknown ordinary name":  "type Unknown struct { Value Missing }\n",
	} {
		t.Run(name, func(t *testing.T) {
			source := strings.Replace(nativeHeaderUninstantiatedRootsSource,
				"import dep \"example.invalid/dependency\"", "import dep \"example.invalid/dependency\"\nimport u \"unsafe\"", 1)
			sources := map[string]string{"header.go": source + suffix}
			if err := PreflightNativeGeneratedHeaderSource("example.invalid/header", "linux/amd64", "go1.20", sources); !NativeHeaderSourceDomainUnsupported(err) {
				t.Fatalf("unclosed concrete property was omitted: %v", err)
			}
			definitions, err := ReplayNativeGeneratedHeaderWithImportMap("example.invalid/header", "linux/amd64", "go1.20", sources,
				map[string]string{"example.invalid/dependency": "example.invalid/dependency", "unsafe": "unsafe"})
			if definitions != nil || !NativeHeaderSourceDomainUnsupported(err) {
				t.Fatalf("unclosed concrete property acquired a partial header: %v %v", definitions, err)
			}
		})
	}
}

func TestNativeHeaderConcreteGenericRootsRequireCompleteClosure(t *testing.T) {
	source := strings.Replace(nativeHeaderUninstantiatedRootsSource,
		"import dep \"example.invalid/dependency\"", "import dep \"example.invalid/dependency\"\nimport u \"unsafe\"", 1) + `
type Concrete = Frame[uint64, string]
type Named Frame[uint64, string]
type Nested struct { Value State[uint32, byte] }
const Width = u.Sizeof(Frame[uint64, string]{})
`
	dependencies := map[string]string{
		"example.invalid/dependency": "package dependency\nfunc New(value string) string { return value }\n",
	}
	for _, target := range []string{"linux/386", "linux/amd64", "linux/arm", "linux/arm64", "js/wasm"} {
		t.Run(target, func(t *testing.T) {
			actual := compileNativeHeaderRulesWithImports(t, target, source, dependencies)
			for _, property := range []string{"Concrete__size", "Named__size", "Nested__size", "const_Width"} {
				if actual[property] == "" {
					t.Fatalf("actual compiler omitted required concrete generic property %s: %v", property, actual)
				}
			}
			// This finite adapter does not close instantiated declarations
			// when foreign imports require selective AST replay. It must fail
			// the entire query, never emit just the independent Record subset.
			definitions, err := ReplayNativeGeneratedHeaderWithImportMap("example.invalid/header", target, "go1.20",
				map[string]string{"header.go": source},
				map[string]string{"example.invalid/dependency": "example.invalid/dependency", "unsafe": "unsafe"})
			if definitions != nil || !NativeHeaderSourceDomainUnsupported(err) {
				t.Fatalf("required native properties became a partial header: actual=%v replay=%v error=%v", actual, definitions, err)
			}
		})
	}
}

func TestNativeHeaderGenericRootsRetainMalformedAndUnknownRoles(t *testing.T) {
	for name, suffix := range map[string]string{
		"duplicate generic":  "type Frame[T any] struct { Value T }\n",
		"duplicate ordinary": "type Record struct {}\n",
		"malformed generic":  "type Broken[T any struct {}\n",
	} {
		t.Run(name, func(t *testing.T) {
			sources := map[string]string{"header.go": nativeHeaderUninstantiatedRootsSource + suffix}
			if err := PreflightNativeGeneratedHeaderSource("example.invalid/header", "linux/amd64", "go1.20", sources); err == nil || NativeHeaderSourceDomainUnsupported(err) {
				t.Fatalf("invalid source was omitted or hidden as a domain fallback: %v", err)
			}
		})
	}
	for _, directive := range []string{"unknown", "linkname Holder other.Holder", "systemstack"} {
		t.Run(directive, func(t *testing.T) {
			source := strings.Replace(nativeHeaderUninstantiatedRootsSource, "//go:noinline", "//go:"+directive, 1)
			if err := PreflightNativeGeneratedHeaderSource("example.invalid/header", "linux/amd64", "go1.20",
				map[string]string{"header.go": source}); !NativeHeaderSourceDomainUnsupported(err) {
				t.Fatalf("generic omission laundered an unknown source role: %v", err)
			}
		})
	}
}
