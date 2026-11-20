package gotoolprofile

import (
	"reflect"
	"strings"
	"testing"
)

const nativeHeaderIndependentImportSource = `package header

import (
	dep "example.invalid/dependency"
	word "unsafe"
)

var unusedByHeader = dep.New("initializer")

type Record struct { Value uint64; Tail byte }
type Alias = Record
const Count = 7
const Word = word.Sizeof(uintptr(0))

func Holder() { _ = dep.New("function body") }
`

func TestNativeHeaderPropertyRootsRetainCompleteDefinitionsAndImports(t *testing.T) {
	for _, target := range []string{"linux/386", "linux/amd64", "linux/arm", "linux/arm64", "js/wasm"} {
		t.Run(target, func(t *testing.T) {
			sources := map[string]string{"header.go": nativeHeaderIndependentImportSource}
			if err := PreflightNativeGeneratedHeaderSource("example.invalid/header", target, "go1.20", sources); err != nil {
				t.Fatal(err)
			}
			imports := map[string]string{"example.invalid/dependency": "example.invalid/dependency", "unsafe": "unsafe"}
			got, err := ReplayNativeGeneratedHeaderWithImportMap("example.invalid/header", target, "go1.20", sources, imports)
			word, size := "8", "16"
			if strings.HasSuffix(target, "/386") || strings.HasSuffix(target, "/arm") {
				word, size = "4", "12"
			}
			want := map[string]string{
				"const_Count": "7", "const_Word": word,
				"Record__size": size, "Record_Value": "0", "Record_Tail": "8",
				"Alias__size": size, "Alias_Value": "0", "Alias_Tail": "8",
			}
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("complete independent properties: got=%v want=%v error=%v", got, want, err)
			}
			for _, changed := range []map[string]string{
				nil,
				{"unsafe": "unsafe"},
				{"example.invalid/dependency": "example.invalid/dependency"},
				{"example.invalid/dependency": "example.invalid/dependency", "unsafe": "foreign/unsafe"},
				{"example.invalid/dependency": "example.invalid/dependency", "unsafe": "unsafe", "extra": "extra"},
			} {
				if _, err := ReplayNativeGeneratedHeaderWithImportMap("example.invalid/header", target, "go1.20", sources, changed); err == nil {
					t.Fatal("omitted/extra/changed complete original import map acquired properties")
				}
			}
		})
	}
}

func TestNativeHeaderPropertyRootsMatchActualImportedCompilerHeaders(t *testing.T) {
	dependencies := map[string]string{
		"example.invalid/dependency": "package dependency\nfunc New(value string) string { return value }\n",
	}
	for _, target := range []string{"linux/386", "linux/amd64", "linux/arm", "linux/arm64", "js/wasm"} {
		t.Run(target, func(t *testing.T) {
			actual := compileNativeHeaderRulesWithImports(t, target, nativeHeaderIndependentImportSource, dependencies)
			replayed, err := ReplayNativeGeneratedHeaderWithImportMap("example.invalid/header", target, "go1.20",
				map[string]string{"header.go": nativeHeaderIndependentImportSource},
				map[string]string{"example.invalid/dependency": "example.invalid/dependency", "unsafe": "unsafe"})
			if err != nil || !reflect.DeepEqual(actual, replayed) {
				t.Fatalf("actual complete imported-source header differs: actual=%v replay=%v error=%v", actual, replayed, err)
			}
		})
	}
}

func TestNativeHeaderPropertyRootsKeepDependentImportsConservative(t *testing.T) {
	for name, suffix := range map[string]string{
		"constant":         "const Imported = dep.Value\n",
		"array length":     "type Imported struct { Values [dep.Count]byte }\n",
		"named type":       "type Imported dep.Record\n",
		"struct field":     "type Imported struct { Value dep.Record }\n",
		"local variable":   "const Imported = word.Sizeof(unusedByHeader)\n",
		"concrete generic": "type Generic[T any] struct { Value T }\ntype Concrete = Generic[uint64]\n",
	} {
		t.Run(name, func(t *testing.T) {
			sources := map[string]string{"header.go": nativeHeaderIndependentImportSource + suffix}
			if err := PreflightNativeGeneratedHeaderSource("example.invalid/header", "linux/arm64", "go1.20", sources); !NativeHeaderSourceDomainUnsupported(err) {
				t.Fatalf("unclosed property preflight did not remain conservative: %v", err)
			}
			if got, err := ReplayNativeGeneratedHeader("example.invalid/header", "linux/arm64", "go1.20", sources); got != nil || !NativeHeaderSourceDomainUnsupported(err) {
				t.Fatalf("unclosed property acquired definitions: %v %v", got, err)
			}
		})
	}
}

func TestNativeHeaderPropertyRootsDoNotHideMalformedSource(t *testing.T) {
	for _, source := range []string{
		nativeHeaderIndependentImportSource + "type Record struct {}\n",
		nativeHeaderIndependentImportSource + "const Invalid = (\n",
	} {
		sources := map[string]string{"header.go": source}
		if err := PreflightNativeGeneratedHeaderSource("example.invalid/header", "linux/arm64", "go1.20", sources); err == nil || NativeHeaderSourceDomainUnsupported(err) {
			t.Fatalf("malformed source became a conservative successful query: %v", err)
		}
	}
}
