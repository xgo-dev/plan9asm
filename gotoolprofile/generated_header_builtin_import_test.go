package gotoolprofile

import (
	"reflect"
	"strings"
	"testing"
)

func TestGeneratedHeaderBuiltinUnsafeImportFamilyMatchesNativeObjects(t *testing.T) {
	const original = `package header
import "unsafe"
type Inner struct { Byte byte; Word uintptr }
type Values struct {
	Prefix byte
	Pointer unsafe.Pointer
	Bytes []byte
	Text string
	Map map[byte]byte
	Channel chan byte
	Function func()
	Any interface{}
	Tail [0]byte
}
const Width = unsafe.Sizeof(Values{})
const Alignment = unsafe.Alignof(Values{})
const BytesOffset = unsafe.Offsetof(Values{}.Bytes)
const EmbeddedOffset = unsafe.Offsetof(struct { Prefix byte; Inner }{}.Word)
const Word = unsafe.Sizeof(uintptr(0))
`
	for _, test := range []struct {
		name, source string
	}{
		{name: "qualified", source: original},
		{name: "alias", source: strings.ReplaceAll(strings.Replace(original,
			`import "unsafe"`, `import u "unsafe"`, 1), "unsafe.", "u.")},
		{name: "dot", source: strings.ReplaceAll(strings.Replace(original,
			`import "unsafe"`, `import . "unsafe"`, 1), "unsafe.", "")},
		{name: "escaped path", source: strings.Replace(original, `import "unsafe"`, `import "\u0075nsafe"`, 1)},
		{name: "raw path", source: strings.Replace(original, `import "unsafe"`, "import `unsafe`", 1)},
		{name: "blank", source: "package header\nimport _ \"unsafe\"\ntype Values struct { Bytes []byte }\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, target := range []string{"linux/386", "linux/amd64", "linux/arm", "linux/arm64", "js/wasm"} {
				t.Run(target, func(t *testing.T) {
					actual := compileNativeHeaderRules(t, target, test.source)
					replayed, err := ReplayNativeGeneratedHeader("example.invalid/header", target, "go1.20",
						map[string]string{"header.go": test.source})
					if err != nil || !reflect.DeepEqual(actual, replayed) {
						t.Fatalf("Go-accepted builtin import properties differ from original replay: actual=%v replay=%v error=%v",
							actual, replayed, err)
					}
				})
			}
		})
	}
}

func TestGeneratedHeaderBuiltinImportMapRetainsCompleteOriginalScope(t *testing.T) {
	const source = "package header\nimport \"unsafe\"\nconst Word = unsafe.Sizeof(uintptr(0))\n"
	sources := map[string]string{"header.go": source}
	definitions, err := ReplayNativeGeneratedHeaderWithImportMap("example.invalid/header", "linux/amd64", "go1.20",
		sources, map[string]string{"unsafe": "unsafe"})
	if err != nil || definitions["const_Word"] != "8" {
		t.Fatalf("complete original builtin property query failed: %v %v", definitions, err)
	}
	for _, test := range []struct {
		name    string
		imports map[string]string
	}{
		{name: "absent"},
		{name: "deleted", imports: map[string]string{}},
		{name: "rewritten", imports: map[string]string{"unsafe": "example.invalid/unsafe"}},
		{name: "empty edge", imports: map[string]string{"unsafe": ""}},
		{name: "extra", imports: map[string]string{"unsafe": "unsafe", "fmt": "fmt"}},
		{name: "foreign", imports: map[string]string{"example.invalid/unsafe": "unsafe"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			definitions, err := ReplayNativeGeneratedHeaderWithImportMap("example.invalid/header", "linux/amd64", "go1.20",
				sources, test.imports)
			if definitions != nil || err == nil || NativeHeaderSourceDomainUnsupported(err) {
				t.Fatalf("changed actual import map was accepted or hidden by unsupported fallback: %v %v", definitions, err)
			}
		})
	}
	plain := map[string]string{"header.go": "package header\nconst Word = 8\n"}
	if definitions, err := ReplayNativeGeneratedHeaderWithImportMap("example.invalid/header", "linux/amd64", "go1.20",
		plain, map[string]string{"unsafe": "unsafe"}); definitions != nil || err == nil || NativeHeaderSourceDomainUnsupported(err) {
		t.Fatalf("unused builtin edge was borrowed from unrelated source: %v %v", definitions, err)
	}
	if definitions, err := ReplayNativeGeneratedHeaderWithImportMap("example.invalid/header", "linux/amd64", "go1.20",
		plain, map[string]string{}); err != nil || definitions["const_Word"] != "8" {
		t.Fatalf("complete empty original import map changed: %v %v", definitions, err)
	}
}
