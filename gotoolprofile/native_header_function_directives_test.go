package gotoolprofile

import (
	"reflect"
	"strings"
	"testing"
)

// These directives affect ordinary function code, not the compiler's native
// constant/type header projection. Actual compiler acceptance and all later
// object/source consumers remain separate from this property query.
func TestNativeHeaderOrdinaryFunctionDirectivesMatchActualCompiler(t *testing.T) {
	for _, directive := range []string{"noinline", "nosplit", "noescape", "norace", "nocheckptr", "uintptrescapes"} {
		t.Run(directive, func(t *testing.T) {
			function := "func Body(value uintptr) uintptr { return value }\n"
			if directive == "noescape" {
				function = "func Body(value uintptr) uintptr\n"
			}
			source := "package header\nconst Count = 7\ntype Record struct { Value uint64; Tail byte }\n" +
				"//go:" + directive + "\n" + function
			for _, target := range []string{"linux/386", "linux/amd64", "linux/arm", "linux/arm64", "js/wasm"} {
				t.Run(target, func(t *testing.T) {
					actual := compileNativeHeaderRules(t, target, source)
					sources := map[string]string{"header.go": source}
					if err := PreflightNativeGeneratedHeaderSource("example.invalid/header", target, "go1.20", sources); err != nil {
						t.Fatalf("actual ordinary function directive forced unrelated CPU proposals: %v", err)
					}
					replayed, err := ReplayNativeGeneratedHeader("example.invalid/header", target, "go1.20", sources)
					if err != nil || !reflect.DeepEqual(actual, replayed) {
						t.Fatalf("actual complete header differs: actual=%v replay=%v error=%v", actual, replayed, err)
					}
				})
			}
		})
	}
}

func TestNativeHeaderFunctionDirectivesRetainSourceRoles(t *testing.T) {
	for name, source := range map[string]string{
		"type attachment":     "package header\n//go:nosplit\ntype Record struct { Value uint64 }\n",
		"constant attachment": "package header\n//go:noinline\nconst Count = 7\n",
		"unattached":          "package header\n//go:nosplit\n\nfunc Body() {}\n",
		"function body":       "package header\nfunc Body() {\n//go:noinline\n}\n",
		"unknown":             "package header\n//go:unknown\nfunc Body() {}\n",
		"arguments":           "package header\n//go:nosplit extra\nfunc Body() {}\n",
		"special runtime":     "package header\n//go:systemstack\nfunc Body() {}\n",
		"special barrier":     "package header\n//go:nowritebarrierrec\nfunc Body() {}\n",
		"external symbol":     "package header\n//go:linkname Body other.Body\nfunc Body() {}\n",
		"embedded data":       "package header\n//go:embed data\nvar Data string\n",
		"cgo export":          "package header\n//go:cgo_export_static Body\nfunc Body() {}\n",
		"wasm import":         "package header\n//go:wasmimport env Body\nfunc Body()\n",
	} {
		t.Run(name, func(t *testing.T) {
			sources := map[string]string{"header.go": source}
			if err := PreflightNativeGeneratedHeaderSource("example.invalid/header", "linux/arm64", "go1.20", sources); !NativeHeaderSourceDomainUnsupported(err) {
				t.Fatalf("unregistered directive/source role acquired property preflight: %v", err)
			}
			if properties, err := ReplayNativeGeneratedHeader("example.invalid/header", "linux/arm64", "go1.20", sources); properties != nil || !NativeHeaderSourceDomainUnsupported(err) {
				t.Fatalf("unregistered directive/source role acquired header: %v %v", properties, err)
			}
		})
	}

	source := strings.Replace(nativeHeaderIndependentImportSource,
		"func Holder()", "//go:nosplit\n//go:noinline\nfunc Holder()", 1)
	imports := map[string]string{"example.invalid/dependency": "example.invalid/dependency", "unsafe": "unsafe"}
	for _, variant := range []string{source, strings.Replace(source, "Count = 7", "Count = 9", 1)} {
		properties, err := ReplayNativeGeneratedHeaderWithImportMap("example.invalid/header", "linux/arm64", "go1.20",
			map[string]string{"header.go": variant}, imports)
		if err != nil || properties["const_Count"] == "" || properties["Record_Tail"] != "8" {
			t.Fatalf("function-only directive lost original imported property roots: %v %v", properties, err)
		}
		want := "7"
		if variant != source {
			want = "9"
		}
		if properties["const_Count"] != want {
			t.Fatal("directive property replay hid a changed original constant")
		}
	}
}
