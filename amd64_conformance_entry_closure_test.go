package plan9asm

import (
	"crypto/sha256"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

// This directory checks each original public entry independently, not complete
// program execution. KeepFunc receives the complete original ASM and the same
// complete Go declarations on every request; no producer, DATA or signature is
// rewritten to bypass the first failure in the combined runtime translation.
func TestAMD64ConformanceEveryOriginalEntrySourceClosure(t *testing.T) {
	source, err := os.ReadFile("testdata/conformance/amd64/conformance_amd64.s")
	if err != nil {
		t.Fatal(err)
	}
	declarations, err := os.ReadFile("testdata/conformance/amd64/conformance.go")
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprintf("%x", sha256.Sum256(source)) != "3c105a49b705062c1ced2ecb492e5319e8d6836a8ca35a1cb276b9969f6ebc0e" ||
		fmt.Sprintf("%x", sha256.Sum256(declarations)) != "00bc95eb6d5cd5d1c976c8e077fa3f48f3c65bfd47815d7614b2866d2b7c41d2" {
		t.Fatal("original complete conformance ASM or Go declarations changed")
	}
	file, err := Parse(ArchAMD64, string(source))
	if err != nil {
		t.Fatal(err)
	}
	if len(file.Funcs) != 45 {
		t.Fatal("complete original public entry directory changed", len(file.Funcs))
	}
	pkg := mustGoPackage(t, "amd64conformance", string(declarations))
	resolve := func(symbol string) string {
		return strings.TrimPrefix(goStripABISuffix(symbol), "·")
	}
	signatures, err := goSigsForAsmFile(pkg, file, resolve, "amd64", nil, nil, nil)
	if err != nil || len(signatures) != len(file.Funcs) {
		t.Fatal("complete original Go signature directory differs", len(signatures), err)
	}
	// This existing stock-Go compiler prior includes both entire original
	// files and runs before any translator request, without native execution.
	if !t.Run("OriginalGoObjects", TestAMD64ConformanceOriginalWideSourceCompiles) {
		t.Fatal("original complete Go program must compile before source-closure observations")
	}
	seen := make(map[string]bool)
	for _, fn := range file.Funcs {
		name := resolve(fn.Sym)
		if seen[name] {
			t.Fatal("duplicate original public entry", name)
		}
		seen[name] = true
		t.Run(name, func(t *testing.T) {
			ctx := llvm.NewContext()
			defer ctx.Dispose()
			translated, err := translateGoModuleInContext(ctx, pkg, source, GoModuleOptions{
				FileName: "conformance_amd64.s", GOOS: "linux", GOARCH: "amd64",
				TargetTriple: "x86_64-unknown-linux-gnu", ResolveSym: resolve,
				KeepFunc: func(_ string, resolved string) bool { return resolved == name },
			})
			if translated != nil && !translated.Module.IsNil() {
				defer translated.Module.Dispose()
			}
			if err != nil || translated == nil || translated.Module.IsNil() {
				t.Fatal("original initialized public entry lacks its own complete source closure", err)
			}
			if len(translated.Functions) != 1 || translated.Functions[0].TextSymbol != fn.Sym ||
				translated.Functions[0].ResolvedSymbol != name ||
				!reflect.DeepEqual(translated.Signatures[name], signatures[name]) {
				t.Fatal("isolated entry changed its original public identity or Go signature")
			}
			if translated.Module.String() == "" {
				t.Fatal("source closure returned no original public function")
			}
		})
	}
}
