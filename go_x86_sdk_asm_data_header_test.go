package plan9asm

import (
	"errors"
	"strings"
	"testing"
)

func TestGoX86SDKASMDataImportConfigNativePaths(t *testing.T) {
	selected := goAMD64FrameSelection{
		Imports: []string{"unsafe", "old/path"}, ImportMap: map[string]string{"old/path": "actual/path"},
	}
	for _, filename := range []string{
		"/cache with spaces/object.a", `/cache\name/object.a`,
		`C:\cache with spaces\object.a`, `C:\cache=root\object.a`,
	} {
		imports := map[string]goAMD64FrameSelection{"actual/path": {Export: filename}}
		config, err := sdkASMDataImportConfig(selected, imports)
		want := "importmap old/path=actual/path\npackagefile actual/path=" + filename + "\n"
		if err != nil || string(config) != want {
			t.Fatalf("native export filename %q was not preserved: %q, %v", filename, config, err)
		}
	}
	for _, filename := range []string{"", "missing\npackagefile forged=object.a", "carriage\rreturn", "nul\x00byte", "trailing "} {
		imports := map[string]goAMD64FrameSelection{"actual/path": {Export: filename}}
		if _, err := sdkASMDataImportConfig(selected, imports); !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatalf("ambiguous or injected config filename %q accepted: %v", filename, err)
		}
	}
	if _, err := sdkASMDataImportConfig(selected, nil); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("missing actual export acquired an import config: %v", err)
	}
	for _, path := range []string{"", "wrong=path", "wrong\\path", "wrong\npath", "wrong\x00path", "wrong path"} {
		selected.Imports = []string{path}
		imports := map[string]goAMD64FrameSelection{path: {Export: "/cache/object.a"}}
		if _, err := sdkASMDataImportConfig(selected, imports); !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatalf("invalid import path %q accepted: %v", path, err)
		}
	}
}

func TestGoX86SDKASMDataImportConfigResolvedSourceAliases(t *testing.T) {
	selected := goAMD64FrameSelection{
		Imports:   []string{"encoding/binary", "vendor/golang.org/x/crypto/internal/alias"},
		ImportMap: map[string]string{"golang.org/x/crypto/internal/alias": "vendor/golang.org/x/crypto/internal/alias"},
	}
	imports := map[string]goAMD64FrameSelection{
		"encoding/binary": {Export: "/cache/binary.a"},
		"vendor/golang.org/x/crypto/internal/alias": {Export: "/cache/alias.a"},
	}
	config, err := sdkASMDataImportConfig(selected, imports)
	if err != nil || !strings.Contains(string(config), "importmap golang.org/x/crypto/internal/alias=vendor/golang.org/x/crypto/internal/alias\n") ||
		!strings.Contains(string(config), "packagefile vendor/golang.org/x/crypto/internal/alias=/cache/alias.a\n") {
		t.Fatal("compiler lost its original source import after actual Go resolved the selected dependency", string(config), err)
	}
	for _, target := range []string{"missing/dependency", "bad\nnamespace", "bad=namespace"} {
		selected.ImportMap["golang.org/x/crypto/internal/alias"] = target
		if _, err := sdkASMDataImportConfig(selected, imports); !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("unobserved source import alias acquired a compiler route", target, err)
		}
	}
}
