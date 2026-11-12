//go:build go1.27

package plan9asm

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestARM64ByteCarrierGoOptionsRemainOriginal(t *testing.T) {
	directory, packagePath, _ := arm64ByteCarrierFixture(t)
	declarations, err := os.ReadFile(filepath.Join(directory, "decl.go"))
	if err != nil {
		t.Fatal(err)
	}
	assembly, err := os.ReadFile(filepath.Join(directory, "original_arm64.s"))
	if err != nil {
		t.Fatal(err)
	}
	request := arm64ByteCarrierRequest(t, directory, packagePath)
	for _, test := range []struct {
		name   string
		mutate func(GoPackage, *GoModuleOptions)
	}{
		{"foreign-source-OS", func(_ GoPackage, options *GoModuleOptions) { options.GOOS = "windows" }},
		{"missing-source-OS", func(_ GoPackage, options *GoModuleOptions) { options.GOOS = "" }},
		{"filtered-call-graph", func(_ GoPackage, options *GoModuleOptions) {
			options.KeepFunc = func(_, _ string) bool { return false }
		}},
		{"late-Go-syntax", func(pkg GoPackage, options *GoModuleOptions) {
			resolve := options.ResolveSym
			options.ResolveSym = func(symbol string) string {
				pkg.Syntax[0].Name.Name = "changed"
				return resolve(symbol)
			}
		}},
		{"late-result-metadata", func(_ GoPackage, options *GoModuleOptions) {
			resolve := options.ResolveSym
			calls := 0
			options.ResolveSym = func(symbol string) string {
				calls++
				if calls > 1 {
					return "example.invalid/foreign." + symbol
				}
				return resolve(symbol)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			lease, release := runtimeOracleStageContext(t)
			defer release()
			source, err := CaptureGoARM64ByteCarrierSource(lease, request)
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			pkg := mustGoPackage(t, packagePath, string(declarations))
			ir, err := arm64ByteCarrierTranslateAPI(t, "Go", source, pkg, string(assembly), "aarch64-unknown-linux-gnu",
				func(_ *File, _ *Options, options *GoModuleOptions) { test.mutate(pkg, options) })
			if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
				t.Fatalf("changed original Go semantics returned LLVM output: %v", err)
			}
			if !errors.Is(source.Verify(lease), ErrProbeNeedsContext) {
				t.Fatal("failed semantic join did not permanently revoke source")
			}
		})
	}
}

func TestARM64ByteCarrierConsumersRequireActualOwner(t *testing.T) {
	directory, packagePath, _ := arm64ByteCarrierFixture(t)
	declarations, err := os.ReadFile(filepath.Join(directory, "decl.go"))
	if err != nil {
		t.Fatal(err)
	}
	assembly, err := os.ReadFile(filepath.Join(directory, "original_arm64.s"))
	if err != nil {
		t.Fatal(err)
	}
	pkg := mustGoPackage(t, packagePath, string(declarations))
	request := arm64ByteCarrierRequest(t, directory, packagePath)
	for _, kind := range []string{"copy", "JSON", "closed", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			bounded, release := runtimeOracleStageContext(t)
			defer release()
			lease, cancel := context.WithCancelCause(bounded)
			defer cancel(context.Canceled)
			source, err := CaptureGoARM64ByteCarrierSource(lease, request)
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			candidate := source
			cause := errors.New("original owner cancelled before consumer entry")
			switch kind {
			case "copy":
				candidate = &GoARM64ByteCarrierSource{identity: source, ready: true, lease: lease, guard: source.guard}
			case "JSON":
				candidate = new(GoARM64ByteCarrierSource)
				if err := json.Unmarshal(source.raw, candidate); err != nil {
					t.Fatal(err)
				}
			case "closed":
				if err := source.Close(); err != nil {
					t.Fatal(err)
				}
			case "cancelled":
				cancel(cause)
			}
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := arm64ByteCarrierTranslateAPI(t, api, candidate, pkg, string(assembly), "aarch64-unknown-linux-gnu", nil)
					if !errors.Is(err, ErrProbeNeedsContext) || ir != "" || kind == "cancelled" && !errors.Is(err, cause) {
						t.Fatalf("non-owner returned output or lost cancellation cause: %v", err)
					}
				})
			}
			if (kind == "copy" || kind == "JSON") && source.Verify(lease) != nil {
				t.Fatal("untrusted identity revoked its actual original owner")
			}
		})
	}
}

func TestARM64ByteCarrierCallbacksStopAfterSourceClose(t *testing.T) {
	directory, packagePath, _ := arm64ByteCarrierFixture(t)
	declarations, err := os.ReadFile(filepath.Join(directory, "decl.go"))
	if err != nil {
		t.Fatal(err)
	}
	assembly, err := os.ReadFile(filepath.Join(directory, "original_arm64.s"))
	if err != nil {
		t.Fatal(err)
	}
	request := arm64ByteCarrierRequest(t, directory, packagePath)
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			lease, release := runtimeOracleStageContext(t)
			defer release()
			source, err := CaptureGoARM64ByteCarrierSource(lease, request)
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			pkg := mustGoPackage(t, packagePath, string(declarations))
			calls := 0
			resolve := testResolveSym(packagePath)
			ir, err := arm64ByteCarrierTranslateAPI(t, api, source, pkg, string(assembly), "aarch64-unknown-linux-gnu",
				func(_ *File, options *Options, goOptions *GoModuleOptions) {
					callback := func(symbol string) string {
						calls++
						if calls == 1 {
							if err := source.Close(); err != nil {
								t.Fatal(err)
							}
						}
						return resolve(symbol)
					}
					options.ResolveSym, goOptions.ResolveSym = callback, callback
				})
			if !errors.Is(err, ErrProbeNeedsContext) || ir != "" || calls != 1 {
				t.Fatalf("consumer called after owner Close or returned output: calls=%d error=%v", calls, err)
			}
		})
	}
}
