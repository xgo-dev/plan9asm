//go:build go1.27

package plan9asm

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestARM64ByteCarrierConsumersStopAfterOwnerCancellation(t *testing.T) {
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
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			bounded, release := runtimeOracleStageContext(t)
			defer release()
			lease, cancel := context.WithCancelCause(bounded)
			defer cancel(context.Canceled)
			source, err := CaptureGoARM64ByteCarrierSource(lease, request)
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			cause := errors.New("actual original owner cancelled inside resolver")
			calls := 0
			resolve := testResolveSym(packagePath)
			ir, err := arm64ByteCarrierTranslateAPI(t, api, source, pkg, string(assembly), "aarch64-unknown-linux-gnu",
				func(_ *File, options *Options, goOptions *GoModuleOptions) {
					callback := func(symbol string) string {
						calls++
						if calls == 1 {
							cancel(cause)
						}
						return resolve(symbol)
					}
					options.ResolveSym, goOptions.ResolveSym = callback, callback
				})
			if err == nil || !errors.Is(err, cause) || ir != "" {
				t.Fatalf("cancelled original lease returned output or lost its cause: %v", err)
			}
			if calls != 1 {
				t.Fatalf("consumer invoked user callbacks after the original owner was cancelled: %d", calls)
			}
			fresh, stop := runtimeOracleStageContext(t)
			defer stop()
			if !errors.Is(source.Verify(fresh), ErrProbeNeedsContext) {
				t.Fatal("fresh later context renewed a revoked original owner")
			}
		})
	}
}

func TestARM64ByteCarrierRejectsCallerFrameChainAliases(t *testing.T) {
	directory, packagePath, _ := arm64ByteCarrierFixture(t)
	declarations, err := os.ReadFile(filepath.Join(directory, "decl.go"))
	if err != nil {
		t.Fatal(err)
	}
	filename := filepath.Join(directory, "original_arm64.s")
	assembly, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	// The current source caller allocates 64 physical bytes. The previous
	// caller's saved FP is still live at new SP+56, not writable local data.
	// Go assembles this source, but successful encoding is not write authority.
	assembly = []byte(strings.ReplaceAll(string(assembly), "MOVD R0,guard+24(FP)\n    RET",
		"MOVD R0,guard+24(FP)\n    MOVD R0,56(RSP)\n    RET"))
	if !strings.Contains(string(assembly), "56(RSP)") {
		t.Fatal("actual alias control was not inserted")
	}
	if err := os.WriteFile(filename, assembly, 0600); err != nil {
		t.Fatal(err)
	}
	pkg := mustGoPackage(t, packagePath, string(declarations))
	request := arm64ByteCarrierRequest(t, directory, packagePath)
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			lease, release := runtimeOracleStageContext(t)
			defer release()
			source, err := CaptureGoARM64ByteCarrierSource(lease, request)
			if err != nil {
				t.Fatalf("actual compiler/ASM source witness was not captured: %v", err)
			}
			defer source.Close()
			ir, err := arm64ByteCarrierTranslateAPI(t, api, source, pkg, string(assembly), "aarch64-unknown-linux-gnu", nil)
			if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
				t.Fatalf("native store to the previous caller's live FP cell was admitted: %v", err)
			}
		})
	}
}
