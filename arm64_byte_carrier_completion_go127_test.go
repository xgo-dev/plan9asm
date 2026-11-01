//go:build go1.27

package plan9asm

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func arm64ByteCarrierOnStack(name string) bool {
	var pcs [32]uintptr
	frames := runtime.CallersFrames(pcs[:runtime.Callers(2, pcs[:])])
	for {
		frame, more := frames.Next()
		if strings.HasSuffix(frame.Function, name) {
			return true
		}
		if !more {
			return false
		}
	}
}

type arm64ByteCarrierLoweringCancelContext struct {
	context.Context
	cancel  context.CancelCauseFunc
	cause   error
	reached bool
}

func (owner *arm64ByteCarrierLoweringCancelContext) Err() error {
	if arm64ByteCarrierOnStack("(*arm64ByteCarrierBinding).emitIR") {
		owner.reached = true
		owner.cancel(owner.cause)
	}
	return owner.Context.Err()
}

func TestARM64ByteCarrierOriginalLeaseGuardsLoweringAndCompletion(t *testing.T) {
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
	for _, phase := range []string{"lowering", "completion"} {
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(phase+"/"+api, func(t *testing.T) {
				bounded, release := runtimeOracleStageContext(t)
				defer release()
				lease, cancel := context.WithCancelCause(bounded)
				defer cancel(context.Canceled)
				cause := errors.New("original owner cancelled during " + phase)
				instrumented := &arm64ByteCarrierLoweringCancelContext{Context: lease, cancel: cancel, cause: cause}
				var captureOwner context.Context = lease
				if phase == "lowering" {
					captureOwner = instrumented
				}
				source, err := CaptureGoARM64ByteCarrierSource(captureOwner, request)
				if err != nil {
					t.Fatalf("original capture must precede the actual consumer phase: %v", err)
				}
				defer source.Close()
				completed := false
				ir, err := arm64ByteCarrierTranslateAPI(t, api, source, pkg, string(assembly), "aarch64-unknown-linux-gnu",
					func(_ *File, options *Options, goOptions *GoModuleOptions) {
						resolve := testResolveSym(packagePath)
						callback := func(symbol string) string {
							if phase == "completion" && arm64ByteCarrierOnStack("translateARM64ByteCarrierModule.func1") {
								completed = true
								cancel(cause)
							}
							return resolve(symbol)
						}
						options.ResolveSym, goOptions.ResolveSym = callback, callback
					})
				if phase == "lowering" && !instrumented.reached || phase == "completion" && !completed {
					t.Fatal("test did not reach its actual lowering/post-module phase")
				}
				if !errors.Is(err, cause) || !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
					t.Fatalf("cancelled actual phase returned LLVM output or lost cause: %v", err)
				}
				fresh, stop := runtimeOracleStageContext(t)
				defer stop()
				if !errors.Is(source.Verify(fresh), cause) {
					t.Fatal("fresh context revived the cancelled original owner")
				}
			})
		}
	}
}

func TestARM64ByteCarrierGoFinalMetadataUsesOriginalNames(t *testing.T) {
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
	lease, release := runtimeOracleStageContext(t)
	defer release()
	resolve := testResolveSym(packagePath)
	calibration, err := CaptureGoARM64ByteCarrierSource(lease, request)
	if err != nil {
		t.Fatal(err)
	}
	defer calibration.Close()
	count := 0
	ir, err := arm64ByteCarrierTranslateAPI(t, "Go", calibration, pkg, string(assembly), "aarch64-unknown-linux-gnu",
		func(_ *File, _ *Options, options *GoModuleOptions) {
			options.ResolveSym = func(symbol string) string {
				count++
				return resolve(symbol)
			}
		})
	if err != nil || ir == "" || count <= len(calibration.file.Funcs) {
		t.Fatalf("actual successful complete Go callback calibration failed: calls=%d error=%v", count, err)
	}
	firstFinal := count - len(calibration.file.Funcs) + 1
	owner, err := CaptureGoARM64ByteCarrierSource(lease, request)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	calls, changed := 0, false
	ir, err = arm64ByteCarrierTranslateAPI(t, "Go", owner, pkg, string(assembly), "aarch64-unknown-linux-gnu",
		func(_ *File, _ *Options, options *GoModuleOptions) {
			options.ResolveSym = func(symbol string) string {
				calls++
				if calls == firstFinal {
					changed = true
					return packagePath + ".foreign_metadata"
				}
				return resolve(symbol)
			}
		})
	if !changed || calls != count || !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
		t.Fatalf("final Functions metadata escaped the actual LLVM/signature join: calls=%d/%d error=%v", calls, count, err)
	}
	if !errors.Is(owner.Verify(lease), ErrProbeNeedsContext) {
		t.Fatal("final metadata mismatch did not permanently revoke the original owner")
	}
	t.Logf("actual complete callbacks=%d; changed final metadata callback=%d", count, firstFinal)
}

func TestARM64ByteCarrierMainObservationDoesNotGrantConsumerRole(t *testing.T) {
	directory, packagePath, _ := arm64ByteCarrierFixture(t)
	filename := filepath.Join(directory, "decl.go")
	declarations, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	declarations = []byte(strings.Replace(string(declarations), "package carrierfixture", "package main", 1) + "\nfunc main() {}\n")
	if err := os.WriteFile(filename, declarations, 0600); err != nil {
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
			lease, release := runtimeOracleStageContext(t)
			defer release()
			owner, err := CaptureGoARM64ByteCarrierSource(lease, request)
			if err != nil || owner == nil || owner.report.NativePackagePath != "main" {
				t.Fatalf("actual main namespace observation failed before consumer: %v", err)
			}
			defer owner.Close()
			ir, err := arm64ByteCarrierTranslateAPI(t, api, owner, pkg, string(assembly), "aarch64-unknown-linux-gnu", nil)
			if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
				t.Fatalf("observational main package acquired private library authority: %v", err)
			}
		})
	}
}
