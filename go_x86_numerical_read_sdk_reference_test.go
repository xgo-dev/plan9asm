//go:build go1.27

package plan9asm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
)

func numericalSDKReferencedInputSource(t *testing.T, arch string) *GoX86NumericalReadSource {
	t.Helper()
	ctx, request, _ := numericalSDKCPURequest(t, arch)
	root := filepath.Dir(filepath.Dir(request.GoBinary))
	request.Directory = filepath.Join(root, "src", "internal", "bytealg")
	request.PackagePath = "internal/bytealg"
	request.AssemblyFile = "compare_" + arch + ".s"
	return numericalSDKInputSource(t, ctx, request)
}

func TestGoX86SDKNumericalReadReferencedArchiveSealAndSourceIdentity(t *testing.T) {
	for _, kind := range []string{"missing target", "wrong package", "different same-SDK archive", "changed byte", "member source", "foreign export route", "copied source"} {
		t.Run(kind, func(t *testing.T) {
			source := numericalSDKReferencedInputSource(t, "amd64")
			ctx := source.sdk.originalContext
			original, present := source.sdk.Referenced["internal/cpu"]
			if !present || len(original.Archive) == 0 {
				t.Fatal("actual retained SDK reference precondition")
			}
			if kind == "copied source" {
				copied := new(GoX86NumericalReadSource)
				reflect.ValueOf(copied).Elem().Set(reflect.ValueOf(source).Elem())
				if !errors.Is(copied.verifySDKObservation(ctx), ErrProbeNeedsContext) ||
					!errors.Is(copied.Close(), ErrProbeNeedsContext) {
					t.Fatal("copied source borrowed SDK indexed metadata or removed original resources")
				}
				if err := source.verifySDKObservation(ctx); err != nil {
					t.Fatal("rejecting copied SDK referenced source revoked original", err)
				}
				return
			}
			changed := original
			restore := func() { source.sdk.Referenced["internal/cpu"] = original }
			switch kind {
			case "missing target":
				delete(source.sdk.Referenced, "internal/cpu")
			case "wrong package":
				changed.PackagePath = "internal/bytealg"
				source.sdk.Referenced["internal/cpu"] = changed
			case "different same-SDK archive":
				changed.Archive = append([]byte(nil), source.sdk.Archive...)
				source.sdk.Referenced["internal/cpu"] = changed
			case "changed byte":
				changed.Archive = append([]byte(nil), original.Archive...)
				changed.Archive[len(changed.Archive)/2] ^= 1
				source.sdk.Referenced["internal/cpu"] = changed
			case "member source":
				changed.Sources = []string{"foreign.s"}
				source.sdk.Referenced["internal/cpu"] = changed
			case "foreign export route":
				selection := source.sdk.Imports["internal/cpu"]
				originalSelection := selection
				selection.Export = source.guard.selection.Export
				source.sdk.Imports["internal/cpu"] = selection
				restore = func() { source.sdk.Imports["internal/cpu"] = originalSelection }
			}
			err := source.verifySDKObservation(ctx)
			restore()
			if !errors.Is(err, ErrProbeNeedsContext) || !errors.Is(source.verifySDKObservation(ctx), ErrProbeNeedsContext) {
				t.Fatal("foreign/restored SDK referenced metadata revived its source lease", err)
			}
			if err := source.request.Owners[0].Verify(ctx); err != nil {
				t.Fatal("rejecting source metadata revoked unrelated SDK CPU numerical storage owner", err)
			}
		})
	}
}

type numericalSDKReferencedMutationContext struct {
	context.Context
	once   sync.Once
	mutate func()
}

func (ctx *numericalSDKReferencedMutationContext) Err() error {
	pc, _, _, valid := runtime.Caller(1)
	if valid && strings.HasSuffix(runtime.FuncForPC(pc).Name(), "(*GoAMD64FrameSource).run") {
		ctx.once.Do(ctx.mutate)
	}
	return ctx.Context.Err()
}

func TestGoX86SDKNumericalReadReferencedArchiveCommandTOCTOU(t *testing.T) {
	source := numericalSDKReferencedInputSource(t, "amd64")
	ctx := source.sdk.originalContext
	original := source.sdk.Referenced["internal/cpu"]
	called := false
	wrapped := &numericalSDKReferencedMutationContext{Context: ctx, mutate: func() {
		called = true
		changed := original
		changed.Archive = append([]byte(nil), original.Archive...)
		changed.Archive[0] ^= 1
		source.sdk.Referenced["internal/cpu"] = changed
	}}
	err := source.verifySDKObservation(wrapped)
	source.sdk.Referenced["internal/cpu"] = original
	if !called || !errors.Is(err, ErrProbeNeedsContext) || !errors.Is(source.verifySDKObservation(ctx), ErrProbeNeedsContext) {
		t.Fatal("SDK input pre/post guard published or revived changed metadata around an actual command", called, err)
	}
	if source.ready || len(source.reads) != 0 || source.file != nil {
		t.Fatal("SDK metadata TOCTOU left a numerical/native certificate")
	}
	if err := source.request.Owners[0].Verify(ctx); err != nil {
		t.Fatal("SDK metadata postcheck revoked the independent CPU numerical owner", err)
	}
}

func TestGoX86SDKNumericalReadActualReferencedArchiveHandoff(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			source := numericalSDKReferencedInputSource(t, arch)
			selected, exists := source.sdk.Imports["internal/cpu"]
			archive, retained := source.sdk.Referenced["internal/cpu"]
			if !exists || !retained || selected.Export == "" || archive.PackagePath != selected.ImportPath ||
				!reflect.DeepEqual(archive.Sources, selected.SFiles) || len(archive.Archive) == 0 {
				t.Fatal("actual SDK graph did not hand off the exact referenced compiler archive")
			}
			actual, err := os.ReadFile(selected.Export)
			if err != nil || !bytes.Equal(actual, archive.Archive) ||
				source.sdk.Inputs[selected.Export] != sha256.Sum256(actual) {
				t.Fatal("referenced SDK compiler bytes escaped their complete original input seal", err)
			}
			if source.ready || source.file != nil || len(source.reads) != 0 {
				t.Fatal("SDK indexed metadata handed off a numerical/native permission")
			}
			if err := source.verifySDKObservation(source.sdk.originalContext); err != nil {
				t.Fatal("actual same-SDK referenced graph cannot verify", err)
			}
		})
	}
}
