//go:build go1.27

package plan9asm

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func numericalSDKInputSource(t *testing.T, ctx context.Context, request GoX86NumericalReadCaptureRequest) *GoX86NumericalReadSource {
	t.Helper()
	source, err := captureGoX86NumericalReadSource(ctx, request, numericalSBSDKSource, true)
	if err != nil {
		t.Fatal("actual independent SDK input observation precondition", err)
	}
	t.Cleanup(func() {
		if err := source.Close(); err != nil {
			t.Error(err)
		}
	})
	return source
}

func TestGoX86SDKNumericalReadSealedRoleGraphAndObjectMutations(t *testing.T) {
	ctx, request, _ := numericalSDKCPURequest(t, "amd64")
	for _, test := range []struct {
		name   string
		mutate func(*GoX86NumericalReadSource) func()
	}{
		{"role", func(s *GoX86NumericalReadSource) func() {
			s.role = numericalSBOwnedSource
			return func() { s.role = numericalSBSDKSource }
		}},
		{"package", func(s *GoX86NumericalReadSource) func() {
			original := s.request.PackagePath
			s.request.PackagePath = "hash/crc32"
			return func() { s.request.PackagePath = original }
		}},
		{"standard selection", func(s *GoX86NumericalReadSource) func() {
			s.guard.selection.Standard = false
			return func() { s.guard.selection.Standard = true }
		}},
		{"selected source", func(s *GoX86NumericalReadSource) func() {
			original := s.guard.selection.SFiles
			s.guard.selection.SFiles = nil
			return func() { s.guard.selection.SFiles = original }
		}},
		{"export route", func(s *GoX86NumericalReadSource) func() {
			original := s.guard.selection.Export
			s.guard.selection.Export = filepath.Join(s.guard.owned, "foreign.a")
			return func() { s.guard.selection.Export = original }
		}},
		{"whole graph", func(s *GoX86NumericalReadSource) func() {
			original := s.sdk.Graph
			s.sdk.Graph = append(append([]byte(nil), original...), []byte("{}")...)
			return func() { s.sdk.Graph = original }
		}},
		{"whole archive", func(s *GoX86NumericalReadSource) func() {
			s.sdk.Archive[0] ^= 1
			return func() { s.sdk.Archive[0] ^= 1 }
		}},
		{"member ordinal", func(s *GoX86NumericalReadSource) func() {
			s.sdk.ArchiveMembers[1].Offset++
			return func() { s.sdk.ArchiveMembers[1].Offset-- }
		}},
		{"compiled request environment", func(s *GoX86NumericalReadSource) func() {
			original := s.guard.request.Environment
			s.guard.request.Environment = append(append([]string(nil), original...), "GOAMD64=v3")
			return func() { s.guard.request.Environment = original }
		}},
		{"borrowed read token", func(s *GoX86NumericalReadSource) func() {
			s.guard.request.NumericalReads = new(GoX86NumericalReadBinding)
			return func() { s.guard.request.NumericalReads = nil }
		}},
		{"original input hash", func(s *GoX86NumericalReadSource) func() {
			name := filepath.Join(s.request.Directory, s.request.AssemblyFile)
			original := s.guard.inputs[name]
			changed := original
			changed[0] ^= 1
			s.guard.inputs[name] = changed
			return func() { s.guard.inputs[name] = original }
		}},
		{"same-shaped foreign owner", func(s *GoX86NumericalReadSource) func() {
			original := s.request.Owners[0]
			s.request.Owners[0] = &GoNumericalStorageOwner{observation: original.observation}
			return func() { s.request.Owners[0] = original }
		}},
		{"original context identity", func(s *GoX86NumericalReadSource) func() {
			original := s.sdk.context
			s.sdk.context = context.Background()
			return func() { s.sdk.context = original }
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			source := numericalSDKInputSource(t, ctx, request)
			restore := test.mutate(source)
			err := source.verifySDKObservation(ctx)
			restore()
			if !errors.Is(err, ErrProbeNeedsContext) || !errors.Is(source.verifySDKObservation(ctx), ErrProbeNeedsContext) {
				t.Fatal("mutated/restored SDK observation became valid again", err)
			}
			if err := request.Owners[0].Verify(ctx); err != nil {
				t.Fatal("SDK source rejection revoked an independent data owner", err)
			}
		})
	}
}

func TestGoX86SDKNumericalReadCopiedSourceCannotBorrowOrCloseOriginal(t *testing.T) {
	ctx, request, _ := numericalSDKCPURequest(t, "amd64")
	for _, operation := range []string{"input verify", "public verify", "bind", "close"} {
		t.Run(operation, func(t *testing.T) {
			source := numericalSDKInputSource(t, ctx, request)
			copied := new(GoX86NumericalReadSource)
			reflect.ValueOf(copied).Elem().Set(reflect.ValueOf(source).Elem())
			var err error
			switch operation {
			case "input verify":
				err = copied.verifySDKObservation(ctx)
			case "public verify":
				err = copied.Verify(ctx)
			case "bind":
				var options Options
				options, err = copied.BindNumericalReads(ctx, GoPackage{}, nil, Options{})
				if options.NumericalReads != nil {
					t.Fatal("copied SDK source produced a numerical token")
				}
			case "close":
				err = copied.Close()
			}
			if !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("copied SDK source borrowed the original generation", err)
			}
			if err := source.verifySDKObservation(ctx); err != nil {
				t.Fatal("rejecting a SDK source copy revoked the original", err)
			}
			if _, err := os.Stat(source.guard.owned); err != nil {
				t.Fatal("copied SDK source removed the original owned artifacts", err)
			}
		})
	}
}

func TestGoX86SDKNumericalReadInvalidVerificationCauseAndCloseRemainFinal(t *testing.T) {
	ctx, request, owner := numericalSDKCPURequest(t, "amd64")
	for _, kind := range []string{"nil", "cancelled", "deadline", "closed"} {
		t.Run(kind, func(t *testing.T) {
			source := numericalSDKInputSource(t, ctx, request)
			var invalid context.Context
			want := ErrProbeNeedsContext
			switch kind {
			case "cancelled":
				var stop context.CancelFunc
				invalid, stop = context.WithCancel(ctx)
				stop()
				want = context.Canceled
			case "deadline":
				var stop context.CancelFunc
				invalid, stop = context.WithDeadline(ctx, time.Now().Add(-time.Second))
				defer stop()
				want = context.DeadlineExceeded
			case "closed":
				if err := source.Close(); err != nil {
					t.Fatal(err)
				}
				invalid = ctx
			}
			first := source.verifySDKObservation(invalid)
			if !errors.Is(first, want) || want != ErrProbeNeedsContext && errors.Is(first, ErrProbeNeedsContext) {
				t.Fatal("SDK verification lost its original cause", first)
			}
			if !errors.Is(source.verifySDKObservation(ctx), ErrProbeNeedsContext) {
				t.Fatal("SDK lease was revived after failure/Close")
			}
			if err := owner.Verify(ctx); err != nil {
				t.Fatal("invalid SDK verification revoked the independent CPU owner", err)
			}
		})
	}
}

func TestGoX86SDKNumericalReadConcurrentVerifyAndCloseHaveNoPermission(t *testing.T) {
	ctx, request, _ := numericalSDKCPURequest(t, "amd64")
	source := numericalSDKInputSource(t, ctx, request)
	var workers sync.WaitGroup
	for ordinal := 0; ordinal < 4; ordinal++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			// Published verification uses this same source lock. The input-only
			// observation has no public ready/source/LLVM certificate to publish.
			source.mu.Lock()
			err := source.verifySDKObservation(ctx)
			source.mu.Unlock()
			if err != nil && !errors.Is(err, ErrProbeNeedsContext) {
				t.Error("unexpected concurrent SDK verification error", err)
			}
		}()
	}
	workers.Add(1)
	go func() {
		defer workers.Done()
		if err := source.Close(); err != nil {
			t.Error(err)
		}
	}()
	workers.Wait()
	if source.ready || !source.sdk.closed || !errors.Is(source.Verify(ctx), ErrProbeNeedsContext) {
		t.Fatal("concurrent SDK input observation acquired or revived numerical permission")
	}
}

func TestGoX86SDKNumericalReadExplicitFactoryCannotBorrowOwnedOrAliasSource(t *testing.T) {
	ctx, request, owner := numericalSDKCPURequest(t, "amd64")
	_, owned, _, _ := numericalSBFixture(t, "amd64")
	for _, kind := range []string{"owned-main", "physical SDK alias"} {
		t.Run(kind, func(t *testing.T) {
			changed := request
			if kind == "owned-main" {
				changed.Directory, changed.PackagePath, changed.AssemblyFile = owned.Directory, "example.invalid/numericalfixture", owned.AssemblyFile
			} else {
				alias := filepath.Join(t.TempDir(), "sdk-alias")
				if err := os.Symlink(request.Directory, alias); err != nil {
					t.Fatal(err)
				}
				changed.Directory = alias
			}
			source, err := CaptureGoX86SDKNumericalReadSource(ctx, changed)
			if source != nil || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("SDK factory borrowed a non-SDK or aliased physical source role", err)
			}
			if err := owner.Verify(ctx); err != nil {
				t.Fatal("non-SDK source rejection revoked the actual SDK CPU owner", err)
			}
		})
	}
}

func TestGoX86SDKNumericalReadCompleteRawGraphRejectsMissingAndUnknownMetadata(t *testing.T) {
	first := []byte(`{"ImportPath":"unsafe","Stale":true,"StaleReason":"initial"}
{"ImportPath":"internal/cpu","Export":"cpu.a","Standard":true}`)
	if !numericalSameRawSDKGraph(first, []byte(`{"ImportPath":"unsafe","Stale":false}
{"ImportPath":"internal/cpu","Export":"cpu.a","Standard":true}`)) {
		t.Fatal("official typed stale-display difference changed source identity")
	}
	for _, changed := range []string{
		`{"ImportPath":"unsafe"}`,
		`{"ImportPath":"internal/cpu","Export":"cpu.a","Standard":true} {"ImportPath":"unsafe"}`,
		`{"ImportPath":"unsafe"} {"ImportPath":"internal/cpu","Export":"foreign.a","Standard":true}`,
		`{"ImportPath":"unsafe"} {"ImportPath":"internal/cpu","Export":"cpu.a","Standard":true,"FutureRole":true}`,
		`{"ImportPath":"unsafe","Stale":null} {"ImportPath":"internal/cpu","Export":"cpu.a","Standard":true}`,
		`{"ImportPath":"unsafe"} {"ImportPath":"internal/cpu","Export":"cpu.a","Standard":true} garbage`,
	} {
		if numericalSameRawSDKGraph(first, []byte(changed)) {
			t.Fatal("partial/reordered/foreign/unknown complete graph was normalized away", strings.TrimSpace(changed))
		}
	}
}
