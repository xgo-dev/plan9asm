//go:build go1.27

package gotoolprofile

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm"
)

func amd64DownloadedFramePublicFixture(t *testing.T, variant string) (AMD64OriginalObservationRequest, plan9asm.GoPackage, plan9asm.GoAMD64DownloadedFrameCaptureRequest) {
	t.Helper()
	request, path, version := amd64DownloadedObservationFixture(t, variant)
	set := token.NewFileSet()
	syntax, err := parser.ParseFile(set, filepath.Join(request.Directory, "value.go"), nil, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	typed := types.NewPackage(request.PackagePath, "observation")
	if len(syntax.Imports) == 0 {
		typed, err = (&types.Config{Sizes: types.SizesFor("gc", "amd64")}).Check(request.PackagePath, set, []*ast.File{syntax}, nil)
		if err != nil {
			t.Fatal(err)
		}
	}
	// Import negatives deliberately supply no imported type authority. The
	// public factory must reject their actual Go import graph before admission.
	pkg := plan9asm.GoPackage{Path: request.PackagePath, Types: typed, Syntax: []*ast.File{syntax}}
	capture := plan9asm.GoAMD64DownloadedFrameCaptureRequest{
		Original: plan9asm.GoAMD64FrameCaptureRequest{GoBinary: request.GoBinary,
			Directory: request.Directory, AssemblyFile: "value_amd64.s", Target: request.Target,
			Environment: append([]string(nil), request.Environment...)},
		SourceModule: path, SourceVersion: version,
	}
	return request, pkg, capture
}

func TestAMD64DownloadedFramePublicFactoryAndIdentity(t *testing.T) {
	for _, operation := range []string{"Verify", "Close", "archive namespace alias", "nested package"} {
		t.Run(operation, func(t *testing.T) {
			variant := "fixed-local"
			if operation == "archive namespace alias" {
				variant = "alias"
			} else if operation == "nested package" {
				variant = "nested"
			}
			request, pkg, capture := amd64DownloadedFramePublicFixture(t, variant)
			ctx, cancel := amd64OriginalObservationContext(t)
			defer cancel()
			source, err := plan9asm.CaptureGoAMD64DownloadedFrameSource(ctx, pkg, capture)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := source.Close(); err != nil {
					t.Error(err)
				}
			}()
			if err := source.Verify(ctx); err != nil {
				t.Fatal("actual exact original source/object did not verify", err)
			}
			if operation == "nested package" {
				return
			}
			if operation == "archive namespace alias" {
				if pkg.Path == capture.SourceModule {
					t.Fatal("first-party ZIP namespace alias control was lost")
				}
				return
			}
			copied := new(plan9asm.GoAMD64FrameSource)
			reflect.ValueOf(copied).Elem().Set(reflect.ValueOf(source).Elem())
			if operation == "Verify" {
				err = copied.Verify(ctx)
			} else {
				err = copied.Close()
			}
			if !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
				t.Fatal("whole-value copy borrowed exact original frame role", err)
			}
			if err := source.Verify(ctx); err != nil {
				t.Fatal("copied operation revoked or deleted original artifacts", err)
			}
			if _, err := os.Stat(request.Directory); err != nil {
				t.Fatal("factory changed its original cache directory", err)
			}
		})
	}
}

func TestAMD64DownloadedFramePublicSourceRevocation(t *testing.T) {
	for _, role := range []string{"source", "ZIP", "metadata", "close", "canceled"} {
		t.Run(role, func(t *testing.T) {
			request, pkg, capture := amd64DownloadedFramePublicFixture(t, "fixed-local")
			ctx, cancel := amd64OriginalObservationContext(t)
			defer cancel()
			source, err := plan9asm.CaptureGoAMD64DownloadedFrameSource(ctx, pkg, capture)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := source.Close(); err != nil {
					t.Error(err)
				}
			}()
			if err := source.Verify(ctx); err != nil {
				t.Fatal(err)
			}
			switch role {
			case "close":
				if err := source.Close(); err != nil {
					t.Fatal(err)
				}
			case "canceled":
				canceled, stop := context.WithCancel(ctx)
				stop()
				err := source.Verify(canceled)
				if !errors.Is(err, context.Canceled) || !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
					t.Fatal("verification discarded cancellation cause", err)
				}
			default:
				name := filepath.Join(request.Directory, "value.go")
				if role != "source" {
					cache := originalObservationEnvironment(request.Environment, "GOMODCACHE")
					suffix := ".zip"
					if role == "metadata" {
						suffix = ".mod"
					}
					name = filepath.Join(cache, "cache", "download", capture.SourceModule, "@v", capture.SourceVersion+suffix)
				}
				before, err := os.ReadFile(name)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(name, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(name, append(append([]byte(nil), before...), '\n'), 0600); err != nil {
					t.Fatal(err)
				}
				if !errors.Is(source.Verify(ctx), plan9asm.ErrProbeNeedsContext) {
					t.Fatal("changed original bytes retained a frame capability")
				}
				if err := os.WriteFile(name, before, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if !errors.Is(source.Verify(ctx), plan9asm.ErrProbeNeedsContext) {
				t.Fatal("restoring bytes or context revived a revoked original source")
			}
			if _, err := os.Stat(request.Directory); err != nil {
				t.Fatal("revocation removed original source cache", err)
			}
		})
	}
}

func TestAMD64DownloadedFramePublicRejectedRoles(t *testing.T) {
	for _, variant := range []string{"import", "foreign", "data"} {
		t.Run(variant, func(t *testing.T) {
			_, pkg, capture := amd64DownloadedFramePublicFixture(t, variant)
			ctx, cancel := amd64OriginalObservationContext(t)
			defer cancel()
			source, err := plan9asm.CaptureGoAMD64DownloadedFrameSource(ctx, pkg, capture)
			if source != nil {
				if err := source.Close(); err != nil {
					t.Error(err)
				}
			}
			if !errors.Is(err, plan9asm.ErrProbeNeedsContext) || source != nil {
				t.Fatal("broader source role acquired a downloaded frame", err)
			}
			if (variant == "import" || variant == "foreign") && !strings.Contains(err.Error(), "actual selected declarations differ") {
				t.Fatal("unbound supplied types were not rejected by the independent source typecheck", err)
			}
		})
	}
}

func TestAMD64DownloadedFramePublicInputIdentityAndCancellation(t *testing.T) {
	_, pkg, capture := amd64DownloadedFramePublicFixture(t, "fixed-local")
	ctx, cancel := amd64OriginalObservationContext(t)
	defer cancel()
	for _, role := range []string{"latest", "wrong original root", "canceled"} {
		t.Run(role, func(t *testing.T) {
			request, current := capture, ctx
			switch role {
			case "latest":
				request.SourceVersion = "latest"
			case "wrong original root":
				owned, _, _, _, _ := amd64OriginalFixedLocalFixture(t)
				request.Original.Directory = owned.Directory
			case "canceled":
				canceled, stop := context.WithCancel(ctx)
				stop()
				current = canceled
			}
			source, err := plan9asm.CaptureGoAMD64DownloadedFrameSource(current, pkg, request)
			if source != nil {
				if err := source.Close(); err != nil {
					t.Error(err)
				}
			}
			if !errors.Is(err, plan9asm.ErrProbeNeedsContext) || source != nil {
				t.Fatal("wrong exact original input acquired a frame", err)
			}
			if role == "canceled" && !errors.Is(err, context.Canceled) {
				t.Fatal("capture lost the actual cancellation cause", err)
			}
		})
	}
}

func TestAMD64DownloadedFixedLocalRejectsOwnedAndResolverRevokes(t *testing.T) {
	t.Run("owned-only observation", func(t *testing.T) {
		request, pkg, file, options, _ := amd64OriginalFixedLocalFixture(t)
		ctx, cancel := amd64OriginalObservationContext(t)
		defer cancel()
		observed, err := CaptureAMD64OriginalPackageObservation(ctx, request, RunBounded)
		if err != nil {
			t.Fatal(err)
		}
		defer observed.Close()
		_, lease, err := observed.BindDownloadedFixedLocal(ctx, pkg, file, "value_amd64.s", options)
		if !errors.Is(err, plan9asm.ErrProbeNeedsContext) || lease != nil {
			t.Fatal("owned-only query acquired an exact downloaded route", err)
		}
		if err := observed.Verify(ctx); err != nil {
			t.Fatal("rejected route revoked unchanged original query", err)
		}
	})
	t.Run("resolver closes original owner", func(t *testing.T) {
		request, pkg, capture := amd64DownloadedFramePublicFixture(t, "fixed-local")
		ctx, cancel := amd64OriginalObservationContext(t)
		defer cancel()
		observed, err := captureAMD64DownloadedForTest(ctx, request, capture.SourceModule, capture.SourceVersion)
		if err != nil {
			t.Fatal(err)
		}
		defer observed.Close()
		_, _, file, options, _ := amd64OriginalFixedLocalFixture(t)
		resolve := options.ResolveSym
		options.ResolveSym = func(symbol string) string {
			if err := observed.Close(); err != nil {
				t.Error(err)
			}
			return resolve(symbol)
		}
		_, lease, err := observed.BindDownloadedFixedLocal(ctx, pkg, file, "value_amd64.s", options)
		if err == nil || lease != nil {
			t.Fatal("resolver close did not revoke eventual independent handoff", err)
		}
	})
}
