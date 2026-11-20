package plan9asm

import (
	"context"
	"errors"
	"os"
	"reflect"
	"testing"
)

func TestGoOriginalInputGuardCannotSupplyFrameAuthority(t *testing.T) {
	request := GoAMD64FrameCaptureRequest{Environment: []string{"GOFLAGS="}}
	first, second := newGoOriginalInputGuard(request), newGoOriginalInputGuard(request)
	request.Environment[0] = "GOFLAGS=-overlay=foreign.json"
	if first.request.Environment[0] != "GOFLAGS=" || second.request.Environment[0] != "GOFLAGS=" {
		t.Fatal("query-only guard retained caller environment storage")
	}
	first.inputs["first-only"] = [32]byte{1}
	if len(second.inputs) != 0 {
		t.Fatal("independent query-only guards shared input maps")
	}
	for _, source := range []*GoAMD64FrameSource{first, second} {
		if source.ready || source.owned != "" || len(source.functions) != 0 || len(source.declarations) != 0 ||
			source.downloadedOrigin != nil || source.downloadedModule != nil {
			t.Fatal("input initialization created an object or original-source capability")
		}
		if !errors.Is(source.Verify(context.Background()), ErrProbeNeedsContext) {
			t.Fatal("query-only guard verified as a frame")
		}
		if _, err := source.BindFixedLocal(context.Background(), GoPackage{}, nil, Options{}); !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("query-only guard admitted fixed-local memory", err)
		}
		if err := source.Close(); err != nil {
			t.Fatal("original query guard could not close its empty resource role", err)
		}
	}
}

func TestGoAMD64FrameSourceCopyCannotBorrowOrCleanOriginal(t *testing.T) {
	for _, operation := range []string{"Verify", "Close"} {
		t.Run(operation, func(t *testing.T) {
			pkg, request := goAMD64FrameSourceFixture(t)
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			source, err := CaptureGoAMD64FrameSource(ctx, pkg, request)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := source.Close(); err != nil {
					t.Error(err)
				}
			}()
			if err := source.Verify(ctx); err != nil {
				t.Fatal("actual original public factory did not verify", err)
			}
			owned := source.owned
			before, err := os.Lstat(owned)
			if err != nil {
				t.Fatal(err)
			}
			// Deliberately model the public whole-value operation without hiding
			// a mutex copy behind a constructor or serializing private fields.
			copied := new(GoAMD64FrameSource)
			reflect.ValueOf(copied).Elem().Set(reflect.ValueOf(source).Elem())
			if operation == "Verify" {
				err = copied.Verify(ctx)
			} else {
				err = copied.Close()
			}
			if !errors.Is(err, ErrProbeNeedsContext) {
				t.Errorf("whole-value copied frame %s borrowed its original owner role: %v", operation, err)
			}
			after, err := os.Lstat(owned)
			if err != nil || !os.SameFile(before, after) {
				t.Error("copied frame operation removed or replaced original artifacts", err)
			}
			if err := source.Verify(ctx); err != nil {
				t.Error("copied frame operation revoked its original object", err)
			}
		})
	}
}
