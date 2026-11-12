//go:build go1.27

package plan9asm

import (
	"errors"
	"strings"
	"testing"
)

func TestGoX86SDKLiteralAlignmentOriginalVendorPackageNamespace(t *testing.T) {
	ctx, request := sdkASMDataRequest(t, "amd64", "vendor/golang.org/x/crypto/chacha20poly1305")
	source, err := CaptureGoX86SDKASMDataSource(ctx, request)
	if err != nil {
		t.Fatal("complete original vendored SDK source", err)
	}
	defer source.Close()

	owner, err := CaptureGoX86SDKReadonlyLiteralDataOwner(ctx, source)
	if err != nil {
		t.Fatal("independent original literal initializer", err)
	}
	defer owner.Close()

	observed, err := CaptureGoX86SDKLiteralAlignment(ctx, owner)
	if observed != nil {
		defer observed.Close()
		t.Fatal("unused vendored assembly unexpectedly acquired retained literal alignment")
	}
	// The ordinary empty-main link does not call this package's assembly.
	// Reaching that real dead-stripping boundary is distinct from failing a
	// cmd/go query through the package directory's unrelated module namespace.
	if !errors.Is(err, ErrProbeNeedsContext) ||
		!strings.Contains(err.Error(), "no uniquely retained original literal has observed minimum alignment") {
		t.Fatal("vendored alignment observation did not reach its genuine linker boundary", err)
	}
	if err := owner.Verify(ctx); err != nil {
		t.Fatal("rejected alignment disposed its borrowed original initializer", err)
	}
	if err := source.Verify(ctx); err != nil {
		t.Fatal("rejected alignment changed its complete original SDK source", err)
	}
}
