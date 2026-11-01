//go:build go1.27

package plan9asm

import (
	"errors"
	"os"
	"testing"
)

func TestGoX86NumericalReadRevokePreservesArtifactLifetime(t *testing.T) {
	source, err := numericalSDKMapsReadCapture(t, "amd64", "memhash_nosimd_amd64.s")
	if err != nil {
		t.Fatal(err)
	}
	ctx := source.sdk.originalContext
	pkg, file, options := numericalSDKLiteralPackage(t, source.literals.source, source.request.AssemblyFile)
	bound, err := source.BindNumericalReads(ctx, pkg, file, options)
	if err != nil {
		t.Fatal(err)
	}
	owned := source.guard.owned
	foreign := &GoX86NumericalReadSource{identity: source}
	if err := foreign.Revoke(); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("foreign source revoked original publication", err)
	}
	if err := source.Verify(ctx); err != nil {
		t.Fatal("foreign revoke affected original source", err)
	}
	if err := source.Revoke(); err != nil {
		t.Fatal(err)
	}
	if err := source.Revoke(); err != nil {
		t.Fatal("revoke was not idempotent", err)
	}
	if info, err := os.Stat(owned); err != nil || !info.IsDir() {
		t.Fatal("revoke disposed active artifacts", err)
	}
	for _, api := range []string{"Verify", "Bind", "Translate"} {
		var err error
		switch api {
		case "Verify":
			err = source.Verify(ctx)
		case "Bind":
			_, err = source.BindNumericalReads(ctx, pkg, file, options)
		case "Translate":
			_, err = Translate(file, bound)
		}
		if !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("revoked original source retained publication", api, err)
		}
	}
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(owned); !os.IsNotExist(err) {
		t.Fatal("owning Close did not release deferred artifacts", err)
	}
}
