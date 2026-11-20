//go:build go1.27

package plan9asm

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestGoAMD64FrameSourceNumericalDriverAliasCannotBorrowSealedIdentity(t *testing.T) {
	ctx, pkg, request, _, bound, _, _ := numericalLocalFactory(t)
	request.NumericalReads = bound.NumericalReads
	original, err := CaptureGoAMD64FrameSource(ctx, pkg, request)
	if err != nil {
		t.Fatal("actual complete numerical/frame join precondition:", err)
	}
	defer original.Close()
	alias := goAMD64FrameDriverDirectoryAlias(t, ctx, filepath.Dir(request.GoBinary))
	request.GoBinary = filepath.Join(alias, filepath.Base(request.GoBinary))
	foreign, err := CaptureGoAMD64FrameSource(ctx, pkg, request)
	if foreign != nil {
		defer foreign.Close()
	}
	if foreign != nil || !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("a physical driver alias borrowed a differently spelled sealed numerical request:", err)
	}
	if err := original.Verify(ctx); err != nil {
		t.Fatal("foreign alias rejection revoked the original complete join:", err)
	}
}
