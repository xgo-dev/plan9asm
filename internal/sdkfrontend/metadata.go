package sdkfrontend

import (
	"context"
	"errors"
	"path/filepath"

	"github.com/xgo-dev/plan9asm"
	"github.com/xgo-dev/plan9asm/internal/sourcepath"
)

// CaptureMetadata returns an actual selected whole member and its existing
// live metadata-only owner. It creates no numerical/readonly/minimum owner,
// Options, native entry or frame. Callers must close the returned source and
// keep its original context live; diagnostic File/report values are not tokens.
// This explicit role is never a broad fallback from another source error.
// Only actual GoBinary/Directory/PackagePath/AssemblyFile/Target/Environment
// select this producer. CaptureRequest.Root and Package supply no permission.
// Canonical member selection does not certify a caller's original alias node;
// a caller/member lifetime proof must independently preserve that request.
func CaptureMetadata(ctx context.Context, request CaptureRequest) (_ *plan9asm.File, _ *plan9asm.GoX86SDKASMDataSource, result error) {
	if ctx == nil {
		return nil, nil, contextError("metadata capture needs its original bounded context")
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	directory, err := sourcepath.Resolve(request.Directory)
	if err != nil {
		return nil, nil, err
	}
	assembly, err := sourcepath.Resolve(request.AssemblyFile)
	if err != nil || filepath.Dir(assembly) != directory {
		return nil, nil, contextError("metadata assembly origin differs from its actual package")
	}
	source, err := plan9asm.CaptureGoX86SDKASMDataSource(ctx, plan9asm.GoX86SDKASMDataCaptureRequest{
		GoBinary: request.GoBinary, Directory: directory, PackagePath: request.PackagePath,
		Target: request.Target, Environment: request.Environment,
	})
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		if result != nil {
			result = errors.Join(result, source.Close())
		}
	}()
	file, err := source.Assembly(ctx, filepath.Base(assembly))
	if err != nil {
		return nil, nil, err
	}
	return file, source, nil
}
