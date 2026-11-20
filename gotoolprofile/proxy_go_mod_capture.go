package gotoolprofile

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/xgo-dev/plan9asm/internal/golegacymod"
)

// CaptureDownloadedProxyGoMod authenticates an actual Go-downloaded metadata
// file which is not in the original ZIP. This grants no source/package role;
// callers still prove ZIP absence, full original inventory and actual imports.
func CaptureDownloadedProxyGoMod(ctx context.Context, binary, directory string, env []string, name, version, zipSum, modSum, metadata string, prior *ProxyGoModProof) (*ProxyGoModProof, string, error) {
	output, _, err := RunBounded(ctx, directory, env, binary, "env", "-json", "GOMODCACHE", "GOPROXY")
	if err != nil {
		return nil, "", err
	}
	var actual map[string]string
	if err := json.Unmarshal(output, &actual); err != nil || len(actual) != 2 || !filepath.IsAbs(actual["GOMODCACHE"]) {
		return nil, "", fmt.Errorf("invalid actual metadata cache observation")
	}
	return golegacymod.CaptureCachedProxyGoMod(ctx, actual["GOMODCACHE"], actual["GOPROXY"],
		name, version, zipSum, modSum, metadata, prior)
}
