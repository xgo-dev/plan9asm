package golegacymod

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/xgo-dev/plan9asm/internal/sourcepath"
	"golang.org/x/mod/module"
)

// CaptureCachedProxyGoMod authenticates metadata in a separately observed Go
// cache. Its caller must bind cache/proxy to the actual Go environment and
// independently observe the whole ZIP/tree, including the absent go.mod.
// No package-selection or assembly authority follows from this proof.
func CaptureCachedProxyGoMod(ctx context.Context, cache, proxy, name, version, zipSum, modSum, metadata string, prior *ProxyGoModProof) (*ProxyGoModProof, string, error) {
	if ctx == nil {
		return nil, "", fmt.Errorf("legacy metadata capture needs a live context")
	}
	if err := ctx.Err(); err != nil {
		return nil, "", err
	}
	if !filepath.IsAbs(cache) {
		return nil, "", fmt.Errorf("invalid actual metadata cache observation")
	}
	escapedModule, err := module.EscapePath(name)
	if err != nil {
		return nil, "", err
	}
	escapedVersion, err := module.EscapeVersion(version)
	if err != nil {
		return nil, "", err
	}
	wanted := filepath.Join(cache, "cache", "download", filepath.FromSlash(escapedModule), "@v", escapedVersion+".mod")
	if filepath.Clean(metadata) != wanted {
		return nil, "", fmt.Errorf("proxy go.mod is not the actual exact-version download metadata")
	}
	info, err := os.Lstat(wanted)
	if err != nil || !info.Mode().IsRegular() {
		return nil, "", fmt.Errorf("proxy metadata is not a regular exact-version download file")
	}
	canonical, err := sourcepath.Resolve(wanted)
	if err != nil {
		return nil, "", err
	}
	contents, err := ReadChecksumFile(canonical, 1024)
	if err != nil {
		return nil, "", err
	}
	if prior != nil {
		// Revalidate the signature/inclusion and current bytes. The immutable
		// exact pair does not require another public checkpoint or network read.
		if err := ValidateProxyGoMod(prior); err != nil {
			return nil, "", err
		}
		if prior.Module != name || prior.Version != version || prior.ModuleSum != zipSum || prior.GoModSum != modSum ||
			prior.Contents != string(contents) || prior.SHA256 != bytesSHA256(contents) {
			return nil, "", fmt.Errorf("downloaded metadata differs from authenticated producer origin")
		}
		proof := *prior
		proof.Inclusion = append([]string(nil), prior.Inclusion...)
		return &proof, canonical, nil
	}
	reader, err := NewSumDBReader(ctx, cache, proxy)
	if err != nil {
		return nil, "", err
	}
	lookup, err := reader.Read("lookup/"+escapedModule+"@"+escapedVersion, 16<<10)
	if err != nil {
		return nil, "", err
	}
	proof, err := CaptureProxyGoMod(name, version, zipSum, modSum, contents, lookup, reader)
	if err != nil {
		return nil, "", err
	}
	return proof, canonical, nil
}
