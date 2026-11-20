package plan9asm

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"path/filepath"

	"github.com/xgo-dev/plan9asm/internal/golegacymod"
	"github.com/xgo-dev/plan9asm/internal/gooriginalsrc"
	"github.com/xgo-dev/plan9asm/internal/sourcepath"
)

// The frame factory independently observes exact dependency downloads. The
// outer package query and caller-supplied types cannot supply these origins.
func (source *GoAMD64FrameSource) captureDownloadedDeclarationOrigins(ctx context.Context, output []byte) error {
	if source.downloadedModule == nil {
		return nil
	}
	if len(output) > 16<<20 {
		return goAMD64FrameContext("declaration import graph exceeds its bound")
	}
	if err := source.verifyDownloadedOrigin(); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(output))
	for count := 0; ; count++ {
		var selected goAMD64FrameSelection
		if err := decoder.Decode(&selected); err == io.EOF {
			break
		} else if err != nil {
			return err
		}
		if count >= 4096 {
			return goAMD64FrameContext("downloaded declaration import graph exceeds its count bound")
		}
		if selected.Standard {
			continue // The SDK source/export consumer validates this role.
		}
		actual := selected.Module
		if actual == nil || len(actual.Replace) != 0 && string(actual.Replace) != "null" {
			return goAMD64FrameContext("downloaded dependency has an unbound module/replacement role")
		}
		if !actual.Main {
			key := actual.Path + "@" + actual.Version
			if _, exists := source.downloadedImports[key]; !exists {
				if source.ready {
					return goAMD64FrameContext("actual declaration import graph acquired a new module")
				}
				original, err := source.observeDownloadedModule(ctx, source.downloadedOrigin,
					goAMD64DownloadedIdentity{module: actual.Path, version: actual.Version}, source.env["GOTMPDIR"])
				if err != nil {
					return err
				}
				if source.downloadedImports == nil {
					source.downloadedImports = make(map[string]gooriginalsrc.Module)
				}
				source.downloadedImports[key] = original
			}
		}
		if _, err := source.downloadedDeclarationDirectory(selected); err != nil {
			return err
		}
	}
	return source.verifyDownloadedOrigin()
}

func (source *GoAMD64FrameSource) downloadedDeclarationDirectory(selected goAMD64FrameSelection) (string, error) {
	actual := selected.Module
	if source.downloadedOrigin == nil || source.downloadedModule == nil || selected.Standard || actual == nil ||
		len(actual.Replace) != 0 && string(actual.Replace) != "null" {
		return "", goAMD64FrameContext("foreign declaration dependency needs authenticated original handoff")
	}
	original := *source.downloadedModule
	version := "" // Go's actual cache-CWD main role is not its download version.
	if !actual.Main {
		var found bool
		original, found = source.downloadedImports[actual.Path+"@"+actual.Version]
		if !found {
			return "", goAMD64FrameContext("declaration dependency lacks its exact original download")
		}
		version = original.SourceVersion
	}
	root, rootErr := sourcepath.Resolve(actual.Dir)
	metadata, metadataErr := sourcepath.Resolve(actual.GoMod)
	if rootErr != nil || metadataErr != nil || root != original.Root ||
		actual.Path != original.ModulePath || actual.Version != version ||
		actual.GoVersion != gooriginalsrc.SelectedGoVersion(original.GoVersion, actual.Main) ||
		metadata != original.GoMod && metadata != filepath.Join(original.Root, "go.mod") {
		return "", goAMD64FrameContext("declaration dependency differs from its original module metadata")
	}
	if original.GoModOrigin == golegacymod.ProxyGoModProtocol && (actual.Main || metadata != original.GoMod) {
		return "", goAMD64FrameContext("legacy proxy metadata requires its exact dependency role")
	}
	directory, err := sourcepath.Resolve(selected.Dir)
	if err != nil {
		return "", err
	}
	path, err := goAMD64DownloadedPackagePath(original, directory)
	if err != nil || path != selected.ImportPath {
		return "", goAMD64FrameContext("declaration dependency escaped its original package namespace")
	}
	return directory, nil
}
