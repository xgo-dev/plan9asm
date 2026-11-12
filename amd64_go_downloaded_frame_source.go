package plan9asm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/xgo-dev/plan9asm/internal/goasmcmd"
	"github.com/xgo-dev/plan9asm/internal/golegacymod"
	"github.com/xgo-dev/plan9asm/internal/gooriginalsrc"
	"github.com/xgo-dev/plan9asm/internal/sourcepath"
	"golang.org/x/mod/module"
)

// GoAMD64DownloadedFrameCaptureRequest names original exact cache inputs. It
// carries no observation, checker, object, signature or permission callback.
type GoAMD64DownloadedFrameCaptureRequest struct {
	Original                    GoAMD64FrameCaptureRequest
	SourceModule, SourceVersion string
}

type goAMD64DownloadedIdentity struct {
	module, version string
}

// CaptureGoAMD64DownloadedFrameSource independently executes stock Go and
// closes the original ZIP, extracted members, declarations and whole objects.
// Downloaded roles retain their primary module and independently observed
// original import graph. Capture itself grants no memory permission.
func CaptureGoAMD64DownloadedFrameSource(ctx context.Context, pkg GoPackage, request GoAMD64DownloadedFrameCaptureRequest) (*GoAMD64FrameSource, error) {
	if module.Check(request.SourceModule, request.SourceVersion) != nil ||
		module.CanonicalVersion(request.SourceVersion) != request.SourceVersion {
		return nil, goAMD64FrameContext("downloaded capture requires a canonical exact source identity")
	}
	return captureGoAMD64FrameSource(ctx, pkg, request.Original,
		&goAMD64DownloadedIdentity{module: request.SourceModule, version: request.SourceVersion})
}

func (source *GoAMD64FrameSource) captureDownloadedOrigin(ctx context.Context, exact goAMD64DownloadedIdentity, temporary string) (result error) {
	cache, err := sourcepath.Resolve(source.env["GOMODCACHE"])
	if err != nil {
		return err
	}
	origins, err := gooriginalsrc.NewOriginSet(cache, source.request.GoBinary)
	if err != nil {
		return err
	}
	original, err := source.observeDownloadedModule(ctx, origins, exact, temporary)
	if err != nil {
		return err
	}
	if _, err := goAMD64DownloadedPackagePath(original, source.request.Directory); err != nil {
		return err
	}
	source.downloadedOrigin, source.downloadedModule = origins, &original
	source.downloadedImports = map[string]gooriginalsrc.Module{original.SourceModule + "@" + original.SourceVersion: original}
	return source.verifyDownloadedOrigin()
}

func (source *GoAMD64FrameSource) legacyDownloadedModule() bool {
	return source.downloadedModule != nil && source.downloadedModule.GoModOrigin == golegacymod.ProxyGoModProtocol
}

func (source *GoAMD64FrameSource) runDownloadedList(ctx context.Context, args []string) ([]byte, error) {
	if source.numericalBinding != nil {
		return nil, goAMD64FrameContext("legacy dependency query needs its separate numerical-command binding")
	}
	original := source.downloadedModule
	path, err := goAMD64DownloadedPackagePath(*original, source.request.Directory)
	if err != nil {
		return nil, err
	}
	env, err := gooriginalsrc.DependencyQueryEnvironment(source.request.Environment)
	if err != nil {
		return nil, err
	}
	arguments := append([]string(nil), args...)
	for index, argument := range arguments {
		switch argument {
		case ".":
			arguments[index] = path
		}
	}
	return gooriginalsrc.RunDependencyList(ctx, source.env["GOTMPDIR"],
		original.SourceModule, original.SourceVersion, arguments, func(directory string, arguments []string) ([]byte, []byte, error) {
			observed, err := goasmcmd.Observe(ctx, directory, env, source.request.GoBinary, arguments...)
			return observed.Stdout, observed.Stderr, err
		})
}

func (source *GoAMD64FrameSource) observeDownloadedModule(ctx context.Context, origins *gooriginalsrc.OriginSet,
	exact goAMD64DownloadedIdentity, temporary string,
) (_ gooriginalsrc.Module, result error) {
	if module.Check(exact.module, exact.version) != nil || module.CanonicalVersion(exact.version) != exact.version {
		return gooriginalsrc.Module{}, goAMD64FrameContext("downloaded dependency requires a canonical exact source identity")
	}
	boundary, err := gooriginalsrc.NewDownloadBoundary(temporary, "plan9asm-frame-download-", "example.invalid/plan9asm-frame-download")
	if err != nil {
		return gooriginalsrc.Module{}, err
	}
	defer func() {
		result = errors.Join(result, boundary.Close())
	}()
	// This private command boundary is not a copied main/source module. Its
	// sole purpose is to prevent stock Go mutating an ancestor go.mod/go.sum.
	if err := boundary.Prepare(); err != nil {
		return gooriginalsrc.Module{}, err
	}
	commandContext, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	data, err := goasmcmd.Run(commandContext, boundary.Directory(), source.request.Environment,
		source.request.GoBinary, "mod", "download", "-json", exact.module+"@"+exact.version)
	err = errors.Join(err, commandContext.Err())
	if err != nil {
		return gooriginalsrc.Module{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	var receipt gooriginalsrc.DownloadReceipt
	if err := decoder.Decode(&receipt); err != nil {
		return gooriginalsrc.Module{}, err
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return gooriginalsrc.Module{}, goAMD64FrameContext("actual exact download receipt has incomplete or additional JSON")
	}
	var proxyMetadata *golegacymod.ProxyGoModProof
	if _, err := os.Lstat(filepath.Join(receipt.Dir, "go.mod")); os.IsNotExist(err) {
		// Source capture pins GOPROXY=off, but authenticated public checksum
		// metadata remains independently readable. This neither creates a ZIP
		// member nor turns a legacy dependency into an original main module.
		proxyMetadata, _, err = golegacymod.CaptureCachedProxyGoMod(commandContext,
			source.env["GOMODCACHE"], "off", exact.module, exact.version,
			receipt.Sum, receipt.GoModSum, receipt.GoMod, nil)
		if err != nil {
			return gooriginalsrc.Module{}, err
		}
	}
	original, err := origins.ObserveLegacy(ctx, exact.module, exact.version, receipt, proxyMetadata)
	if err != nil {
		return gooriginalsrc.Module{}, errors.Join(goAMD64FrameContext("exact original archive/source is not closed"), err)
	}
	return original, nil
}

func (source *GoAMD64FrameSource) verifyDownloadedOrigin() error {
	if source.downloadedOrigin == nil && source.downloadedModule == nil {
		return nil
	}
	if source.downloadedOrigin == nil || source.downloadedModule == nil {
		return goAMD64FrameContext("missing exact original download/source role")
	}
	if _, err := goAMD64DownloadedPackagePath(*source.downloadedModule, source.request.Directory); err != nil {
		return err
	}
	if err := source.downloadedOrigin.Verify(); err != nil {
		return errors.Join(goAMD64FrameContext("exact original source was changed or revoked"), err)
	}
	return nil
}

// The original archive namespace and the declared Go package namespace are
// distinct. Derive the latter only from the guarded module's own go.mod and
// the actual canonical package directory, never from an import-path prefix.
func goAMD64DownloadedPackagePath(original gooriginalsrc.Module, directory string) (string, error) {
	relative, err := filepath.Rel(original.Root, directory)
	if err != nil || !filepath.IsAbs(original.Root) || !filepath.IsAbs(directory) || !filepath.IsLocal(relative) {
		return "", goAMD64FrameContext("downloaded package must remain inside its actual exact primary cache root")
	}
	path := original.ModulePath
	if relative != "." {
		path += "/" + filepath.ToSlash(relative)
	}
	if module.CheckImportPath(path) != nil {
		return "", goAMD64FrameContext("downloaded package has an invalid original module-relative identity")
	}
	return path, nil
}
