package plan9asm

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmcmd"
	"github.com/xgo-dev/plan9asm/internal/sourcepath"
)

func goAMD64FrameDriverDirectoryAlias(t *testing.T, ctx context.Context, target string) string {
	t.Helper()
	alias := filepath.Join(t.TempDir(), "selected-sdk")
	goAMD64FrameDriverDirectoryLink(t, ctx, alias, target)
	return alias
}

func goAMD64FrameDriverDirectoryLink(t *testing.T, ctx context.Context, alias, target string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		output, err := goasmcmd.Run(ctx, "", nil, "cmd", "/c", "mklink", "/J", alias, target)
		if err != nil {
			t.Fatalf("create actual driver directory junction: %v\n%s", err, output)
		}
	} else if err := os.Symlink(target, alias); err != nil {
		t.Fatal(err)
	}
}

func TestGoAMD64FrameSourceDriverDirectoryIdentity(t *testing.T) {
	for _, name := range []string{"bin-directory", "SDK-and-command-root"} {
		t.Run(name, func(t *testing.T) {
			pkg, request := goAMD64FrameSourceFixture(t)
			physicalDriver := request.GoBinary
			physicalRoot := filepath.Dir(filepath.Dir(physicalDriver))
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			commandRoot := physicalRoot
			var alias string
			if name == "bin-directory" {
				alias = goAMD64FrameDriverDirectoryAlias(t, ctx, filepath.Dir(physicalDriver))
				request.GoBinary = filepath.Join(alias, filepath.Base(physicalDriver))
			} else {
				commandRoot = goAMD64FrameDriverDirectoryAlias(t, ctx, physicalRoot)
				request.GoBinary = filepath.Join(commandRoot, "bin", filepath.Base(physicalDriver))
			}
			var environment []string
			for _, entry := range request.Environment {
				if !strings.HasPrefix(entry, "GOROOT=") {
					environment = append(environment, entry)
				}
			}
			request.Environment = append(environment, "GOROOT="+commandRoot)
			info, err := sourcepath.Lstat(request.GoBinary)
			if err != nil || !info.Mode().IsRegular() {
				t.Fatalf("directory alias must retain a regular final driver: %v", err)
			}
			actual, err := sourcepath.Resolve(request.GoBinary)
			if err != nil || actual != physicalDriver || actual == request.GoBinary {
				t.Fatalf("driver alias did not resolve to the actual SDK binary: %q; %v", actual, err)
			}
			original := append(append([]string(nil), request.Environment...), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0", "GOTOOLCHAIN=local", "GOENV=off", "GOWORK=off", "GOPROXY=off")
			if output, err := goasmcmd.Run(ctx, request.Directory, original, request.GoBinary, "build", "."); err != nil {
				t.Fatalf("actual aliased driver cannot build original Go assembly: %v\n%s", err, output)
			}
			source, err := CaptureGoAMD64FrameSource(ctx, pkg, request)
			if err != nil {
				t.Fatal("actual regular driver through a directory alias must capture:", err)
			}
			t.Cleanup(func() {
				if err := source.Close(); err != nil {
					t.Error(err)
				}
			})
			if source.request.GoBinary != request.GoBinary || source.env["GOROOT"] != physicalRoot || source.env["command/GOROOT"] != commandRoot {
				t.Fatal("command driver/SDK spelling and physical SDK identities were conflated")
			}
			if _, retained := source.inputs[physicalDriver]; !retained {
				t.Fatal("capture did not retain the actual physical driver bytes")
			}
			if err := source.Verify(ctx); err != nil {
				t.Fatal(err)
			}
			if name == "bin-directory" {
				data, err := os.ReadFile(physicalDriver)
				if err != nil || sha256.Sum256(data) != source.inputs[physicalDriver] {
					t.Fatal("cannot retain actual same-bytes driver replacement:", err)
				}
				replacement := t.TempDir()
				if err := os.WriteFile(filepath.Join(replacement, filepath.Base(physicalDriver)), data, 0700); err != nil {
					t.Fatal(err)
				}
				data = nil
				if err := os.Remove(alias); err != nil {
					t.Fatal(err)
				}
				goAMD64FrameDriverDirectoryLink(t, ctx, alias, replacement)
				output, err := goasmcmd.Run(ctx, request.Directory, request.Environment, request.GoBinary, "version")
				if err != nil || !strings.Contains(string(output), source.env["GOVERSION"]) {
					t.Fatalf("retargeted same-bytes driver is not independently executable: %v\n%s", err, output)
				}
				if err := source.Verify(ctx); !errors.Is(err, ErrProbeNeedsContext) || source.ready {
					t.Fatal("same-bytes driver outside the actual SDK borrowed its live identity:", err)
				}
			}
		})
	}
}
