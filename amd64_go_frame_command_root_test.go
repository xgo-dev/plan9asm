package plan9asm

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmcmd"
	"github.com/xgo-dev/plan9asm/internal/sourcepath"
)

func TestGoAMD64FrameSourceRetainsCommandSDKIdentity(t *testing.T) {
	for _, mutation := range []string{"command-spelling", "physical-root"} {
		t.Run(mutation, func(t *testing.T) {
			pkg, request := goAMD64FrameSourceFixture(t)
			physical, err := sourcepath.Resolve(filepath.Dir(filepath.Dir(request.GoBinary)))
			if err != nil {
				t.Fatal(err)
			}
			alias := filepath.Join(t.TempDir(), "selected-sdk")
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			link := func(target string) {
				t.Helper()
				if runtime.GOOS == "windows" {
					output, err := goasmcmd.Run(ctx, "", nil, "cmd", "/c", "mklink", "/J", alias, target)
					if err != nil {
						t.Fatalf("create actual SDK junction: %v; %s", err, output)
					}
				} else if err := os.Symlink(target, alias); err != nil {
					t.Fatal(err)
				}
			}
			link(physical)
			request.Environment = append(request.Environment, "GOROOT="+alias)
			original, err := goasmcmd.Run(ctx, request.Directory, request.Environment, request.GoBinary, "env", "GOROOT")
			if err != nil || strings.TrimSpace(string(original)) != alias || alias == physical {
				t.Fatalf("actual driver did not retain a distinct SDK spelling: %q; %v", original, err)
			}
			source, err := CaptureGoAMD64FrameSource(ctx, pkg, request)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := source.Close(); err != nil {
					t.Error(err)
				}
			})
			if source.env["command/GOROOT"] != alias || source.env["GOROOT"] != physical {
				t.Fatalf("command spelling and physical SDK were conflated: %v", source.env)
			}
			if err := source.Verify(ctx); err != nil {
				t.Fatal(err)
			}
			switch mutation {
			case "command-spelling":
				// The same physical SDK under a new command spelling can change
				// compiled builtin tools; it must not reuse the observation.
				source.request.Environment = append(source.request.Environment, "GOROOT="+physical)
			case "physical-root":
				if err := os.Remove(alias); err != nil {
					t.Fatal(err)
				}
				link(t.TempDir())
			}
			if err := source.Verify(ctx); err == nil || source.ready {
				t.Fatalf("changed %s retained source observation: %v", mutation, err)
			} else if mutation == "command-spelling" && !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("changed command identity was not rejected as source context: %v", err)
			}
		})
	}
}
