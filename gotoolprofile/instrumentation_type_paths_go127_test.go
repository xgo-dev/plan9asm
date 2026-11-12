//go:build go1.27

package gotoolprofile

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm/internal/sourcepath"
)

func TestInstrumentationTypeSourceCaptureActualLogicalRoot(t *testing.T) {
	t.Setenv("GOFLAGS", "-tags=plan9asm_fixture_ambient")
	binary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	marker, err := CaptureInstrumentationExportObservation(ctx, binary, instrumentationMarkerDirectory(t), os.Environ(), "darwin/arm64", InstrumentationRace, "0", nil, RunBounded)
	if err != nil {
		t.Fatal(err)
	}
	original := instrumentationOriginalFixture(t, marker.Early)
	physical, err := sourcepath.Resolve(original.SourceRoot)
	if err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "module")
	if err := os.Symlink(physical, alias); err != nil {
		t.Fatal(err)
	}
	original.SourceRoot = alias
	inventory, err := CaptureInstrumentationOriginalSourceInventory(original, ".")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := PlanInstrumentationOriginalPackage(original, inventory, marker.Early, ".", nil)
	if err != nil {
		t.Fatal(err)
	}
	input, err := NewInstrumentationConsumerInput(original, inventory, marker, plan)
	if err != nil {
		t.Fatal(err)
	}
	observed := 0
	run := func(ctx context.Context, directory string, env []string, command string, args ...string) ([]byte, []byte, error) {
		// SDK tool-route queries deliberately have no source working directory.
		if directory != "" && directory != physical {
			return nil, nil, fmt.Errorf("type capture must use one physical invocation directory, got %q", directory)
		}
		stdout, stderr, err := RunBounded(ctx, directory, env, command, args...)
		if err != nil || len(args) == 0 || args[0] != "list" {
			return stdout, stderr, err
		}
		decoder := json.NewDecoder(bytes.NewReader(stdout))
		for {
			var pkg instrumentationTypeListPackage
			if err := decoder.Decode(&pkg); err == io.EOF {
				break
			} else if err != nil {
				return nil, nil, err
			}
			if pkg.ImportPath == plan.PackagePath {
				if pkg.Dir != physical || pkg.Dir == original.SourceRoot {
					return nil, nil, fmt.Errorf("actual stock Go did not expose the distinct physical root: %q", pkg.Dir)
				}
				observed++
				data, err := json.Marshal(pkg)
				if err != nil {
					return nil, nil, err
				}
				t.Logf("unaltered stock Go root JSON export=%t: %s", containsString(args, "-export"), data)
			}
		}
		return stdout, stderr, nil
	}
	env := instrumentationFixtureEnvironment(os.Environ(), marker.Early)
	proof, err := CaptureInstrumentationTypeSources(ctx, binary, alias, env, input, run)
	if err != nil {
		t.Fatal(err)
	}
	if observed != 2 {
		t.Fatalf("did not retain both actual pre/post selection commands: %d", observed)
	}
	original.SourceRoot = physical
	canonical, err := CaptureInstrumentationTypeSources(ctx, binary, physical, env, input, RunBounded)
	if err != nil || !reflect.DeepEqual(proof, canonical) {
		t.Fatalf("same physical source acquired a different portable type identity: %v", err)
	}
	foreign := instrumentationOriginalFixture(t, marker.Early)
	original.SourceRoot = foreign.SourceRoot
	if _, err := CaptureInstrumentationTypeSources(ctx, binary, physical, env, input, RunBounded); err == nil || !strings.Contains(err.Error(), "actual imported module root differs from the authenticated original source") {
		t.Fatalf("equal-byte foreign source root did not retain the exact physical origin rejection: %v", err)
	}
	original.SourceRoot = physical
	t.Log("actual pre/post stock-Go JSON and same-root alias binding; equal-byte other root rejected, no LLVM or runtime claim")
}
