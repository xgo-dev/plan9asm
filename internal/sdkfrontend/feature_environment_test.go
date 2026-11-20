package sdkfrontend

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
	"github.com/xgo-dev/plan9asm/internal/sourcepath"
)

func TestFeatureEnvironmentRetainsActualGOROOTCommand(t *testing.T) {
	alias := filepath.Join(t.TempDir(), "selected-sdk")
	sdkEnvironmentAlias(t, alias, runtime.GOROOT())
	input := append(os.Environ(), "GOROOT="+alias, "GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local", "CGO_ENABLED=0", "GOFLAGS=")
	before := append([]string(nil), input...)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	query := func(environment []string) map[string]string {
		data, stderr, err := gotoolprofile.RunBounded(ctx, "", environment, "go",
			"env", "-json", "GOROOT", "CGO_ENABLED", "GOFLAGS")
		if err != nil || len(stderr) != 0 {
			t.Fatalf("actual Go environment: %v; %s", err, stderr)
		}
		var actual map[string]string
		if err := json.Unmarshal(data, &actual); err != nil {
			t.Fatal(err)
		}
		return actual
	}
	original := query(input)
	physical, err := sourcepath.Resolve(original["GOROOT"])
	if err != nil || physical == original["GOROOT"] {
		t.Fatalf("fixture did not retain a distinct actual SDK spelling: %q, %q, %v", original["GOROOT"], physical, err)
	}
	for _, row := range []struct {
		name  string
		apply func(string, string, []string) ([]string, error)
		want  string
	}{
		{"feature", FeatureEnvironment, original["GOROOT"]},
		{"ordinary", OrdinaryEnvironment, physical},
	} {
		t.Run(row.name, func(t *testing.T) {
			environment, err := row.apply("linux", "amd64", input)
			if err != nil {
				t.Fatal(err)
			}
			values, err := EnvironmentValues(environment)
			if err != nil || values["GOROOT"] != row.want {
				t.Errorf("selected command GOROOT: got %q, want %q (%v)", values["GOROOT"], row.want, err)
			}
			resolved, err := sourcepath.Resolve(values["GOROOT"])
			if err != nil || resolved != physical {
				t.Errorf("changed physical SDK: %q, want %q (%v)", resolved, physical, err)
			}
			observed := query(environment)
			if observed["GOROOT"] != row.want || observed["CGO_ENABLED"] != original["CGO_ENABLED"] || observed["GOFLAGS"] != original["GOFLAGS"] {
				t.Errorf("actual Go command selection changed: %v", observed)
			}
			if !reflect.DeepEqual(input, before) {
				t.Fatal("consumer changed its producer's environment")
			}
		})
	}
}
