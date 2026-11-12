package sdkfrontend

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
	"github.com/xgo-dev/plan9asm/internal/sourcepath"
)

type Loader func(context.Context, string, []string) (*Package, error)

// Reload invokes the frontend's real loader under owned command roots, then
// compares its complete source/import graph, sizes and selected source bytes.
// The resulting types must come from this new load, never an environment label
// attached to the original load. Compiler defaults are observed, not replaced.
func Reload(ctx context.Context, binary string, pkg *Package, selected *Selection, load Loader) (_ *Package, _ *Selection, _ func() error, result error) {
	if ctx != nil && ctx.Err() != nil {
		return nil, nil, nil, ctx.Err()
	}
	if ctx == nil || selected == nil || load == nil {
		return nil, nil, nil, contextError("reload requires its live context and actual-load selection")
	}
	if _, bounded := ctx.Deadline(); !bounded {
		return nil, nil, nil, contextError("reload requires a bounded context")
	}
	if err := Check(pkg, selected, selected.target); err != nil {
		return nil, nil, nil, err
	}
	observed, stderr, err := gotoolprofile.RunBounded(ctx, pkg.Dir, selected.env, binary, "env", "-json",
		"GOOS", "GOARCH", "GOAMD64", "GO386", "GOFLAGS", "GOEXPERIMENT", "CGO_ENABLED", "GOROOT", "GOCACHE")
	if err != nil || len(stderr) != 0 {
		return nil, nil, nil, errors.Join(err, Stderr(stderr))
	}
	var actual map[string]string
	if err := json.Unmarshal(observed, &actual); err != nil {
		return nil, nil, nil, err
	}
	goos, arch, _ := strings.Cut(selected.target, "/")
	baseline := arch == "amd64" && actual["GOAMD64"] == "v1" || arch == "386" && actual["GO386"] == "sse2"
	if !gostaticstorage.X86SDKTarget(selected.target) || actual["GOOS"] != goos || actual["GOARCH"] != arch || !baseline || actual["GOFLAGS"] != "" ||
		actual["GOEXPERIMENT"] != "" || actual["CGO_ENABLED"] != "0" && actual["CGO_ENABLED"] != "1" {
		return nil, nil, nil, contextError("source requires the actual baseline x86 compiler profile")
	}
	if selected.mode != nil && *selected.mode != actual["GOFLAGS"] {
		return nil, nil, nil, contextError("effective source flags changed after selection")
	}
	// cmd/go leaves an unset, inactive architecture's CPU setting empty. Give
	// that unused mode its baseline spelling for the observer's complete x86
	// command profile; the active setting was independently checked above.
	if arch != "amd64" && actual["GOAMD64"] == "" {
		actual["GOAMD64"] = "v1"
	}
	if arch != "386" && actual["GO386"] == "" {
		actual["GO386"] = "sse2"
	}
	cache, err := sourcepath.Resolve(actual["GOCACHE"])
	if err != nil || !filepath.IsAbs(cache) {
		return nil, nil, nil, contextError("build cache is not an existing absolute directory")
	}
	root, err := sourcepath.Resolve(actual["GOROOT"])
	if err != nil {
		return nil, nil, nil, err
	}
	directory, err := sourcepath.Resolve(pkg.Dir)
	if err != nil || !filepath.IsLocal(filepath.FromSlash(pkg.Path)) || directory != filepath.Join(root, "src", filepath.FromSlash(pkg.Path)) {
		return nil, nil, nil, contextError(fmt.Sprintf("selected package is not inside the invoked SDK: %v", err))
	}
	before, err := Graph(pkg)
	if err != nil {
		return nil, nil, nil, err
	}
	inputs, err := GraphHashes(pkg)
	if err != nil {
		return nil, nil, nil, err
	}
	values, err := EnvironmentValues(selected.env)
	if err != nil {
		return nil, nil, nil, err
	}
	// Honor the actual invocation's temporary root rather than ambient state.
	workspace, close, err := newReloadWorkspace(values["TMPDIR"])
	if err != nil {
		return nil, nil, nil, err
	}
	defer func() {
		if result != nil {
			result = errors.Join(result, close())
		}
	}()
	workspace, err = sourcepath.Resolve(workspace)
	if err != nil {
		return nil, nil, nil, err
	}
	for key, value := range map[string]string{
		"GOENV": "off", "GOWORK": "off", "GOTOOLCHAIN": "local", "GOPROXY": "off",
		"GOFLAGS": actual["GOFLAGS"], "GOEXPERIMENT": actual["GOEXPERIMENT"],
		"CGO_ENABLED": actual["CGO_ENABLED"], "GOPACKAGESDRIVER": "off",
		"GOOS": actual["GOOS"], "GOARCH": actual["GOARCH"],
		"GOAMD64": actual["GOAMD64"], "GO386": actual["GO386"], "GOROOT": root, "GOCACHE": cache,
	} {
		values[key] = value
	}
	for _, key := range []string{"GOPATH", "GOMODCACHE", "TMPDIR", "GOTMPDIR"} {
		path := filepath.Join(workspace, strings.ToLower(key))
		if err := os.Mkdir(path, 0700); err != nil {
			return nil, nil, nil, err
		}
		values[key] = path
	}
	environment := EncodeEnvironment(values)
	reloaded, err := load(ctx, directory, environment)
	if err != nil {
		return nil, nil, nil, err
	}
	if reloaded == nil || reloaded.Module || reloaded.IllTyped || len(reloaded.Errors) != 0 ||
		reloaded.Path != pkg.Path || reloaded.Types == nil || reloaded.Test || reloaded.Types == pkg.Types {
		return nil, nil, nil, contextError("actual reload is not the same ordinary SDK package with distinct types")
	}
	after, err := Graph(reloaded)
	if err != nil || !reflect.DeepEqual(before, after) || !reflect.DeepEqual(Sizes(pkg.Sizes), Sizes(reloaded.Sizes)) {
		return nil, nil, nil, contextError(fmt.Sprintf("source/import graph differs after actual reload: %v", err))
	}
	afterInputs, err := GraphHashes(reloaded)
	if err != nil || !reflect.DeepEqual(inputs, afterInputs) {
		return nil, nil, nil, contextError(fmt.Sprintf("source bytes changed during actual reload: %v", err))
	}
	return reloaded, CaptureSelection(reloaded, selected.target, environment, nil), close, nil
}

func newReloadWorkspace(parent string) (string, func() error, error) {
	owned, err := os.MkdirTemp(parent, "plan9asm-sdk-numerical-load-")
	if err != nil {
		return "", nil, err
	}
	// Capture the actual directory ID before any consumer can replace it.
	// os.Lstat's Windows FileInfo defers that observation until SameFile.
	identity, err := sourcepath.Lstat(owned)
	if err != nil {
		return "", nil, err
	}
	close := func() error {
		now, err := sourcepath.Lstat(owned)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil || !now.IsDir() || !os.SameFile(identity, now) {
			return contextError("owned reload directory changed before cleanup")
		}
		return os.RemoveAll(owned)
	}
	return owned, close, nil
}

func EnvironmentValues(environment []string) (map[string]string, error) {
	values := make(map[string]string)
	for _, entry := range environment {
		key, value, valid := strings.Cut(entry, "=")
		if !valid || key == "" || strings.ContainsRune(entry, '\x00') {
			return nil, fmt.Errorf("malformed actual SDK loading environment")
		}
		values[key] = value
	}
	return values, nil
}

func EncodeEnvironment(values map[string]string) []string {
	result := make([]string, 0, len(values))
	for key, value := range values {
		result = append(result, key+"="+value)
	}
	sort.Strings(result)
	return result
}

func Stderr(stderr []byte) error {
	if len(stderr) == 0 {
		return nil
	}
	return fmt.Errorf("actual Go stderr: %s", strings.TrimSpace(string(stderr)))
}
