package sdkfrontend

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
	"github.com/xgo-dev/plan9asm/internal/sourcepath"
)

// FeatureEnvironment prepares a compiler consumer's command directories while
// retaining the already observed Go tool invocation.
func FeatureEnvironment(goos, goarch string, input []string) ([]string, error) {
	return commandEnvironment(goos, goarch, input, true)
}

// Resolve the ordinary load environment before packages.Load. Its later source
// observers receive this exact environment, never defaults reconstructed from
// the process after selection. Explicit nonordinary settings remain visible
// and cannot acquire an ordinary source proof.
func OrdinaryEnvironment(goos, goarch string, input []string) ([]string, error) {
	return commandEnvironment(goos, goarch, input, false)
}

func commandEnvironment(goos, goarch string, input []string, retainGOROOT bool) ([]string, error) {
	values := make(map[string]string)
	for _, item := range input {
		key, value, ok := strings.Cut(item, "=")
		if !ok || key == "" || strings.ContainsRune(item, '\x00') {
			return nil, fmt.Errorf("malformed package-load environment")
		}
		values[key] = value
	}
	values["GOOS"], values["GOARCH"] = goos, goarch
	if values["GOTOOLCHAIN"] == "" {
		values["GOTOOLCHAIN"] = "local"
	}
	if values["GOPACKAGESDRIVER"] == "" {
		// Match packages.Load's automatic discovery, including its use of
		// the process PATH. A discovered driver is not an ordinary Go load.
		driver, err := exec.LookPath("gopackagesdriver")
		if err != nil {
			driver = "off"
		}
		values["GOPACKAGESDRIVER"] = driver
	}
	encode := func() []string {
		result := make([]string, 0, len(values))
		for key, value := range values {
			result = append(result, key+"="+value)
		}
		sort.Strings(result)
		return result
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	stdout, stderr, err := gotoolprofile.RunBounded(ctx, "", encode(), "go",
		"env", "-json", "GOROOT", "GOCACHE", "GOMODCACHE", "GOPATH", "CGO_ENABLED", "GOENV", "GOWORK", "GOFLAGS")
	if err != nil || len(stderr) != 0 {
		return nil, fmt.Errorf("resolve package-load cache environment: %v (stderr: %s)", err, stderr)
	}
	var actual map[string]string
	if err := json.Unmarshal(stdout, &actual); err != nil {
		return nil, fmt.Errorf("decode package-load cache environment: %w", err)
	}
	// Stock Go selects its cgo default for the requested target. Forcing zero
	// here would silently drop selected assembly (including runtime/cgo).
	// Pure-Go source proofs still require an explicitly compatible profile.
	if actual["CGO_ENABLED"] != "0" && actual["CGO_ENABLED"] != "1" {
		return nil, fmt.Errorf("invalid effective package-load CGO_ENABLED")
	}
	values["CGO_ENABLED"] = actual["CGO_ENABLED"]
	values["GOFLAGS"] = actual["GOFLAGS"]
	goenv, err := GoEnvFile(values["GOENV"], actual["GOENV"])
	if err != nil {
		return nil, fmt.Errorf("resolve package-load GOENV: %w", err)
	}
	actual["GOENV"] = goenv
	for _, key := range []string{"GOENV", "GOWORK"} {
		values[key] = actual[key]
		if values[key] == "" {
			values[key] = "off"
		}
	}
	for _, key := range []string{"GOROOT", "GOCACHE", "GOMODCACHE", "GOPATH"} {
		paths := []string{actual[key]}
		if key == "GOPATH" {
			paths = filepath.SplitList(actual[key])
		}
		if len(paths) == 0 {
			return nil, fmt.Errorf("package-load %s has no actual path", key)
		}
		for index, path := range paths {
			if !filepath.IsAbs(path) {
				return nil, fmt.Errorf("package-load %s must resolve to absolute paths", key)
			}
			// A local module may never download a dependency, so cmd/go need
			// not create GOPATH/GOMODCACHE. Prepare each actual selected path
			// before the load captures it, never repair a later source proof.
			if key != "GOROOT" {
				if err := os.MkdirAll(path, 0755); err != nil {
					return nil, fmt.Errorf("prepare package-load %s: %w", key, err)
				}
			}
			// Fix the actual filesystem target before packages.Load. Alias,
			// case and separator spellings are not canonical source identity,
			// even when cmd/go preserves them in its original go env output.
			paths[index], err = sourcepath.Resolve(path)
			if err != nil {
				return nil, fmt.Errorf("resolve package-load %s: %w", key, err)
			}
			info, err := sourcepath.Lstat(paths[index])
			if err != nil {
				return nil, fmt.Errorf("inspect package-load %s: %w", key, err)
			}
			if !info.IsDir() {
				return nil, fmt.Errorf("package-load %s is not its actual directory", key)
			}
		}
		if key == "GOROOT" && retainGOROOT {
			// The physical directory was validated above. Changing this
			// command spelling can rebuild builtin Go tools with different
			// bytes/routes, invalidating an already captured feature profile.
			values[key] = actual[key]
		} else {
			values[key] = strings.Join(paths, string(filepath.ListSeparator))
		}
	}
	for _, key := range []string{"TMPDIR", "GOTMPDIR"} {
		if values[key] == "" {
			values[key] = values["TMPDIR"]
			if values[key] == "" {
				values[key] = os.TempDir()
			}
		}
		path, err := filepath.Abs(values[key])
		if err != nil {
			return nil, err
		}
		values[key], err = sourcepath.Resolve(path)
		if err != nil {
			return nil, fmt.Errorf("resolve package-load %s: %w", key, err)
		}
		info, err := sourcepath.Lstat(values[key])
		if err != nil {
			return nil, fmt.Errorf("inspect package-load %s: %w", key, err)
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("package-load %s is not its actual directory", key)
		}
	}
	return encode(), nil
}

func GoEnvFile(requested, actual string) (string, error) {
	if actual == "" || actual == "off" {
		return actual, nil
	}
	// Resolve the absence before packages.Load. An implicit missing config
	// carries Go's defaults; explicitly fixing that choice prevents a later
	// file from changing the compiler invocation observed by source guards.
	// User-selected paths and existing settings keep their original role.
	_, err := os.Lstat(actual)
	if os.IsNotExist(err) {
		if requested != "" {
			return actual, nil // Keep an explicitly selected missing config visible.
		}
		return "off", nil
	}
	if err != nil {
		return "", err
	}
	// Preserve the chosen file and its settings, but hand its opened physical
	// spelling to the actual load. SDK observers still require that exact file
	// and recheck its eager identity/bytes; this is never a config substitution.
	return sourcepath.Resolve(actual)
}
