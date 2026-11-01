package gotoolprofile

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/sourcepath"
)

var discoveryFeatureSubtools = []string{"asm", "compile", "link", "nm", "vet"}

type discoveryFeatureToolState struct {
	directory  string
	digests    map[string]string
	origins    map[string]string
	routing    string
	dispatcher string
}

// Resolve this exact driver's executable, not a guessed GOTOOLDIR path.
// Recent official distributions build builtin nm into the caller-owned
// GOCACHE. -n may build that official tool but does not execute it.
func captureDiscoveryFeatureSubtools(ctx context.Context, binary string, env []string, actual map[string]string, run Runner) (*discoveryFeatureToolState, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, fmt.Errorf("actual Go subtool resolution requires a live context")
	}
	root, directory, cache := actual["GOROOT"], actual["GOTOOLDIR"], actual["GOCACHE"]
	if !filepath.IsAbs(root) || !filepath.IsAbs(directory) || !filepath.IsAbs(cache) {
		return nil, fmt.Errorf("actual Go subtool root/directory/cache must be absolute")
	}
	resolvedRoot, err := sourcepath.Resolve(root)
	if err != nil {
		return nil, fmt.Errorf("resolve actual Go GOROOT: %w", err)
	}
	resolvedDirectory, err := sourcepath.Resolve(directory)
	if err != nil {
		return nil, fmt.Errorf("resolve actual Go GOTOOLDIR: %w", err)
	}
	resolvedCache, err := sourcepath.Resolve(cache)
	if err != nil {
		return nil, fmt.Errorf("resolve actual Go GOCACHE: %w", err)
	}
	relative, err := filepath.Rel(resolvedRoot, resolvedDirectory)
	if err != nil || !validDiscoveryFeatureToolDirectory(filepath.ToSlash(relative)) {
		return nil, fmt.Errorf("actual Go subtools are outside the bound GOROOT tool directory")
	}
	state := &discoveryFeatureToolState{directory: filepath.ToSlash(relative), digests: make(map[string]string), origins: make(map[string]string)}
	dispatcherFile := filepath.Join(resolvedRoot, "src", "cmd", "go", "internal", "tool", "tool.go")
	state.dispatcher, err = discoveryFeatureFileSHA256(dispatcherFile)
	if err != nil {
		return nil, fmt.Errorf("actual Go tool dispatcher: %w", err)
	}
	routes := map[string]string{"GOCACHE": resolvedCache}
	env = replaceEnv(env, actual)
	env = replaceEnv(env, map[string]string{"GOTOOLCHAIN": "local", "GOWORK": "off", "GOFLAGS": ""})
	for _, name := range discoveryFeatureSubtools {
		output, _, err := run(ctx, "", env, binary, "tool", "-n", name)
		if err != nil {
			return nil, fmt.Errorf("resolve actual Go %s route: %w", name, err)
		}
		file := strings.TrimSpace(string(output))
		if !filepath.IsAbs(file) || strings.ContainsAny(file, "\r\n") {
			return nil, fmt.Errorf("actual Go %s route is not one absolute executable", name)
		}
		resolved, err := sourcepath.Resolve(file)
		if err != nil {
			return nil, fmt.Errorf("actual Go %s executable: %w", name, err)
		}
		suffix := ""
		if strings.HasPrefix(filepath.Base(resolvedDirectory), "windows_") {
			suffix = ".exe"
		}
		if resolved == filepath.Join(resolvedDirectory, name+suffix) {
			state.origins[name] = "goroot/" + state.directory + "/" + name + suffix
		} else {
			minor, err := goMinor(actual["GOVERSION"])
			cacheRelative, relErr := filepath.Rel(resolvedCache, resolved)
			if err != nil || minor < 25 || (name != "nm" && name != "vet") || relErr != nil || !filepath.IsLocal(cacheRelative) || filepath.Base(resolved) != name+suffix {
				return nil, fmt.Errorf("unrecognized actual Go %s executable route", name)
			}
			state.origins[name] = "gocache/builtin/cmd/" + name
		}
		digest, err := discoveryFeatureFileSHA256(resolved)
		if err != nil {
			return nil, fmt.Errorf("actual Go %s tool: %w", name, err)
		}
		state.digests[name], routes[name] = digest, resolved
	}
	encoded, err := json.Marshal(routes)
	if err != nil {
		return nil, err
	}
	// Bind machine-local routing/cache identity without exporting paths.
	state.routing = discoveryFeatureBytesSHA256(encoded)
	afterDispatcher, err := discoveryFeatureFileSHA256(dispatcherFile)
	if err != nil || afterDispatcher != state.dispatcher {
		return nil, fmt.Errorf("actual Go tool dispatcher changed during resolution")
	}
	return state, nil
}

func validDiscoveryFeatureToolDirectory(directory string) bool {
	parts := strings.Split(directory, "/")
	return len(parts) == 3 && parts[0] == "pkg" && parts[1] == "tool" &&
		parts[2] != "" && parts[2] != "." && parts[2] != ".." && !strings.ContainsAny(parts[2], "\\:") &&
		strings.Count(parts[2], "_") == 1
}

func equalDiscoveryFeatureToolStates(a, b *discoveryFeatureToolState) bool {
	return a != nil && b != nil && a.directory == b.directory && a.routing == b.routing && a.dispatcher == b.dispatcher &&
		reflect.DeepEqual(a.digests, b.digests) && reflect.DeepEqual(a.origins, b.origins)
}
