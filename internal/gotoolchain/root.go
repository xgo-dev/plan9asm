package gotoolchain

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
)

var fallback struct {
	once sync.Once
	root string
	err  error
}

// Root returns the toolchain root that owns this binary's standard headers.
// Trimpath builds omit the embedded GOROOT, so ask the matching go command.
func Root() (string, error) {
	if root := runtime.GOROOT(); root != "" {
		return root, nil
	}
	fallback.once.Do(func() {
		out, err := exec.Command("go", "env", "-json", "GOROOT", "GOVERSION").Output()
		if err != nil {
			fallback.err = fmt.Errorf("resolve GOROOT for trimpath binary: %w", err)
			return
		}
		fallback.root, fallback.err = parseRoot(out, runtime.Version())
	})
	return fallback.root, fallback.err
}

func parseRoot(output []byte, binaryVersion string) (string, error) {
	var env struct {
		GOROOT    string `json:"GOROOT"`
		GOVERSION string `json:"GOVERSION"`
	}
	if err := json.Unmarshal(output, &env); err != nil {
		return "", fmt.Errorf("decode Go toolchain environment: %w", err)
	}
	if env.GOVERSION != binaryVersion {
		return "", fmt.Errorf("Go toolchain version %q does not match binary version %q", env.GOVERSION, binaryVersion)
	}
	if !filepath.IsAbs(env.GOROOT) {
		return "", fmt.Errorf("Go toolchain GOROOT %q is not absolute", env.GOROOT)
	}
	return env.GOROOT, nil
}
