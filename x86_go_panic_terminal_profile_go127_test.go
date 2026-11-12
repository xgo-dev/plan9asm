//go:build go1.27

package plan9asm

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestX86GoPanicTerminalAuditedPatchSources(t *testing.T) {
	roles := x86GoPanicTerminalCompilerSourceRoles()
	if len(roles) != 14 {
		t.Fatal("panic compiler/linker source inventory changed", len(roles))
	}
	sources := make(map[string][]byte, len(roles))
	for name := range roles {
		data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), filepath.FromSlash(name)))
		if err != nil {
			t.Fatal(err)
		}
		sources[name] = data
	}
	environment := func(version string) map[string]string {
		return map[string]string{"GOVERSION": version, "GOOS": "linux", "GOARCH": "386", "GO386": "sse2"}
	}
	for _, version := range []string{"go1.27.2", "go1.27.3"} {
		t.Run(version, func(t *testing.T) {
			seen := make(map[string]bool)
			err := x86GoPanicTerminalCompilerSources(environment(version), func(name string) ([]byte, error) {
				seen[name] = true
				return sources[name], nil
			})
			if err != nil || len(seen) != len(roles) {
				t.Fatal("audited exact patch did not check every original producer file", err, len(seen))
			}
		})
	}
	for _, version := range []string{"go1.27.2", "go1.27.3"} {
		for name := range roles {
			t.Run(version+"/changed/"+name, func(t *testing.T) {
				seen := false
				err := x86GoPanicTerminalCompilerSources(environment(version), func(role string) ([]byte, error) {
					if role == name {
						seen = true
						return append(append([]byte(nil), sources[role]...), '\n'), nil
					}
					return sources[role], nil
				})
				if !seen || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("changed exact producer bytes were not independently rejected", seen, err)
				}
			})
		}
		if err := x86GoPanicTerminalCompilerSources(environment(version), func(string) ([]byte, error) {
			return nil, os.ErrNotExist
		}); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("guarded reader failure was hidden", version, err)
		}
	}
	for _, version := range []string{"go1.27.4", "go1.27", "go1.27.3-custom", "devel go1.27.3"} {
		t.Run("unregistered/"+version, func(t *testing.T) {
			err := x86GoPanicTerminalCompilerSources(environment(version), func(string) ([]byte, error) {
				t.Fatal("unregistered patch consulted producer bytes")
				return nil, nil
			})
			if !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("unaudited patch acquired compiler roles", err)
			}
		})
	}
}
