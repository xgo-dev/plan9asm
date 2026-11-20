//go:build go1.27

package gostaticstorage

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestASMGeneratedAuditedPatchSources(t *testing.T) {
	for _, profile := range []struct {
		name  string
		count int
		roles map[string]string
		check func(string, func(string) ([]byte, error)) error
	}{
		{"funcdata", 7, generatedFuncdataSourceRoles, GeneratedFuncdataSources},
		{"float pool", 6, generatedFloatPoolSourceRoles, GeneratedFloatPoolSources},
	} {
		t.Run(profile.name, func(t *testing.T) {
			if len(profile.roles) != profile.count {
				t.Fatal("audited generated-metadata producer inventory changed", len(profile.roles))
			}
			sources := make(map[string][]byte, len(profile.roles))
			for name := range profile.roles {
				data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), filepath.FromSlash(name)))
				if err != nil {
					t.Fatal(err)
				}
				sources[name] = data
			}
			for _, version := range []string{"go1.27.2", "go1.27.3"} {
				t.Run(version, func(t *testing.T) {
					seen := make(map[string]bool)
					err := profile.check(version, func(name string) ([]byte, error) {
						seen[name] = true
						return sources[name], nil
					})
					if err != nil || len(seen) != len(profile.roles) {
						t.Fatal("audited exact patch did not check every original producer file", err, len(seen))
					}
				})
			}
			for _, version := range []string{"go1.27.2", "go1.27.3"} {
				for name := range profile.roles {
					t.Run(version+"/changed/"+name, func(t *testing.T) {
						seen := false
						if err := profile.check(version, func(role string) ([]byte, error) {
							if role == name {
								seen = true
								return append(append([]byte(nil), sources[role]...), '\n'), nil
							}
							return sources[role], nil
						}); !seen || !errors.Is(err, ErrContext) {
							t.Fatal("changed exact producer source was not independently rejected", seen, err)
						}
					})
				}
				if err := profile.check(version, func(string) ([]byte, error) { return nil, os.ErrNotExist }); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("guarded reader failure was hidden", version, err)
				}
			}
			for _, version := range []string{"go1.27.4", "go1.27", "go1.27.3-custom", "devel go1.27.3"} {
				t.Run("unregistered/"+version, func(t *testing.T) {
					if err := profile.check(version, func(string) ([]byte, error) {
						t.Fatal("unregistered patch consulted producer bytes")
						return nil, nil
					}); !errors.Is(err, ErrContext) {
						t.Fatal("unaudited patch acquired generated metadata roles", err)
					}
				})
			}
		})
	}
}
