package gooriginalsrc

import (
	"context"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestOriginalDependencyListSeparatesPreparationAndEvidence(t *testing.T) {
	for _, variant := range []string{"complete", "prepare error", "unknown diagnostic", "final diagnostic", "final error", "changed sum", "changed pin"} {
		t.Run(variant, func(t *testing.T) {
			calls := 0
			failure := errors.New("actual command failed")
			args := []string{"list", "-deps", "-export", "-json", "-mod=readonly", "example.invalid/legacy"}
			original := append([]string(nil), args...)
			output, err := RunDependencyList(context.Background(), t.TempDir(), "example.invalid/legacy", "v1.2.3", args,
				func(directory string, command []string) ([]byte, []byte, error) {
					calls++
					actual := strings.Join(command, " ")
					if calls == 1 {
						if !strings.Contains(actual, "-mod=mod") || strings.Contains(actual, "-export") {
							t.Fatal("preparation compiled an export or lost its private metadata role")
						}
						if variant == "prepare error" {
							return nil, nil, failure
						}
						if variant == "unknown diagnostic" {
							return nil, []byte("go: unknown tool failure\n"), nil
						}
						if variant == "changed pin" {
							file := filepath.Join(directory, "go.mod")
							data, err := os.ReadFile(file)
							if err != nil {
								t.Fatal(err)
							}
							return nil, nil, os.WriteFile(file, []byte(strings.ReplaceAll(string(data), "v1.2.3", "v1.2.4")), 0600)
						}
						if err := os.WriteFile(filepath.Join(directory, "go.sum"), []byte("prepared checksums\n"), 0600); err != nil {
							t.Fatal(err)
						}
						return []byte("not evidence"), []byte("go: finding module for package example.invalid/dep\ngo: found example.invalid/dep in example.invalid/dep v1.0.0\n"), nil
					}
					if calls != 2 || !strings.Contains(actual, "-mod=readonly") || !strings.Contains(actual, "-export") {
						t.Fatal("actual query lost its complete read-only export command")
					}
					switch variant {
					case "final diagnostic":
						return nil, []byte("go: downloading example.invalid/dep v1.0.0\n"), nil
					case "final error":
						return nil, nil, failure
					case "changed sum":
						return nil, nil, os.WriteFile(filepath.Join(directory, "go.sum"), []byte("changed\n"), 0600)
					}
					return []byte("actual read-only output"), nil, nil
				})
			if !reflect.DeepEqual(args, original) {
				t.Fatal("query mutated caller command arguments")
			}
			if variant == "complete" {
				if err != nil || calls != 2 || string(output) != "actual read-only output" {
					t.Fatal("read-only query did not close independently", err)
				}
			} else if err == nil {
				t.Fatal("failed or changed query became evidence")
			}
			if (variant == "prepare error" || variant == "final error") && !errors.Is(err, failure) {
				t.Fatal("actual command failure was hidden", err)
			}
			if (variant == "prepare error" || variant == "unknown diagnostic" || variant == "changed pin") && calls != 1 {
				t.Fatal("unclosed preparation reached the export command")
			}
		})
	}
}

func TestOriginalDependencyProgressIsNotArbitraryDiagnostics(t *testing.T) {
	for _, diagnostic := range []string{
		"warning: uncertain result\n", "go: downloading example.invalid/lib nope\n",
		"go: found ./local in example.invalid/lib v1.0.0\n", "go: finding module for package ../local\n",
		"go: downloading example.invalid/lib v1.0.0\nunknown failure\n", "\n",
	} {
		if dependencyPreparationDiagnostics([]byte(diagnostic)) == nil {
			t.Fatal("unregistered diagnostic was hidden", diagnostic)
		}
	}
}

func TestOriginalDependencyEnvironmentHasNoNetworkFallback(t *testing.T) {
	cache := filepath.Join(t.TempDir(), "cache, direct|fallback")
	env := []string{"GOMODCACHE=" + cache, "GOPROXY=https://example.invalid,direct", "GONOPROXY=*", "GOTOOLCHAIN=local", "GOSUMDB=sum.golang.org"}
	original := append([]string(nil), env...)
	actual, err := DependencyQueryEnvironment(env)
	if err != nil || !reflect.DeepEqual(env, original) {
		t.Fatal("query altered its caller environment", err)
	}
	proxies := 0
	for _, item := range actual {
		if strings.HasPrefix(item, "GOPROXY=") {
			proxies++
			if !strings.HasPrefix(item, "GOPROXY=file:///") || strings.ContainsAny(item, ",|") {
				t.Fatal("query acquired a network/direct fallback", item)
			}
			location, err := url.Parse(strings.TrimPrefix(item, "GOPROXY="))
			wanted := filepath.ToSlash(filepath.Join(cache, "cache", "download"))
			if !strings.HasPrefix(wanted, "/") {
				wanted = "/" + wanted
			}
			if err != nil || location.Path != wanted {
				t.Fatal("cache proxy no longer names the observed directory", item, err)
			}
		}
		if strings.HasPrefix(item, "GONOPROXY=") && item != "GONOPROXY=none" {
			t.Fatal("private pattern bypassed the cache-only proxy")
		}
	}
	if proxies != 1 {
		t.Fatal("ambiguous cache-only proxy environment")
	}
}

func TestOriginalDependencyListRejectsUnboundQueryRoles(t *testing.T) {
	for _, arguments := range [][]string{
		{"list", "-e", "-json", "-mod=readonly", "example.invalid/legacy"},
		{"list", "-test", "-json", "-mod=readonly", "example.invalid/legacy"},
		{"list", "-json", "-mod=vendor", "example.invalid/legacy"},
		{"list", "-json", "-json", "-mod=readonly", "example.invalid/legacy"},
		{"list", "-json", "-mod=readonly", "example.invalid/other"},
		{"list", "-json", "-mod=readonly", "example.invalid/legacy/..."},
	} {
		called := false
		_, err := RunDependencyList(context.Background(), t.TempDir(), "example.invalid/legacy", "v1.2.3", arguments,
			func(string, []string) ([]byte, []byte, error) {
				called = true
				return nil, nil, nil
			})
		if err == nil || called {
			t.Fatal("unbound role reached an actual query", arguments, err)
		}
	}
}
