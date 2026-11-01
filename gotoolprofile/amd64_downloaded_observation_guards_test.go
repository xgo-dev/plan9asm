package gotoolprofile

import (
	"context"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm"
)

func TestAMD64DownloadedObservationRejectsUnprovedInputs(t *testing.T) {
	for _, name := range []string{"latest", "different version", "different module", "owned copy", "changed source", "added ignored source", "changed ZIP", "changed metadata"} {
		t.Run(name, func(t *testing.T) {
			request, path, version := amd64DownloadedObservationFixture(t, "data")
			ctx, cancel := amd64OriginalObservationContext(t)
			defer cancel()
			prefix := filepath.Join(originalObservationEnvironment(request.Environment, "GOMODCACHE"), "cache", "download", path, "@v", version)
			switch name {
			case "latest":
				version = "latest"
			case "different version":
				version = "v1.0.1"
			case "different module":
				path = "example.invalid/unobserved"
			case "owned copy":
				request.Directory = amd64OriginalObservationFixture(t, "data").Directory
			case "changed source":
				mutateAMD64DownloadedFile(t, filepath.Join(request.Directory, "value.go"), "\nconst Changed = 1\n")
			case "added ignored source":
				if err := os.Chmod(request.Directory, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(request.Directory, "ignored_windows.go"), []byte("package observation\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "changed ZIP":
				mutateAMD64DownloadedFile(t, prefix+".zip", "different exact archive encoding")
				// HashZip alone intentionally ignores trailing ZIP encoding bytes.
				// Go's actual complete download format must still validate first.
				if err := os.WriteFile(prefix+".zip", []byte("not a ZIP"), 0600); err != nil {
					t.Fatal(err)
				}
			case "changed metadata":
				mutateAMD64DownloadedFile(t, prefix+".mod", "\nrequire example.invalid/unobserved v1.0.0\n")
			}
			if observed, err := captureAMD64DownloadedForTest(ctx, request, path, version); err == nil {
				observed.Close()
				t.Fatal("unobserved or different original source acquired a download observation")
			}
		})
	}
}

func TestAMD64DownloadedObservationRejectsDownloadJSONForgery(t *testing.T) {
	for _, field := range []string{"Path", "Version", "Dir", "Zip", "GoMod", "Sum", "GoModSum", "Error", "Dir as ZIP", "ZIP as metadata"} {
		t.Run(field, func(t *testing.T) {
			request, path, version := amd64DownloadedObservationFixture(t, "data")
			ctx, cancel := amd64OriginalObservationContext(t)
			defer cancel()
			changed := false
			run := func(ctx context.Context, dir string, env []string, binary string, args ...string) ([]byte, []byte, error) {
				data, stderr, err := RunBounded(ctx, dir, env, binary, args...)
				if err != nil || len(args) < 2 || args[0] != "mod" || args[1] != "download" {
					return data, stderr, err
				}
				var object map[string]json.RawMessage
				if err := json.Unmarshal(data, &object); err != nil {
					return nil, nil, err
				}
				switch field {
				case "Dir as ZIP":
					object["Dir"] = object["Zip"]
				case "ZIP as metadata":
					object["Zip"] = object["GoMod"]
				default:
					object[field], err = json.Marshal("unobserved")
					if err != nil {
						return nil, nil, err
					}
				}
				changed = true
				data, err = json.Marshal(object)
				return data, stderr, err
			}
			observed, err := CaptureAMD64DownloadedPackageObservation(ctx, AMD64DownloadedObservationRequest{
				Original: request, SourceModule: path, SourceVersion: version,
			}, run)
			if err == nil {
				observed.Close()
				t.Fatal("portable JSON impersonated an actual exact original source")
			}
			if !changed {
				t.Fatal("negative never reached its actual download seam")
			}
		})
	}
}

func TestAMD64DownloadedObservationMarkerCannotInheritCallerModule(t *testing.T) {
	request, path, version := amd64DownloadedObservationFixture(t, "data")
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	goMod := []byte("module example.invalid/caller-canary\ngo 1.20\nrequire " + path + " " + version + "\n")
	if err := os.WriteFile(filepath.Join(parent, "go.mod"), goMod, 0600); err != nil {
		t.Fatal(err)
	}
	// A caller-owned checksum file is a source input, not the factory's scratch.
	goSum := []byte("\n")
	if err := os.WriteFile(filepath.Join(parent, "go.sum"), goSum, 0600); err != nil {
		t.Fatal(err)
	}
	tmp := filepath.Join(parent, "tmp")
	if err := os.Mkdir(tmp, 0700); err != nil {
		t.Fatal(err)
	}
	request.Environment = replaceEnv(request.Environment, map[string]string{"GOTMPDIR": tmp})
	ctx, cancel := amd64OriginalObservationContext(t)
	defer cancel()
	observed, captureErr := captureAMD64DownloadedForTest(ctx, request, path, version)
	if observed != nil {
		defer observed.Close()
	}
	for name, expected := range map[string][]byte{"go.mod": goMod, "go.sum": goSum} {
		actual, err := os.ReadFile(filepath.Join(parent, name))
		if err != nil || string(actual) != string(expected) {
			t.Errorf("factory download inherited and modified caller's %s: %v", name, err)
		}
	}
	if captureErr != nil {
		t.Fatal(captureErr)
	}
}

func TestAMD64DownloadedObservationQueryOnlyCannotBindFixedLocal(t *testing.T) {
	request, path, version := amd64DownloadedObservationFixture(t, "fixed-local")
	ctx, cancel := amd64OriginalObservationContext(t)
	defer cancel()
	observed, err := captureAMD64DownloadedForTest(ctx, request, path, version)
	if err != nil {
		t.Fatal(err)
	}
	defer observed.Close()
	set := token.NewFileSet()
	syntax, err := parser.ParseFile(set, filepath.Join(request.Directory, "value.go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	sizes := types.SizesFor("gc", "amd64")
	typed, err := (&types.Config{Sizes: sizes}).Check(request.PackagePath, set, []*ast.File{syntax}, nil)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := plan9asm.DeriveGoFuncABI0Signature(request.PackagePath+".Value", typed.Scope().Lookup("Value").(*types.Func), "amd64", sizes)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(request.Directory, "value_amd64.s"))
	if err != nil {
		t.Fatal(err)
	}
	expanded := strings.Replace(string(data), "#include \"textflag.h\"", "#define NOSPLIT 4", 1)
	expanded = strings.Replace(expanded, "#include \"local.h\"", "#define ADVANCE 32", 1)
	file, err := plan9asm.Parse(plan9asm.ArchAMD64, expanded)
	if err != nil {
		t.Fatal(err)
	}
	pkg := plan9asm.GoPackage{Path: typed.Path(), Types: typed, Syntax: []*ast.File{syntax}}
	options := plan9asm.Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu",
		ResolveSym: func(symbol string) string { return strings.Replace(symbol, "·", typed.Path()+".", 1) },
		Sigs:       map[string]plan9asm.FuncSig{sig.Name: sig},
	}
	_, binding, err := observed.BindFixedLocal(ctx, pkg, file, "value_amd64.s", options)
	if binding != nil {
		defer binding.Close()
	}
	if !errors.Is(err, plan9asm.ErrProbeNeedsContext) || binding != nil {
		t.Fatalf("query-only downloaded observation silently exposed an owned-main frame/object consumer: %v", err)
	}
	if err := observed.Verify(ctx); err != nil {
		t.Fatal("rejecting unimplemented consumer must not revoke an unchanged source observation", err)
	}
}

func TestAMD64DownloadedObservationImmutableSourceAndRevocation(t *testing.T) {
	for _, role := range []string{"source", "unselected source", "foreign source", "ZIP", "metadata", "module directory", "close"} {
		t.Run(role, func(t *testing.T) {
			variant := "data"
			if role == "foreign source" {
				variant = "foreign"
			}
			request, path, version := amd64DownloadedObservationFixture(t, variant)
			ctx, cancel := amd64OriginalObservationContext(t)
			defer cancel()
			observed, err := captureAMD64DownloadedForTest(ctx, request, path, version)
			if err != nil {
				t.Fatal(err)
			}
			defer observed.Close()
			prefix := filepath.Join(originalObservationEnvironment(request.Environment, "GOMODCACHE"), "cache", "download", path, "@v", version)
			name, suffix := filepath.Join(request.Directory, "value.go"), "\nconst Changed = 1\n"
			switch role {
			case "unselected source":
				name, suffix = filepath.Join(request.Directory, "local.h"), "\n#define UNUSED 1\n"
			case "foreign source":
				foreign := observed.downloaded.modules["example.invalid/foreign-observation@"+version]
				if foreign == nil {
					t.Fatal("test lacks its actual separately observed foreign module")
				}
				name = filepath.Join(foreign.root, "shape.go")
			case "ZIP":
				name, suffix = prefix+".zip", "same h1, different retained original encoding"
			case "metadata":
				name = prefix + ".mod"
			case "module directory":
				moved := request.Directory + "-moved"
				if err := os.Chmod(request.Directory, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(filepath.Dir(request.Directory), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(request.Directory, moved); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(request.Directory, 0700); err != nil {
					t.Fatal(err)
				}
				if err := observed.Verify(ctx); err == nil {
					t.Fatal("changed original source directory identity was accepted")
				}
				if err := os.Remove(request.Directory); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(moved, request.Directory); err != nil {
					t.Fatal(err)
				}
				if err := observed.Verify(ctx); err == nil {
					t.Fatal("restoring the original cache directory resurrected a revoked observation")
				}
				return
			case "close":
				if err := observed.Close(); err != nil {
					t.Fatal(err)
				}
				if _, err := os.Stat(name); err != nil {
					t.Fatal("Close removed caller/Go-owned original module source", err)
				}
				if err := observed.Verify(ctx); err == nil {
					t.Fatal("closed source observation was usable")
				}
				return
			}
			original, err := os.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			mutateAMD64DownloadedFile(t, name, suffix)
			if err := observed.Verify(ctx); err == nil {
				t.Fatal("mutated source/archive was recaptured as a new blessed baseline")
			}
			if err := os.WriteFile(name, original, 0600); err != nil {
				t.Fatal(err)
			}
			if err := observed.Verify(ctx); err == nil {
				t.Fatal("restored bytes resurrected a revoked download observation")
			}
		})
	}
}

func TestAMD64DownloadedObservationCacheRootContinuity(t *testing.T) {
	request, path, version := amd64DownloadedObservationFixture(t, "data")
	ctx, cancel := amd64OriginalObservationContext(t)
	defer cancel()
	observed, err := captureAMD64DownloadedForTest(ctx, request, path, version)
	if err != nil {
		t.Fatal(err)
	}
	defer observed.Close()
	cache := originalObservationEnvironment(request.Environment, "GOMODCACHE")
	moved, replacement := cache+"-original", cache+"-replacement"
	if err := os.Mkdir(replacement, 0700); err != nil {
		t.Fatal(err)
	}
	members, err := os.ReadDir(cache)
	if err != nil {
		t.Fatal(err)
	}
	// Retain every module and metadata subtree inode, byte and path role. Only
	// the actual cache root directory's identity changes at the same pathname.
	for _, member := range members {
		if err := os.Rename(filepath.Join(cache, member.Name()), filepath.Join(replacement, member.Name())); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Rename(cache, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, cache); err != nil {
		t.Fatal(err)
	}
	// Restore the fixture-owned cache even if the current implementation fails
	// this regression. Never remove a Go/caller-owned module subtree.
	defer func() {
		for _, member := range members {
			if err := os.Rename(filepath.Join(cache, member.Name()), filepath.Join(moved, member.Name())); err != nil {
				t.Error(err)
				return
			}
		}
		if err := os.Remove(cache); err != nil {
			t.Error(err)
			return
		}
		if err := os.Rename(moved, cache); err != nil {
			t.Error(err)
			return
		}
		if err := observed.Verify(ctx); err == nil {
			t.Error("restoring the original cache root resurrected a revoked observation")
		}
	}()
	if err := observed.Verify(ctx); err == nil {
		t.Fatal("replacement cache root preserved all module bytes/inodes but acquired the original cache role")
	}
}

func TestAMD64DownloadedObservationRejectsSameBytesFileReplacement(t *testing.T) {
	for _, role := range []string{"source", "ZIP", "metadata"} {
		t.Run(role, func(t *testing.T) {
			request, modulePath, version := amd64DownloadedObservationFixture(t, "data")
			ctx, cancel := amd64OriginalObservationContext(t)
			defer cancel()
			observed, err := captureAMD64DownloadedForTest(ctx, request, modulePath, version)
			if err != nil {
				t.Fatal(err)
			}
			defer observed.Close()
			prefix := filepath.Join(originalObservationEnvironment(request.Environment, "GOMODCACHE"),
				"cache", "download", modulePath, "@v", version)
			name := filepath.Join(request.Directory, "value.go")
			if role == "ZIP" {
				name = prefix + ".zip"
			} else if role == "metadata" {
				name = prefix + ".mod"
			}
			original, err := os.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			before, err := os.Lstat(name)
			if err != nil {
				t.Fatal(err)
			}
			// Windows Lstat defers the file ID lookup until SameFile. Bind it
			// before replacement, while this path still names the original.
			if !os.SameFile(before, before) {
				t.Fatal("original physical identity could not be observed")
			}
			if err := os.Chmod(filepath.Dir(name), 0700); err != nil {
				t.Fatal(err)
			}
			backup := filepath.Join(t.TempDir(), "original")
			if err := os.Rename(name, backup); err != nil {
				t.Fatal(err)
			}
			restored := false
			defer func() {
				if !restored {
					if err := os.Remove(name); err != nil && !os.IsNotExist(err) {
						t.Error(err)
					}
					if err := os.Rename(backup, name); err != nil {
						t.Error(err)
					}
				}
			}()
			if err := os.WriteFile(name, original, 0600); err != nil {
				t.Fatal(err)
			}
			after, err := os.Lstat(name)
			if err != nil || os.SameFile(before, after) {
				t.Fatal("negative did not change the original physical file identity", err)
			}
			if err := observed.Verify(ctx); err == nil {
				t.Fatal("same source bytes at a replacement inode acquired the original source role")
			}
			if err := os.Remove(name); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(backup, name); err != nil {
				t.Fatal(err)
			}
			restored = true
			if err := observed.Verify(ctx); err == nil {
				t.Fatal("restoring the original file resurrected the revoked observation")
			}
		})
	}
}

func mutateAMD64DownloadedFile(t *testing.T, name, suffix string) {
	t.Helper()
	if err := os.Chmod(name, 0600); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsRune(suffix, '\x00') {
		t.Fatal("fixture source mutation must be explicit readable bytes")
	}
	if err := os.WriteFile(name, append(data, []byte(suffix)...), 0600); err != nil {
		t.Fatal(err)
	}
}
