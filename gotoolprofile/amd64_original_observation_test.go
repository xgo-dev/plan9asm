package gotoolprofile

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm"
)

func amd64OriginalObservationFixture(t *testing.T, variant string) AMD64OriginalObservationRequest {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dir, path := root, "example.invalid/observation"
	if variant == "nested" {
		dir, path = filepath.Join(root, "internal", "kernel"), path+"/internal/kernel"
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	source := "package observation\nfunc Value(a uint64) uint64\n"
	if variant == "bodyful" {
		source += "func Reference(a uint64) uint64 { return a + 1 }\n"
	} else if variant == "import" {
		source = "package observation\nimport _ \"math/bits\"\nfunc Value(a uint64) uint64\n"
	} else if variant == "sdk-import" {
		source = "package observation\nimport \"errors\"\nfunc Value(a uint64) uint64\n" +
			"func Error() error { return errors.New(\"first-party witness\") }\n"
	}
	files := map[string]string{
		filepath.Join(root, "go.mod"):  "module example.invalid/observation\ngo 1.20\n",
		filepath.Join(dir, "value.go"): source,
		filepath.Join(dir, "value_amd64.s"): "#include \"textflag.h\"\nTEXT ·Value(SB),NOSPLIT,$160-16\n" +
			"MOVQ a+0(FP),AX\nMOVQ AX,16(SP)\nMOVQ 16(SP),AX\nMOVQ AX,ret+8(FP)\nRET\n",
	}
	if variant == "data" {
		files[filepath.Join(dir, "local.h")] = "#define VALUE 1\n"
		files[filepath.Join(dir, "data_amd64.s")] = "#include \"textflag.h\"\n#include \"local.h\"\nDATA ·constant<>+0(SB)/8,$VALUE\nGLOBL ·constant<>(SB),RODATA|NOPTR,$8\n"
	}
	if variant == "sibling" {
		helper := filepath.Join(root, "helper")
		if err := os.Mkdir(helper, 0700); err != nil {
			t.Fatal(err)
		}
		files[filepath.Join(helper, "helper.go")] = "package helper\nfunc Reference(a uint64) uint64 { return a + 1 }\n"
		files[filepath.Join(dir, "value.go")] = "package observation\nimport _ \"example.invalid/observation/helper\"\nfunc Value(a uint64) uint64\n"
	}
	for name, data := range files {
		if err := os.WriteFile(name, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	binary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	binary, err = filepath.Abs(binary)
	if err != nil {
		t.Fatal(err)
	}
	// The actual-object factory retains this exact physical input path.
	// PATH may contain symlinks or noncanonical Windows path casing.
	binary, err = filepath.EvalSymlinks(binary)
	if err != nil {
		t.Fatal(err)
	}
	env := os.Environ()
	for _, key := range []string{"GOPATH", "GOMODCACHE", "GOCACHE", "TMPDIR", "GOTMPDIR"} {
		if !filepath.IsAbs(os.Getenv(key)) {
			env = replaceEnv(env, map[string]string{key: t.TempDir()})
		}
	}
	env = replaceEnv(env, map[string]string{"GOOS": "linux", "GOARCH": "amd64", "CGO_ENABLED": "0", "GOFLAGS": "",
		"GOENV": "off", "GOWORK": "off", "GOTOOLCHAIN": "local", "GOPROXY": "off", "GOSUMDB": "off",
		"GOAMD64": "v1", "GO386": "", "GOARM": "", "GOARM64": "", "GOWASM": "", "GOEXPERIMENT": ""})
	return AMD64OriginalObservationRequest{GoBinary: binary, Directory: dir, PackagePath: path, Target: "linux/amd64", Environment: env}
}

func amd64OriginalObservationContext(t *testing.T) (context.Context, context.CancelFunc) {
	t.Helper()
	return context.WithTimeout(context.Background(), 5*time.Minute)
}

func TestAMD64OriginalObservationActualFourRoles(t *testing.T) {
	for _, variant := range []string{"nested", "bodyful", "import", "data", "sibling"} {
		t.Run(variant, func(t *testing.T) {
			request := amd64OriginalObservationFixture(t, variant)
			ctx, cancel := amd64OriginalObservationContext(t)
			defer cancel()
			observed, err := CaptureAMD64OriginalPackageObservation(ctx, request, RunBounded)
			if err != nil {
				t.Fatal(err)
			}
			defer observed.Close()
			pkg := observed.state.packages[request.PackagePath]
			if pkg.Module == nil || !pkg.Module.Main || pkg.Module.Version != "" || observed.state.declarations["Value"] != "func(a uint64) uint64" {
				t.Fatalf("missing actual main/checked declaration identity: %+v, %v", pkg, observed.state.declarations)
			}
			if variant == "nested" && pkg.Dir == pkg.Module.Dir || variant == "data" && len(pkg.SFiles) != 2 ||
				variant == "import" && observed.state.packages["math/bits"].Export == "" {
				t.Fatalf("original role was lost: %+v", pkg)
			}
			if err := observed.Verify(ctx); err != nil {
				t.Fatal(err)
			}
			t.Logf("actual ordinary %s source/export graph: %d packages, %d bound files; observation only", variant, len(observed.state.packages), len(observed.state.files.hashes))
		})
	}
}

func TestAMD64OriginalObservationActualSelectionNegatives(t *testing.T) {
	for _, name := range []string{"roundtrip control", "paired ASM deletion", "paired Go deletion", "module version", "module language", "module replacement", "foreign dependency", "nonstandard dependency", "wrong physical root", "missing export", "unknown ImportMap", "Cgo", "test", "embed", "unknown diagnostic",
		"SDK roundtrip control", "SDK nonstandard", "SDK module", "SDK physical root", "SDK Go deletion", "SDK ASM deletion", "SDK missing export"} {
		t.Run(name, func(t *testing.T) {
			variant := "data"
			if strings.HasPrefix(name, "SDK ") {
				variant = "sdk-import"
			}
			request := amd64OriginalObservationFixture(t, variant)
			ctx, cancel := amd64OriginalObservationContext(t)
			defer cancel()
			changed := false
			run := func(ctx context.Context, dir string, env []string, binary string, args ...string) ([]byte, []byte, error) {
				stdout, stderr, err := RunBounded(ctx, dir, env, binary, args...)
				if err != nil || len(args) == 0 || args[0] != "list" || !containsString(args, "-deps") {
					return stdout, stderr, err
				}
				var output bytes.Buffer
				decoder := json.NewDecoder(bytes.NewReader(stdout))
				for {
					var original map[string]json.RawMessage
					var pkg amd64OriginalListPackage
					if err := decoder.Decode(&original); err == io.EOF {
						break
					} else if err != nil {
						return nil, nil, err
					}
					encoded, err := json.Marshal(original)
					if err != nil {
						return nil, nil, err
					}
					if err := json.Unmarshal(encoded, &pkg); err != nil {
						return nil, nil, err
					}
					before, err := json.Marshal(pkg)
					if err != nil {
						return nil, nil, err
					}
					target := request.PackagePath
					if strings.HasPrefix(name, "SDK ") {
						target = "runtime"
					}
					if pkg.ImportPath == target {
						changed = true
						switch name {
						case "paired ASM deletion":
							pkg.SFiles = []string{"value_amd64.s"}
						case "paired Go deletion":
							pkg.GoFiles, pkg.CompiledGoFiles = nil, nil
						case "module version":
							pkg.Module.Version = "v1.0.0"
						case "module language":
							pkg.Module.GoVersion = "1.22"
						case "module replacement":
							pkg.Module.Replace = &amd64OriginalListModule{Path: "example.invalid/other", Version: "v1.0.0", Dir: request.Directory}
						case "foreign dependency":
							pkg.Module.Main = false
						case "nonstandard dependency":
							pkg.Module = nil
						case "wrong physical root":
							pkg.Dir = filepath.Dir(pkg.Dir)
						case "missing export":
							pkg.Export = ""
						case "unknown ImportMap":
							pkg.ImportMap = map[string]string{"math/bits": "example.invalid/missing"}
						case "Cgo":
							pkg.CgoFiles = []string{"value.go"}
						case "test":
							pkg.ForTest = request.PackagePath
						case "embed":
							pkg.EmbedFiles = []string{"value.go"}
						case "unknown diagnostic":
							stderr = []byte("unregistered successful diagnostic\n")
						case "SDK nonstandard":
							pkg.Standard = false
						case "SDK module":
							pkg.Module = &amd64OriginalListModule{Path: "runtime", Dir: pkg.Dir, Main: true}
						case "SDK physical root":
							pkg.Dir = request.Directory
						case "SDK Go deletion":
							pkg.GoFiles, pkg.CompiledGoFiles = nil, nil
						case "SDK ASM deletion":
							pkg.SFiles = nil
						case "SDK missing export":
							pkg.Export = ""
						}
					}
					// Preserve the actual Go fields/omissions. Encoding the modeled
					// struct alone would add Error:null, invalidating every axis for
					// an unrelated reason. The control proves exact semantic replay.
					after, err := json.Marshal(pkg)
					if err != nil {
						return nil, nil, err
					}
					var oldFields, newFields map[string]json.RawMessage
					if err := json.Unmarshal(before, &oldFields); err != nil {
						return nil, nil, err
					}
					if err := json.Unmarshal(after, &newFields); err != nil {
						return nil, nil, err
					}
					for key, value := range newFields {
						if !bytes.Equal(oldFields[key], value) {
							original[key] = value
						}
					}
					if err := json.NewEncoder(&output).Encode(original); err != nil {
						return nil, nil, err
					}
				}
				return output.Bytes(), stderr, nil
			}
			observed, err := CaptureAMD64OriginalPackageObservation(ctx, request, run)
			if observed != nil {
				defer observed.Close()
			}
			if name == "roundtrip control" || name == "SDK roundtrip control" {
				if err != nil || observed == nil || !changed {
					t.Fatalf("actual Go JSON no-change replay failed: %v", err)
				}
			} else if err == nil || observed != nil || !changed {
				t.Fatalf("changed actual source identity/selection was accepted: %v; fixture=%v", err, changed)
			} else {
				t.Logf("exact actual-list %s rejection: %v", name, err)
			}
		})
	}
}

func TestAMD64OriginalObservationMutationAndRevocation(t *testing.T) {
	for _, name := range []string{"source", "ASM", "header", "go.mod", "absent go.sum", "late file", "export", "source symlink", "directory replacement"} {
		t.Run(name, func(t *testing.T) {
			request := amd64OriginalObservationFixture(t, "data")
			ctx, cancel := amd64OriginalObservationContext(t)
			defer cancel()
			observed, err := CaptureAMD64OriginalPackageObservation(ctx, request, RunBounded)
			if err != nil {
				t.Fatal(err)
			}
			defer observed.Close()
			file := filepath.Join(request.Directory, "value.go")
			switch name {
			case "ASM":
				file = filepath.Join(request.Directory, "data_amd64.s")
			case "header":
				file = filepath.Join(request.Directory, "local.h")
			case "go.mod":
				file = filepath.Join(request.Directory, "go.mod")
			case "absent go.sum":
				file = filepath.Join(request.Directory, "go.sum")
			case "late file":
				file = filepath.Join(request.Directory, "late.go")
			case "export":
				// Preserve the cache artifact after this actual mutation test.
				file = observed.state.packages[request.PackagePath].Export
			}
			prior, readErr := os.ReadFile(file)
			if readErr != nil && !os.IsNotExist(readErr) {
				t.Fatal(readErr)
			}
			if name == "source symlink" {
				other := filepath.Join(t.TempDir(), "same.go")
				if err := os.WriteFile(other, prior, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(file); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(other, file); err != nil {
					t.Fatal(err)
				}
			} else if name == "directory replacement" {
				if err := os.Rename(request.Directory, request.Directory+"-original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(request.Directory, 0700); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(file, append(prior, []byte("\nchanged\n")...), 0600); err != nil {
				t.Fatal(err)
			}
			if err := observed.Verify(ctx); err == nil {
				t.Fatal("original input mutation did not revoke the observation")
			}
			if name == "export" {
				if err := os.WriteFile(file, prior, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if observed.ready || observed.Verify(ctx) == nil {
				t.Fatal("a revoked observation was restored")
			}
		})
	}
}

func TestAMD64OriginalObservationCloseJSONAndReentrancy(t *testing.T) {
	request := amd64OriginalObservationFixture(t, "bodyful")
	ctx, cancel := amd64OriginalObservationContext(t)
	defer cancel()
	var observed *AMD64OriginalPackageObservation
	armed := false
	run := func(ctx context.Context, dir string, env []string, binary string, args ...string) ([]byte, []byte, error) {
		if armed {
			armed = false
			if err := observed.Close(); err != nil {
				return nil, nil, err
			}
		}
		return RunBounded(ctx, dir, env, binary, args...)
	}
	var err error
	observed, err = CaptureAMD64OriginalPackageObservation(ctx, request, run)
	if err != nil {
		t.Fatal(err)
	}
	defer observed.Close()
	data, err := json.Marshal(observed)
	if err != nil || string(data) != "{}" {
		t.Fatalf("private observation leaked JSON authority: %s, %v", data, err)
	}
	var restored AMD64OriginalPackageObservation
	if err := json.Unmarshal(data, &restored); err != nil || restored.Verify(ctx) == nil {
		t.Fatalf("JSON restored observation authority: %v", err)
	}
	armed = true
	if err := observed.Verify(ctx); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("reentrant Close did not revoke the in-flight verification: %v", err)
	}
}

func TestAMD64OriginalObservationRejectsUnboundProfiles(t *testing.T) {
	for _, value := range []string{"-race", "-msan", "-asan", "-tags=custom"} {
		t.Run(value, func(t *testing.T) {
			request := amd64OriginalObservationFixture(t, "bodyful")
			request.Environment = replaceEnv(request.Environment, map[string]string{"GOFLAGS": value})
			ctx, cancel := amd64OriginalObservationContext(t)
			defer cancel()
			if observed, err := CaptureAMD64OriginalPackageObservation(ctx, request, RunBounded); !errors.Is(err, plan9asm.ErrProbeNeedsContext) || observed != nil {
				t.Fatalf("unbound mode was relabeled ordinary: %v", err)
			}
		})
	}
}

func TestAMD64OriginalObservationActualForeignSourceNeedsContext(t *testing.T) {
	request := amd64OriginalObservationFixture(t, "bodyful")
	foreign := t.TempDir()
	for name, data := range map[string]string{"go.mod": "module example.invalid/foreign\ngo 1.20\n", "foreign.go": "package foreign\nfunc Value() uint64 { return 1 }\n"} {
		if err := os.WriteFile(filepath.Join(foreign, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	mod := "module example.invalid/observation\ngo 1.20\nrequire example.invalid/foreign v1.0.0\nreplace example.invalid/foreign => " + filepath.ToSlash(foreign) + "\n"
	if err := os.WriteFile(filepath.Join(request.Directory, "go.mod"), []byte(mod), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(request.Directory, "value.go"), []byte("package observation\nimport _ \"example.invalid/foreign\"\nfunc Value(a uint64) uint64\n"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := amd64OriginalObservationContext(t)
	defer cancel()
	if observed, err := CaptureAMD64OriginalPackageObservation(ctx, request, RunBounded); !errors.Is(err, plan9asm.ErrProbeNeedsContext) || observed != nil {
		t.Fatalf("actual foreign/local replacement became a main source or signed identity: %v", err)
	}
}

func TestAMD64OriginalObservationRejectsLateSourceAndEnvironment(t *testing.T) {
	for _, name := range []string{"source", "environment"} {
		t.Run(name, func(t *testing.T) {
			request := amd64OriginalObservationFixture(t, "bodyful")
			ctx, cancel := amd64OriginalObservationContext(t)
			defer cancel()
			changed := false
			run := func(ctx context.Context, dir string, env []string, binary string, args ...string) ([]byte, []byte, error) {
				stdout, stderr, err := RunBounded(ctx, dir, env, binary, args...)
				if err != nil {
					return stdout, stderr, err
				}
				if !changed && len(args) > 0 && args[0] == "list" && containsString(args, "-deps") && containsString(args, "-export") {
					changed = true
					if name == "source" {
						file := filepath.Join(request.Directory, "value.go")
						data, err := os.ReadFile(file)
						if err != nil {
							return nil, nil, err
						}
						if err := os.WriteFile(file, append(data, []byte("\n// late source mutation\n")...), 0600); err != nil {
							return nil, nil, err
						}
					}
				}
				if changed && name == "environment" && len(args) > 0 && args[0] == "env" {
					var actual map[string]string
					if err := json.Unmarshal(stdout, &actual); err != nil {
						return nil, nil, err
					}
					actual["CGO_ENABLED"] = "1"
					stdout, err = json.Marshal(actual)
				}
				return stdout, stderr, err
			}
			if observed, err := CaptureAMD64OriginalPackageObservation(ctx, request, run); err == nil || observed != nil || !changed {
				t.Fatalf("late original source/environment mutation was accepted: %v", err)
			}
		})
	}
}

func TestAMD64OriginalObservationEnvironmentCopyAndConcurrentClose(t *testing.T) {
	request := amd64OriginalObservationFixture(t, "bodyful")
	ctx, cancel := amd64OriginalObservationContext(t)
	defer cancel()
	observed, err := CaptureAMD64OriginalPackageObservation(ctx, request, RunBounded)
	if err != nil {
		t.Fatal(err)
	}
	defer observed.Close()
	for index, item := range request.Environment {
		if strings.HasPrefix(item, "GOFLAGS=") {
			request.Environment[index] = "GOFLAGS=-race"
		}
	}
	if err := observed.Verify(ctx); err != nil {
		t.Fatalf("caller environment slice mutated the sealed invocation: %v", err)
	}
	finished := make(chan error, 1)
	go func() { finished <- observed.Verify(ctx) }()
	if err := observed.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-finished:
		if err == nil {
			t.Fatal("concurrent Close did not revoke verification")
		}
	case <-ctx.Done():
		t.Fatal("concurrent verification/Close did not terminate")
	}
}

func TestAMD64OriginalObservationActiveIncludeNeedsClosedOrigin(t *testing.T) {
	for _, inactive := range []bool{false, true} {
		name := "active"
		if inactive {
			name = "inactive control"
		}
		t.Run(name, func(t *testing.T) {
			request := amd64OriginalObservationFixture(t, "data")
			outside := filepath.Join(filepath.Dir(request.Directory), "outside.h")
			if err := os.WriteFile(outside, []byte("#define VALUE 1\n"), 0600); err != nil {
				t.Fatal(err)
			}
			include := "#include \"../outside.h\"\n"
			if inactive {
				include = "#ifdef UNDEFINED\n" + include + "#endif\n#define VALUE 1\n"
			}
			source := "#include \"textflag.h\"\n" + include + "DATA ·constant<>+0(SB)/8,$VALUE\nGLOBL ·constant<>(SB),RODATA|NOPTR,$8\n"
			if err := os.WriteFile(filepath.Join(request.Directory, "data_amd64.s"), []byte(source), 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := amd64OriginalObservationContext(t)
			defer cancel()
			// Actual original compiler accepts both; outside active inputs are
			// nevertheless not a closed source origin for this observation.
			stdout, stderr, err := RunBounded(ctx, request.Directory, request.Environment, request.GoBinary,
				"list", "-deps", "-compiled", "-export", "-json", "-mod=readonly", request.PackagePath)
			if err != nil || len(stdout) == 0 || len(stderr) != 0 {
				t.Fatalf("actual original Go include compilation failed: %v; %s", err, stderr)
			}
			observed, err := CaptureAMD64OriginalPackageObservation(ctx, request, RunBounded)
			if observed != nil {
				defer observed.Close()
			}
			if inactive {
				if err != nil || observed == nil {
					t.Fatalf("inactive include was treated as actual consumption: %v", err)
				}
			} else if !errors.Is(err, plan9asm.ErrProbeNeedsContext) || observed != nil {
				t.Fatalf("unclosed active source include acquired a complete observation: %v", err)
			}
		})
	}
}

func TestAMD64OriginalObservationActiveIncludeGuards(t *testing.T) {
	for _, name := range []string{"same-module control", "header bytes", "paired input deletion", "late header", "generated header"} {
		t.Run(name, func(t *testing.T) {
			request := amd64OriginalObservationFixture(t, "nested")
			root := filepath.Dir(filepath.Dir(request.Directory))
			header := filepath.Join(root, "shared.h")
			if err := os.WriteFile(header, []byte("#define VALUE 1\n"), 0600); err != nil {
				t.Fatal(err)
			}
			include := "#include \"../../shared.h\"\n"
			if name == "generated header" {
				include = "#include \"go_asm.h\"\n#define VALUE 1\n"
			}
			assembly := filepath.Join(request.Directory, "data_amd64.s")
			source := "#include \"textflag.h\"\n" + include +
				"DATA ·constant<>+0(SB)/8,$VALUE\nGLOBL ·constant<>(SB),RODATA|NOPTR,$8\n"
			if err := os.WriteFile(assembly, []byte(source), 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := amd64OriginalObservationContext(t)
			defer cancel()
			stdout, stderr, err := RunBounded(ctx, request.Directory, request.Environment, request.GoBinary,
				"list", "-deps", "-compiled", "-export", "-json", "-mod=readonly", request.PackagePath)
			if err != nil || len(stdout) == 0 || len(stderr) != 0 {
				t.Fatalf("actual original Go include export failed: %v; %s", err, stderr)
			}
			changed := false
			run := func(ctx context.Context, dir string, env []string, binary string, args ...string) ([]byte, []byte, error) {
				stdout, stderr, err := RunBounded(ctx, dir, env, binary, args...)
				if name == "late header" && !changed && err == nil && len(args) != 0 && args[0] == "list" && containsString(args, "-export") {
					changed = true
					err = os.WriteFile(header, []byte("#define VALUE 2\n"), 0600)
				}
				return stdout, stderr, err
			}
			observed, err := CaptureAMD64OriginalPackageObservation(ctx, request, run)
			if observed != nil {
				defer observed.Close()
			}
			if name == "generated header" {
				if observed != nil || !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
					t.Fatalf("unproved generated include acquired observation: %v", err)
				}
				return
			}
			if name == "late header" {
				if observed != nil || err == nil || !changed {
					t.Fatalf("actual active header changed across export without revocation: %v, %v", err, changed)
				}
				return
			}
			if err != nil || observed == nil {
				t.Fatal(err)
			}
			proof := observed.state.files.cpp[assembly]
			if proof.Expanded == "" || !containsString(proof.Inputs, header) || len(proof.Inputs) != 3 || observed.state.files.hashes[header] == "" {
				t.Fatalf("actual active module/tool input sequence was not bound: %+v", proof)
			}
			switch name {
			case "same-module control":
				if err := observed.Verify(ctx); err != nil {
					t.Fatal(err)
				}
				return
			case "header bytes":
				if err := os.WriteFile(header, []byte("#define VALUE 2\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "paired input deletion":
				proof.Inputs = proof.Inputs[:2]
				observed.state.files.cpp[assembly] = proof
				delete(observed.state.files.hashes, header)
				delete(observed.state.files.paths, header)
			}
			if err := observed.Verify(ctx); err == nil || observed.ready {
				t.Fatalf("active input mutation/deletion did not revoke the observation: %v", err)
			}
		})
	}
}
