package plan9asm

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmcmd"
)

// This real-driver comparison also runs on the minimum SDK. It checks list
// output semantics, independently of the Go 1.27 numerical owner contract.
func TestGoX86SDKListRootMatchesWholeGraph(t *testing.T) {
	_, request := goAMD64FrameSourceFixture(t)
	ctx, cancel := runtimeOracleProofContext(t)
	defer cancel()
	for _, arch := range []string{"386", "amd64"} {
		for _, path := range []string{"internal/cpu", "internal/bytealg", "hash/crc32"} {
			t.Run(arch+"/"+path, func(t *testing.T) {
				env := append([]string(nil), request.Environment...)
				for key, value := range map[string]string{
					"GOOS": "linux", "GOARCH": arch, "GOAMD64": "v1", "GO386": "sse2",
					"GOFLAGS": "", "GOEXPERIMENT": "", "GOTOOLCHAIN": "local",
					"CGO_ENABLED": "0", "GOWORK": "off", "GOENV": "off", "GOPROXY": "off",
				} {
					for index := len(env) - 1; index >= 0; index-- {
						if strings.HasPrefix(env[index], key+"=") {
							env = append(env[:index], env[index+1:]...)
						}
					}
					env = append(env, key+"="+value)
				}
				dir := filepath.Join(filepath.Dir(filepath.Dir(request.GoBinary)), "src", filepath.FromSlash(path))
				var outputs [][]byte
				for _, deps := range []bool{false, true} {
					args := []string{"list", "-json", "-compiled", "-export", "-mod=readonly"}
					if deps {
						args = append(args, "-deps")
					}
					args = append(args, path)
					observed, err := goasmcmd.Observe(ctx, dir, env, request.GoBinary, args...)
					if err != nil || observed.PID <= 0 || !observed.Waited || observed.ExitCode != 0 || len(observed.Stderr) != 0 {
						t.Fatalf("actual Go list deps=%v: %+v, %v", deps, observed, err)
					}
					outputs = append(outputs, observed.Stdout)
					if root := os.Getenv("PLAN9ASM_STATIC_STORAGE_ARTIFACT_DIR"); root != "" {
						name := fmt.Sprintf("list-%s-%s-deps-%v.json", arch, strings.ReplaceAll(path, "/", "-"), deps)
						if err := os.MkdirAll(root, 0700); err != nil {
							t.Fatal(err)
						}
						if err := os.WriteFile(filepath.Join(root, name), observed.Stdout, 0600); err != nil {
							t.Fatal(err)
						}
					}
				}
				decoder := json.NewDecoder(bytes.NewReader(outputs[1]))
				matches := 0
				for {
					var raw json.RawMessage
					if err := decoder.Decode(&raw); err == io.EOF {
						break
					} else if err != nil {
						t.Fatal(err)
					}
					var selected struct{ ImportPath string }
					if err := json.Unmarshal(raw, &selected); err != nil {
						t.Fatal(err)
					}
					if selected.ImportPath == path {
						matches++
						if !numericalSameRawSelection(outputs[0], raw) {
							t.Fatal("complete root metadata changed between actual list commands")
						}
					}
				}
				if matches != 1 {
					t.Fatalf("dependency output has %d original roots", matches)
				}
			})
		}
	}
}

func TestNumericalSDKGraphRootKeepsCompleteSelection(t *testing.T) {
	root := `{"ImportPath":"internal/cpu","Match":["internal/cpu"],"Export":"cpu.a","FutureRole":{"Value":1}}`
	graph := []byte("{\"ImportPath\":\"unsafe\"}\n" + root)
	raw, err := numericalSDKGraphRoot(graph, "internal/cpu")
	if err != nil || !bytes.Equal(raw, []byte(root)) || !numericalSameRawSDKGraph(graph, graph) {
		t.Fatal("whole root or dependency metadata was lost", err)
	}
	for _, change := range []struct{ name, graph string }{
		{"missing", `{"ImportPath":"unsafe"}`},
		{"duplicate", root + "\n" + root},
		{"malformed", string(graph) + " garbage"},
		{"wrong shape", `[]`},
		{"wrong path type", `{"ImportPath":1}`},
		{"empty", ""},
		{"too many records", strings.Repeat("{}\n", 4096) + root},
		{"too many bytes", strings.Repeat(" ", 16<<20) + root},
	} {
		t.Run(change.name, func(t *testing.T) {
			if _, err := numericalSDKGraphRoot([]byte(change.graph), "internal/cpu"); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("incomplete root acquired a selection", err)
			}
		})
	}
	for _, change := range []struct{ name, root string }{
		{"match", strings.Replace(root, `"Match":["internal/cpu"]`, `"Match":["."]`, 1)},
		{"dependency role", strings.Replace(root, `"Export"`, `"DepOnly":true,"Export"`, 1)},
		{"unknown field", strings.Replace(root, `"Value":1`, `"Value":2`, 1)},
		{"export", strings.Replace(root, `"cpu.a"`, `"foreign.a"`, 1)},
		{"source addition", strings.Replace(root, `"Export"`, `"GoFiles":["new.go"],"Export"`, 1)},
	} {
		t.Run(change.name, func(t *testing.T) {
			changed := bytes.Replace(graph, []byte(root), []byte(change.root), 1)
			raw, err := numericalSDKGraphRoot(changed, "internal/cpu")
			if err != nil {
				t.Fatal("valid changed JSON must reach the complete identity comparison", err)
			}
			if numericalSameRawSelection([]byte(root), raw) || numericalSameRawSDKGraph(graph, changed) {
				t.Fatal("changed complete metadata was normalized away")
			}
		})
	}
}

func TestGoAMD64RawPackageSelectionReadsActualExport(t *testing.T) {
	_, request := goAMD64FrameSourceFixture(t)
	cache, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// The archive below is produced in this test's cache, never a shared SDK or
	// user's cache. Only negative parser controls alter these owned bytes.
	for _, key := range []string{"GOCACHE", "GOOS", "GOARCH"} {
		for index := len(request.Environment) - 1; index >= 0; index-- {
			if strings.HasPrefix(request.Environment[index], key+"=") {
				request.Environment = append(request.Environment[:index], request.Environment[index+1:]...)
			}
		}
	}
	request.Environment = append(request.Environment, "GOCACHE="+cache, "GOOS=linux", "GOARCH=amd64")
	source := newGoOriginalInputGuard(request)
	source.env = map[string]string{"GOCACHE": cache}
	ctx, cancel := runtimeOracleProofContext(t)
	defer cancel()
	selected, raw, err := source.loadWithRawPackage(ctx, ".")
	if err != nil {
		t.Fatal("real original package/export precondition", err)
	}
	if _, found := source.inputs[selected.Export]; !found {
		t.Fatal("actual export read was not retained")
	}
	for _, name := range []string{"missing export", "empty export", "outside cache", "absent file", "error", "dependency error", "extra record", "changed bytes"} {
		t.Run(name, func(t *testing.T) {
			var value map[string]json.RawMessage
			if err := json.Unmarshal(raw, &value); err != nil {
				t.Fatal(err)
			}
			setExport := func(path string) { value["Export"], _ = json.Marshal(path) }
			switch name {
			case "missing export":
				delete(value, "Export")
			case "empty export", "outside cache":
				dir := cache
				var data []byte
				if name == "outside cache" {
					dir = t.TempDir()
					data = []byte("not this cache's compiler output")
				}
				path := filepath.Join(dir, "invalid.a")
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
				setExport(path)
			case "absent file":
				setExport(filepath.Join(cache, "missing.a"))
			case "error":
				value["Error"] = json.RawMessage(`{"Err":"invalid root"}`)
			case "dependency error":
				value["DepsErrors"] = json.RawMessage(`[{"Err":"invalid dependency"}]`)
			case "changed bytes":
				original, err := os.ReadFile(selected.Export)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(selected.Export, 0600); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := os.WriteFile(selected.Export, original, 0600); err != nil {
						t.Error(err)
					}
				})
				if err := os.WriteFile(selected.Export, append(original, '\n'), 0600); err != nil {
					t.Fatal(err)
				}
			}
			changed, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			if name == "extra record" {
				changed = append(changed, []byte("\n{}")...)
			}
			if _, _, err := source.readRawPackageSelection(changed); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("changed actual root/export accepted", err)
			}
		})
	}
}
