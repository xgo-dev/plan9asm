package gotoolprofile

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// These ordinary first-party archives exercise the actual query/role consumer.
// They deliberately do not claim signed legacy origins or a frame capability.
func TestAMD64DownloadedDependencyQueryActualGo(t *testing.T) {
	for _, variant := range []string{"fixed-local-no-go", "fixed-local-nested-no-go"} {
		t.Run(variant, func(t *testing.T) {
			request, module, version := amd64DownloadedObservationFixture(t, variant)
			ctx, cancel := amd64OriginalObservationContext(t)
			defer cancel()
			originalDir := request.Directory
			root := originalDir
			if variant == "fixed-local-nested-no-go" {
				root = filepath.Dir(filepath.Dir(root))
			}
			before, err := os.ReadFile(filepath.Join(root, "go.mod"))
			if err != nil {
				t.Fatal(err)
			}
			metadata := filepath.Join(originalObservationEnvironment(request.Environment, "GOMODCACHE"),
				"cache", "download", module, "@v", version+".mod")
			source := &amd64DownloadedModule{sourceModule: module, sourceVersion: version,
				root: root, goMod: metadata, modulePath: module, goModOrigin: ProxyGoModProtocol}
			sources := &amd64DownloadedSources{primary: source}
			var packages map[string]amd64OriginalListPackage
			for query := 0; query < 2; query++ {
				data, diagnostics, err := sources.runList(ctx, request, RunBounded,
					"list", "-deps", "-compiled", "-export", "-json", "-mod=readonly", request.PackagePath)
				if err != nil || len(diagnostics) != 0 {
					t.Fatalf("actual independent dependency query: %v; %s", err, diagnostics)
				}
				decoder := json.NewDecoder(bytes.NewReader(data))
				actual := make(map[string]amd64OriginalListPackage)
				for {
					var selected amd64OriginalListPackage
					if err := decoder.Decode(&selected); err == io.EOF {
						break
					} else if err != nil {
						t.Fatal(err)
					}
					actual[selected.ImportPath] = selected
				}
				if query > 0 && !reflect.DeepEqual(actual, packages) {
					t.Fatal("new temporary query changed original selection or compiler-export identity")
				}
				packages = actual
			}
			selected := packages[request.PackagePath]
			if selected.Dir != originalDir || selected.Export == "" || !source.matchesPrimary(selected.Module) ||
				selected.Module.Main || selected.Module.Version != version || selected.Module.GoVersion != "" {
				t.Fatal("query changed original source, exact version, dependency language or compiler export")
			}
			declarations, err := checkAMD64OriginalDeclarations(packages, request.PackagePath)
			if err != nil || len(declarations) == 0 {
				t.Fatal("actual dependency export lost its complete source typecheck", err)
			}
			after, err := os.ReadFile(filepath.Join(root, "go.mod"))
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("query rewrote original archive metadata", err)
			}
			if sources.verify() == nil {
				t.Fatal("a successful query manufactured authenticated original-source authority")
			}
		})
	}
}
