//go:build go1.27

package plan9asm

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/gooriginalsrc"
	"github.com/xgo-dev/plan9asm/internal/sourcepath"
)

// The proxy contains only generated first-party fixture code. Actual Go
// download/extraction and go list, not invented selection JSON, select its role.
func numericalCachedFixture(t *testing.T, assembly bool) GoX86NumericalReadCaptureRequest {
	return numericalCachedFixtureWithAlias(t, assembly, false)
}

func numericalCachedFixtureWithAlias(t *testing.T, assembly, alias bool) GoX86NumericalReadCaptureRequest {
	t.Helper()
	pkg, template, _, _ := numericalSBFixture(t, "amd64")
	proxy, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// A comma is a GOPROXY separator unless the local path is escaped. The
	// suffix deliberately says "off", so a broken fixture cannot use network
	// fallback while this regression reproduces the parsing failure.
	proxy = filepath.Join(proxy, "proxy,off")
	if err := os.Mkdir(proxy, 0700); err != nil {
		t.Fatal(err)
	}
	cache, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		// This exact cache was freshly allocated by this fixture. Go makes
		// extracted module directories read-only; restore only our own tree.
		if err := filepath.WalkDir(cache, func(name string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				return os.Chmod(name, 0700)
			}
			return nil
		}); err != nil {
			t.Error(err)
		}
	})
	version := "v1.0.0"
	goSource := "package numericalfixture\nvar Mutable [32]byte\n"
	files := map[string][]byte{
		"go.mod": []byte("module " + pkg.Path + "\ngo 1.27\n"), "value.go": []byte(goSource),
	}
	if assembly {
		version = "v1.0.1"
		files["value.go"] = append(files["value.go"], []byte("func Feature() byte\n")...)
		files[template.AssemblyFile], err = os.ReadFile(filepath.Join(template.Directory, template.AssemblyFile))
		if err != nil {
			t.Fatal(err)
		}
	}
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	for _, name := range []string{"go.mod", "value.go", template.AssemblyFile} {
		data, exists := files[name]
		if !exists {
			continue
		}
		member, err := writer.Create(pkg.Path + "@" + version + "/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := member.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	versions := filepath.Join(proxy, filepath.FromSlash(pkg.Path), "@v")
	if err := os.MkdirAll(versions, 0700); err != nil {
		t.Fatal(err)
	}
	for suffix, data := range map[string][]byte{
		".mod": files["go.mod"], ".zip": archive.Bytes(),
		".info": []byte(`{"Version":"` + version + `","Time":"2026-01-01T00:00:00Z"}`),
	} {
		if err := os.WriteFile(filepath.Join(versions, version+suffix), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	var environment []string
	for _, pair := range template.Environment {
		key, _, _ := strings.Cut(pair, "=")
		if key != "GOMODCACHE" && key != "GOSUMDB" {
			environment = append(environment, pair)
		}
	}
	environment = append(environment, "GOMODCACHE="+cache, "GOSUMDB=off")
	downloadEnvironment := append([]string(nil), environment...)
	proxyURL, err := gooriginalsrc.FileProxyURL(proxy)
	if err != nil {
		t.Fatal(err)
	}
	for index, pair := range downloadEnvironment {
		if strings.HasPrefix(pair, "GOPROXY=") {
			downloadEnvironment[index] = "GOPROXY=" + proxyURL
		}
	}
	run := func(directory string, env []string, arguments ...string) []byte {
		t.Helper()
		ctx, cancel := runtimeOracleStageContext(t)
		defer cancel()
		command := exec.CommandContext(ctx, template.GoBinary, arguments...)
		command.Dir, command.Env = directory, env
		output, diagnostics, err := runtimeOracleMachineOutput(ctx, command)
		if err != nil {
			t.Fatalf("actual first-party cache fixture command %q: %v\n%s\n%s", arguments, err, output, diagnostics)
		}
		t.Logf("ACTUAL_FIRST_PARTY_CACHE_COMMAND directory=%q binary=%q argv=%q stdout=%q stderr=%q", directory, template.GoBinary, arguments, output, diagnostics)
		return output
	}
	data := run(template.Directory, downloadEnvironment, "mod", "download", "-json", pkg.Path+"@"+version)
	var downloaded struct{ Path, Version, Dir, Error string }
	if err := json.Unmarshal(data, &downloaded); err != nil || downloaded.Error != "" ||
		downloaded.Path != pkg.Path || downloaded.Version != version || downloaded.Dir == "" {
		t.Fatal("actual first-party Go download did not select exact original cache source", err)
	}
	if alias {
		alternate := strings.ToUpper(cache)
		original, err := os.Stat(cache)
		if err != nil {
			t.Fatal(err)
		}
		other, err := os.Stat(alternate)
		if err != nil || !os.SameFile(original, other) {
			t.Log("physical cache has no case alias on this filesystem; distinct-case directory control covers it")
			return GoX86NumericalReadCaptureRequest{}
		}
		if alternate == cache {
			t.Fatal("case-alias fixture has no spelling difference")
		}
		for index, pair := range environment {
			if strings.HasPrefix(pair, "GOMODCACHE=") {
				environment[index] = "GOMODCACHE=" + alternate
			}
		}
		t.Logf("ACTUAL_FIRST_PARTY_CACHE_ALIAS source=%q cache=%q alias=%q same_file=true", downloaded.Dir, cache, alternate)
	}
	selection := run(downloaded.Dir, environment, "list", "-json", "-compiled", "-export", "-mod=readonly", ".")
	var selected goAMD64FrameSelection
	if err := json.Unmarshal(selection, &selected); err != nil || selected.Dir != downloaded.Dir ||
		selected.Module == nil || !selected.Module.Main || selected.Module.Version != "" || selected.Module.Dir != downloaded.Dir {
		t.Fatal("real cached-CWD Main=true/empty-version precondition differs", err)
	}
	return GoX86NumericalReadCaptureRequest{GoBinary: template.GoBinary, Directory: downloaded.Dir, PackagePath: pkg.Path,
		AssemblyFile: template.AssemblyFile, Target: template.Target, Environment: environment}
}

func TestGoX86NumericalSBReadCachedSourceCannotAcquireOwnedRole(t *testing.T) {
	testNumericalCachedSourceCannotAcquireOwnedRole(t, false)
}

func TestGoX86NumericalSBReadCachedSourceCaseAliasCannotAcquireOwnedRole(t *testing.T) {
	testNumericalCachedSourceCannotAcquireOwnedRole(t, true)
}

func testNumericalCachedSourceCannotAcquireOwnedRole(t *testing.T, alias bool) {
	t.Run("ordinary data owner", func(t *testing.T) {
		request := numericalCachedFixtureWithAlias(t, false, alias)
		if request.GoBinary == "" {
			return
		}
		ctx, cancel := runtimeOracleStageContext(t)
		defer cancel()
		owner, err := CaptureGoNumericalStorageOwner(ctx, GoNumericalStorageCaptureRequest{
			GoBinary: request.GoBinary, Directory: request.Directory, PackagePath: request.PackagePath,
			Target: request.Target, Environment: request.Environment,
			Variables: []GoNumericalStorageReference{{PackagePath: request.PackagePath, Name: "Mutable"}},
		})
		if owner != nil {
			owner.Close()
		}
		if owner != nil || !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("downloaded cache acquired an ordinary owned storage role", err)
		}
	})
	t.Run("numerical original source", func(t *testing.T) {
		request := numericalCachedFixtureWithAlias(t, true, alias)
		if request.GoBinary == "" {
			return
		}
		ctx, cancel := runtimeOracleStageContext(t)
		defer cancel()
		// The separate positive SDK owner requires canonical command roots.
		// Preserve the alias in request itself: that is the negative source
		// admission input, not a reason to break this independent control.
		ownerEnvironment := append([]string(nil), request.Environment...)
		for index, pair := range ownerEnvironment {
			if strings.HasPrefix(pair, "GOMODCACHE=") {
				physical, err := sourcepath.Resolve(strings.TrimPrefix(pair, "GOMODCACHE="))
				if err != nil {
					t.Fatal(err)
				}
				ownerEnvironment[index] = "GOMODCACHE=" + physical
			}
		}
		owner, err := CaptureGoNumericalStorageOwner(ctx, GoNumericalStorageCaptureRequest{
			GoBinary: request.GoBinary, Directory: filepath.Join(filepath.Dir(filepath.Dir(request.GoBinary)), "src", "internal", "cpu"),
			PackagePath: "internal/cpu", Target: request.Target, Environment: ownerEnvironment, SDKCPU: true,
			Variables: []GoNumericalStorageReference{{PackagePath: "internal/cpu", Name: "X86"}},
		})
		if err != nil {
			t.Fatal("separate actual SDK numerical owner precondition", err)
		}
		defer owner.Close()
		request.Owners = []*GoNumericalStorageOwner{owner}
		source, err := CaptureGoX86NumericalReadSource(ctx, request)
		if source != nil {
			source.Close()
		}
		if source != nil || !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("downloaded cache acquired an owned numerical original source role", err)
		}
	})
}
