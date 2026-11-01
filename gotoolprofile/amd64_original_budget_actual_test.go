package gotoolprofile

import (
	"bytes"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A normal first-party numeric package imports these SDK packages without
// requiring native/generated code or granting a private frame capability.
func TestAMD64OriginalObservationActualSDKGraphBudget(t *testing.T) {
	for _, crypto := range []bool{false, true} {
		name := "driver-collision"
		if crypto {
			name = "recursive-sdk"
		}
		t.Run(name, func(t *testing.T) {
			amd64OriginalActualSDKGraphBudget(t, crypto, "linux")
		})
	}
}

func TestAMD64OriginalObservationCrossTargetSDKGraphBudget(t *testing.T) {
	amd64OriginalActualSDKGraphBudget(t, true, "darwin")
}

func amd64OriginalActualSDKGraphBudget(t *testing.T, crypto bool, goos string) {
	t.Helper()
	request := amd64OriginalObservationFixture(t, "sdk-import")
	request.Target = goos + "/amd64"
	request.Environment = replaceEnv(request.Environment, map[string]string{"GOOS": goos})
	source := `package observation
import (
 "encoding/binary"
 "fmt"
)
func Value(a uint64) uint64
func Decode(p []byte) (uint64,error) {
 if len(p)<8 {
  return 0,fmt.Errorf("short input: %d",len(p))
 }
 return binary.LittleEndian.Uint64(p),nil
}
`
	if crypto {
		source = strings.Replace(source, "import (", "import (\n _ \"crypto\"", 1)
	}
	if err := os.WriteFile(filepath.Join(request.Directory, "value.go"), []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := amd64OriginalObservationContext(t)
	defer cancel()
	output, diagnostic, err := RunBounded(ctx, request.Directory, request.Environment,
		request.GoBinary, "list", "-deps", "-compiled", "-export", "-json", "-mod=readonly", request.PackagePath)
	if err != nil || len(diagnostic) != 0 {
		t.Fatalf("actual Go SDK graph: %v\n%s", err, diagnostic)
	}
	// Independent accounting of the actual graph, not a replacement for the
	// producer's role/lifetime checks. Macro-source inputs can add further bytes.
	seen := make(map[string]bool)
	var sourceBytes, packageLocalBytes, exportBytes int64
	packages := 0
	decoder := json.NewDecoder(bytes.NewReader(output))
	for {
		var pkg amd64OriginalListPackage
		if err := decoder.Decode(&pkg); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		packages++
		entries, err := os.ReadDir(pkg.Dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			info, err := entry.Info()
			if err != nil {
				t.Fatal(err)
			}
			packageLocalBytes += info.Size()
		}
		var packageBytes int64
		if err := filepath.WalkDir(pkg.Dir, func(path string, entry fs.DirEntry, err error) error {
			if err != nil || entry.IsDir() || seen[path] {
				return err
			}
			info, err := entry.Info()
			if err != nil {
				return err
			}
			if !info.Mode().IsRegular() {
				t.Fatalf("nonregular original SDK fixture member: %s", path)
			}
			seen[path] = true
			packageBytes += info.Size()
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		sourceBytes += packageBytes
		var compiledBytes int64
		if pkg.Export != "" && !seen[pkg.Export] {
			info, err := os.Stat(pkg.Export)
			if err != nil {
				t.Fatal(err)
			}
			seen[pkg.Export] = true
			compiledBytes = info.Size()
			exportBytes += compiledBytes
		}
		if packageBytes+compiledBytes >= 1<<20 {
			t.Logf("actual package=%s complete-source=%d export=%d", pkg.ImportPath, packageBytes, compiledBytes)
		}
	}
	driver, err := os.Stat(request.GoBinary)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("actual graph packages=%d complete-source=%d exports=%d driver=%d total-floor=%d (registered macro sources additional)",
		packages, sourceBytes, exportBytes, driver.Size(), sourceBytes+exportBytes+driver.Size())
	t.Logf("actual graph direct package members=%d; local-members/exports/driver floor=%d (SDK include closure additional)",
		packageLocalBytes, packageLocalBytes+exportBytes+driver.Size())
	observed, err := CaptureAMD64OriginalPackageObservation(ctx, request, RunBounded)
	if err != nil {
		t.Fatalf("original-Go accepted SDK graph must retain a complete bounded observation: %v", err)
	}
	defer func() {
		if err := observed.Close(); err != nil {
			t.Error(err)
		}
	}()
	if crypto {
		if _, exists := observed.state.packages["crypto/tls"]; exists {
			t.Fatal("fixture unexpectedly imports the unrelated descendant package")
		}
		root := observed.state.environment["GOROOT"]
		if observed.state.files.hashes[filepath.Join(root, "src", "crypto", "tls", "tls.go")] != "" {
			t.Fatal("SDK ancestor imported an unrelated descendant's contents")
		}
	}
	if err := observed.Verify(ctx); err != nil {
		t.Fatal(err)
	}
}
