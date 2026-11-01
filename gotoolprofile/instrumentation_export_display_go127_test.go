//go:build go1.27

package gotoolprofile

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestInstrumentationExportActualGoQuotedOwnedPath(t *testing.T) {
	binary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	owned := filepath.Join(instrumentationMarkerDirectory(t), "owned marker with spaces")
	if err := os.Mkdir(owned, 0700); err != nil {
		t.Fatal(err)
	}
	// The final archive-cache copy is a separate command-display producer
	// from the compiler and assembler. Exercise its actual quoting on every
	// host, not only Windows (where each backslash also requires quoting).
	cache := filepath.Join(t.TempDir(), "cache with spaces")
	if err := os.Mkdir(cache, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOCACHE", cache)
	var trace, nm []byte
	run := func(ctx context.Context, dir string, env []string, name string, args ...string) ([]byte, []byte, error) {
		stdout, stderr, err := RunBounded(ctx, dir, env, name, args...)
		if len(args) > 2 && args[0] == "list" && args[1] == "-a" && args[2] == "-x" {
			trace = append([]byte(nil), stderr...)
		}
		if len(args) == 3 && args[0] == "tool" && args[1] == "nm" {
			nm = append([]byte(nil), stdout...)
		}
		return stdout, stderr, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	proof, err := CaptureInstrumentationExportObservation(ctx, binary, owned, os.Environ(), "darwin/arm64",
		InstrumentationRace, "0", nil, run)
	if err != nil {
		t.Logf("actual original export -x trace:\n%s", trace)
		t.Logf("actual original export nm output:\n%s", nm)
		t.Fatal(err)
	}
	if !strings.Contains(string(trace), "owned marker with spaces") || !strings.Contains(string(trace), `"`) {
		t.Fatal("actual original export did not exercise Go's quoted path command display")
	}
	if err := ValidateInstrumentationExportObservation(proof); err != nil {
		t.Fatal(err)
	}
	t.Logf("actual selected SDK/target=%s/%s raw trace SHA256=%s portable routing SHA256=%s archive SHA256=%s",
		proof.Early.SourceRules.GoVersion, proof.Early.Target, bytesSHA256(trace), proof.Routing.TraceSHA256, proof.ArchiveSHA256)
}

func TestInstrumentationExportCommandDisplayActualRegisteredSDKSource(t *testing.T) {
	name := "src/cmd/go/internal/work/shell.go"
	data, err := readInstrumentationRegistration(filepath.Join(runtime.GOROOT(), filepath.FromSlash(name)))
	if err != nil {
		t.Fatal(err)
	}
	if bytesSHA256(data) != instrumentationExportEnvironmentSourceRegistration[name] {
		t.Fatal("command display's complete actual SDK source differs from its registered primary")
	}
	for _, declaration := range []string{"joinUnambiguously", "fmtCmd", "ShowCmd"} {
		text, digest, err := instrumentationExportDeclaration(name, data, declaration)
		if err != nil || len(text) == 0 || digest != instrumentationExportEnvironmentRegistrations[name+"#"+declaration] {
			t.Fatalf("missing complete actual display declaration %s: %v", declaration, err)
		}
		t.Logf("source=%s wholeSHA256=%s declaration=%s ASTSHA256=%s", name, bytesSHA256(data), declaration, digest)
		receipt, err := json.Marshal(map[string]string{"source_ref": name + "#" + declaration, "source_declaration": text, "ast_sha256": digest})
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("GO_EXPORT_DISPLAY_SOURCE %s", receipt)
	}
}

func TestInstrumentationExportCacheCopyActualRegisteredSDKSource(t *testing.T) {
	const name = "src/cmd/go/internal/work/buildid.go"
	const declaration = "updateBuildID"
	data, err := readInstrumentationRegistration(filepath.Join(runtime.GOROOT(), filepath.FromSlash(name)))
	if err != nil {
		t.Fatal(err)
	}
	text, digest, err := instrumentationExportDeclaration(name, data, declaration)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := json.Marshal(map[string]string{
		"source_ref": name + "#" + declaration, "source_sha256": bytesSHA256(data),
		"source_declaration": text, "ast_sha256": digest,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("GO_EXPORT_CACHE_SOURCE %s", receipt)
	if bytesSHA256(data) != instrumentationExportEnvironmentSourceRegistration[name] ||
		digest != instrumentationExportEnvironmentRegistrations[name+"#"+declaration] {
		t.Fatal("complete actual cache-copy producer is not registered")
	}
}
