//go:build go1.27 && ((linux && amd64) || (darwin && (amd64 || arm64)))

package gotoolprofile

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/gooriginalsrc"
)

// This exact fixture is a required Linux/amd64 CI counterpart to numerical
// observations on Darwin/Rosetta. Rosetta is not native alignment/fault proof.
func TestAMD64DownloadedFixedLocalLLVM22Numerical(t *testing.T) {
	ctx, cancel := amd64OriginalObservationContext(t)
	defer cancel()
	goos, triple := "linux", "x86_64-unknown-linux-gnu"
	var prefix []string
	if runtime.GOOS == "darwin" {
		goos, triple = "darwin", "x86_64-apple-darwin"
		if runtime.GOARCH == "arm64" {
			prefix = []string{"/usr/bin/arch", "-x86_64"}
		}
	}
	fixture := captureAMD64DownloadedLLVMFixture(t, ctx, goos, triple)
	llc := amd64DownloadedLLVM22Tool(t, ctx, fixture, "llc")
	clang := amd64DownloadedLLVM22Tool(t, ctx, fixture, "clang")
	if len(prefix) != 0 {
		output, stderr, err := RunBounded(ctx, fixture.request.Directory, fixture.request.Environment,
			prefix[0], append(prefix[1:], "/usr/bin/true")...)
		if err != nil || len(stderr) != 0 {
			t.Fatalf("required Rosetta numerical transport unavailable: %v; %s%s", err, output, stderr)
		}
		t.Log("ROSETTA_NUMERICAL_OBSERVATION_ONLY: no native alignment, fault or runtime-matrix claim")
	}
	if !t.Run("OriginalGoExactImport", func(t *testing.T) {
		fixture.originalGoNumerical(t, ctx, prefix)
	}) {
		return // An unsuccessful Go control cannot certify this numerical kernel.
	}
	for _, api := range []string{"Translate", "Module", "GoModule"} {
		t.Run(api, func(t *testing.T) {
			ir := fixture.ir(t, api)
			for _, level := range []string{"-O0", "-O2"} {
				t.Run(level, func(t *testing.T) {
					object := fixture.object(t, ctx, llc, ir, level)
					fixture.llvmNumerical(t, ctx, clang, object, prefix)
				})
			}
		})
	}
	if err := fixture.binding.Verify(ctx); err != nil {
		t.Fatal("runtime driver changed the original source/frame inputs", err)
	}
}

func (fixture amd64DownloadedLLVMFixture) runNumerical(t *testing.T, ctx context.Context, directory, executable string, prefix []string) {
	t.Helper()
	command := append(append([]string(nil), prefix...), executable)
	output, stderr, err := RunBounded(ctx, directory, fixture.request.Environment, command[0], command[1:]...)
	if err != nil || len(stderr) != 0 || string(output) != "DOWNLOADED_NUMERICAL_PASS 4096\n" {
		t.Fatalf("actual downloaded numerical execution: %v; %s%s", err, output, stderr)
	}
	t.Logf("ACTUAL_DOWNLOADED_NUMERICAL target=%s transport=%q %s", fixture.request.Target, prefix, strings.TrimSpace(string(output)))
}

func (fixture amd64DownloadedLLVMFixture) originalGoNumerical(t *testing.T, ctx context.Context, prefix []string) {
	t.Helper()
	directory := t.TempDir()
	metadata := "module example.invalid/downloaded-driver\ngo 1.20\nrequire " + fixture.sourceModule + " " + fixture.version + "\n"
	for name, source := range map[string]string{
		"go.mod":  metadata,
		"main.go": fmt.Sprintf(amd64DownloadedGoNumericalDriver, fixture.sourceModule),
	} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
	}
	// Only the independent driver is owned main. Its imported module must be
	// the exact original cache tree, never a replace or a copied source module.
	environment := replaceEnv(fixture.request.Environment, map[string]string{"GOPROXY": "off"})
	data, stderr, err := RunBounded(ctx, directory, environment, fixture.request.GoBinary,
		"list", "-compiled", "-export", "-json", "-mod=mod", fixture.sourceModule)
	if err != nil || len(stderr) != 0 {
		t.Fatalf("actual exact driver import failed: %v; %s%s", err, data, stderr)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	var selected amd64OriginalListPackage
	var extra any
	if err := decoder.Decode(&selected); err != nil || decoder.Decode(&extra) != io.EOF ||
		selected.Dir != fixture.request.Directory || selected.ImportPath != fixture.pkg.Path || selected.Export == "" ||
		selected.Module == nil || selected.Module.Main || selected.Module.Replace != nil ||
		selected.Module.Path != fixture.sourceModule || selected.Module.Version != fixture.version {
		t.Fatal("driver import did not retain the exact original downloaded identity", err)
	}
	t.Logf("ACTUAL_DRIVER_EXACT_IMPORT\n%s", data)
	executable := filepath.Join(directory, "original-go")
	output, stderr, err := RunBounded(ctx, directory, environment, fixture.request.GoBinary,
		"build", "-mod=readonly", "-o", executable, ".")
	if err != nil || len(stderr) != 0 {
		t.Fatalf("stock Go exact import driver build: %v; %s%s", err, output, stderr)
	}
	fixture.runNumerical(t, ctx, directory, executable, prefix)
	if err := fixture.observed.Verify(ctx); err != nil {
		t.Fatal("Go import driver changed original downloaded source bytes", err)
	}
}

func (fixture amd64DownloadedLLVMFixture) llvmNumerical(t *testing.T, ctx context.Context, clang, object string, prefix []string) {
	t.Helper()
	directory := t.TempDir()
	source, executable := filepath.Join(directory, "main.c"), filepath.Join(directory, "translated")
	symbol := fixture.pkg.Path + ".Value"
	if strings.HasPrefix(fixture.request.Target, "darwin/") {
		symbol = "_" + symbol
	}
	if err := os.WriteFile(source, []byte(fmt.Sprintf(amd64DownloadedCNumericalDriver, symbol)), 0600); err != nil {
		t.Fatal(err)
	}
	arguments := []string{"-target", fixture.backendTriple()}
	var macInputs *amd64DownloadedMacLinkInputs
	if strings.HasPrefix(fixture.request.Target, "darwin/") {
		macInputs = fixture.macLinkInputs(t, ctx, directory)
		// A version-specific clang default config can silently override the
		// linker sysroot. Select every SDK input explicitly instead.
		arguments = append(arguments, "--no-default-config", "-isysroot", macInputs.root,
			"-nostdlib", macInputs.systemLibrary)
	}
	arguments = append(arguments, object, source, "-O2", "-o", executable)
	t.Logf("ACTUAL_DOWNLOADED_LINK_ARGS binary=%q argv=%q", clang, arguments)
	output, stderr, err := RunBounded(ctx, directory, fixture.request.Environment, clang, arguments...)
	if macInputs != nil {
		macInputs.verify(t)
	}
	if err != nil || len(stderr) != 0 {
		t.Fatalf("LLVM22 actual downloaded numerical link: %v; %s%s", err, output, stderr)
	}
	fixture.runNumerical(t, ctx, directory, executable, prefix)
}

// These retained IO observations prove only the numerical link's real inputs.
// They never enter the downloaded factory, Source, signatures or Frame roles.
type amd64DownloadedMacLinkInputs struct {
	root, systemLibrary string
	info                os.FileInfo
	names               []string
	files               map[string]string
	snapshot            *gooriginalsrc.Snapshot
}

func (fixture amd64DownloadedLLVMFixture) macLinkInputs(t *testing.T, ctx context.Context, directory string) *amd64DownloadedMacLinkInputs {
	t.Helper()
	inputs := &amd64DownloadedMacLinkInputs{snapshot: gooriginalsrc.NewSnapshot(), files: make(map[string]string)}
	inputs.retain(t, "/usr/bin/xcrun")
	inputs.retain(t, "/usr/bin/ld")
	arguments := []string{"--sdk", "macosx", "--show-sdk-path"}
	data, stderr, err := RunBounded(ctx, directory, fixture.request.Environment, "/usr/bin/xcrun", arguments...)
	if err != nil || len(stderr) != 0 || !bytes.HasSuffix(data, []byte("\n")) {
		t.Fatalf("required actual macOS linker SDK: %v; %s%s", err, data, stderr)
	}
	requested := strings.TrimSuffix(string(data), "\n")
	if !filepath.IsAbs(requested) || strings.ContainsAny(requested, "\r\n") {
		t.Fatal("actual SDK path output is not one complete absolute path")
	}
	inputs.root, err = filepath.EvalSymlinks(requested)
	if err != nil {
		t.Fatal(err)
	}
	entries, info, err := gooriginalsrc.ReadDirectory(inputs.root, 256)
	if err != nil {
		t.Fatal(err)
	}
	inputs.info = info
	for _, entry := range entries {
		inputs.names = append(inputs.names, entry.Name())
	}
	inputs.systemLibrary = inputs.retain(t, filepath.Join(inputs.root, "usr", "lib", "libSystem.tbd"))
	for _, name := range []string{"SDKSettings.json", "SDKSettings.plist"} {
		inputs.retain(t, filepath.Join(inputs.root, name))
	}
	t.Logf("ACTUAL_MAC_SDK_SELECTION argv=%q stdout_hex=%x stderr_hex=%x requested=%q physical=%q identity=%+v members=%q",
		arguments, data, stderr, requested, inputs.root, info.Sys(), inputs.names)
	inputs.verify(t)
	return inputs
}

func (inputs *amd64DownloadedMacLinkInputs) retain(t *testing.T, name string) string {
	t.Helper()
	physical, err := filepath.EvalSymlinks(name)
	if err != nil {
		t.Fatal(err)
	}
	if err := inputs.snapshot.Retain(physical); err != nil {
		t.Fatal(err)
	}
	data, err := inputs.snapshot.ReadRetained(physical)
	if err != nil {
		t.Fatal(err)
	}
	inputs.files[physical] = bytesSHA256(data)
	t.Logf("ACTUAL_MAC_LINK_INPUT_BEFORE path=%q bytes=%d sha256=%s", physical, len(data), inputs.files[physical])
	return physical
}

func (inputs *amd64DownloadedMacLinkInputs) verify(t *testing.T) {
	t.Helper()
	entries, info, err := gooriginalsrc.ReadDirectory(inputs.root, 256)
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	if err != nil || !os.SameFile(inputs.info, info) || !reflect.DeepEqual(inputs.names, names) {
		t.Fatal("actual macOS SDK identity or inventory changed", err)
	}
	if err := inputs.snapshot.Verify(); err != nil {
		t.Fatal("actual macOS linker tool/SDK input changed", err)
	}
	for name, expected := range inputs.files {
		data, err := inputs.snapshot.ReadRetained(name)
		if err != nil || bytesSHA256(data) != expected {
			t.Fatal("actual macOS linker input bytes changed", err)
		}
		t.Logf("ACTUAL_MAC_LINK_INPUT_AFTER path=%q bytes=%d sha256=%s", name, len(data), expected)
	}
}

// Go and C independently compute two lane-wise uint32 additions. uint64 carry
// across lane boundaries is deliberately wrong; inputs include both overflow
// directions, all-zero/all-one values and 4,096 deterministic mixed bit patterns.
const amd64DownloadedGoNumericalDriver = `package main
import (
    "fmt"
    original %q
)
func main() {
    seed := uint64(0x9e3779b97f4a7c15)
    next := func() uint64 { seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17; return seed }
    edges := []uint64{0, 1, 0xffffffff, 0x100000000, 0xffffffff00000000, 0x7fffffff80000000, 0x800000007fffffff, ^uint64(0)}
    for i := 0; i < 4096; i++ {
        a, b, c, d := next(), next(), next(), next()
        if i < 64 { a, c = edges[i / 8], edges[i %% 8] }
        want := uint64(uint32(a) + uint32(c)) | uint64(uint32(a >> 32) + uint32(c >> 32)) << 32
        if got := original.Value(a, b, c, d); got != want { panic(fmt.Sprintf("case=%%d got=%%#x want=%%#x", i, got, want)) }
    }
    fmt.Println("DOWNLOADED_NUMERICAL_PASS 4096")
}
`

const amd64DownloadedCNumericalDriver = `typedef unsigned long long word;
extern int printf(const char *, ...);
extern word kernel(word, word, word, word) __asm__(%q);
static word seed = 0x9e3779b97f4a7c15ULL;
static word next(void) {
    seed ^= seed << 13;
    seed ^= seed >> 7;
    seed ^= seed << 17;
    return seed;
}
int main(void) {
    const word edges[] = {0, 1, 0xffffffffULL, 0x100000000ULL, 0xffffffff00000000ULL,
                         0x7fffffff80000000ULL, 0x800000007fffffffULL, ~0ULL};
    for (unsigned i = 0; i < 4096; ++i) {
        word a = next(), b = next(), c = next(), d = next();
        if (i < 64) { a = edges[i / 8]; c = edges[i %% 8]; }
        word low = (unsigned)a + (unsigned)c;
        word high = (unsigned)(a >> 32) + (unsigned)(c >> 32);
        word want = (low & 0xffffffffULL) | ((high & 0xffffffffULL) << 32);
        word got = kernel(a, b, c, d);
        if (got != want) {
            printf("case=%%u got=%%llx want=%%llx\n", i, got, want);
            return 1;
        }
    }
    printf("DOWNLOADED_NUMERICAL_PASS 4096\n");
    return 0;
}
`
