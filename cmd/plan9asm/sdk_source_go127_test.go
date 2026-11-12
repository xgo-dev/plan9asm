//go:build go1.27

package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"go/types"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm"
	"github.com/xgo-dev/plan9asm/gotoolprofile"
	"github.com/xgo-dev/plan9asm/internal/sdkfrontend"
)

func setSimpleSDKProfile(t *testing.T) {
	t.Helper()
	for key, value := range map[string]string{
		"GOENV": "off", "GOWORK": "off", "GOTOOLCHAIN": "local",
		"GOFLAGS": "", "GOEXPERIMENT": "", "GOPACKAGESDRIVER": "off",
		"GOAMD64": "v1", "GO386": "sse2",
	} {
		t.Setenv(key, value)
	}
	for _, key := range []string{"CGO_ENABLED", "GOPATH", "GOMODCACHE", "GOTMPDIR"} {
		t.Setenv(key, "")
		if err := os.Unsetenv(key); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("GOCACHE", t.TempDir())
}

func TestTranslateOriginalSDKCRC32NumericalSource(t *testing.T) {
	verifyOriginalSDKCRC32NumericalSource(t, "linux")
}

func TestTranslateOriginalSDKCRC32NumericalSourceNonLinux(t *testing.T) {
	for _, goos := range []string{"darwin", "windows"} {
		t.Run(goos, func(t *testing.T) {
			verifyOriginalSDKCRC32NumericalSource(t, goos)
		})
	}
}

func verifyOriginalSDKCRC32NumericalSource(t *testing.T, goos string) {
	t.Helper()
	setSimpleSDKProfile(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	input := filepath.Join(runtime.GOROOT(), "src", "hash", "crc32", "crc32_amd64.s")
	original, err := os.ReadFile(input)
	if err != nil || !strings.Contains(string(original), "CMPB internal∕cpu·X86+") {
		t.Fatal("actual SDK CRC32 counterexample is absent", err)
	}
	pkg, err := loadPackage("hash/crc32", goos, "amd64")
	if err != nil {
		t.Fatal(err)
	}
	tr, ok, err := translateAsmForPackage(pkg.Package, input, goos, "amd64", false, pkg.selected)
	if err != nil || !ok {
		t.Fatalf("unchanged original SDK translation: %v (TEXT=%t)", err, ok)
	}
	if !strings.Contains(tr.LLVMIR, "target triple = \""+targetTriple(goos, "amd64")+"\"") {
		t.Fatal("translated SDK source did not retain its actual target triple")
	}
	llc := sdkLLVM22LLC(t, ctx)
	folder := t.TempDir()
	ir, object := filepath.Join(folder, "crc32.ll"), filepath.Join(folder, "crc32.o")
	if err := os.WriteFile(ir, []byte(tr.LLVMIR), 0600); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, err := gotoolprofile.RunBounded(ctx, folder, os.Environ(), llc, "-filetype=obj", "-o", object, ir)
	if err != nil || len(stderr) != 0 {
		t.Fatalf("actual SDK LLVM22 object: %v\n%s%s", err, stdout, stderr)
	}
	info, err := os.Stat(object)
	if err != nil || info.Size() == 0 {
		t.Fatal("LLVM22 object is absent", err)
	}
	after, err := os.ReadFile(input)
	if err != nil || sha256.Sum256(after) != sha256.Sum256(original) {
		t.Fatal("selected original SDK bytes changed", err)
	}
	t.Logf("original SDK SHA256=%x; LLVM22 object bytes=%d", sha256.Sum256(original), info.Size())
}

func TestSimpleCLIOriginalSDKCRC32PublicationAndRejection(t *testing.T) {
	setSimpleSDKProfile(t)
	input := filepath.Join(runtime.GOROOT(), "src", "hash", "crc32", "crc32_amd64.s")
	original, err := os.ReadFile(input)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"file", "package", "file-cgo"} {
		t.Run(mode, func(t *testing.T) {
			if mode == "file-cgo" {
				t.Setenv("CGO_ENABLED", "1")
			}
			folder := t.TempDir()
			meta := filepath.Join(folder, "metadata.json")
			output := filepath.Join(folder, "crc32.ll")
			args := []string{"-goos=linux", "-goarch=amd64", "-meta=" + meta}
			if strings.HasPrefix(mode, "file") {
				args = append(args, "-i="+input, "-o="+output)
			} else {
				args = append(args, "-dir="+folder, "hash/crc32")
				output = filepath.Join(folder, "crc32_amd64.s.ll")
			}
			if err := runTranspile(args); err != nil {
				t.Fatalf("public %s entry point rejected unchanged SDK source: %v", mode, err)
			}
			ir, err := os.ReadFile(output)
			if err != nil || !strings.Contains(string(ir), "hash/crc32.r2r1<>") ||
				!strings.Contains(string(ir), "internal/cpu.X86") || strings.Contains(string(ir), "hash/crc32.r2r1$local") {
				t.Fatalf("public SDK result lost the original native namespace: %v", err)
			}
			raw, err := os.ReadFile(meta)
			if err != nil || !json.Valid(raw) || !strings.Contains(string(raw), `"package": "hash/crc32"`) ||
				!strings.Contains(string(raw), `"resolved": "hash/crc32.ieeeCLMUL"`) {
				t.Fatalf("public SDK metadata is absent/incomplete: %v\n%s", err, raw)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			object := filepath.Join(folder, "crc32.o")
			stdout, stderr, err := gotoolprofile.RunBounded(ctx, folder, os.Environ(), sdkLLVM22LLC(t, ctx),
				"-filetype=obj", "-o", object, output)
			if err != nil || len(stderr) != 0 {
				t.Fatalf("public SDK LLVM22 object: %v\n%s%s", err, stdout, stderr)
			}
			if info, err := os.Stat(object); err != nil || info.Size() == 0 {
				t.Fatal("public SDK object is absent", err)
			}
		})
	}
	for _, row := range []struct{ key, value string }{{"GOAMD64", "v2"}, {"GOFLAGS", "-tags=unobserved_sdk_profile"}} {
		t.Run("reject-"+row.key, func(t *testing.T) {
			t.Setenv(row.key, row.value)
			folder := t.TempDir()
			output, meta := filepath.Join(folder, "rejected.ll"), filepath.Join(folder, "rejected.json")
			const retained = "preexisting output\n"
			for _, name := range []string{output, meta} {
				if err := os.WriteFile(name, []byte(retained), 0600); err != nil {
					t.Fatal(err)
				}
			}
			err := runTranspile([]string{"-goos=linux", "-goarch=amd64", "-i=" + input, "-o=" + output, "-meta=" + meta})
			if !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
				t.Fatalf("unobserved profile was not rejected with its missing source contract: %v", err)
			}
			for _, name := range []string{output, meta} {
				actual, err := os.ReadFile(name)
				if err != nil || string(actual) != retained {
					t.Fatalf("failed source observation published/overwrote output: %v", err)
				}
			}
		})
	}
	after, err := os.ReadFile(input)
	if err != nil || sha256.Sum256(after) != sha256.Sum256(original) {
		t.Fatal("public CLI changed original selected SDK source", err)
	}
}

func TestSimpleSDKVariableQueryUsesOriginalMapsSource(t *testing.T) {
	setSimpleSDKProfile(t)
	pkg, err := loadPackage("internal/runtime/maps", "linux", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(pkg.Dir, "memhash_amd64.s")
	selected := false
	for _, name := range pkg.OtherFiles {
		selected = selected || name == input
	}
	if !selected {
		t.Fatal("the actual original SDK load did not select its AES source")
	}
	source, err := plan9asm.ReadGoAssemblySource(input, pkg.Dir)
	if err != nil {
		t.Fatal(err)
	}
	file, err := plan9asm.ParseWithDefines(plan9asm.ArchAMD64, string(source), plan9asm.GoAssemblerDefines("linux", "amd64"))
	if err != nil {
		t.Fatal(err)
	}
	view := sdkPackageView(pkg.Package)
	if sdkfrontend.CPUOwnerRequested(view, file, "linux/amd64") || !sdkfrontend.NumericalOwnerRequested(view, file, "linux/amd64") {
		t.Fatal("the original SDK's Go-variable source still depends on the CPU-only cost query")
	}
	queries := sdkfrontend.OwnerRequests(view, file, "linux/amd64")
	if len(queries) != 1 || queries[0].CPU || queries[0].PackagePath != pkg.PkgPath || len(queries[0].Variables) != 1 ||
		queries[0].Variables[0].Name != "aeskeysched" {
		t.Fatalf("original typed Go-variable query is incomplete: %+v", queries)
	}
	variable, valid := pkg.Types.Scope().Lookup("aeskeysched").(*types.Var)
	if !valid || pkg.TypesSizes.Sizeof(variable.Type()) != 128 {
		t.Fatal("actual compiler-selected variable/type extent differs")
	}
	// This original-source/type query is not an ABIInternal/native-entry join
	// or successful maps translation. Those remain independent core contracts.
}

func TestSimpleCLIOriginalSDKMapsScalarRegisterSource(t *testing.T) {
	setSimpleSDKProfile(t)
	input := filepath.Join(runtime.GOROOT(), "src", "internal", "runtime", "maps", "memhash_nosimd_amd64.s")
	original, err := os.ReadFile(input)
	if err != nil || !strings.Contains(string(original), "TEXT ·memHash32AES<ABIInternal>") ||
		!strings.Contains(string(original), "TEXT ·memHash64AES<ABIInternal>") {
		t.Fatal("complete original SDK scalar-register counterexample is absent", err)
	}
	folder := t.TempDir()
	output, meta := filepath.Join(folder, "maps.ll"), filepath.Join(folder, "maps.json")
	if err := runTranspile([]string{"-goos=linux", "-goarch=amd64", "-i=" + input, "-o=" + output, "-meta=" + meta}); err != nil {
		t.Fatalf("complete unchanged SDK scalar-register source: %v", err)
	}
	raw, err := os.ReadFile(meta)
	if err != nil {
		t.Fatal(err)
	}
	var metadata struct{ Functions []functionInfo }
	if err := json.Unmarshal(raw, &metadata); err != nil || len(metadata.Functions) != 2 {
		t.Fatalf("complete SDK scalar-register functions were not published: %v\n%s", err, raw)
	}
	for index, fn := range metadata.Functions {
		first := "i32"
		if index == 1 {
			first = "i64"
		}
		if fn.Resolved != "internal/runtime/maps.memHash"+map[int]string{0: "32", 1: "64"}[index]+"AES" ||
			len(fn.Args) != 2 || fn.Args[0] != first || fn.Args[1] != "i64" || fn.Ret != "i64" {
			t.Fatalf("actual integer declaration/namespace changed: %+v", fn)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	llc := sdkLLVM22LLC(t, ctx)
	for _, optimization := range []string{"0", "2"} {
		object := filepath.Join(folder, "maps-O"+optimization+".o")
		stdout, stderr, err := gotoolprofile.RunBounded(ctx, folder, os.Environ(), llc,
			"-O="+optimization, "-filetype=obj", "-o", object, output)
		if err != nil || len(stderr) != 0 {
			t.Fatalf("complete SDK scalar-register LLVM22 O%s object: %v\n%s%s", optimization, err, stdout, stderr)
		}
		if info, err := os.Stat(object); err != nil || info.Size() == 0 {
			t.Fatal("complete SDK scalar-register object is absent", err)
		}
	}
	after, err := os.ReadFile(input)
	if err != nil || sha256.Sum256(after) != sha256.Sum256(original) {
		t.Fatal("SDK scalar-register original source changed", err)
	}
	t.Logf("complete original SDK scalar-register SHA256=%x; both declarations and LLVM22 O0/O2 objects passed", sha256.Sum256(original))
}

func sdkLLVM22LLC(t *testing.T, ctx context.Context) string {
	t.Helper()
	candidates := []string{"llc-22", "llc"}
	if config := os.Getenv("LLVM_CONFIG"); config != "" {
		bin, stderr, err := gotoolprofile.RunBounded(ctx, "", os.Environ(), config, "--bindir")
		if err != nil || len(stderr) != 0 {
			t.Fatalf("selected LLVM_CONFIG: %v\n%s%s", err, bin, stderr)
		}
		candidates = []string{filepath.Join(strings.TrimSpace(string(bin)), "llc")}
	}
	for _, candidate := range candidates {
		llc, err := exec.LookPath(candidate)
		if err != nil {
			continue
		}
		version, stderr, err := gotoolprofile.RunBounded(ctx, "", os.Environ(), llc, "--version")
		if err == nil && len(stderr) == 0 && strings.Contains(string(version), "LLVM version 22.") {
			return llc
		}
	}
	t.Fatal("required LLVM22 llc is absent")
	return ""
}
