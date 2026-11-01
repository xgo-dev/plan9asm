//go:build go1.27

package plan9asm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
	"github.com/xgo-dev/plan9asm/internal/gotoolchain"
	"github.com/xgo-dev/plan9asm/internal/sourcepath"
)

// Reuse the native-width family, not Or32 or a fabricated allocation. All
// declarations and assembly calls are private, numeric and in one source file.
func arm64ByteCarrierFixture(t *testing.T) (string, string, []arm64NativeResultTailCase) {
	t.Helper()
	directory := t.TempDir()
	var err error
	directory, err = filepath.EvalSymlinks(directory)
	if err != nil {
		t.Fatal(err)
	}
	packagePath := "example.invalid/carrierfixture"
	cases := arm64NativeResultTailCases()
	var declarations, assembly strings.Builder
	declarations.WriteString("package carrierfixture\n\n")
	for _, test := range cases {
		name := strings.ToLower(test.name())
		declarations.WriteString(strings.ReplaceAll(test.declaration(), test.name(), name))
		fmt.Fprintf(&declarations, "func observe_%s(input uint64) (value,native,guard uint64)\n", name)
		fmt.Fprintf(&declarations, "func entry_%s(input uint64) (uint64,uint64,uint64) {\nreturn observe_%s(input)\n}\n", name, name)
		assembly.WriteString(strings.ReplaceAll(test.source(), test.name(), name))
		assembly.WriteString(strings.ReplaceAll(arm64NativeResultTailObserver(test), test.name(), name))
	}
	for name, data := range map[string]string{
		"go.mod":  "module " + packagePath + "\ngo 1.20\n",
		"decl.go": declarations.String(), "original_arm64.s": assembly.String(),
	} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return directory, packagePath, cases
}

func arm64ByteCarrierOriginal(t *testing.T, directory, packagePath string) ([]byte, []byte, []byte) {
	t.Helper()
	return arm64ByteCarrierOriginalForOS(t, "linux", directory, packagePath)
}

func arm64ByteCarrierOriginalForOS(t *testing.T, goos, directory, packagePath string) ([]byte, []byte, []byte) {
	t.Helper()
	selection := arm64ABI0RegionCommand(t, goos, directory, "list", "-json", "-compiled", "-export", "-mod=readonly", ".")
	var selected goAMD64FrameSelection
	decoder := json.NewDecoder(bytes.NewReader(selection))
	if err := decoder.Decode(&selected); err != nil {
		t.Fatal(err)
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF || selected.ImportPath != packagePath ||
		len(selected.SFiles) != 1 || selected.SFiles[0] != "original_arm64.s" || selected.Export == "" {
		t.Fatalf("actual complete first-party source selection differs: %s", selection)
	}
	archive, err := os.ReadFile(selected.Export)
	if err != nil {
		t.Fatal(err)
	}
	objectName := filepath.Join(t.TempDir(), "original.o")
	arm64ABI0RegionCommand(t, goos, directory, "tool", "asm", "-p", packagePath,
		"-o", objectName, "original_arm64.s")
	object, err := os.ReadFile(objectName)
	if err != nil {
		t.Fatal(err)
	}
	builtins, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/goobj/builtinlist.go"))
	if err != nil {
		t.Fatal(err)
	}
	return archive, object, builtins
}

func TestARM64ByteCarrierActualSourceTargetMatrix(t *testing.T) {
	directory, packagePath, cases := arm64ByteCarrierFixture(t)
	base := arm64ByteCarrierRequest(t, directory, packagePath)
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	for _, goos := range []string{"darwin", "linux", "windows", "freebsd", "openbsd"} {
		t.Run(goos, func(t *testing.T) {
			archive, object, builtins := arm64ByteCarrierOriginalForOS(t, goos, directory, packagePath)
			target := goos + "/arm64"
			if records, err := gostaticstorage.ObserveARM64AssemblyText(object, builtins, target); err != nil || len(records) != 18 {
				t.Fatalf("actual target standalone object differs: %v", err)
			}
			if members, err := gostaticstorage.ObserveARM64AssemblyArchive(archive, builtins, target, []string{"original_arm64.s"}); err != nil || len(members) != 3 {
				t.Fatalf("actual target complete archive differs: %v", err)
			}
			request := base
			request.Target = target
			request.Environment = append([]string(nil), base.Environment...)
			for index, pair := range request.Environment {
				if strings.HasPrefix(pair, "GOOS=") {
					request.Environment[index] = "GOOS=" + goos
				}
			}
			source, err := CaptureGoARM64ByteCarrierSource(ctx, request)
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			if len(source.report.Calls) != len(cases) || len(source.report.Archive[1].Texts) != 27 {
				t.Fatal("target lost actual native caller or original typed compiler entry")
			}
		})
	}
}

func TestARM64ByteCarrierActualMainPackageIdentity(t *testing.T) {
	directory, packagePath, cases := arm64ByteCarrierFixture(t)
	filename := filepath.Join(directory, "decl.go")
	declarations, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	declarations = bytes.Replace(declarations, []byte("package carrierfixture"), []byte("package main"), 1)
	declarations = append(declarations, []byte("\nfunc main() {}\n")...)
	if err := os.WriteFile(filename, declarations, 0600); err != nil {
		t.Fatal(err)
	}
	base := arm64ByteCarrierRequest(t, directory, packagePath)
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	for _, goos := range []string{"darwin", "linux", "windows", "freebsd", "openbsd"} {
		t.Run(goos, func(t *testing.T) {
			// The driver determines its native -p identity from the package role,
			// not the module's import path. Inspect the actual archive independently.
			raw := arm64ABI0RegionCommand(t, goos, directory, "list", "-json", "-compiled", "-export", "-mod=readonly", ".")
			var selected goAMD64FrameSelection
			decoder := json.NewDecoder(bytes.NewReader(raw))
			var extra any
			if decoder.Decode(&selected) != nil || decoder.Decode(&extra) != io.EOF ||
				selected.Name != "main" || selected.ImportPath != packagePath {
				t.Fatalf("actual main package selection differs: %s", raw)
			}
			archive, err := os.ReadFile(selected.Export)
			if err != nil {
				t.Fatal(err)
			}
			builtins, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/goobj/builtinlist.go"))
			if err != nil {
				t.Fatal(err)
			}
			members, err := gostaticstorage.ObserveARM64AssemblyArchive(archive, builtins, goos+"/arm64", []string{"original_arm64.s"})
			if err != nil || len(members) != 3 {
				t.Fatalf("actual complete main archive differs: %v", err)
			}
			for _, text := range members[2].Texts {
				if !strings.HasPrefix(text.Name, "main.") || text.ABI != 0 {
					t.Fatalf("original driver did not use the main ASM identity: %+v", text)
				}
			}
			request := base
			request.Target = goos + "/arm64"
			request.Environment = append([]string(nil), base.Environment...)
			for index, pair := range request.Environment {
				if strings.HasPrefix(pair, "GOOS=") {
					request.Environment[index] = "GOOS=" + goos
				}
			}
			source, err := CaptureGoARM64ByteCarrierSource(ctx, request)
			if err != nil {
				t.Fatalf("actual main compiler/ASM identities fail their complete source join: %v", err)
			}
			defer source.Close()
			if len(source.report.Calls) != len(cases) {
				t.Fatal("main source omitted an actual call")
			}
			if source.report.NativePackagePath != "main" || source.request.PackagePath != packagePath {
				t.Fatal("native observation changed the original module identity")
			}
			arguments := source.report.Commands[len(source.report.Commands)-1].Arguments
			if len(arguments) < 5 || arguments[0] != "tool" || arguments[1] != "asm" || arguments[3] != "-p" || arguments[4] != "main" {
				t.Fatal("standalone namespace is not the actual ordinary driver's identity")
			}
			for _, call := range source.report.Calls {
				if !strings.HasPrefix(call.Caller, "main.") || !strings.HasPrefix(call.Callee, "main.") {
					t.Fatal("source observation reconstructed main identity from the import path")
				}
			}
		})
	}
}

func arm64ByteCarrierRequest(t *testing.T, directory, packagePath string) GoARM64ByteCarrierCaptureRequest {
	t.Helper()
	return arm64ByteCarrierRequestWithBuildCache(t, directory, packagePath, "")
}

func arm64ByteCarrierRequestWithBuildCache(t *testing.T, directory, packagePath, buildCache string) GoARM64ByteCarrierCaptureRequest {
	t.Helper()
	provided := make(map[string]string)
	for _, pair := range os.Environ() {
		key, value, _ := strings.Cut(pair, "=")
		provided[key] = value
	}
	for _, key := range []string{"GOCACHE", "GOMODCACHE", "GOPATH", "TMPDIR", "GOTMPDIR"} {
		if key == "GOCACHE" && buildCache != "" {
			root, err := filepath.EvalSymlinks(buildCache)
			if err != nil || !filepath.IsAbs(root) {
				t.Fatalf("shared owned build cache must be absolute: %v", err)
			}
			provided[key] = root
			continue
		}
		root, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		provided[key] = root
	}
	for key, value := range map[string]string{
		"GOOS": "linux", "GOARCH": "arm64", "GOARM64": "v8.0", "GOAMD64": "v1",
		"CGO_ENABLED": "0", "GOTOOLCHAIN": "local", "GOENV": "off", "GOWORK": "off",
		"GOFLAGS": "", "GOEXPERIMENT": "", "GOPROXY": "off", "GOPACKAGESDRIVER": "off",
	} {
		provided[key] = value
	}
	var environment []string
	for key, value := range provided {
		environment = append(environment, key+"="+value)
	}
	sort.Strings(environment)
	binary, err := sourcepath.Resolve(filepath.Join(runtime.GOROOT(), "bin", gotoolchain.HostExecutable("go")))
	if err != nil {
		t.Fatal("resolve the actual host Go driver", err)
	}
	return GoARM64ByteCarrierCaptureRequest{
		GoBinary: binary, Directory: directory,
		PackagePath: packagePath, AssemblyFile: "original_arm64.s", Target: "linux/arm64", Environment: environment,
	}
}

func TestARM64ByteCarrierSharedBuildCacheKeepsRequestsIndependent(t *testing.T) {
	cache := t.TempDir()
	first := arm64ByteCarrierRequestWithBuildCache(t, t.TempDir(), "example.invalid/first", cache)
	second := arm64ByteCarrierRequestWithBuildCache(t, t.TempDir(), "example.invalid/second", cache)
	environment := func(request GoARM64ByteCarrierCaptureRequest) map[string]string {
		values := make(map[string]string)
		for _, item := range request.Environment {
			key, value, _ := strings.Cut(item, "=")
			values[key] = value
		}
		return values
	}
	a, b := environment(first), environment(second)
	if a["GOCACHE"] != b["GOCACHE"] || a["GOCACHE"] == "" {
		t.Fatal("subtests must reuse the parent's owned build cache")
	}
	for _, key := range []string{"GOMODCACHE", "GOPATH", "TMPDIR", "GOTMPDIR"} {
		if a[key] == b[key] || a[key] == a["GOCACHE"] || b[key] == b["GOCACHE"] {
			t.Fatalf("source observation state shares %s", key)
		}
	}
	if first.Directory == second.Directory || first.PackagePath == second.PackagePath {
		t.Fatal("independent original source roles were reused")
	}
}

func TestARM64ByteCarrierActualSourceObservation(t *testing.T) {
	directory, packagePath, cases := arm64ByteCarrierFixture(t)
	// Original compiler success is established independently of the proposed
	// live source. The factory must then join all original entry/call records.
	arm64ByteCarrierOriginal(t, directory, packagePath)
	request := arm64ByteCarrierRequest(t, directory, packagePath)
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	source, err := CaptureGoARM64ByteCarrierSource(ctx, request)
	if err != nil {
		t.Fatalf("actual complete numeric caller/entry source is not observed: %v", err)
	}
	defer source.Close()
	raw, err := source.Readback(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var report struct {
		Protocol string
		Calls    []struct {
			Caller, Callee          string
			CallPC, ContinuationPC  int64
			CallerCode, CalleeCode  [32]byte
			CalleeSPReads, SPWrites []arm64ByteCarrierMemory
		}
		Archive []gostaticstorage.TextMember
	}
	if err := json.Unmarshal(raw, &report); err != nil || report.Protocol != "actual_go_arm64_byte_carrier_observation_v1" ||
		len(report.Calls) != len(cases) || len(report.Archive) != 3 || len(report.Archive[1].Texts) != 27 {
		t.Fatalf("actual complete caller/entry source observation differs: %v", err)
	}
	for _, call := range report.Calls {
		if call.Caller == "" || call.Callee == "" || call.CallPC < 0 || call.ContinuationPC != call.CallPC+4 {
			t.Fatalf("original call/continuation physical identity differs: %+v", call)
		}
		var family *arm64NativeResultTailCase
		for ordinal := range cases {
			if call.Callee == packagePath+"."+strings.ToLower(cases[ordinal].name()) {
				family = &cases[ordinal]
			}
		}
		if family == nil || len(call.CalleeSPReads) != 1 || len(call.SPWrites) != 1 ||
			call.CalleeSPReads[0].PC != 0 || call.CalleeSPReads[0].Offset != 8 || call.CalleeSPReads[0].Bytes != 8 ||
			call.SPWrites[0].PC != 4 || call.SPWrites[0].Offset != 16 || call.SPWrites[0].Bytes != int64(family.storeBits/8) {
			t.Fatalf("actual leaf byte-region mapping is not complete: %+v", call)
		}
		for _, text := range report.Archive[2].Texts {
			if text.Name == call.Caller && sha256.Sum256(text.Code) != call.CallerCode ||
				text.Name == call.Callee && sha256.Sum256(text.Code) != call.CalleeCode {
				t.Fatal("call/continuation joined a foreign original native object")
			}
		}
	}
	for _, test := range cases {
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(test.name()+"/no-consumer/"+api, func(t *testing.T) {
				_, err := arm64ResultTailAuditTranslate(t, api, "aarch64-unknown-linux-gnu", test.declaration(), test.source())
				if err == nil || !strings.Contains(err.Error(), "FP") {
					t.Fatalf("source observation fabricated writable FP tail: %v", err)
				}
			})
		}
	}
	if err := source.Close(); err != nil || !errors.Is(source.Verify(ctx), ErrProbeNeedsContext) {
		t.Fatalf("closed source retained a live observation: %v", err)
	}
}

func TestARM64ByteCarrierSourceRevocation(t *testing.T) {
	directory, packagePath, _ := arm64ByteCarrierFixture(t)
	request := arm64ByteCarrierRequest(t, directory, packagePath)
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	for _, test := range []struct {
		name   string
		mutate func(*GoARM64ByteCarrierSource) func()
	}{
		{"native-package-namespace", func(source *GoARM64ByteCarrierSource) func() {
			prior := source.report.NativePackagePath
			source.report.NativePackagePath = "main"
			return func() { source.report.NativePackagePath = prior }
		}},
		{"source-request", func(source *GoARM64ByteCarrierSource) func() {
			prior := source.request.PackagePath
			source.request.PackagePath += "/foreign"
			return func() { source.request.PackagePath = prior }
		}},
		{"call-continuation", func(source *GoARM64ByteCarrierSource) func() {
			source.report.Calls[0].ContinuationPC += 4
			return func() { source.report.Calls[0].ContinuationPC -= 4 }
		}},
		{"native-store-width", func(source *GoARM64ByteCarrierSource) func() {
			source.report.Calls[0].SPWrites[0].Bytes++
			return func() { source.report.Calls[0].SPWrites[0].Bytes-- }
		}},
		{"whole-callee-object", func(source *GoARM64ByteCarrierSource) func() {
			source.report.Standalone[0].Code[0] ^= 1
			return func() { source.report.Standalone[0].Code[0] ^= 1 }
		}},
		{"original-source-bytes", func(source *GoARM64ByteCarrierSource) func() {
			name := filepath.Join(directory, "decl.go")
			prior, err := os.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(name, append(append([]byte(nil), prior...), '\n'), 0600); err != nil {
				t.Fatal(err)
			}
			return func() {
				if err := os.WriteFile(name, prior, 0600); err != nil {
					t.Fatal(err)
				}
			}
		}},
		{"same-bytes-object-inode", func(source *GoARM64ByteCarrierSource) func() {
			name := filepath.Join(source.guard.owned, "original.o")
			backup := name + ".saved"
			prior, err := os.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(name, backup); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(name, prior, 0600); err != nil {
				t.Fatal(err)
			}
			return func() {
				if err := os.Rename(backup, name); err != nil {
					t.Fatal(err)
				}
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			source, err := CaptureGoARM64ByteCarrierSource(ctx, request)
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			restore := test.mutate(source)
			if !errors.Is(source.Verify(ctx), ErrProbeNeedsContext) {
				t.Fatal("changed actual source/caller identity remained live")
			}
			restore()
			if !errors.Is(source.Verify(ctx), ErrProbeNeedsContext) {
				t.Fatal("restoring bytes revived a revoked source")
			}
		})
	}
	for _, kind := range []string{"nil", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			source, err := CaptureGoARM64ByteCarrierSource(ctx, request)
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			var invalid context.Context
			cause := errors.New("source owner explicitly revoked")
			if kind == "cancelled" {
				cancelled, stop := context.WithCancelCause(ctx)
				stop(cause)
				invalid = cancelled
			}
			err = source.Verify(invalid)
			if !errors.Is(err, ErrProbeNeedsContext) || kind == "cancelled" && !errors.Is(err, cause) ||
				!errors.Is(source.Verify(ctx), ErrProbeNeedsContext) {
				t.Fatalf("invalid context revived a source or lost its actual cause: %v", err)
			}
		})
	}
	// A copied pointer graph cannot acquire the producer's identity, and
	// refusing the copy must not revoke or release the original source.
	source, err := CaptureGoARM64ByteCarrierSource(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	copied := &GoARM64ByteCarrierSource{identity: source, ready: true, guard: source.guard}
	if !errors.Is(copied.Verify(ctx), ErrProbeNeedsContext) || !errors.Is(copied.Close(), ErrProbeNeedsContext) || source.Verify(ctx) != nil {
		t.Fatal("copied source borrowed identity or released the original observation")
	}
}

func TestARM64ByteCarrierOriginalLeaseCannotBeRenewed(t *testing.T) {
	directory, packagePath, _ := arm64ByteCarrierFixture(t)
	request := arm64ByteCarrierRequest(t, directory, packagePath)
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	lease, stop := context.WithCancelCause(ctx)
	defer stop(nil)
	source, err := CaptureGoARM64ByteCarrierSource(lease, request)
	if err != nil {
		t.Fatalf("original bounded lease did not capture its complete source: %v", err)
	}
	defer source.Close()
	cause := errors.New("original source lease ended")
	stop(cause)
	err = source.Verify(ctx)
	if !errors.Is(err, ErrProbeNeedsContext) || !errors.Is(err, cause) {
		t.Fatalf("fresh verification context renewed the original cancelled source lease: %v", err)
	}
	if _, err := source.Readback(ctx); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("revoked lease yielded a portable source observation")
	}
}

func TestARM64ByteCarrierLeaseCancelsBoundedOperation(t *testing.T) {
	directory, packagePath, _ := arm64ByteCarrierFixture(t)
	request := arm64ByteCarrierRequest(t, directory, packagePath)
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	lease, stop := context.WithCancelCause(ctx)
	defer stop(nil)
	source, err := CaptureGoARM64ByteCarrierSource(lease, request)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	operation, release, err := source.executionContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	cause := errors.New("actual capture lease revoked during operation")
	stop(cause)
	select {
	case <-operation.Done():
		if !errors.Is(context.Cause(operation), cause) {
			t.Fatal("bounded operation lost its original lease cause")
		}
	case <-ctx.Done():
		t.Fatal("original lease did not cancel its live operation")
	}
}

func TestARM64ByteCarrierSourceRejectsOpenRoles(t *testing.T) {
	base, packagePath, _ := arm64ByteCarrierFixture(t)
	request := arm64ByteCarrierRequest(t, base, packagePath)
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	for _, test := range []struct {
		name   string
		file   string
		change func(string) string
	}{
		{"exported-entry", "decl.go", func(text string) string { return text + "\nfunc Visible() {}\n" }},
		{"function-address", "decl.go", func(text string) string { return text + "\nfunc escaped() { _ = movd_u32 }\n" }},
		{"pointer-transport", "decl.go", func(text string) string {
			return strings.Replace(text, "func movd_u32(input uint64)", "func movd_u32(input *uint64)", 1)
		}},
		{"linkname", "decl.go", func(text string) string {
			return strings.Replace(text, "package carrierfixture", "package carrierfixture\nimport _ \"unsafe\"", 1) +
				"\n//go:linkname movd_u32 foreign.movd_u32\n"
		}},
		{"text-declaration-mismatch", "original_arm64.s", func(text string) string { return strings.Replace(text, "$0-12", "$0-16", 1) }},
		{"native-code-address", "original_arm64.s", func(text string) string {
			return strings.Replace(text, "MOVD input+0(FP),R0", "MOVD $·movd_u32(SB),R0", 1)
		}},
		{"unknown-memory", "original_arm64.s", func(text string) string { return strings.Replace(text, "MOVD R0,8(RSP)", "MOVD R0,(R1)", 1) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"go.mod", "decl.go", "original_arm64.s"} {
				data, err := os.ReadFile(filepath.Join(base, name))
				if err != nil {
					t.Fatal(err)
				}
				if name == test.file {
					data = []byte(test.change(string(data)))
				}
				if err := os.WriteFile(filepath.Join(directory, name), data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			changed := request
			changed.Directory = directory
			// These counterexamples are accepted by the original Go compiler
			// and assembler. A factory role refusal is not a compiler-error pass.
			arm64ByteCarrierOriginal(t, directory, packagePath)
			if source, err := CaptureGoARM64ByteCarrierSource(ctx, changed); source != nil || !errors.Is(err, ErrProbeNeedsContext) {
				if source != nil {
					source.Close()
				}
				t.Fatalf("open/contradictory source role was admitted: %v", err)
			}
		})
	}
}

func TestARM64ByteCarrierActualArchiveObservation(t *testing.T) {
	directory, packagePath, cases := arm64ByteCarrierFixture(t)
	archive, object, builtins := arm64ByteCarrierOriginal(t, directory, packagePath)
	standalone, err := gostaticstorage.ObserveARM64AssemblyText(object, builtins, "linux/arm64")
	if err != nil {
		t.Fatalf("actual original Go caller/callee object is not observed: %v", err)
	}
	members, err := gostaticstorage.ObserveARM64AssemblyArchive(archive, builtins, "linux/arm64", []string{"original_arm64.s"})
	if err != nil {
		t.Fatalf("actual original Go complete caller/entry archive is not observed: %v", err)
	}
	if len(members) != 3 || members[1].Name != "_go_.o" || members[2].Name != "original_arm64.o" ||
		len(standalone) != 18 || len(members[2].Texts) != len(standalone) {
		t.Fatalf("incomplete original caller/callee/entry inventory: members=%d standalone=%d", len(members), len(standalone))
	}
	texts := make(map[string]gostaticstorage.TextRecord)
	for _, text := range members[2].Texts {
		texts[text.Name] = text
	}
	for _, original := range standalone {
		archived, exists := texts[original.Name]
		if !exists || original.ABI != archived.ABI || !bytes.Equal(original.Code, archived.Code) ||
			len(original.Relocations) != len(archived.Relocations) || len(archived.Positions) == 0 {
			t.Fatalf("standalone/archive original instruction join differs: %s", original.Name)
		}
	}
	for _, test := range cases {
		t.Run(test.name(), func(t *testing.T) {
			name := strings.ToLower(test.name())
			callee := texts[packagePath+"."+name]
			caller := texts[packagePath+".observe_"+name]
			if callee.ABI != 0 || caller.ABI != 0 || len(callee.Code) < 12 || len(caller.Code) == 0 {
				t.Fatal("original ABI0 caller/callee physical identity is missing")
			}
			// The actual native store keeps its whole width even when its Go
			// result is narrow. No padded FrameSlot is introduced by this test.
			store := binary.LittleEndian.Uint32(callee.Code[4:8])
			wanted := map[int]uint32{16: 0x790023e0, 32: 0xb90013e0, 64: 0xf9000be0}[test.storeBits]
			if store != wanted {
				t.Fatalf("native store width changed: got=%08x want=%08x", store, wanted)
			}
			calls := 0
			for _, relocation := range caller.Relocations {
				if relocation.Target.Name != callee.Name {
					continue
				}
				calls++
				pc := relocation.Offset
				if relocation.Size != 4 || pc < 0 || pc+8 > int64(len(caller.Code)) ||
					binary.LittleEndian.Uint32(caller.Code[pc:pc+4])&0xfc000000 != 0x94000000 ||
					!relocation.Target.ABIKnown || relocation.Target.ABI != callee.ABI {
					t.Fatalf("original direct call/continuation is not bound: %+v", relocation)
				}
			}
			if calls != 1 {
				t.Fatalf("same-file caller has %d original direct calls", calls)
			}
		})
	}
	for _, test := range []struct {
		name    string
		data    []byte
		target  string
		sources []string
	}{
		{"truncated", archive[:len(archive)-1], "linux/arm64", []string{"original_arm64.s"}},
		{"trailing", append(append([]byte(nil), archive...), 0), "linux/arm64", []string{"original_arm64.s"}},
		{"wrong-target", archive, "linux/amd64", []string{"original_arm64.s"}},
		{"omitted-member", archive, "linux/arm64", nil},
		{"foreign-member", archive, "linux/arm64", []string{"foreign.s"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := gostaticstorage.ObserveARM64AssemblyArchive(test.data, builtins, test.target, test.sources); err == nil {
				t.Fatal("incomplete or mismatched original archive was accepted")
			}
		})
	}
}
