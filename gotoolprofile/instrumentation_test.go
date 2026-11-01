package gotoolprofile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestInstrumentationBuildFlagsAreExclusiveDriverModes(t *testing.T) {
	for _, mode := range []string{"race", "msan", "asan"} {
		flags, err := InstrumentationBuildFlags(InstrumentationMode(mode))
		if err != nil || !reflect.DeepEqual(flags, []string{"-" + mode}) {
			t.Fatalf("%s: flags=%v err=%v", mode, flags, err)
		}
		flags[0] = "-tags=" + mode
		again, _ := InstrumentationBuildFlags(InstrumentationMode(mode))
		if again[0] != "-"+mode {
			t.Fatal("caller mutated another invocation's flags")
		}
	}
	for _, mode := range []string{"", "baseline", "Race", "race,asan", "-race", "race -asan", "cgo", "race\n"} {
		if _, err := InstrumentationBuildFlags(InstrumentationMode(mode)); err == nil {
			t.Fatalf("accepted non-mode %q", mode)
		}
	}
}

func TestInstrumentationRulesReadActualGoRegistration(t *testing.T) {
	rules, err := CaptureInstrumentationSourceRules(runtime.GOROOT(), runtime.Version())
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		target, mode, buildmode string
		cgo                     bool
	}{
		{"darwin/arm64", "race", "default", false},
		{"linux/arm64", "race", "default", true},
		{"linux/amd64", "msan", "default", true},
		{"linux/arm64", "msan", "pie", true},
		{"linux/arm64", "asan", "default", true},
	} {
		if required, err := rules.RequiresCGO(test.target, InstrumentationMode(test.mode)); err != nil || required != test.cgo {
			t.Fatalf("%+v: CGO=%v err=%v", test, required, err)
		}
		if mode, err := rules.EffectiveBuildMode(test.target, InstrumentationMode(test.mode)); err != nil || mode != test.buildmode {
			t.Fatalf("%+v: buildmode=%q err=%v", test, mode, err)
		}
	}
	if err := rules.Recheck(); err != nil {
		t.Fatal(err)
	}
	sources, registration := rules.SourceHashes(), rules.RegistrationHashes()
	if len(sources) != 3 || len(registration) != 4 {
		t.Fatalf("incomplete source and registration identities: %v / %v", sources, registration)
	}
	sources["VERSION"], registration["instrumentInit"] = "changed", "changed"
	if err := rules.Recheck(); err != nil {
		t.Fatalf("caller mutated private rule capture through an accessor: %v", err)
	}
	var missing *InstrumentationSourceRules
	if _, err := missing.TargetSupported("darwin/arm64", InstrumentationRace); err == nil {
		t.Fatal("missing registration became target exclusion")
	}
	for _, target := range []string{"", "darwin", "darwin/arm64/race", "darwin /arm64", "linux/arm64\n", "linux/mips"} {
		if _, err := rules.TargetSupported(target, InstrumentationRace); err == nil {
			t.Fatalf("invalid or out-of-scope target %q was classified", target)
		}
	}
	if _, err := rules.RequiresCGO("darwin/arm64", InstrumentationASan); err == nil {
		t.Fatal("rejected target received an effective CGO claim")
	}
	if _, err := rules.EffectiveBuildMode("darwin/arm64", InstrumentationMSan); err == nil {
		t.Fatal("rejected target received an effective PIE claim")
	}
	minor, err := goMinor(runtime.Version())
	if err != nil {
		t.Fatal(err)
	}
	wrongMinor := 20
	if minor == wrongMinor {
		wrongMinor++
	}
	for _, version := range []string{"go1.19.13", "go1.28.0", fmt.Sprintf("go1.%d.0", wrongMinor)} {
		if _, err := CaptureInstrumentationSourceRules(runtime.GOROOT(), version); err == nil {
			t.Fatalf("accepted wrong or unaudited version %s", version)
		}
	}
}

func TestInstrumentationSourceRegistrationRejectsChangedAndMissingRules(t *testing.T) {
	root := t.TempDir()
	for _, name := range instrumentationRuleSources {
		data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), filepath.FromSlash(name)))
		if err != nil {
			t.Fatal(err)
		}
		writeInstrumentationFixture(t, root, name, data)
	}
	rules, err := CaptureInstrumentationSourceRules(root, runtime.Version())
	if err != nil {
		t.Fatal(err)
	}
	initPath := filepath.Join(root, "src/cmd/go/internal/work/init.go")
	initial, err := os.ReadFile(initPath)
	if err != nil {
		t.Fatal(err)
	}
	changed := strings.Replace(string(initial), `cfg.Goos != "darwin"`, `cfg.Goos != "linux"`, 1)
	if changed == string(initial) {
		t.Fatal("actual registered CGO condition was not found")
	}
	writeInstrumentationFixture(t, root, "src/cmd/go/internal/work/init.go", []byte(changed))
	if _, err := CaptureInstrumentationSourceRules(root, runtime.Version()); err == nil {
		t.Fatal("accepted changed CGO/source semantics")
	}
	if err := rules.Recheck(); err == nil {
		t.Fatal("source mutation after capture was ignored")
	}
	writeInstrumentationFixture(t, root, "src/cmd/go/internal/work/init.go", initial)
	if err := os.Remove(filepath.Join(root, "src/internal/platform/supported.go")); err != nil {
		t.Fatal(err)
	}
	if _, err := CaptureInstrumentationSourceRules(root, runtime.Version()); err == nil {
		t.Fatal("missing platform registration became unsupported target")
	}
}

func TestInstrumentationTargetGrammarIsCompleteAndFailClosed(t *testing.T) {
	valid := `package platform
func RaceDetectorSupported(goos, goarch string) bool {
 switch goos {
 case "linux", "freebsd": return goarch == "amd64" || goarch == "arm64"
 case "darwin": return "amd64" == goarch
 default: return false
 }
}`
	targets, err := parseInstrumentationTargetRule([]byte(valid), "RaceDetectorSupported")
	if err != nil || !targets["linux/amd64"] || !targets["freebsd/arm64"] || !targets["darwin/amd64"] || targets["darwin/arm64"] {
		t.Fatalf("source-derived target rule=%v err=%v", targets, err)
	}
	for _, changed := range []string{
		strings.Replace(valid, `goarch == "arm64"`, `goarch != "arm64"`, 1),
		strings.Replace(valid, `return false`, `return true`, 1),
		strings.Replace(valid, `case "darwin"`, `case "linux"`, 1),
		strings.Replace(valid, `return "amd64" == goarch`, `log(); return "amd64" == goarch`, 1),
		strings.Replace(valid, `switch goos`, `switch unknown`, 1),
		strings.Replace(valid, `goos, goarch string`, `goos, goarch int`, 1),
		strings.Replace(valid, `goarch == "arm64"`, `goarch == "amd64"`, 1),
		strings.Replace(valid, `default: return false`, ``, 1),
		strings.Replace(valid, `"linux", "freebsd"`, `"linux", "linux"`, 1),
		strings.Replace(valid, `"arm64"`, `"arm 64"`, 1),
		valid + `
func RaceDetectorSupported(goos, goarch string) bool { return true }`,
	} {
		if _, err := parseInstrumentationTargetRule([]byte(changed), "RaceDetectorSupported"); err == nil {
			t.Fatalf("accepted incomplete/unknown target grammar: %s", changed)
		}
	}
}

// This checks actual cmd/go early target rules and source selection, not
// compile/export, sanitizer libraries, cross SDKs, or runtime support.
func TestInstrumentationActualGoEarlyRulesAllDefaultTargets(t *testing.T) {
	rules, err := CaptureInstrumentationSourceRules(runtime.GOROOT(), runtime.Version())
	if err != nil {
		t.Fatal(err)
	}
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	directory := instrumentationMarkerDirectory(t)
	tags := []string{"asan", "msan", "race"}
	for name, data := range MarkerFiles(tags) {
		writeInstrumentationFixture(t, directory, name, data)
	}
	targets := []string{"darwin/amd64", "darwin/arm64", "linux/386", "linux/amd64", "linux/arm", "linux/arm64", "windows/386", "windows/amd64", "windows/arm64", "js/wasm", "wasip1/wasm"}
	for _, target := range targets {
		for _, mode := range tags {
			t.Run(target+"/"+mode, func(t *testing.T) {
				// Go 1.20 has no wasip1, but mode validation runs before
				// target package loading and must still reject this pair.
				env := instrumentationActualEnv(target, "1")
				flags, _ := InstrumentationBuildFlags(InstrumentationMode(mode))
				args := append([]string{"list", "-find", "-json", "-mod=readonly"}, flags...)
				args = append(args, ".")
				stdout, stderr, commandErr := instrumentationActualCommand(t, directory, env, goBinary, args...)
				status, err := ClassifyInstrumentationEarlyResult(rules, target, InstrumentationMode(mode), stdout, stderr, commandErr)
				if err != nil {
					t.Fatalf("actual driver: %s: %v", stderr, err)
				}
				if status == InstrumentationOfficialTargetUnsupported {
					return
				}
				selected, err := DecodeMarkers(stdout, directory, tags)
				if err != nil {
					t.Fatal(err)
				}
				for _, tag := range tags {
					if selected[tag] != (tag == mode) {
						t.Fatalf("mode flags did not independently select complete marker namespace: %v", selected)
					}
				}
			})
		}
	}
	if err := rules.Recheck(); err != nil {
		t.Fatal(err)
	}
}

func TestInstrumentationActualGoPrerequisitesAndConflictStayFailures(t *testing.T) {
	rules, err := CaptureInstrumentationSourceRules(runtime.GOROOT(), runtime.Version())
	if err != nil {
		t.Fatal(err)
	}
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	directory := instrumentationMarkerDirectory(t)
	for name, data := range MarkerFiles([]string{"asan", "msan", "race"}) {
		writeInstrumentationFixture(t, directory, name, data)
	}
	for _, mode := range []string{"race", "msan", "asan"} {
		stdout, stderr, commandErr := instrumentationActualCommand(t, directory, instrumentationActualEnv("linux/arm64", "0"), goBinary, "list", "-find", "-json", "-"+mode, ".")
		if commandErr == nil || !strings.HasPrefix(string(stderr), "go: -"+mode+" requires cgo") {
			t.Fatalf("actual CGO prerequisite missing: %s: %v", stderr, commandErr)
		}
		if _, err := ClassifyInstrumentationEarlyResult(rules, "linux/arm64", InstrumentationMode(mode), stdout, stderr, commandErr); err == nil {
			t.Fatal("CGO/tool failure became target rejection or acceptance")
		}
	}
	for _, modes := range [][2]string{{"race", "msan"}, {"race", "asan"}, {"msan", "asan"}} {
		_, stderr, commandErr := instrumentationActualCommand(t, directory, instrumentationActualEnv("linux/arm64", "1"), goBinary, "list", "-find", "-"+modes[0], "-"+modes[1], ".")
		want := "go: may not use -" + modes[0] + " and -" + modes[1] + " simultaneously\n"
		if commandErr == nil || string(stderr) != want {
			t.Fatalf("actual mode conflict=%q err=%v", stderr, commandErr)
		}
	}
	env := replaceEnv(instrumentationActualEnv("linux/arm64", "1"), map[string]string{"CC": filepath.Join(directory, "missing-clang")})
	stdout, stderr, commandErr := instrumentationActualCommand(t, directory, env, goBinary, "list", "-find", "-asan", ".")
	if commandErr == nil {
		t.Fatal("actual missing CC did not fail")
	}
	if _, err := ClassifyInstrumentationEarlyResult(rules, "linux/arm64", "asan", stdout, stderr, commandErr); err == nil {
		t.Fatal("missing CC became source/target N/A")
	}
}

func TestInstrumentationEarlyRejectionRequiresExactCompleteActualExit(t *testing.T) {
	rules, err := CaptureInstrumentationSourceRules(runtime.GOROOT(), runtime.Version())
	if err != nil {
		t.Fatal(err)
	}
	directory := instrumentationMarkerDirectory(t)
	for name, data := range MarkerFiles([]string{"asan"}) {
		writeInstrumentationFixture(t, directory, name, data)
	}
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	stdout, stderr, actualErr := instrumentationActualCommand(t, directory, instrumentationActualEnv("darwin/arm64", "1"), goBinary, "list", "-find", "-asan", ".")
	if status, err := ClassifyInstrumentationEarlyResult(rules, "darwin/arm64", "asan", stdout, stderr, actualErr); err != nil || status != InstrumentationOfficialTargetUnsupported {
		t.Fatalf("exact actual rejection=%s err=%v", status, err)
	}
	for _, bad := range []struct {
		stdout, stderr []byte
		err            error
	}{
		{[]byte("{}"), stderr, actualErr},
		{nil, append(append([]byte(nil), stderr...), []byte("network failure\n")...), actualErr},
		{nil, []byte("-asan is not supported on linux/arm64\n"), actualErr},
		{nil, stderr, errors.New("exit status 2")},
		{nil, stderr, errors.Join(actualErr, context.DeadlineExceeded)},
		{nil, stderr, nil},
	} {
		if _, err := ClassifyInstrumentationEarlyResult(rules, "darwin/arm64", "asan", bad.stdout, bad.stderr, bad.err); err == nil {
			t.Fatal("partial, mixed, fabricated, timed-out, or successful diagnostic became target exclusion")
		}
	}
	for _, stdout := range [][]byte{nil, []byte("null"), []byte("{}"), []byte(`{"Dir":"a","ImportPath":"b","GoFiles":["a.go"],"Error":{"Err":"failed"}}`)} {
		if _, err := ClassifyInstrumentationEarlyResult(rules, "darwin/arm64", "race", stdout, nil, nil); err == nil {
			t.Fatal("empty, malformed, or failed package output became actual selection")
		}
	}
}

func TestInstrumentationAcceptedEarlyResultRejectsUnknownStderr(t *testing.T) {
	rules, err := CaptureInstrumentationSourceRules(runtime.GOROOT(), runtime.Version())
	if err != nil {
		t.Fatal(err)
	}
	directory := instrumentationMarkerDirectory(t)
	for name, data := range MarkerFiles([]string{"asan", "msan", "race"}) {
		writeInstrumentationFixture(t, directory, name, data)
	}
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	stdout, stderr, commandErr := instrumentationActualCommand(t, directory, instrumentationActualEnv("darwin/arm64", "0"), goBinary, "list", "-find", "-json", "-race", ".")
	if commandErr != nil || len(stderr) != 0 {
		t.Fatalf("zero-dependency actual marker emitted unexpected diagnostics: %s: %v", stderr, commandErr)
	}
	if status, err := ClassifyInstrumentationEarlyResult(rules, "darwin/arm64", InstrumentationRace, stdout, stderr, nil); err != nil || status != InstrumentationEarlyRuleAccepted {
		t.Fatalf("complete actual marker was rejected: %s: %v", status, err)
	}
	for _, diagnostics := range []string{
		"unknown tool warning\n", "go: downloading unregistered/module v1.0.0\n",
		"go: network unavailable\n", "-race is not supported on darwin/arm64\n",
		"actual informational message\ncompiler error\n", " ",
	} {
		if _, err := ClassifyInstrumentationEarlyResult(rules, "darwin/arm64", InstrumentationRace, stdout, []byte(diagnostics), nil); err == nil {
			t.Fatalf("accepted unregistered stderr alongside successful actual selection: %q", diagnostics)
		}
	}
	env := replaceEnv(instrumentationActualEnv("darwin/arm64", "0"), map[string]string{"GODEBUG": "cpu.plan9asm_unregistered=off"})
	stdout, stderr, commandErr = instrumentationActualCommand(t, directory, env, goBinary, "list", "-find", "-json", "-race", ".")
	if commandErr != nil || !strings.Contains(string(stderr), "unknown cpu feature \"plan9asm_unregistered\"") {
		t.Fatalf("actual successful driver warning was not reproduced: %s: %v", stderr, commandErr)
	}
	t.Logf("actual exit-0 driver warning: %q", stderr)
	if _, err := ClassifyInstrumentationEarlyResult(rules, "darwin/arm64", InstrumentationRace, stdout, stderr, commandErr); err == nil {
		t.Fatal("actual exit-0 unknown CPU warning became accepted instrumentation selection")
	}
}

func instrumentationMarkerDirectory(t *testing.T) string {
	t.Helper()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return directory
}

func writeInstrumentationFixture(t *testing.T, root, name string, data []byte) {
	t.Helper()
	file := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func instrumentationActualEnv(target, cgo string) []string {
	parts := strings.Split(target, "/")
	return replaceEnv(os.Environ(), map[string]string{"GOOS": parts[0], "GOARCH": parts[1], "CGO_ENABLED": cgo, "GOTOOLCHAIN": "local", "GOWORK": "off", "GOFLAGS": "", "GOENV": "off", "GOEXPERIMENT": ""})
}

func instrumentationActualCommand(t *testing.T, dir string, env []string, binary string, args ...string) ([]byte, []byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	return RunBounded(ctx, dir, env, binary, args...)
}

func decodeInstrumentationAssemblySelection(t *testing.T, stdout []byte) (string, []string, []string) {
	t.Helper()
	var pkg struct {
		Export, ImportPath string
		GoFiles, SFiles    []string
		Error              *struct{ Err string }
	}
	if err := json.Unmarshal(stdout, &pkg); err != nil || pkg.Error != nil || pkg.ImportPath != "example.invalid/instrumentation-assembly" {
		t.Fatalf("actual assembly marker package: %s: %v", stdout, err)
	}
	return pkg.Export, pkg.GoFiles, pkg.SFiles
}
