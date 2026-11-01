package plan9asm

import (
	"context"
	"encoding/json"
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

var compileBenchmarkScriptTargets = []string{
	"linux/386", "linux/amd64", "linux/arm", "linux/arm64", "js/wasm",
}

// These are command/report protocol fixtures, not Go/LLVM compilers or object
// evidence. Real standard-library compilation remains a separate required gate.
const compileBenchmarkScriptGoFixture = `#!/usr/bin/env bash
set -euo pipefail
if [[ "$1" == env && "$2" == GOVERSION ]]; then
  printf 'go1.27.1\n'
  exit 0
fi
if [[ "$1" != build ]]; then
  exit 91
fi
while (( $# > 0 )); do
  if [[ "$1" == -o ]]; then
    cp "$PLAN9ASM_BENCH_TEST_TRANSLATOR" "$2"
    exit 0
  fi
  shift
done
exit 92
`

const compileBenchmarkScriptTranslatorFixture = `#!/usr/bin/env bash
set -euo pipefail
goos= goarch= report= out= keep_going=
for arg in "$@"; do
  case "$arg" in
    -goos=*) goos=${arg#*=} ;;
    -goarch=*) goarch=${arg#*=} ;;
    -report=*) report=${arg#*=} ;;
    -out=*) out=${arg#*=} ;;
    -keep-going=*) keep_going=${arg#*=} ;;
  esac
done
printf '%s/%s %s\n' "$goos" "$goarch" "$keep_going" >> "$PLAN9ASM_BENCH_TEST_TRACE"
mkdir -p "$out"
printf 'protocol fixture only, not an LLVM object\n' > "$out/fixture.txt"

total=2 success=2 failed=0 na=0 code=0
if [[ "$goarch" == 386 ]]; then
  case "$PLAN9ASM_BENCH_TEST_MODE" in
    command_failure) success=1; failed=1; code=17 ;;
    failed_counts) success=1; failed=1 ;;
    nonzero_success_counts) code=17 ;;
    incomplete) success=1 ;;
    source_na) success=1; na=1 ;;
    empty) total=0; success=0 ;;
    negative_counts) success=-1; failed=3 ;;
    excessive_counts) success=3 ;;
    wrong_target) goarch=arm64 ;;
    target_budget) sleep 2 ;;
    malformed)
      printf '{invalid report\n' > "$report"
      exit 17
      ;;
    missing) exit 17 ;;
  esac
fi
printf '{"goos":"%s","goarch":"%s","asm_files":["one.s","two.s"],"total_asm":%s,"success":%s,"failed":%s,"not_applicable":%s,"duration":"1ms"}\n' \
  "$goos" "$goarch" "$total" "$success" "$failed" "$na" > "$report"
if (( failed > 0 )); then
  jq --argjson count "$failed" '
    .fails = [range(0; $count) | {pkg_path:"fixture", asm_file:"one.s", err:"protocol failure"}]
  ' "$report" > "$report.changed"
  mv "$report.changed" "$report"
fi
if [[ "$goarch" == 386 && "$PLAN9ASM_BENCH_TEST_MODE" == stale_failures ]]; then
  jq '.fails = [{pkg_path:"fixture", asm_file:"one.s", err:"retained failure"}]' \
    "$report" > "$report.changed"
  mv "$report.changed" "$report"
fi
if [[ "$goarch" == 386 && "$PLAN9ASM_BENCH_TEST_MODE" == duplicate_files ]]; then
  jq '.asm_files = ["one.s", "one.s"]' "$report" > "$report.changed"
  mv "$report.changed" "$report"
fi
exit "$code"
`

type compileBenchmarkScriptFixture struct {
	directory, report, trace, script string
	environment                      []string
}

func newCompileBenchmarkScriptFixture(t *testing.T, mode string) compileBenchmarkScriptFixture {
	t.Helper()
	jq, err := exec.LookPath("jq")
	if err != nil {
		t.Fatalf("benchmark protocol tests require jq: %v", err)
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	scripts := filepath.Join(dir, "scripts")
	for _, name := range []string{bin, scripts} {
		if err := os.Mkdir(name, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"benchmark-compile.sh", "llvm22.sh"} {
		data, err := os.ReadFile(filepath.Join("scripts", name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(scripts, name), data, 0700); err != nil {
			t.Fatal(err)
		}
	}
	translator := filepath.Join(bin, "protocol-translator")
	for name, source := range map[string]string{
		"go":                  compileBenchmarkScriptGoFixture,
		"protocol-translator": compileBenchmarkScriptTranslatorFixture,
		"llc-22":              "#!/bin/sh\nprintf 'LLVM version 22.1.8\\n'\n",
	} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(source), 0700); err != nil {
			t.Fatal(err)
		}
	}
	fixture := compileBenchmarkScriptFixture{
		directory: dir, report: filepath.Join(dir, "reports"),
		trace: filepath.Join(dir, "trace.txt"), script: filepath.Join(scripts, "benchmark-compile.sh"),
	}
	// The command directory remains native; Bash inputs and PATH must use
	// that shell's actual path mapping, not Windows' semicolon search list.
	paths := []string{bin, filepath.Dir(jq), translator, fixture.trace, fixture.script, fixture.report}
	if runtime.GOOS == "windows" {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		args := append([]string{"-c", `for name in "$@"; do cygpath -u -- "$name" || exit; done`, "fixture-paths"}, paths...)
		output, err := exec.CommandContext(ctx, "bash", args...).CombinedOutput()
		if err != nil {
			t.Fatalf("resolve native paths for the actual Bash fixture: %v\n%s", err, output)
		}
		converted := strings.Split(strings.TrimSuffix(string(output), "\n"), "\n")
		if len(converted) != len(paths) {
			t.Fatalf("incomplete shell path mapping: %q", output)
		}
		paths = converted
	}
	fixture.script = paths[4]
	fixture.environment = append(os.Environ(),
		"PATH="+paths[0]+":"+paths[1]+":/usr/bin:/bin",
		"PLAN9ASM_BENCH_TEST_TRANSLATOR="+paths[2],
		"PLAN9ASM_BENCH_TEST_MODE="+mode,
		"PLAN9ASM_BENCH_TEST_TRACE="+paths[3],
		"PLAN9ASM_BENCHMARK_TARGETS="+strings.Join(compileBenchmarkScriptTargets, ","),
		"PLAN9ASM_BENCHMARK_REPORT_DIR="+paths[5],
		"PLAN9ASM_BENCHMARK_MAX_TARGET_SECONDS=300",
		"PLAN9ASM_BENCHMARK_MAX_TOTAL_SECONDS=900",
		"GITHUB_ACTIONS=true", "GITHUB_STEP_SUMMARY=",
	)
	if mode == "target_budget" {
		fixture.environment = append(fixture.environment, "PLAN9ASM_BENCHMARK_MAX_TARGET_SECONDS=1")
	}
	return fixture
}

func (fixture compileBenchmarkScriptFixture) run(t *testing.T) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "bash", fixture.script)
	command.Dir, command.Env = fixture.directory, fixture.environment
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("benchmark protocol fixture exceeded its bounded operation: %v\n%s", ctx.Err(), output)
	}
	return string(output), err
}

func TestCompileBenchmarkRetainsWholeFailedTargetMatrix(t *testing.T) {
	fixture := newCompileBenchmarkScriptFixture(t, "command_failure")
	output, err := fixture.run(t)
	if err == nil {
		t.Fatalf("failed command became a passing benchmark: %s", output)
	}
	data, err := os.ReadFile(fixture.trace)
	if err != nil {
		t.Fatalf("benchmark fixture did not execute its target matrix: %v\n%s", err, output)
	}
	var want []string
	for _, target := range compileBenchmarkScriptTargets {
		want = append(want, target+" true")
	}
	if got := strings.Split(strings.TrimSpace(string(data)), "\n"); !reflect.DeepEqual(got, want) {
		t.Fatalf("first failure hid untested files or remaining platforms: got=%v want=%v\n%s", got, want, output)
	}
	if strings.Count(output, "::group::") != strings.Count(output, "::endgroup::") {
		t.Fatalf("failed target left benchmark details unfolded: %s", output)
	}
}

func TestCompileBenchmarkSummaryNeverHidesFailures(t *testing.T) {
	for _, mode := range []string{
		"success", "command_failure", "failed_counts", "nonzero_success_counts",
		"incomplete", "source_na", "empty", "malformed", "missing",
		"negative_counts", "excessive_counts", "wrong_target", "target_budget", "stale_failures", "duplicate_files",
	} {
		t.Run(mode, func(t *testing.T) {
			fixture := newCompileBenchmarkScriptFixture(t, mode)
			output, runErr := fixture.run(t)
			data, err := os.ReadFile(filepath.Join(fixture.report, "summary.json"))
			if err != nil {
				t.Fatalf("failed benchmark omitted its complete summary: %v\n%s", err, output)
			}
			var summary struct {
				SchemaVersion int  `json:"schema_version"`
				AllPassed     bool `json:"all_passed"`
				Targets       []struct {
					Target      string `json:"target"`
					Status      string `json:"status"`
					CommandExit int    `json:"command_exit"`
					ReportValid bool   `json:"report_valid"`
					Unattempted *int   `json:"unattempted"`
					Success     *int   `json:"success"`
					Failed      *int   `json:"failed"`
				} `json:"targets"`
			}
			if err := json.Unmarshal(data, &summary); err != nil {
				t.Fatal(err)
			}
			if summary.SchemaVersion != 2 || len(summary.Targets) != len(compileBenchmarkScriptTargets) {
				t.Fatalf("incomplete benchmark matrix: %s", data)
			}
			for index, target := range summary.Targets {
				if target.Target != compileBenchmarkScriptTargets[index] ||
					index > 0 && (target.Status != "passed" || target.CommandExit != 0) {
					t.Fatalf("matrix lost independent later targets: %s", data)
				}
			}
			wantPass := mode == "success"
			if summary.AllPassed != wantPass || (runErr == nil) != wantPass ||
				(summary.Targets[0].Status == "passed") != wantPass {
				t.Fatalf("failed/missing/unattempted evidence became successful: mode=%s error=%v summary=%s", mode, runErr, data)
			}
			if mode == "command_failure" || mode == "nonzero_success_counts" || mode == "missing" || mode == "malformed" {
				if summary.Targets[0].CommandExit != 17 {
					t.Fatalf("actual command failure was discarded: %s", data)
				}
			}
			if mode == "incomplete" && (summary.Targets[0].Unattempted == nil || *summary.Targets[0].Unattempted != 1) {
				t.Fatalf("unattempted file was hidden: %s", data)
			}
			if mode == "command_failure" || mode == "failed_counts" {
				first := summary.Targets[0]
				if !first.ReportValid || first.Success == nil || *first.Success != 1 || first.Failed == nil || *first.Failed != 1 {
					t.Fatalf("valid failure evidence lost its actual counters: %s", data)
				}
			}
			switch mode {
			case "negative_counts", "excessive_counts", "wrong_target", "empty", "malformed", "missing", "stale_failures", "duplicate_files":
				if summary.Targets[0].ReportValid || summary.Targets[0].Unattempted != nil {
					t.Fatalf("invalid evidence supplied known counts or a valid report: %s", data)
				}
			}
		})
	}
}

func TestCompileBenchmarkRefusesToOverwriteExistingEvidence(t *testing.T) {
	fixture := newCompileBenchmarkScriptFixture(t, "success")
	if err := os.Mkdir(fixture.report, 0700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(fixture.report, "summary.json")
	original := []byte("retained failed report; not a reusable current-head pass\n")
	if err := os.WriteFile(file, original, 0600); err != nil {
		t.Fatal(err)
	}
	output, err := fixture.run(t)
	if err == nil {
		t.Fatalf("existing reports were silently overwritten: %s", output)
	}
	got, err := os.ReadFile(file)
	if err != nil || string(got) != string(original) {
		t.Fatalf("previous evidence was changed: %q %v", got, err)
	}
}

func TestCompileBenchmarkRejectsDuplicateTargets(t *testing.T) {
	fixture := newCompileBenchmarkScriptFixture(t, "success")
	fixture.environment = append(fixture.environment, "PLAN9ASM_BENCHMARK_TARGETS=linux/amd64,linux/amd64")
	output, err := fixture.run(t)
	if err == nil {
		t.Fatalf("duplicate target reuses one report as independent coverage: %s", output)
	}
	if _, err := os.Stat(fixture.trace); !os.IsNotExist(err) {
		t.Fatalf("invalid target matrix launched a compiler: %v", err)
	}
	t.Log(fmt.Sprintf("duplicate target protocol was rejected: %s", strings.TrimSpace(output)))
}
