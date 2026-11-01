//go:build go1.27

package gotoolprofile

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// External instrumentation capture uses the current toolchain, not the
// historical root compatibility matrix. These are real Go library exports,
// assembly definitions and asmdecl checks; no new program is executed.
func TestInstrumentationExportActualGoSameModeAndReplay(t *testing.T) {
	binary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	for _, cgo := range []string{"0", "1"} {
		t.Run("DarwinRaceCGO="+cgo, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			proof, err := CaptureInstrumentationExportObservation(ctx, binary, instrumentationMarkerDirectory(t), os.Environ(), "darwin/arm64", InstrumentationRace, cgo, nil, RunBounded)
			if err != nil {
				t.Fatal(err)
			}
			if proof.Early.Environment["CGO_ENABLED"] != cgo || proof.BuildPlan.RequestedBuildMode != "default" ||
				proof.BuildPlan.SourceLinkMode != "pie" || len(proof.BuildPlan.CodegenFlags) != 1 ||
				proof.BuildPlan.CodegenFlags[0] != "-shared" || !strings.Contains(proof.NMOutput, "@export(mode_race.o):") {
				t.Fatalf("incomplete actual same-mode export: %+v", proof)
			}
			data, err := json.Marshal(proof)
			if err != nil {
				t.Fatal(err)
			}
			var restored InstrumentationExportObservation
			if err := json.Unmarshal(data, &restored); err != nil {
				t.Fatal(err)
			}
			if err := ValidateInstrumentationExportObservation(&restored); err != nil {
				t.Fatal(err)
			}
			for name, mutate := range map[string]func(*InstrumentationExportObservation){
				"missing protocol":        func(p *InstrumentationExportObservation) { p.Protocol = "" },
				"early only":              func(p *InstrumentationExportObservation) { p.Routing = nil },
				"missing archive":         func(p *InstrumentationExportObservation) { p.ArchiveSHA256 = "" },
				"wrong asm source":        func(p *InstrumentationExportObservation) { p.Selection.SFiles = []string{"mode_msan.s"} },
				"missing excluded source": func(p *InstrumentationExportObservation) { p.Selection.IgnoredOtherFiles = nil },
				"missing real asm symbol": func(p *InstrumentationExportObservation) {
					p.NMOutput = strings.ReplaceAll(p.NMOutput, "mode_race.o", "unrelated.o")
					p.NMSHA256 = bytesSHA256([]byte(p.NMOutput))
				},
				"compile as early only": func(p *InstrumentationExportObservation) { p.ExportArgs = p.Early.CommandArgs },
				"ordinary asmdecl":      func(p *InstrumentationExportObservation) { p.VetArgs = []string{"vet", "-asmdecl", "."} },
				"CGO foundation substitution": func(p *InstrumentationExportObservation) {
					p.Early.CGOEnabled = "1"
					p.Early.Environment["CGO_ENABLED"] = "0"
				},
				"unbound generated input": func(p *InstrumentationExportObservation) { delete(p.FixtureSHA256, "mode_race.s") },
			} {
				t.Run(name, func(t *testing.T) {
					var forged InstrumentationExportObservation
					if err := json.Unmarshal(data, &forged); err != nil {
						t.Fatal(err)
					}
					mutate(&forged)
					if err := ValidateInstrumentationExportObservation(&forged); err == nil {
						t.Fatal("accepted incomplete or changed actual export proof")
					}
				})
			}
		})
	}
}

func TestInstrumentationExportFailureCannotBecomeEarlySupportOrSourceNA(t *testing.T) {
	binary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	for _, failure := range []string{"export", "vet", "nm", "unknown trace", "source mutation"} {
		t.Run(failure, func(t *testing.T) {
			runner := func(ctx context.Context, dir string, env []string, name string, args ...string) ([]byte, []byte, error) {
				if len(args) > 2 && args[0] == "list" && args[1] == "-a" {
					if failure == "export" {
						return nil, []byte("missing SDK\n"), exec.ErrNotFound
					}
					stdout, stderr, err := RunBounded(ctx, dir, env, name, args...)
					if failure == "unknown trace" {
						stderr = append(stderr, []byte("go: warning\n")...)
					}
					if failure == "source mutation" {
						if writeErr := os.WriteFile(dir+"/mode_race.s", []byte("// changed original marker\n"), 0600); writeErr != nil {
							t.Fatal(writeErr)
						}
					}
					return stdout, stderr, err
				}
				if len(args) > 0 && (failure == "vet" && args[0] == "vet" || failure == "nm" && args[0] == "tool" && args[len(args)-2] == "nm") {
					return nil, []byte("missing required tool\n"), exec.ErrNotFound
				}
				return RunBounded(ctx, dir, env, name, args...)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			if _, err := CaptureInstrumentationExportObservation(ctx, binary, instrumentationMarkerDirectory(t), os.Environ(), "darwin/arm64", InstrumentationRace, "0", nil, runner); err == nil {
				t.Fatal("failed compiler/asmdecl/tool or changed input became a completed export observation")
			}
		})
	}
}

func TestInstrumentationExportActualGoModeAndTargetFamily(t *testing.T) {
	binary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range []struct {
		target string
		mode   InstrumentationMode
		cgo    string
	}{
		{"darwin/amd64", InstrumentationRace, "0"},
		{"linux/amd64", InstrumentationRace, "1"},
		{"linux/arm64", InstrumentationRace, "1"},
		{"freebsd/amd64", InstrumentationRace, "1"},
		{"windows/amd64", InstrumentationRace, "1"},
		{"linux/amd64", InstrumentationMSan, "1"},
		{"linux/arm64", InstrumentationMSan, "1"},
		{"linux/amd64", InstrumentationASan, "1"},
		{"linux/arm64", InstrumentationASan, "1"},
	} {
		t.Run(input.target+"/"+string(input.mode), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			proof, err := CaptureInstrumentationExportObservation(ctx, binary, instrumentationMarkerDirectory(t), os.Environ(), input.target, input.mode, input.cgo, nil, RunBounded)
			if err != nil {
				t.Fatal(err)
			}
			if proof.Early.Environment["CGO_ENABLED"] != input.cgo || proof.Early.Mode != input.mode || proof.Early.Target != input.target {
				t.Fatal("another CGO/mode/target impersonated this actual library export")
			}
		})
	}
}

func TestInstrumentationExportActualGoAMD64CPUFamily(t *testing.T) {
	binary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	for _, level := range []string{"v1", "v2", "v3", "v4"} {
		t.Run(level, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			var actualTrace []byte
			runner := func(ctx context.Context, dir string, env []string, name string, args ...string) ([]byte, []byte, error) {
				stdout, stderr, err := RunBounded(ctx, dir, env, name, args...)
				if len(args) > 2 && args[0] == "list" && args[1] == "-a" && args[2] == "-x" {
					actualTrace = append([]byte(nil), stderr...)
				}
				return stdout, stderr, err
			}
			proof, err := CaptureInstrumentationExportObservation(ctx, binary, instrumentationMarkerDirectory(t),
				os.Environ(), "darwin/amd64", InstrumentationRace, "0", map[string]string{"GOAMD64": level}, runner)
			if err != nil {
				t.Fatalf("actual same-mode CPU %s export routing: %v\n%s", level, err, actualTrace)
			}
			if proof.Early.Environment["GOAMD64"] != level || proof.Routing == nil ||
				!strings.Contains(proof.Routing.CanonicalTrace, " -D GOAMD64_"+level+" ") {
				t.Fatal("actual CPU level was lost or replaced by cumulative build tags")
			}
			encoded, err := json.Marshal(proof)
			if err != nil {
				t.Fatal(err)
			}
			var replay InstrumentationExportObservation
			if err := json.Unmarshal(encoded, &replay); err != nil {
				t.Fatal(err)
			}
			if err := ValidateInstrumentationExportObservation(&replay); err != nil {
				t.Fatalf("independent CPU mode export replay: %v", err)
			}
		})
	}
}

func TestInstrumentationExportActualGoARM64CPUFamily(t *testing.T) {
	binary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	for _, level := range []string{"v8.0", "v8.0,lse", "v8.1", "v8.2", "v8.4", "v9.0", "v9.1", "v9.5"} {
		t.Run(level, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			proof, err := CaptureInstrumentationExportObservation(ctx, binary, instrumentationMarkerDirectory(t),
				os.Environ(), "darwin/arm64", InstrumentationRace, "0", map[string]string{"GOARM64": level}, RunBounded)
			if err != nil {
				t.Fatal(err)
			}
			if proof.Early.Environment["GOARM64"] != level {
				t.Fatal("actual ARM64 CPU was replaced by a different assembler feature profile")
			}
			if err := ValidateInstrumentationExportObservation(proof); err != nil {
				t.Fatal(err)
			}
		})
	}
}
