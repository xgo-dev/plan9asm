//go:build go1.27

package gotoolprofile

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestInstrumentationOriginalExportActualSameModeAndReadback(t *testing.T) {
	binary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	marker, err := CaptureInstrumentationExportObservation(ctx, binary, instrumentationMarkerDirectory(t), os.Environ(), "darwin/arm64", InstrumentationRace, "0", nil, RunBounded)
	if err != nil {
		t.Fatal(err)
	}
	input := instrumentationOriginalFixture(t, marker.Early)
	inventory, err := CaptureInstrumentationOriginalSourceInventory(input, ".")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := PlanInstrumentationOriginalPackage(input, inventory, marker.Early, ".", nil)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := CaptureInstrumentationOriginalExport(ctx, binary, input.SourceRoot, os.Environ(), input, inventory, marker, plan, RunBounded)
	if err != nil {
		t.Fatal(err)
	}
	if proof.Status != "consumer_pending" || proof.Package.SourceRole != "main" ||
		len(proof.Package.CompiledGoFiles) != 2 || proof.ArchiveSHA256 == "" {
		t.Fatalf("incomplete original same-mode export: %+v", proof)
	}
	data, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	var restored InstrumentationOriginalExportProof
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatal(err)
	}
	if err := ValidateInstrumentationOriginalExport(input, inventory, marker, plan, &restored); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeInstrumentationOriginalExport(strings.NewReader(string(data)), input, inventory, marker, plan); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{string(data) + "{}", strings.Replace(string(data), "\"protocol\":", "\"unknown\":true,\"protocol\":", 1)} {
		if _, err := DecodeInstrumentationOriginalExport(strings.NewReader(invalid), input, inventory, marker, plan); err == nil {
			t.Fatal("portable original export reader accepted unknown or trailing input")
		}
	}
	for name, change := range map[string]func(*InstrumentationOriginalExportProof){
		"erase mode": func(p *InstrumentationOriginalExportProof) {
			p.ExportArgs = []string{"list", "-export", p.Package.PackagePath}
		},
		"ordinary vet": func(p *InstrumentationOriginalExportProof) {
			p.VetArgs = []string{"vet", "-asmdecl", p.Package.PackagePath}
		},
		"claim pass":           func(p *InstrumentationOriginalExportProof) { p.Status = "passed" },
		"fake generated":       func(p *InstrumentationOriginalExportProof) { p.Package.CompiledGoFiles = []string{"generated.go"} },
		"delete ignored scope": func(p *InstrumentationOriginalExportProof) { p.Plan.Decisions = p.Plan.Decisions[1:] },
		"other module":         func(p *InstrumentationOriginalExportProof) { p.Package.ModulePath = "example.invalid/foreign" },
		"foreign main config": func(p *InstrumentationOriginalExportProof) {
			p.InvocationConfigSHA256["go.mod"] = bytesSHA256([]byte("foreign"))
		},
		"missing archive": func(p *InstrumentationOriginalExportProof) { p.ArchiveSHA256 = "" },
	} {
		t.Run(name, func(t *testing.T) {
			var changed InstrumentationOriginalExportProof
			if err := json.Unmarshal(data, &changed); err != nil {
				t.Fatal(err)
			}
			change(&changed)
			if err := ValidateInstrumentationOriginalExport(input, inventory, marker, plan, &changed); err == nil {
				t.Fatal("accepted missing or changed original same-mode export")
			}
		})
	}
	for _, phase := range []string{"export", "vet", "unknown stderr", "source mutation", "new sibling"} {
		t.Run(phase, func(t *testing.T) {
			run := func(ctx context.Context, dir string, env []string, name string, args ...string) ([]byte, []byte, error) {
				if len(args) > 1 && args[0] == "list" && args[1] == "-export" {
					if phase == "export" {
						return nil, []byte("missing compiler or SDK\n"), exec.ErrNotFound
					}
					out, stderr, err := RunBounded(ctx, dir, env, name, args...)
					if phase == "unknown stderr" {
						stderr = append(stderr, []byte("unknown warning\n")...)
					}
					if phase == "source mutation" || phase == "new sibling" {
						file := "mode_asan.s"
						if phase == "new sibling" {
							file = "late.s"
						}
						if err := os.WriteFile(filepath.Join(input.SourceRoot, file), []byte("// changed source\n"), 0600); err != nil {
							t.Fatal(err)
						}
					}
					return out, stderr, err
				}
				if len(args) > 1 && args[0] == "tool" && args[1] == "vet" && phase == "vet" {
					return nil, []byte("missing vet tool\n"), exec.ErrNotFound
				}
				return RunBounded(ctx, dir, env, name, args...)
			}
			if _, err := CaptureInstrumentationOriginalExport(ctx, binary, input.SourceRoot, os.Environ(), input, inventory, marker, plan, run); err == nil {
				t.Fatal("actual source/tool/SDK failure or warning became export proof")
			}
			if phase == "source mutation" {
				if err := os.WriteFile(filepath.Join(input.SourceRoot, "mode_asan.s"), instrumentationExportFixture()["mode_asan.s"], 0600); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestInstrumentationOriginalExportActualExclusiveModeFamily(t *testing.T) {
	binary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	for _, config := range []struct {
		target string
		mode   InstrumentationMode
	}{
		{"darwin/arm64", InstrumentationRace},
		{"linux/arm64", InstrumentationMSan},
		{"linux/arm64", InstrumentationASan},
	} {
		t.Run(config.target+"/"+string(config.mode)+"/CGO1", func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			marker, err := CaptureInstrumentationExportObservation(ctx, binary, instrumentationMarkerDirectory(t), os.Environ(), config.target, config.mode, "1", nil, RunBounded)
			if err != nil {
				t.Fatal(err)
			}
			input := instrumentationOriginalFixture(t, marker.Early)
			sources, err := CaptureInstrumentationOriginalSourceInventory(input, ".")
			if err != nil {
				t.Fatal(err)
			}
			plan, err := PlanInstrumentationOriginalPackage(input, sources, marker.Early, ".", nil)
			if err != nil {
				t.Fatal(err)
			}
			proof, err := CaptureInstrumentationOriginalExport(ctx, binary, input.SourceRoot, os.Environ(), input, sources, marker, plan, RunBounded)
			if err != nil {
				t.Fatal(err)
			}
			if err := ValidateInstrumentationOriginalExport(input, sources, marker, plan, proof); err != nil {
				t.Fatal(err)
			}
			if plan.CGOEnabled != "1" || proof.Status != "consumer_pending" || proof.Package.Macros != nil {
				t.Fatal("CGO1 original export borrowed ordinary/CPP consumption")
			}
		})
	}
}
