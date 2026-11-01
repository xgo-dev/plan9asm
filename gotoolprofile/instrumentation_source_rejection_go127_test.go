//go:build go1.27 && (darwin || linux) && (amd64 || arm64)

package gotoolprofile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func instrumentationSourceRejectionFixture(t *testing.T, marker *InstrumentationExportObservation, previous, current string) (*ConsumerInput, *InstrumentationOriginalSourceInventory, *InstrumentationOriginalPackagePlan) {
	t.Helper()
	input := instrumentationOriginalFixture(t, marker.Early)
	for name, declaration := range map[string]string{"base.go": previous, "mode_race.go": current} {
		contents := input.Headers[name] + "\n" + declaration + "\n"
		if err := os.WriteFile(filepath.Join(input.SourceRoot, name), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
		input.Headers[name], input.Sources[name] = contents, bytesSHA256([]byte(contents))
	}
	inventory, err := CaptureInstrumentationOriginalSourceInventory(input, ".")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := PlanInstrumentationOriginalPackage(input, inventory, marker.Early, ".", nil)
	if err != nil {
		t.Fatal(err)
	}
	return input, inventory, plan
}

func instrumentationSourceRejectionMarker(t *testing.T, ctx context.Context, binary string) *InstrumentationExportObservation {
	t.Helper()
	marker, err := CaptureInstrumentationExportObservation(ctx, binary, instrumentationMarkerDirectory(t), os.Environ(),
		runtime.GOOS+"/"+runtime.GOARCH, InstrumentationRace, "1", nil, RunBounded)
	if err != nil {
		t.Fatal(err)
	}
	return marker
}

func TestInstrumentationSourceRejectionActualGoDeclarationFamily(t *testing.T) {
	binary := filepath.Join(runtime.GOROOT(), "bin", "go")
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	marker := instrumentationSourceRejectionMarker(t, ctx, binary)
	for _, previous := range instrumentationRedeclarationKinds {
		for _, current := range instrumentationRedeclarationKinds {
			t.Run(previous.name+"/"+current.name, func(t *testing.T) {
				input, inventory, plan := instrumentationSourceRejectionFixture(t, marker, previous.declaration, current.declaration)
				proof, err := CaptureInstrumentationSourceRejection(ctx, binary, input.SourceRoot, os.Environ(), input, inventory, marker, plan, RunBounded)
				if err != nil {
					t.Fatal("actual original compiler family rejection: ", err)
				}
				if proof.ExitCode != 1 || len(proof.Redeclarations) != 1 || proof.Redeclarations[0].Name != "Item" {
					t.Fatalf("actual compiler refusal did not match complete declaration replay: %+v", proof)
				}
				data, err := json.Marshal(proof)
				if err != nil {
					t.Fatal(err)
				}
				var replayed InstrumentationSourceRejection
				if err := json.Unmarshal(data, &replayed); err != nil {
					t.Fatal(err)
				}
				if err := ValidateInstrumentationSourceRejection(input, inventory, marker, plan, &replayed); err != nil {
					t.Fatal("portable original refusal replay: ", err)
				}
				t.Logf("actual %s %s %s/%s compiler exit1, complete physical redeclarations=%+v",
					runtime.Version(), plan.Target, previous.name, current.name, proof.Redeclarations)
			})
		}
	}
}

func TestInstrumentationSourceRejectionActualFailureAndSourceGuards(t *testing.T) {
	binary := filepath.Join(runtime.GOROOT(), "bin", "go")
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	marker := instrumentationSourceRejectionMarker(t, ctx, binary)
	for _, phase := range []string{
		"missing tool", "joined transport error", "joined context error", "unknown diagnostic",
		"missing diagnostic", "missing selection", "source mutation", "new sibling", "metadata alias",
	} {
		t.Run(phase, func(t *testing.T) {
			input, inventory, plan := instrumentationSourceRejectionFixture(t, marker, "const Item = 1", "const Item = 2")
			observedExit := false
			run := func(ctx context.Context, dir string, env []string, name string, args ...string) ([]byte, []byte, error) {
				if len(args) < 2 || args[0] != "list" || args[1] != "-export" {
					return RunBounded(ctx, dir, env, name, args...)
				}
				if phase == "missing tool" {
					return nil, []byte("missing actual compiler\n"), exec.ErrNotFound
				}
				stdout, stderr, err := RunBounded(ctx, dir, env, name, args...)
				code, plain := instrumentationRejectionExitCode(err)
				if !plain || code != 1 {
					t.Fatalf("tripwire prerequisite lacks the unchanged actual compiler exit1: %v", err)
				}
				observedExit = true
				switch phase {
				case "joined transport error":
					err = errors.Join(err, fmt.Errorf("unknown transport failure"))
				case "joined context error":
					err = errors.Join(err, context.DeadlineExceeded)
				case "unknown diagnostic":
					stderr = append(stderr, []byte("unknown compiler warning\n")...)
				case "missing diagnostic":
					stderr = nil
				case "missing selection":
					stdout = nil
				case "source mutation", "new sibling":
					file := "mode_asan.s"
					if phase == "new sibling" {
						file = "late.go"
					}
					if err := os.WriteFile(filepath.Join(input.SourceRoot, file), []byte("package late\n"), 0600); err != nil {
						t.Fatal(err)
					}
				case "metadata alias":
					metadata := filepath.Join(input.SourceRoot, "go.mod")
					original := filepath.Join(t.TempDir(), "original-go.mod")
					if err := os.Rename(metadata, original); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(original, metadata); err != nil {
						t.Fatal(err)
					}
				}
				return stdout, stderr, err
			}
			if proof, err := CaptureInstrumentationSourceRejection(ctx, binary, input.SourceRoot, os.Environ(), input, inventory, marker, plan, run); err == nil || proof != nil {
				t.Fatal("actual tool/transport/diagnostic/source failure became a source refusal")
			}
			if phase != "missing tool" && !observedExit {
				t.Fatal("negative fixture never reached its actual compiler rejection")
			}
		})
	}
}

func TestInstrumentationSourceRejectionMainMetadataAndPortableTripwires(t *testing.T) {
	binary := filepath.Join(runtime.GOROOT(), "bin", "go")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	marker := instrumentationSourceRejectionMarker(t, ctx, binary)
	input, inventory, plan := instrumentationSourceRejectionFixture(t, marker, "const Item = 1", "const Item = 2")
	proof, err := CaptureInstrumentationSourceRejection(ctx, binary, input.SourceRoot, os.Environ(), input, inventory, marker, plan, RunBounded)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*InstrumentationSourceRejection){
		"protocol":      func(p *InstrumentationSourceRejection) { p.Protocol = "unregistered" },
		"exit":          func(p *InstrumentationSourceRejection) { p.ExitCode = 2 },
		"command":       func(p *InstrumentationSourceRejection) { p.ExportArgs = nil },
		"marker":        func(p *InstrumentationSourceRejection) { p.MarkerObservationID = strings.Repeat("a", 64) },
		"physical line": func(p *InstrumentationSourceRejection) { p.Redeclarations[0].Current.Line++ },
		"deleted pair":  func(p *InstrumentationSourceRejection) { p.Redeclarations = nil },
		"foreign main config": func(p *InstrumentationSourceRejection) {
			p.InvocationConfigSHA256["go.mod"] = bytesSHA256([]byte("foreign configuration"))
		},
	} {
		t.Run(name, func(t *testing.T) {
			var changed InstrumentationSourceRejection
			if err := json.Unmarshal(encoded, &changed); err != nil {
				t.Fatal(err)
			}
			mutate(&changed)
			if err := ValidateInstrumentationSourceRejection(input, inventory, marker, plan, &changed); err == nil {
				t.Fatal("changed original main-package metadata or compiler/source scope was accepted")
			}
		})
	}
}

func TestInstrumentationSourceRejectionCanonicalInvocationAndOriginalRoot(t *testing.T) {
	binary := filepath.Join(runtime.GOROOT(), "bin", "go")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	marker := instrumentationSourceRejectionMarker(t, ctx, binary)
	for _, redirectSource := range []bool{false, true} {
		name := "canonical command directory survives unused logical alias"
		if redirectSource {
			name = "original source alias cannot change physical origin"
		}
		t.Run(name, func(t *testing.T) {
			input, inventory, plan := instrumentationSourceRejectionFixture(t, marker, "const Item = 1", "const Item = 2")
			original, err := filepath.EvalSymlinks(input.SourceRoot)
			if err != nil {
				t.Fatal(err)
			}
			copyRoot := t.TempDir()
			for file, contents := range input.Headers {
				if err := os.WriteFile(filepath.Join(copyRoot, file), []byte(contents), 0600); err != nil {
					t.Fatal(err)
				}
			}
			alias := filepath.Join(t.TempDir(), "invocation")
			if err := os.Symlink(original, alias); err != nil {
				t.Fatal(err)
			}
			if redirectSource {
				input.SourceRoot = alias
			}
			didRun := false
			run := func(ctx context.Context, dir string, env []string, name string, args ...string) ([]byte, []byte, error) {
				if len(args) > 1 && args[0] == "list" && args[1] == "-export" {
					if dir != original {
						t.Fatalf("actual export used unbound logical CWD %q, expected original physical %q", dir, original)
					}
					if err := os.Remove(alias); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(copyRoot, alias); err != nil {
						t.Fatal(err)
					}
					didRun = true
				}
				return RunBounded(ctx, dir, env, name, args...)
			}
			proof, err := CaptureInstrumentationSourceRejection(ctx, binary, alias, os.Environ(), input, inventory, marker, plan, run)
			if !didRun {
				t.Fatal("physical-identity fixture never reached the actual compiler")
			}
			if redirectSource {
				if err == nil || proof != nil {
					t.Fatal("equal-byte original source root redirection became a source refusal")
				}
			} else if err != nil || proof == nil {
				t.Fatalf("unused alias changed the canonical actual invocation: %v", err)
			}
		})
	}
}
