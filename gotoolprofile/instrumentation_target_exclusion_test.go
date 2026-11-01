package gotoolprofile

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func captureActualTargetExclusion(t *testing.T, run Runner) *InstrumentationTargetExclusion {
	t.Helper()
	binary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	_, proof, err := CaptureInstrumentationScopeObservation(ctx, binary, instrumentationMarkerDirectory(t), os.Environ(), "windows/arm64", InstrumentationRace, "1", nil, []string{"alpha", "beta"}, run)
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

func TestInstrumentationTargetExclusionActualTagsAndStrictReplay(t *testing.T) {
	proof := captureActualTargetExclusion(t, RunBounded)
	tags := []string{"alpha", "beta"}
	if err := ValidateInstrumentationTargetExclusion(proof, tags); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(proof.CommandArgs, []string{"list", "-find", "-json", "-mod=readonly", "-race", "-tags=alpha,beta", "."}) ||
		strings.Contains(strings.Join(proof.Early.CommandArgs, " "), "-tags") {
		t.Fatal("tagged scope command impersonated or altered the original v1 early command")
	}
	data, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*InstrumentationTargetExclusion){
		"delete protocol":  func(p *InstrumentationTargetExclusion) { p.Protocol = "" },
		"delete tags":      func(p *InstrumentationTargetExclusion) { p.CustomTags = nil },
		"replace tags":     func(p *InstrumentationTargetExclusion) { p.CustomTags[0] = "other" },
		"delete argv tags": func(p *InstrumentationTargetExclusion) { p.CommandArgs = p.Early.CommandArgs },
		"wrong exit":       func(p *InstrumentationTargetExclusion) { p.ExitCode = 1 },
		"mixed diagnostic": func(p *InstrumentationTargetExclusion) { p.Stderr += "missing SDK\n" },
		"nonempty stdout":  func(p *InstrumentationTargetExclusion) { p.StdoutSHA256 = bytesSHA256([]byte("unexpected")) },
		"different target": func(p *InstrumentationTargetExclusion) { p.Early.Target = "windows/amd64" },
		"different mode":   func(p *InstrumentationTargetExclusion) { p.Early.Mode = InstrumentationASan },
		"missing CGO":      func(p *InstrumentationTargetExclusion) { p.Early.CGOEnabled = "" },
		"missing source rule": func(p *InstrumentationTargetExclusion) {
			delete(p.Early.SourceRules.SourceText, "src/cmd/go/internal/work/init.go")
		},
		"different actual tool": func(p *InstrumentationTargetExclusion) {
			p.Early.ModeTools.BinarySHA256["asm"] = strings.Repeat("0", 64)
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			var changed InstrumentationTargetExclusion
			if err := json.Unmarshal(data, &changed); err != nil {
				t.Fatal(err)
			}
			mutate(&changed)
			if err := ValidateInstrumentationTargetExclusion(&changed, tags); err == nil {
				t.Fatal("incomplete or substituted scope refusal accepted")
			}
		})
	}
}

func TestInstrumentationTargetExclusionRejectsChangedActualCommand(t *testing.T) {
	binary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	for _, failure := range []string{"timeout", "missing SDK", "missing CC", "missing CGO", "mixed", "stdout", "marker"} {
		t.Run(failure, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			seen := 0
			run := func(ctx context.Context, dir string, env []string, binary string, args ...string) ([]byte, []byte, error) {
				if !strings.Contains(strings.Join(args, " "), "-tags=alpha") {
					return RunBounded(ctx, dir, env, binary, args...)
				}
				seen++
				if failure == "marker" {
					stdout, stderr, err := RunBounded(ctx, dir, env, binary, args...)
					if writeErr := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module forged\n"), 0600); writeErr != nil {
						t.Fatal(writeErr)
					}
					return stdout, stderr, err
				}
				if failure == "timeout" {
					return nil, nil, context.DeadlineExceeded
				}
				stdout, stderr, err := RunBounded(ctx, dir, env, binary, args...)
				if failure == "stdout" {
					stdout = []byte("unexpected")
				} else {
					stderr = append(stderr, []byte(failure+"\n")...)
				}
				return stdout, stderr, err
			}
			_, proof, err := CaptureInstrumentationScopeObservation(ctx, binary, instrumentationMarkerDirectory(t), os.Environ(), "windows/arm64", InstrumentationRace, "1", nil, []string{"alpha"}, run)
			if err == nil || proof != nil || seen != 1 {
				t.Fatalf("changed actual command became an exclusion: seen=%d proof=%v error=%v", seen, proof != nil, err)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, proof, err := CaptureInstrumentationScopeObservation(ctx, binary, instrumentationMarkerDirectory(t), os.Environ(), "windows/arm64", InstrumentationRace, "1", nil, nil, RunBounded); err == nil || proof != nil || !errors.Is(ctx.Err(), context.Canceled) {
		t.Fatal("cancelled command accepted")
	}
}
