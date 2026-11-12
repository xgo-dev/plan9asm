//go:build go1.27

package gostaticstorage

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func request(t *testing.T, dir, binary, target string) Request {
	t.Helper()
	return Request{GoBinary: binary, Directory: dir, PackagePath: fixtureModule, Target: target,
		Environment: fixtureEnv(t, target), Variables: []Reference{
			{fixtureModule, "Keys"}, {fixtureModule, "Data"}, {fixtureModule, "Mixed"}, {fixtureModule, "Relocated"},
			{fixtureModule + "/dep", "Flags"}, {fixtureModule + "/dep", "Keys"},
		}}
}

func captured(t *testing.T, req Request) (*Observation, Report) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	o, err := Capture(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(o.Close)
	report, err := o.Readback(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return o, report
}

func TestGoStaticStorageTypedProducerAndReader(t *testing.T) {
	dir, binary, _ := fixture(t)
	for _, target := range []string{"linux/386", "linux/amd64", "linux/arm", "linux/arm64", "js/wasm"} {
		t.Run(target, func(t *testing.T) {
			o, report := captured(t, request(t, dir, binary, target))
			word := int64(8)
			if strings.HasSuffix(target, "/386") || strings.HasSuffix(target, "/arm") {
				word = 4
			}
			expected := map[string][]Span{
				fixtureModule + ".Keys":      {{0, 48}},
				fixtureModule + ".Data":      {{0, 4}},
				fixtureModule + ".Mixed":     {{0, 1}, {4, 4}, {8 + word, 3}},
				fixtureModule + ".Relocated": {{0, 4}},
				fixtureModule + "/dep.Flags": {{64, 4}},
				fixtureModule + "/dep.Keys":  {{0, 16}},
			}
			for _, variable := range report.Variables {
				if !reflect.DeepEqual(variable.Numerical, expected[variable.NativeName]) || variable.Alignment != 0 {
					t.Fatalf("numerical/blank/pointer/padding or real alignment observation differs: %+v", variable)
				}
			}
			data, err := json.MarshalIndent(report, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			var decoded Report
			if err := json.Unmarshal(data, &decoded); err != nil || o.CheckReport(context.Background(), decoded) != nil {
				t.Fatalf("independent readback failed: %v", err)
			}
			if artifact := os.Getenv("PLAN9ASM_STATIC_STORAGE_ARTIFACT_DIR"); artifact != "" {
				folder := filepath.Join(artifact, strings.ReplaceAll(target, "/", "-"))
				if err := os.MkdirAll(folder, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(folder, "producer-report.json"), data, 0600); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func cloneReport(t *testing.T, report Report) Report {
	t.Helper()
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	var result Report
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestGoStaticStorageReaderMutationGuards(t *testing.T) {
	dir, binary, _ := fixture(t)
	o, report := captured(t, request(t, dir, binary, "linux/amd64"))
	for name, mutate := range map[string]func(*Report){
		"target":      func(r *Report) { r.Target = "linux/386" },
		"owner":       func(r *Report) { r.Variables[0].PackagePath += "/other" },
		"native name": func(r *Report) { r.Variables[0].NativeName += "other" },
		"size":        func(r *Report) { r.Variables[0].Size++ },
		"alignment":   func(r *Report) { r.Variables[0].Alignment = 16 },
		"blank bytes": func(r *Report) {
			for i := range r.Variables {
				if r.Variables[i].Name == "Mixed" {
					r.Variables[i].Numerical = []Span{{0, r.Variables[i].Size}}
				}
			}
		},
		"source bytes":       func(r *Report) { r.Source["storage.go"][0] ^= 1 },
		"source hash":        func(r *Report) { r.SourceSHA256["storage.go"] = strings.Repeat("0", 64) },
		"archive bytes":      func(r *Report) { r.Archives[fixtureModule][0] ^= 1 },
		"archive hash":       func(r *Report) { r.ArchiveSHA256[fixtureModule] = strings.Repeat("0", 64) },
		"format rules":       func(r *Report) { r.Tools["src/cmd/internal/goobj/objfile.go"] = strings.Repeat("0", 64) },
		"tool":               func(r *Report) { r.Tools["compile"] = strings.Repeat("0", 64) },
		"command dir":        func(r *Report) { r.CommandDirectory += "/other" },
		"command argv":       func(r *Report) { r.CommandArguments = append(r.CommandArguments, "./...") },
		"effective tmpdir":   func(r *Report) { r.CommandEnvironment["TMPDIR"] += "other" },
		"trailing JSON":      func(r *Report) { r.RawSelection = append(r.RawSelection, []byte("garbage")...) },
		"omitted archive":    func(r *Report) { delete(r.Archives, fixtureModule+"/dep") },
		"duplicate variable": func(r *Report) { r.Variables = append(r.Variables, r.Variables[0]) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := cloneReport(t, report)
			mutate(&changed)
			if err := o.CheckReport(context.Background(), changed); !errors.Is(err, ErrContext) {
				t.Fatalf("changed recorded input acquired authority: %v", err)
			}
		})
	}
	var decoded Observation
	data, _ := json.Marshal(o)
	if err := json.Unmarshal(data, &decoded); err != nil || !errors.Is(decoded.Verify(context.Background()), ErrContext) {
		t.Fatal("JSON recreated sealed producer")
	}
	if !errors.Is((*Observation)(nil).Verify(context.Background()), ErrContext) || !errors.Is((*Observation)(nil).CheckReport(context.Background(), report), ErrContext) {
		t.Fatal("nil observer must return Context")
	}
	o.Close()
	if !errors.Is(o.Verify(context.Background()), ErrContext) {
		t.Fatal("Close did not revoke")
	}
}

func TestGoStaticStoragePhysicalSourceAndInputGuards(t *testing.T) {
	for _, kind := range []string{"source", "inventory", "temp identity", "requested name", "duplicate", "wrong owner", "wrong package", "flags", "unknown SDK"} {
		t.Run(kind, func(t *testing.T) {
			dir, binary, _ := fixture(t)
			req := request(t, dir, binary, "linux/amd64")
			ownedTemp := ""
			if kind == "temp identity" {
				ownedTemp = t.TempDir()
				ownedTemp, _ = filepath.EvalSymlinks(ownedTemp)
				for i, pair := range req.Environment {
					if strings.HasPrefix(pair, "TMPDIR=") || strings.HasPrefix(pair, "GOTMPDIR=") {
						key, _, _ := strings.Cut(pair, "=")
						req.Environment[i] = key + "=" + ownedTemp
					}
				}
			}
			if kind == "requested name" {
				req.Variables[0].Name = "Read" // function, not variable
			} else if kind == "duplicate" {
				req.Variables = append(req.Variables, req.Variables[0])
			} else if kind == "wrong owner" {
				req.Variables[0].PackagePath += "/other"
			} else if kind == "wrong package" {
				req.PackagePath += "/other"
			} else if kind == "flags" {
				for i, pair := range req.Environment {
					if strings.HasPrefix(pair, "GOFLAGS=") {
						req.Environment[i] = "GOFLAGS=-race"
					}
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			o, err := Capture(ctx, req)
			if kind == "requested name" || kind == "duplicate" || kind == "wrong owner" || kind == "wrong package" || kind == "flags" {
				if err == nil {
					o.Close()
					t.Fatal("invalid identity/role acquired producer")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer o.Close()
			switch kind {
			case "source":
				file := filepath.Join(dir, "storage.go")
				data, _ := os.ReadFile(file)
				if err := os.WriteFile(file, append(data, '\n'), 0600); err != nil {
					t.Fatal(err)
				}
			case "inventory":
				if err := os.WriteFile(filepath.Join(dir, "new.go"), []byte("package staticstorage\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "temp identity":
				// Retarget only an independently fixture-owned directory, never
				// the runner/shared cache. The request's actual role must stay put.
				if err := os.Rename(ownedTemp, ownedTemp+"-old"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(ownedTemp, 0700); err != nil {
					t.Fatal(err)
				}
			case "unknown SDK":
				o.report.Tools["src/cmd/internal/goobj/objfile.go"] = strings.Repeat("0", 64)
			}
			if err := o.Verify(ctx); !errors.Is(err, ErrContext) {
				t.Fatalf("physical original input changed but certificate survived: %v", err)
			}
		})
	}
}
