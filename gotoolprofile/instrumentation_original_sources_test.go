package gotoolprofile

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestInstrumentationOriginalFullSourcesRejectMissingAndChangedInventory(t *testing.T) {
	early := captureActualInstrumentationEarly(t, "darwin/arm64", InstrumentationRace, "0")
	input := instrumentationOriginalFixture(t, early)
	original, err := CaptureInstrumentationOriginalSourceInventory(input, ".")
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeInstrumentationOriginalSourceInventory(strings.NewReader(string(data)), input, "."); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{string(data) + "{}", strings.Replace(string(data), "\"protocol\":", "\"unknown\":true,\"protocol\":", 1)} {
		if _, err := DecodeInstrumentationOriginalSourceInventory(strings.NewReader(invalid), input, "."); err == nil {
			t.Fatal("portable source reader accepted unknown or trailing input")
		}
	}
	for name, change := range map[string]func(*InstrumentationOriginalSourceInventory){
		"missing protocol": func(p *InstrumentationOriginalSourceInventory) { p.Protocol = "" },
		"other module":     func(p *InstrumentationOriginalSourceInventory) { p.Module += "/foreign" },
		"other version":    func(p *InstrumentationOriginalSourceInventory) { p.Version = "v1.0.0" },
		"delete ignored":   func(p *InstrumentationOriginalSourceInventory) { delete(p.Contents, "mode_msan.go") },
		"extra source":     func(p *InstrumentationOriginalSourceInventory) { p.Contents["foreign.go"] = "package foreign\n" },
		"changed body":     func(p *InstrumentationOriginalSourceInventory) { p.Contents["base.go"] += "// changed\n" },
		"over-bound source": func(p *InstrumentationOriginalSourceInventory) {
			p.Contents["base.go"] = strings.Repeat("x", instrumentationOriginalFileLimit+1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			var p InstrumentationOriginalSourceInventory
			if err := json.Unmarshal(data, &p); err != nil {
				t.Fatal(err)
			}
			change(&p)
			if err := ValidateInstrumentationOriginalSourceInventory(input, ".", &p); err == nil {
				t.Fatal("accepted truncated or changed original inventory")
			}
		})
	}
	if err := os.Remove(filepath.Join(input.SourceRoot, "base.go")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(t.TempDir(), "foreign.go"), filepath.Join(input.SourceRoot, "base.go")); err != nil {
		t.Fatal(err)
	}
	if _, err := CaptureInstrumentationOriginalSourceInventory(input, "."); err == nil {
		t.Fatal("read a redirected original source")
	}
}

func TestInstrumentationOriginalPlanFullImportCMatchesActualGo(t *testing.T) {
	binary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	early := captureActualInstrumentationEarly(t, "darwin/arm64", InstrumentationRace, "0")
	input := instrumentationOriginalFixture(t, early)
	for name, body := range map[string]string{
		"plain.go":   "import \"C\"",
		"alias.go":   "import alias \"C\"",
		"escaped.go": "import \"\\x43\"",
		"raw.go":     "import `C`",
	} {
		data := []byte("package markers\n\n" + body + "\n")
		if err := os.WriteFile(filepath.Join(input.SourceRoot, name), data, 0600); err != nil {
			t.Fatal(err)
		}
		input.Sources[name] = bytesSHA256(data)
		// This is the ordinary package-clause-only input: it cannot prove
		// absence of import C. The separate complete source must decide.
		input.Headers[name] = "package markers\n"
		input.Directories["."] = append(input.Directories["."], name)
	}
	sort.Strings(input.Directories["."])
	sources, err := CaptureInstrumentationOriginalSourceInventory(input, ".")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := PlanInstrumentationOriginalPackage(input, sources, early, ".", nil)
	if err != nil {
		t.Fatal(err)
	}
	env := instrumentationActualEnv(early.Target, "0")
	stdout, stderr, err := RunBounded(ctx, input.SourceRoot, env, binary, "list", "-find", "-json", "-mod=readonly", "-race", ".")
	if err != nil || len(stderr) != 0 {
		t.Fatalf("actual Go source selection failed: %v: %s", err, stderr)
	}
	var actual struct{ GoFiles, IgnoredGoFiles []string }
	if err := json.Unmarshal(stdout, &actual); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(actual.GoFiles, plan.GoFiles) || len(actual.IgnoredGoFiles) != 6 {
		t.Fatalf("full import-C source selection differs from actual Go: %+v versus %+v", actual, plan)
	}
	excluded := 0
	for _, decision := range plan.Decisions {
		if decision.Reason == "cgo_import_disabled" {
			excluded++
			if decision.Selected || decision.ModeRequired {
				t.Fatal("disabled import-C source counted as selected instrumentation")
			}
		}
	}
	if excluded != 4 {
		t.Fatalf("unclosed import-C grammar: %d", excluded)
	}
	withCGO := captureActualInstrumentationEarly(t, "darwin/arm64", InstrumentationRace, "1")
	input.Observed, input.ID = withCGO.BaselineFeatures, ProfileID(withCGO.BaselineFeatures)
	cgoPlan, err := PlanInstrumentationOriginalPackage(input, sources, withCGO, ".", nil)
	if err != nil {
		t.Fatal(err)
	}
	stdout, stderr, err = RunBounded(ctx, input.SourceRoot, instrumentationActualEnv(withCGO.Target, "1"), binary, "list", "-find", "-json", "-mod=readonly", "-race", ".")
	if err != nil || len(stderr) != 0 {
		t.Fatalf("actual CGO1 source selection failed: %v: %s", err, stderr)
	}
	var selectedCGO struct{ GoFiles, CgoFiles []string }
	if err := json.Unmarshal(stdout, &selectedCGO); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(selectedCGO.GoFiles, cgoPlan.GoFiles) || !reflect.DeepEqual(selectedCGO.CgoFiles, cgoPlan.CgoFiles) || len(cgoPlan.CgoFiles) != 4 {
		t.Fatalf("CGO1 original roles lost or relabeled as generated ordinary Go: %+v versus %+v", selectedCGO, cgoPlan)
	}
}

func TestInstrumentationOriginalPlanDoesNotTrustStaleHeadersOrIdentity(t *testing.T) {
	early := captureActualInstrumentationEarly(t, "darwin/arm64", InstrumentationRace, "0")
	input := instrumentationOriginalFixture(t, early)
	sources, err := CaptureInstrumentationOriginalSourceInventory(input, ".")
	if err != nil {
		t.Fatal(err)
	}
	input.Headers["mode_msan.go"] = "package markers\n"
	if _, err := PlanInstrumentationOriginalPackage(input, sources, early, ".", nil); err == nil {
		t.Fatal("accepted a compact header which hid the original mode constraint")
	}
	input.Headers["mode_msan.go"] = sources.Contents["mode_msan.go"]
	input.Version = "v1.0.0"
	if _, err := PlanInstrumentationOriginalPackage(input, sources, early, ".", nil); err == nil {
		t.Fatal("assigned a version to the Go main module")
	}
}

func TestInstrumentationOriginalPlanExclusiveModeFamily(t *testing.T) {
	for _, mode := range []InstrumentationMode{InstrumentationRace, InstrumentationMSan, InstrumentationASan} {
		t.Run(string(mode), func(t *testing.T) {
			early := captureActualInstrumentationEarly(t, "linux/arm64", mode, "1")
			input := instrumentationOriginalFixture(t, early)
			sources, err := CaptureInstrumentationOriginalSourceInventory(input, ".")
			if err != nil {
				t.Fatal(err)
			}
			plan, err := PlanInstrumentationOriginalPackage(input, sources, early, ".", nil)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(plan.SFiles, []string{"mode_" + string(mode) + ".s"}) || len(plan.Decisions) != 7 ||
				plan.ModeProfileID != InstrumentationEarlyProfileID(early) || plan.CGOEnabled != "1" {
				t.Fatalf("incomplete exclusive-mode source pairing: %+v", plan)
			}
		})
	}
}
