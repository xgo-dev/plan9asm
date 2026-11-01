package gotoolprofile

import (
	"go/parser"
	"go/token"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestInstrumentationBuildPlanSeparatesRequestedModeAndCodegen(t *testing.T) {
	source, err := CaptureInstrumentationSourceProof(runtime.GOROOT(), runtime.Version())
	if err != nil {
		t.Fatal(err)
	}
	minor, err := goMinor(runtime.Version())
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range []struct {
		target, mode, adjusted, link string
		codegen                      []string
	}{
		{"darwin/arm64", "race", "default", "pie", []string{"-shared"}},
		{"darwin/amd64", "race", "default", "pie", []string{"-shared"}},
		{"windows/amd64", "race", "default", "exe", nil},
		{"linux/arm64", "race", "default", "exe", nil},
		{"linux/arm64", "msan", "pie", "pie", []string{"-shared"}},
		{"linux/amd64", "msan", "default", "exe", nil},
	} {
		t.Run(input.target+"/"+input.mode, func(t *testing.T) {
			if strings.HasPrefix(input.target, "darwin/") && minor == 20 {
				input.link = "exe"
			}
			if input.target == "darwin/amd64" && minor < 22 {
				input.link, input.codegen = "exe", nil
			}
			plan, err := DeriveInstrumentationBuildPlan(source, input.target, InstrumentationMode(input.mode))
			if err != nil {
				t.Fatal(err)
			}
			if plan.RequestedBuildMode != "default" || plan.InstrumentAdjustedBuildMode != input.adjusted ||
				plan.SourceLinkMode != input.link || !reflect.DeepEqual(plan.CodegenFlags, input.codegen) {
				t.Fatalf("wrong source-derived requested/adjusted/codegen/link plan: %+v", plan)
			}
			if err := ValidateInstrumentationBuildPlan(plan, source); err != nil {
				t.Fatal(err)
			}
			plan.SourceLinkMode = "invented"
			if err := ValidateInstrumentationBuildPlan(plan, source); err == nil {
				t.Fatal("accepted a caller-reported final buildmode")
			}
		})
	}
}

func TestInstrumentationBuildPlanRejectsRewrittenDefaultPIEWithFreshHashes(t *testing.T) {
	proof, err := CaptureInstrumentationSourceProof(runtime.GOROOT(), runtime.Version())
	if err != nil {
		t.Fatal(err)
	}
	minor, _ := goMinor(runtime.Version())
	name := "src/internal/platform/supported.go"
	if minor == 20 {
		name = "src/cmd/go/internal/work/init.go"
	}
	set := token.NewFileSet()
	file, err := parser.ParseFile(set, name, proof.SourceText[name], 0)
	if err != nil {
		t.Fatal(err)
	}
	functionName := "DefaultPIE"
	if minor == 20 {
		functionName = "buildModeInit"
	}
	function, err := discoveryAssemblerSourceFunction(file, functionName)
	if err != nil {
		t.Fatal(err)
	}
	start, end := set.Position(function.Pos()).Offset, set.Position(function.End()).Offset
	original := proof.SourceText[name]
	changed := strings.Replace(original[start:end], `"darwin"`, `"plan9"`, 1)
	if changed == original[start:end] {
		t.Fatal("the actual Darwin PIE registration was not found")
	}
	proof.SourceText[name] = original[:start] + changed + original[end:]
	proof.SourceSHA256[name] = bytesSHA256([]byte(proof.SourceText[name]))
	// Existing early-rule registrations remain valid: codegen must validate
	// the complete additional registration, not trust the freshly rewritten
	// source hash or confuse early acceptance with compiler flags.
	if _, err := ReplayInstrumentationSourceProof(proof); err != nil {
		t.Fatal(err)
	}
	if _, err := DeriveInstrumentationBuildPlan(proof, "darwin/arm64", InstrumentationRace); err == nil {
		t.Fatal("accepted a self-consistent rewritten effective PIE registration")
	}
}
