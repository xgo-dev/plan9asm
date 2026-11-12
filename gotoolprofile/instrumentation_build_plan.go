package gotoolprofile

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"strings"
)

// InstrumentationBuildPlan separates the requested driver mode from its
// source-derived compiler/assembler flags. SourceLinkMode is the registered
// driver's planned linker mode, not evidence of an executed linker or an
// available sanitizer runtime. Only an actual same-mode compile observation
// can establish that the compiler and assembler consumed CodegenFlags.
type InstrumentationBuildPlan struct {
	Protocol                    string              `json:"protocol"`
	GoVersion                   string              `json:"go_version"`
	Target                      string              `json:"target"`
	Mode                        InstrumentationMode `json:"mode"`
	RequestedBuildMode          string              `json:"requested_build_mode"`
	InstrumentAdjustedBuildMode string              `json:"instrument_adjusted_build_mode"`
	SourceLinkMode              string              `json:"source_link_mode"`
	CodegenFlags                []string            `json:"codegen_flags,omitempty"`
	RegistrationSHA256          map[string]string   `json:"registration_ast_sha256"`
}

func DeriveInstrumentationBuildPlan(source *InstrumentationSourceProof, target string, mode InstrumentationMode) (*InstrumentationBuildPlan, error) {
	rules, err := ReplayInstrumentationSourceProof(source)
	if err != nil {
		return nil, err
	}
	adjusted, err := rules.EffectiveBuildMode(target, mode)
	if err != nil {
		return nil, err
	}
	minor, _ := goMinor(source.GoVersion)
	registration, err := instrumentationBuildRegistration(source, minor)
	if err != nil {
		return nil, err
	}
	plan := &InstrumentationBuildPlan{
		Protocol: "actual_go_instrumentation_build_plan_v1", GoVersion: source.GoVersion,
		Target: target, Mode: mode, RequestedBuildMode: "default", InstrumentAdjustedBuildMode: adjusted,
		SourceLinkMode: "exe", RegistrationSHA256: registration,
	}
	goos, goarch, _ := strings.Cut(target, "/")
	if adjusted == "pie" {
		plan.SourceLinkMode, plan.CodegenFlags = "pie", []string{"-shared"}
		return plan, nil
	}
	// These branches apply only after the complete source registrations above
	// match their audited Go version. Go 1.20 used an inline default branch;
	// its Darwin ARM64 codegen was shared even though ldBuildmode stayed exe.
	if minor == 20 {
		switch goos {
		case "android", "ios":
			plan.SourceLinkMode, plan.CodegenFlags = "pie", []string{"-shared"}
		case "windows":
			if mode != InstrumentationRace {
				plan.SourceLinkMode = "pie"
			}
		case "darwin":
			if goarch == "arm64" {
				plan.CodegenFlags = []string{"-shared"}
			}
		}
		return plan, nil
	}
	defaultPIE := goos == "android" || goos == "ios" ||
		goos == "windows" && mode != InstrumentationRace ||
		goos == "darwin" && (minor >= 22 || goarch == "arm64")
	if defaultPIE {
		plan.SourceLinkMode = "pie"
		if goos != "windows" {
			plan.CodegenFlags = []string{"-shared"}
		}
	}
	return plan, nil
}

func ValidateInstrumentationBuildPlan(plan *InstrumentationBuildPlan, source *InstrumentationSourceProof) error {
	if plan == nil {
		return fmt.Errorf("missing source-derived instrumentation build plan")
	}
	wanted, err := DeriveInstrumentationBuildPlan(source, plan.Target, plan.Mode)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(plan, wanted) {
		return fmt.Errorf("instrumentation build plan differs from the complete actual driver sources")
	}
	return nil
}

func instrumentationBuildRegistration(source *InstrumentationSourceProof, minor int) (map[string]string, error) {
	registration := make(map[string]string)
	for _, item := range []struct{ file, name string }{
		{"src/cmd/go/internal/work/init.go", "buildModeInit"},
		{"src/internal/platform/supported.go", "DefaultPIE"},
	} {
		set := token.NewFileSet()
		file, err := parser.ParseFile(set, item.file, source.SourceText[item.file], 0)
		if err != nil {
			return nil, err
		}
		function, err := discoveryAssemblerSourceFunction(file, item.name)
		if minor == 20 && item.name == "DefaultPIE" {
			for _, declaration := range file.Decls {
				if fn, ok := declaration.(*ast.FuncDecl); ok && fn.Name.Name == item.name {
					return nil, fmt.Errorf("unexpected Go 1.20 external DefaultPIE registration")
				}
			}
			registration[item.name] = bytesSHA256(nil)
			continue
		}
		if err != nil {
			return nil, err
		}
		registration[item.name], err = ASTSHA(set, function)
		if err != nil {
			return nil, err
		}
	}
	wanted := map[string]string{
		"buildModeInit": "93bbca69e0bd378d09842ab69c01c48e76dad5b6ebb5935674043ab16c50cba7",
		"DefaultPIE":    "e8d3f7e66c3d0c23f4bdd4e5e9927d8adebb19229be425ebe6ad915fdb742374",
	}
	if minor == 20 {
		wanted["buildModeInit"] = "e358c2b632bd5c665bb216cbb551a536dfd7ef556cb5238d0761ab482f8a3e81"
		wanted["DefaultPIE"] = bytesSHA256(nil)
	} else if minor == 21 {
		wanted["buildModeInit"] = "9d5ad2c0f3e2f30c6c40fc75d7141bb35913eca1e0da1c6a11bb4061a2f20c51"
		wanted["DefaultPIE"] = "2df09e5d91da08a13fa6874d579d69e5ef5438e2f0ae793f335329db28307d79"
	}
	if !reflect.DeepEqual(registration, wanted) {
		return nil, fmt.Errorf("unrecognized complete Go codegen/buildmode registration")
	}
	return registration, nil
}
