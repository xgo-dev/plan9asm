package gotoolprofile

import (
	"fmt"
	"io"
	"reflect"

	"github.com/xgo-dev/plan9asm"
)

const InstrumentationConsumerProtocol = "actual_go_instrumentation_source_context_v1"
const InstrumentationPackageSelectionProtocol = "actual_go_instrumentation_package_selection_v1"
const instrumentationAssemblerProtocol = "go_source_instrumentation_assembler_macros_v1"

// InstrumentationConsumerInput keeps the complete original source input in its
// original role. Its CPU foundation is not rewritten into a mode observation.
// This single-package context is not export, header, CPP, LLVM or runtime proof.
// External callers must independently authenticate original ZIP/metadata bytes.
type InstrumentationConsumerInput struct {
	Protocol    string                                  `json:"protocol"`
	ID          string                                  `json:"mode_profile_id"`
	Original    *ConsumerInput                          `json:"original"`
	Sources     *InstrumentationOriginalSourceInventory `json:"original_source_inventory"`
	Observation *InstrumentationExportObservation       `json:"actual_mode_observation"`
	Plan        *InstrumentationOriginalPackagePlan     `json:"original_package_plan"`
	TypeSources *InstrumentationTypeSourceProof         `json:"original_type_sources,omitempty"`
}

// InstrumentationPackageSelectionProof reuses concrete original package/source
// identities but never the ordinary protocol or its profile ID. Actual loaders
// must independently capture/recheck source, tools and selected dependency
// exports; validating this source-only record does not discharge a candidate.
type InstrumentationPackageSelectionProof struct {
	Protocol      string         `json:"protocol"`
	ModeProfileID string         `json:"mode_profile_id"`
	InputSHA256   string         `json:"input_sha256"`
	CustomTags    []string       `json:"custom_tags,omitempty"`
	Packages      []PackageProof `json:"packages"`
	Status        string         `json:"status"`
}

func NewInstrumentationConsumerInput(original *ConsumerInput, sources *InstrumentationOriginalSourceInventory, observed *InstrumentationExportObservation, plan *InstrumentationOriginalPackagePlan) (*InstrumentationConsumerInput, error) {
	if observed == nil || plan == nil {
		return nil, fmt.Errorf("missing actual mode observation or original planning scope")
	}
	input := &InstrumentationConsumerInput{
		Protocol: InstrumentationConsumerProtocol, ID: InstrumentationEarlyProfileID(observed.Early),
		Original: original, Sources: sources, Observation: observed, Plan: plan,
	}
	if err := ValidateInstrumentationConsumerInput(input, plan.PackageDirectory, plan.CustomTags); err != nil {
		return nil, err
	}
	return input, nil
}

func ValidateInstrumentationConsumerInput(input *InstrumentationConsumerInput, directory string, tags []string) error {
	if input == nil || input.Protocol != InstrumentationConsumerProtocol || input.Original == nil || input.Plan == nil || input.Observation == nil {
		return fmt.Errorf("missing independent instrumentation source context")
	}
	if err := ValidateInstrumentationExportObservation(input.Observation); err != nil {
		return err
	}
	if input.ID != InstrumentationEarlyProfileID(input.Observation.Early) || input.ID == input.Original.ID {
		return fmt.Errorf("instrumentation context has a changed or ordinary profile identity")
	}
	if err := ValidateInstrumentationOriginalPackagePlan(input.Original, input.Sources, input.Observation.Early, directory, tags, input.Plan); err != nil {
		return err
	}
	if input.TypeSources != nil {
		return ValidateInstrumentationTypeSources(input, input.TypeSources)
	}
	return nil
}

func DecodeInstrumentationConsumerInput(reader io.Reader, directory string, tags []string) (*InstrumentationConsumerInput, error) {
	var input InstrumentationConsumerInput
	if err := decodeInstrumentationOriginalJSON(reader, 40<<20, &input); err != nil {
		return nil, err
	}
	if err := ValidateInstrumentationConsumerInput(&input, directory, tags); err != nil {
		return nil, err
	}
	return &input, nil
}

func DecodeInstrumentationPackageSelection(reader io.Reader, input *InstrumentationConsumerInput, directory string, tags []string) (*InstrumentationPackageSelectionProof, error) {
	var proof InstrumentationPackageSelectionProof
	if err := decodeInstrumentationOriginalJSON(reader, 8<<20, &proof); err != nil {
		return nil, err
	}
	if err := ValidateInstrumentationPackageSelection(input, directory, tags, &proof); err != nil {
		return nil, err
	}
	return &proof, nil
}

// The private physical source/proxy roots do not become portable identities.
// Every original protocol/resource field and complete observed mode remain
// bound. This digest alone authenticates neither source nor an invocation.
func InstrumentationConsumerInputSHA256(input *InstrumentationConsumerInput) string {
	if input == nil || input.Original == nil {
		return ""
	}
	copy, original := *input, *input.Original
	original.SourceRoot, original.ProxyGoModPath = "", ""
	copy.Original = &original
	return instrumentationObjectSHA(&copy)
}

func ValidateInstrumentationPackageSelection(input *InstrumentationConsumerInput, directory string, tags []string, proof *InstrumentationPackageSelectionProof) error {
	if err := ValidateInstrumentationConsumerInput(input, directory, tags); err != nil {
		return err
	}
	if proof == nil || proof.Protocol != InstrumentationPackageSelectionProtocol || proof.ModeProfileID != input.ID ||
		proof.InputSHA256 != InstrumentationConsumerInputSHA256(input) || !equalDiscoveryStrings(proof.CustomTags, tags) ||
		proof.Status != "consumer_pending" || len(proof.Packages) != 1 {
		return fmt.Errorf("mode package selection differs from its complete independent context")
	}
	plan, pkg := input.Plan, proof.Packages[0]
	if input.Original.SourceModule != "" && input.Original.SourceModule != input.Original.Module && pkg.SourceRole != "version_replace" {
		return fmt.Errorf("mode namespace alias lacks its actual exact-version replacement role")
	}
	if len(plan.CgoFiles) != 0 || pkg.PackagePath != plan.PackagePath || !equalDiscoveryStrings(pkg.GoFiles, plan.GoFiles) ||
		!equalDiscoveryStrings(pkg.CompiledGoFiles, plan.GoFiles) || !equalDiscoveryStrings(pkg.SFiles, plan.SFiles) {
		return fmt.Errorf("mode package has changed original selection or an unproved generated/cgo source role")
	}
	ctx, err := instrumentationOriginalBuildContext(input.Sources, input.Observation.Early, tags, true)
	if err != nil {
		return err
	}
	macros := func(pkg PackageProof) error {
		return ValidateInstrumentationAssemblerMacros(pkg.Macros, input, pkg.PackagePath)
	}
	_, _, err = validatePackageSelectionContext(input.Original, proof.Packages, plan.SFiles, nil, ctx, macros)
	return err
}

// Go's registered asmArgs and experiment-macro rules are shared between modes.
// Capture those actual source registrations unchanged, and separately bind
// them to the independently observed mode environment and profile identity.
func CaptureInstrumentationAssemblerMacros(root string, input *InstrumentationConsumerInput, packagePath string) (*AssemblerMacros, error) {
	if input == nil || input.Plan == nil {
		return nil, fmt.Errorf("missing actual instrumentation context")
	}
	if err := ValidateInstrumentationConsumerInput(input, input.Plan.PackageDirectory, input.Plan.CustomTags); err != nil {
		return nil, err
	}
	proof, err := CaptureAssemblerMacros(root, input.Observation.Early.BaselineFeatures, packagePath)
	if err != nil {
		return nil, err
	}
	proof.Protocol, proof.FeatureID = instrumentationAssemblerProtocol, input.ID
	if err := ValidateInstrumentationAssemblerMacros(proof, input, packagePath); err != nil {
		return nil, err
	}
	return proof, nil
}

func ValidateInstrumentationAssemblerMacros(proof *AssemblerMacros, input *InstrumentationConsumerInput, packagePath string) error {
	if input == nil || input.Plan == nil || input.Observation == nil {
		return fmt.Errorf("missing independent instrumentation assembler context")
	}
	if err := ValidateInstrumentationConsumerInput(input, input.Plan.PackageDirectory, input.Plan.CustomTags); err != nil {
		return err
	}
	if proof == nil || proof.Protocol != instrumentationAssemblerProtocol || proof.FeatureID != input.ID || packagePath != input.Plan.PackagePath {
		return fmt.Errorf("assembler macros lost their actual mode/package binding")
	}
	// This copy validates the unchanged shared source-registration grammar;
	// it is never emitted as an ordinary package/selection observation.
	registration := *proof
	registration.Protocol, registration.FeatureID = "go_source_assembler_macros_v1", input.Original.ID
	if err := ValidateOrdinaryAssemblerMacros(&registration, input.Observation.Early.BaselineFeatures, packagePath); err != nil {
		return err
	}
	early := input.Observation.Early
	defines, err := plan9asm.GoAssemblerDefinesForEnvironment(early.Environment["GOOS"], early.Environment["GOARCH"], early.Environment)
	if err != nil || !reflect.DeepEqual(defines, proof.Defines) || !reflect.DeepEqual(defines, input.Observation.Routing.AssemblerDefines) {
		return fmt.Errorf("assembler definitions differ from the actual mode environment/routing")
	}
	return nil
}
