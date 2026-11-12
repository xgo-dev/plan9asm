package gotoolprofile

import (
	"fmt"

	"github.com/xgo-dev/plan9asm"
)

// These are mode-bound native source roles, not ordinary selection evidence.
// The unchanged listing payload is reused only with the actual mode ID, tools,
// selected source and package. Every role still needs its real LLVM object.
func validateInstrumentationAssemblyEmission(input *InstrumentationConsumerInput, pkg PackageProof, file InstrumentationAssemblyFile, arch plan9asm.Arch) (*plan9asm.File, error) {
	if input == nil || input.Original == nil || input.Observation == nil || input.Observation.Early == nil ||
		input.Observation.Early.BaselineFeatures == nil || input.Observation.Early.ModeTools == nil || pkg.Macros == nil {
		return nil, fmt.Errorf("mode emission lacks its complete independent source/tool scope")
	}
	cpp := file.CPP
	parsed, parseErr := plan9asm.ParseWithDefines(arch, file.TypedSource, pkg.Macros.Defines)
	switch cpp.Emission {
	case "assembly":
		if parseErr != nil || len(parsed.Funcs) == 0 || cpp.EmptyAssembly != nil || cpp.DataOnlyAssembly != nil {
			return nil, fmt.Errorf("mode TEXT source has a contradictory or missing native role: %v", parseErr)
		}
	case "symbol_free":
		if parseErr == nil || parseErr.Error() != "no TEXT directive found" || cpp.EmptyAssembly == nil || cpp.DataOnlyAssembly != nil {
			return nil, fmt.Errorf("mode symbol-free source contradicts its actual native role")
		}
		parsed = &plan9asm.File{Arch: arch}
	case "data_only":
		if parseErr != nil || len(parsed.Funcs) != 0 || len(parsed.Globl) == 0 || cpp.EmptyAssembly != nil || cpp.DataOnlyAssembly == nil {
			return nil, fmt.Errorf("mode data-only source contradicts its actual native role: %v", parseErr)
		}
		if err := ValidateDataOnlySourceSymbols(parsed, pkg.PackagePath, cpp.DataOnlyAssembly.Symbols); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unknown mode assembly emission role")
	}
	if len(file.Declarations) != len(parsed.Funcs) {
		return nil, fmt.Errorf("mode source role lost its exact consumed Go declaration count")
	}
	// Only these scope fields are read by the shared native-listing validators.
	// This private projection never enters ordinary selection validation and is
	// not returned as a new ordinary input or source capability.
	early := input.Observation.Early
	observed := *early.BaselineFeatures
	observed.ToolBinarySHA256 = early.ModeTools.BinarySHA256
	scope := ConsumerInput{ID: input.ID, Observed: &observed,
		SignatureSourceProtocol: input.Original.SignatureSourceProtocol,
		Sources:                 input.Original.Sources}
	if err := ValidateEmptyAssembly(&scope, cpp, pkg); err != nil {
		return nil, err
	}
	return parsed, nil
}
