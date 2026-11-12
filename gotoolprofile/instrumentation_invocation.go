package gotoolprofile

import (
	"fmt"
	"io"
	"reflect"
)

const InstrumentationInvocationProtocol = "actual_go_instrumentation_cli_invocation_v1"

type InstrumentationInvocationPhase string

const (
	InstrumentationMetadataQuery InstrumentationInvocationPhase = "metadata_query"
	InstrumentationObjectCompile InstrumentationInvocationPhase = "llvm_objects"
)

// InstrumentationInvocationProof is the separate CLI result consumed by mode
// callers. An independently expected phase/context and actual LLVM tool are
// mandatory. Metadata queries have no object count; objects prove neither
// final linking nor runtime semantics. No field supplies a candidate PASS.
type InstrumentationInvocationProof struct {
	Protocol         string                           `json:"protocol"`
	Phase            InstrumentationInvocationPhase   `json:"phase"`
	ModeProfileID    string                           `json:"mode_profile_id"`
	InputSHA256      string                           `json:"input_sha256"`
	Target           string                           `json:"target"`
	PackageDirectory string                           `json:"package_directory"`
	PackagePath      string                           `json:"package_path"`
	CustomTags       []string                         `json:"custom_tags,omitempty"`
	AsmFiles         []string                         `json:"asm_files"`
	ObjectCount      int                              `json:"object_count"`
	Metadata         *InstrumentationMetadataProof    `json:"metadata"`
	Consumption      *InstrumentationConsumptionProof `json:"consumption,omitempty"`
	LLVM             *InstrumentationLLVMTool         `json:"llvm,omitempty"`
}

func NewInstrumentationInvocation(input *InstrumentationConsumerInput, phase InstrumentationInvocationPhase,
	metadata *InstrumentationMetadataProof, consumption *InstrumentationConsumptionProof, llvm *InstrumentationLLVMTool,
) (*InstrumentationInvocationProof, error) {
	if input == nil || input.Plan == nil {
		return nil, fmt.Errorf("missing independently bound mode invocation input")
	}
	plan := input.Plan
	proof := &InstrumentationInvocationProof{
		Protocol: InstrumentationInvocationProtocol, Phase: phase, ModeProfileID: input.ID,
		InputSHA256: InstrumentationConsumerInputSHA256(input), Target: plan.Target,
		PackageDirectory: plan.PackageDirectory, PackagePath: plan.PackagePath,
		CustomTags: append([]string(nil), plan.CustomTags...), AsmFiles: append([]string(nil), plan.SFiles...),
		Metadata: metadata, Consumption: consumption, LLVM: llvm,
	}
	if consumption != nil {
		proof.ObjectCount = len(consumption.Files)
	}
	if err := ValidateInstrumentationInvocation(input, phase, metadata, llvm, proof); err != nil {
		return nil, err
	}
	return proof, nil
}

func ValidateInstrumentationInvocation(input *InstrumentationConsumerInput, phase InstrumentationInvocationPhase,
	producer *InstrumentationMetadataProof, llvm *InstrumentationLLVMTool, proof *InstrumentationInvocationProof,
) error {
	if input == nil || input.Plan == nil {
		return fmt.Errorf("missing independently expected original mode invocation scope")
	}
	plan := input.Plan
	if err := ValidateInstrumentationConsumerInput(input, plan.PackageDirectory, plan.CustomTags); err != nil {
		return err
	}
	if proof == nil || proof.Protocol != InstrumentationInvocationProtocol || proof.Phase != phase ||
		proof.ModeProfileID != input.ID || proof.InputSHA256 != InstrumentationConsumerInputSHA256(input) ||
		proof.Target != plan.Target || proof.PackageDirectory != plan.PackageDirectory || proof.PackagePath != plan.PackagePath ||
		!equalDiscoveryStrings(proof.CustomTags, plan.CustomTags) || !equalDiscoveryStrings(proof.AsmFiles, plan.SFiles) {
		return fmt.Errorf("mode invocation lost or changed its independent phase/source/target/profile/tag scope")
	}
	if err := ValidateInstrumentationMetadata(input, plan.PackageDirectory, plan.CustomTags, proof.Metadata); err != nil {
		return err
	}
	sameProducer := false
	if producer != nil {
		if err := ValidateInstrumentationMetadata(input, plan.PackageDirectory, plan.CustomTags, producer); err != nil {
			return err
		}
		wanted, err := compactInstrumentationMetadataLayouts(producer)
		if err != nil {
			return err
		}
		actual, err := compactInstrumentationMetadataLayouts(proof.Metadata)
		if err != nil {
			return err
		}
		// Unlike independent header recapture agreement, invocation producer
		// identity retains every header hash and every other metadata field.
		sameProducer = reflect.DeepEqual(wanted, actual)
	}
	switch phase {
	case InstrumentationMetadataQuery:
		if producer != nil && !sameProducer || llvm != nil || proof.LLVM != nil ||
			proof.Consumption != nil || proof.ObjectCount != 0 {
			return fmt.Errorf("metadata query borrowed object/compiler/other producer evidence")
		}
	case InstrumentationObjectCompile:
		if producer == nil || !sameProducer || !reflect.DeepEqual(proof.LLVM, llvm) ||
			proof.Consumption == nil || proof.ObjectCount != len(plan.SFiles) {
			return fmt.Errorf("mode object invocation lacks its independent original producer/tool/full file denominator")
		}
		return ValidateInstrumentationConsumption(input, producer, llvm, plan.PackageDirectory, plan.CustomTags, proof.Consumption)
	default:
		return fmt.Errorf("unknown instrumentation invocation phase")
	}
	return nil
}

func DecodeInstrumentationInvocation(reader io.Reader, input *InstrumentationConsumerInput, phase InstrumentationInvocationPhase,
	producer *InstrumentationMetadataProof, llvm *InstrumentationLLVMTool,
) (*InstrumentationInvocationProof, error) {
	var proof InstrumentationInvocationProof
	if err := decodeInstrumentationOriginalJSON(reader, 48<<20, &proof); err != nil {
		return nil, err
	}
	if err := ValidateInstrumentationInvocation(input, phase, producer, llvm, &proof); err != nil {
		return nil, err
	}
	return &proof, nil
}
