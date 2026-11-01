package gotoolprofile

import (
	"fmt"
	"path"
	"reflect"
	"strconv"
	"strings"
	"text/scanner"

	"github.com/xgo-dev/plan9asm"
)

const CPPOriginalReplayProtocol = "exact_go_cpp_original_replay_v3"

// CPPOriginalReplayInput transports query inputs, not source authority. Its
// bytes must independently match the actual module/archive and selected SDK.
// RequiredExpandedOperands is populated only after replay with the real header
// and ordered driver defines. A missing or null entry cannot enter CPP/object.
type CPPOriginalReplayInput struct {
	Sources                  map[string]string                 `json:"sources"`
	Units                    map[string]CPPOriginalUnit        `json:"units"`
	RequiredExpandedOperands map[string][]CPPPackageSearchMiss `json:"required_expanded_operands"`
}

type CPPOriginalUnit struct {
	Includes         map[string]string `json:"includes"`
	GeneratedHeaders []string          `json:"generated_headers"`
}

func ValidateCPPOriginalInputs(input *ConsumerInput) error {
	if input == nil {
		return fmt.Errorf("missing CPP original input")
	}
	graph := input.CPPOriginals
	if input.CPPSourceProtocol == "" && graph == nil {
		return nil // Historical inputs retain their physical-literal contract.
	}
	if input.CPPSourceProtocol != CPPOriginalReplayProtocol || graph == nil ||
		len(graph.Sources) == 0 || len(graph.Sources) > 512 || len(graph.Units) == 0 || len(graph.Units) > 512 {
		return fmt.Errorf("CPP original graph/protocol is missing or unbounded")
	}
	total := 0
	for id, text := range graph.Sources {
		origin, file, ok := strings.Cut(id, "/")
		wanted := input.Sources[file]
		if origin == "tool" {
			wanted = input.ToolSources[file]
		}
		if !ok || (origin != "module" && origin != "tool") || !CPPLocalSource(file) ||
			len(text) > 64<<20-total || wanted == "" || bytesSHA256([]byte(text)) != wanted {
			return fmt.Errorf("CPP original bytes lack their independent source hash: %s", id)
		}
		total += len(text)
	}
	for assembly, unit := range graph.Units {
		// The complete source loop already authenticated every module/tool
		// original against its exact hash. Retain the unit's source/edge checks
		// without copying and hashing the same assembly bytes a second time.
		_, original := graph.Sources["module/"+assembly]
		if !CPPLocalSource(assembly) || input.Sources[assembly] == "" ||
			!original || len(unit.Includes) > 100000 {
			return fmt.Errorf("CPP original unit has no complete assembly source")
		}
		for include, id := range unit.Includes {
			module, tool, err := CPPIncludeCandidates(assembly, include)
			_, present := graph.Sources[id]
			if err != nil || !present || id != "module/"+module && id != "tool/"+tool ||
				id == "tool/"+tool && CPPLocalSource(module) && input.Sources[module] != "" {
				return fmt.Errorf("CPP original resource differs from fixed search origins")
			}
		}
		for index, name := range unit.GeneratedHeaders {
			if index != 0 || name != "go_asm.h" || unit.Includes[name] != "" {
				return fmt.Errorf("CPP deferred header has no exact compiler role")
			}
		}
	}
	// Object scope can be narrower than actual Go selection. Both executed
	// originals and registered source-only companions need their complete unit;
	// deleting a companion must not bypass source closure via a smaller graph.
	for _, files := range [][]string{input.AsmFiles, input.RegisteredAsmFiles} {
		for _, assembly := range files {
			if _, exists := graph.Units[assembly]; !exists {
				return fmt.Errorf("CPP original graph omitted selected package assembly: %s", assembly)
			}
		}
	}
	for assembly, required := range graph.RequiredExpandedOperands {
		if _, exists := graph.Units[assembly]; !exists || !containsString(input.AsmFiles, assembly) {
			return fmt.Errorf("CPP expanded operands claim an unknown assembly")
		}
		last := ""
		for _, miss := range required {
			key := cppSearchMissKey(miss)
			if miss.Assembly != assembly || miss.Protocol != CPPExpandedPackageSearchMissProtocol ||
				ValidateCPPPackageSearchMiss(miss) != nil || key <= last || input.ToolSources[miss.ToolSource] == "" {
				return fmt.Errorf("CPP expanded operand set is unbound or noncanonical")
			}
			last = key
		}
	}
	return nil
}

// ReplayCPPOriginal executes the one shared token-stack engine. It does not
// read physical files or authenticate its inputs; producer, consumer and reader
// independently bind those before comparing output, used bytes and operands.
func ReplayCPPOriginal(input *ConsumerInput, assembly, packagePath string, defines []string, header []byte) (plan9asm.AssemblyCPPObservation, map[string]string, []CPPPackageSearchMiss, error) {
	if err := ValidateCPPOriginalInputs(input); err != nil {
		return plan9asm.AssemblyCPPObservation{}, nil, nil, err
	}
	if input.CPPOriginals == nil {
		return plan9asm.AssemblyCPPObservation{}, nil, nil, fmt.Errorf("CPP replay lacks its full original graph")
	}
	graph, unit := input.CPPOriginals, input.CPPOriginals.Units[assembly]
	original := "module/" + assembly
	text, exists := graph.Sources[original]
	if !exists {
		return plan9asm.AssemblyCPPObservation{}, nil, nil, fmt.Errorf("CPP replay has no assembly original")
	}
	used := map[string]string{original: bytesSHA256([]byte(text))}
	observation, err := plan9asm.ObserveAssemblyCPP(text, plan9asm.AssemblyPreprocessOptions{
		FileName: original, Defines: defines,
		ReadInclude: func(_ string, name string) (string, []byte, error) {
			id := unit.Includes[name]
			if id == "" {
				for _, deferred := range unit.GeneratedHeaders {
					if name == deferred && header == nil {
						return "", nil, &cppGeneratedHeaderRequirement{assembly: assembly, operand: name}
					}
					if name == deferred && header != nil && packagePath != "" {
						id = "generated/" + packagePath + "/go_asm.h"
						used[id] = bytesSHA256(header)
						return id, append([]byte(nil), header...), nil
					}
				}
				return "", nil, fmt.Errorf("active CPP operand has no independently registered original: %s", name)
			}
			data, exists := graph.Sources[id]
			if !exists {
				return "", nil, fmt.Errorf("active CPP operand omitted its original bytes")
			}
			used[id] = bytesSHA256([]byte(data))
			return id, []byte(data), nil
		},
	})
	if err != nil {
		return plan9asm.AssemblyCPPObservation{}, nil, nil, err
	}
	required, err := CPPExpandedOperands(input, assembly, observation)
	if err != nil {
		return plan9asm.AssemblyCPPObservation{}, nil, nil, err
	}
	return observation, used, required, nil
}

// CPPExpandedOperands consumes actual execution events, never raw candidate
// records. Physical includes still require their unchanged v1 literal witness.
func CPPExpandedOperands(input *ConsumerInput, assembly string, observation plan9asm.AssemblyCPPObservation) ([]CPPPackageSearchMiss, error) {
	if input == nil || input.CPPOriginals == nil {
		return nil, fmt.Errorf("expanded CPP event has no full original input")
	}
	unit := input.CPPOriginals.Units[assembly]
	required := []CPPPackageSearchMiss{}
	seen := make(map[string]bool)
	for _, event := range observation.Events {
		if event.Kind != "control" || event.Directive != "include" || !event.Executed || !event.EnabledBefore {
			continue
		}
		var include string
		var err error
		for _, token := range event.Tokens {
			if token.Kind == scanner.String {
				include, err = strconv.Unquote(token.RecordedValue)
				break
			}
		}
		module, tool, candidateErr := CPPIncludeCandidates(assembly, include)
		if err != nil || candidateErr != nil || event.Included != unit.Includes[include] && !strings.HasPrefix(event.Included, "generated/") {
			return nil, fmt.Errorf("active expanded include lost its exact operand/origin")
		}
		if CPPLocalSource(module) {
			continue
		}
		if event.Expansion == 0 {
			if err := RequireCPPPackageSearchMiss(input, assembly, event.Position.File, include); err != nil {
				return nil, err
			}
			continue
		}
		miss := CPPPackageSearchMiss{Protocol: CPPExpandedPackageSearchMissProtocol, Assembly: assembly,
			Include: include, PackageCandidate: module, ToolSource: tool}
		if event.Included != "tool/"+tool || ValidateCPPPackageSearchMiss(miss) != nil {
			return nil, fmt.Errorf("expanded outside-package include has no canonical SDK fallback")
		}
		key := cppSearchMissKey(miss)
		if !seen[key] {
			seen[key] = true
			required = append(required, miss)
		}
	}
	SortCPPIncludeSearch(required)
	return required, nil
}

func ValidateCPPExpandedOperands(input *ConsumerInput, assembly string, actual []CPPPackageSearchMiss) error {
	if input == nil || input.CPPOriginals == nil || actual == nil {
		return fmt.Errorf("CPP object lacks its actual expanded operand set")
	}
	wanted, present := input.CPPOriginals.RequiredExpandedOperands[assembly]
	if !present || wanted == nil || !reflect.DeepEqual(wanted, actual) {
		return fmt.Errorf("CPP expanded operands differ from the independently replayed producer inputs")
	}
	var receipts []CPPPackageSearchMiss
	for _, miss := range input.CPPIncludeSearchMisses {
		if miss.Assembly == assembly && miss.Protocol == CPPExpandedPackageSearchMissProtocol {
			receipts = append(receipts, miss)
		}
	}
	if len(receipts) != len(actual) || len(actual) != 0 && !reflect.DeepEqual(receipts, actual) {
		return fmt.Errorf("CPP expanded absence receipts are missing, extra or unconsumed")
	}
	return nil
}

// CPPOriginalExecutionInput is used only after the caller has validated an
// actual mode header/selection. It leaves the original query input and its
// digest untouched; no ordinary/baseline operand collection is inherited.
func CPPOriginalExecutionInput(input *ConsumerInput, assembly, packagePath string, defines []string, header []byte) (*ConsumerInput, []CPPPackageSearchMiss, error) {
	data, err := MarshalConsumerInput(input)
	if err != nil {
		return nil, nil, err
	}
	clone, err := DecodeConsumerInput(strings.NewReader(string(data)))
	if err != nil {
		return nil, nil, err
	}
	_, _, required, err := ReplayCPPOriginal(clone, assembly, packagePath, defines, header)
	if err != nil {
		return nil, nil, err
	}
	clone.CPPOriginals.RequiredExpandedOperands = map[string][]CPPPackageSearchMiss{assembly: required}
	physical := []CPPPackageSearchMiss{}
	for _, miss := range clone.CPPIncludeSearchMisses {
		if miss.Protocol == CPPPackageSearchMissProtocol {
			physical = append(physical, miss)
		}
	}
	clone.CPPIncludeSearchMisses = append(physical, required...)
	SortCPPIncludeSearch(clone.CPPIncludeSearchMisses)
	return clone, required, nil
}

func cppSearchMissKey(miss CPPPackageSearchMiss) string {
	return miss.Assembly + "\x00" + miss.Source + "\x00" + miss.Include
}

// A source-only query may retain inactive SDK resources without claiming an
// active absence receipt. Actual CPP/object additionally checks its full set.
func cppOriginalToolRegistered(input *ConsumerInput, source string) bool {
	if input.CPPOriginals == nil || input.CPPSourceProtocol != CPPOriginalReplayProtocol {
		return false
	}
	for _, unit := range input.CPPOriginals.Units {
		for _, id := range unit.Includes {
			if id == "tool/"+source {
				return true
			}
		}
	}
	return false
}

func CPPOriginalPackagePath(module, assembly string) string {
	if directory := path.Dir(assembly); directory != "." {
		return module + "/" + directory
	}
	return module
}
