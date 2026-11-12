package gostaticstorage

import (
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
)

// ASMDataProtocol describes offline source/object observations only. Neither
// a fragment nor a successful join is a storage, initializer, read or native
// body certificate. Live SDK source provenance is a separate producer role.
const ASMDataProtocol = "actual_go_asm_data_observation_v1"

// ASMDataCPPProtocol does not certify the raw-to-expanded transformation. The
// live SDK producer must independently bind that execution and all its inputs.
const ASMDataCPPProtocol = "actual_go_sdk_cpp_asm_data_observation_v1"

type ASMDataValueKind string

const (
	ASMDataInteger ASMDataValueKind = "integer"
	ASMDataFloat   ASMDataValueKind = "float"
	ASMDataString  ASMDataValueKind = "string"
	ASMDataAddress ASMDataValueKind = "address"
)

type ASMDataAddressValue struct {
	Name   string
	Static bool
	ABI    uint16
	Addend int64
}

// ASMDataFragment retains the source value and its actual encoded bytes. Bits
// are the width-truncated integer or IEEE float bit pattern, not a Go type.
type ASMDataFragment struct {
	Ordinal, Line int
	Offset, Width int64
	Kind          ASMDataValueKind
	Bits          uint64
	String        []byte
	Address       *ASMDataAddressValue
}

type ASMGlobalLayout struct {
	Ordinal, Line int
	Name          string
	Static        bool
	ABI           uint16
	Flags         uint64
	DeclaredSize  int64
	Fragments     []ASMDataFragment
	Definition    ASMDataDefinition
}

// ASMDataDefinition is one exact object-local record. Repeated names, hashes
// or bytes do not merge identities or select a linker winner.
type ASMDataDefinition struct {
	Namespace           TextSymbolNamespace
	Relative, Index     uint32
	Name                string
	ABI                 uint16
	Kind, Flags, Flags2 uint8
	Size, Align         uint32
	Hash                []byte
	DataOffset          uint32
	Data                []byte
	Relocations         []TextRelocation
}

type ASMDataMember struct {
	Name         string
	NameBytes    []byte
	Ordinal      int
	Offset, Size int64
	ObjectOffset int64
	Flags        uint32
	Definitions  []ASMDataDefinition
	Texts        []TextRecord
}

// SDKASMDataSource contains whole, separately retained inputs. The offline
// API does not authenticate a CPP invocation, generated header or SDK origin.
// Original and Expanded must each describe the observed directive grammar;
// unknown macros and generated-header roles remain Context.
type SDKASMDataSource struct {
	Name                           string
	Original, Expanded             []byte
	OriginalObject, ExpandedObject []byte
}

type SDKASMDataObservationRequest struct {
	PackagePath   string
	Target        string
	Archive       []byte
	BuiltinSource []byte
	Sources       []SDKASMDataSource
	Referenced    map[string]SDKReferencedArchive
}

type ASMDataSourceObservation struct {
	Name                           string
	OriginalSHA256, ExpandedSHA256 string
	OriginalObjectSHA256           string
	ExpandedObjectSHA256           string
	OriginalProgramSHA256          string
	ExpandedProgramSHA256          string
	Layouts                        []ASMGlobalLayout
	ExpandedLayouts                []ASMGlobalLayout
	Original, Expanded             ASMDataMember
	TextOrder                      []ASMSourceText
	GeneratedFuncdata              []ASMGeneratedFuncdata
	GeneratedFloatPools            []ASMGeneratedFloatPool
}

type SDKASMDataObservation struct {
	Protocol, PackagePath, Target string
	ArchiveSHA256                 string
	Members                       []ASMDataMember
	Sources                       []ASMDataSourceObservation
}

// ObserveX86SDKASMData is intentionally separate from the existing owned and
// SDK CPU readers. Successful offline parsing cannot mint their permissions.
func ObserveX86SDKASMData(request SDKASMDataObservationRequest) (*SDKASMDataObservation, error) {
	return observeX86SDKASMData(request, false)
}

// ObserveX86SDKCPPASMData observes the complete expanded grammar and checks
// both independently assembled objects against the original compiler archive.
// Raw bytes are retained by digest, not interpreted as an expanded program.
// This offline adapter authenticates no CPP, SDK, header or storage role.
func ObserveX86SDKCPPASMData(request SDKASMDataObservationRequest) (*SDKASMDataObservation, error) {
	return observeX86SDKASMData(request, true)
}

// ObserveX86SDKASMDataListingObjects checks separately assembled listing
// objects against an existing complete source/header-mapped object request.
// Both use the authenticated position-mapped input. Every code byte,
// relocation, DATA definition, object-local identity and complete debug
// position must agree with that source's independently assembled object. This is
// a pure observation, not source, initializer, instruction or read authority.
func ObserveX86SDKASMDataListingObjects(request SDKASMDataObservationRequest, ordinal int, originalBytes, expandedBytes []byte) ([]TextRecord, []TextRecord, error) {
	if ordinal < 0 || ordinal >= len(request.Sources) || len(originalBytes) == 0 || len(expandedBytes) == 0 ||
		len(originalBytes) > archiveLimit || len(expandedBytes) > archiveLimit {
		return nil, nil, contextError("listing objects lack a bounded selected source identity")
	}
	observation, err := ObserveX86SDKCPPASMData(request)
	if err != nil {
		return nil, nil, err
	}
	referenced, err := sdkReferencedArchiveSymbols(request.Referenced, request.Target)
	if err != nil {
		return nil, nil, err
	}
	original, err := observeASMDataObject(originalBytes, request.BuiltinSource, request.Target, sdkAssemblyObjectFlags(request.Target), referenced)
	if err != nil {
		return nil, nil, err
	}
	if !reflect.DeepEqual(original, observation.Sources[ordinal].Original) {
		return nil, nil, contextError("original listing object differs from complete authenticated source metadata")
	}
	expanded, err := observeASMDataObject(expandedBytes, request.BuiltinSource, request.Target, sdkAssemblyObjectFlags(request.Target), referenced)
	if err != nil {
		return nil, nil, err
	}
	if !reflect.DeepEqual(expanded, observation.Sources[ordinal].Expanded) {
		if len(original.Definitions) == len(expanded.Definitions) {
			for index, first := range original.Definitions {
				second := expanded.Definitions[index]
				first.DataOffset, second.DataOffset = 0, 0
				if !reflect.DeepEqual(first, second) {
					return nil, nil, contextError(fmt.Sprintf("expanded listing definition %d differs: namespace=%d name=%q kind=%d sizes=%d/%d", index, first.Namespace, first.Name, first.Kind, first.Size, second.Size))
				}
			}
		}
		return nil, nil, contextError("expanded listing object changed code/DATA/relocation/namespace")
	}
	return original.Texts, expanded.Texts, nil
}

func observeX86SDKASMData(request SDKASMDataObservationRequest, cpp bool) (*SDKASMDataObservation, error) {
	if !X86SDKTarget(request.Target) || request.PackagePath == "" ||
		strings.ContainsAny(request.PackagePath, "\x00\r\n") || len(request.PackagePath) > 4096 {
		return nil, contextError("unobserved SDK DATA target or package identity")
	}
	if len(request.Sources) == 0 || len(request.Sources) > 62 {
		return nil, contextError("SDK DATA source inventory violates the archive member bound")
	}
	total := int64(len(request.Archive)) + int64(len(request.BuiltinSource))
	names := make([]string, len(request.Sources))
	for index, source := range request.Sources {
		if filepath.Base(source.Name) != source.Name || !strings.HasSuffix(source.Name, ".s") {
			return nil, contextError("SDK DATA source name differs from its exact selected route")
		}
		for ordinal, input := range [][]byte{source.Original, source.Expanded, source.OriginalObject, source.ExpandedObject} {
			// A real CPP execution may expand a comments-only selected ASM
			// to empty bytes. Only the CPP adapter admits that grammar; both
			// complete objects and the matching archive member remain required.
			if len(input) == 0 && !(cpp && ordinal == 1) || len(input) > archiveLimit {
				return nil, contextError("SDK DATA source/object input violates its complete byte bound")
			}
			total += int64(len(input))
		}
		names[index] = source.Name
	}
	for _, dependency := range request.Referenced {
		total += int64(len(dependency.Archive))
	}
	if total > 64<<20 {
		return nil, contextError("SDK DATA whole input graph exceeds its existing byte bound")
	}
	memberNames, err := sdkAssemblyMemberNames(names)
	if err != nil {
		return nil, err
	}
	referenced, err := sdkReferencedArchiveSymbols(request.Referenced, request.Target)
	if err != nil {
		return nil, err
	}
	members, err := archiveMembers(request.Archive)
	if err != nil {
		return nil, err
	}
	if len(members) != len(names)+2 || members[0].name != "__.PKGDEF" || members[1].name != "_go_.o" {
		return nil, contextError("SDK DATA archive differs from the complete selected inventory")
	}
	observation := &SDKASMDataObservation{Protocol: ASMDataProtocol, PackagePath: request.PackagePath,
		Target: request.Target, ArchiveSHA256: digest(request.Archive)}
	if cpp {
		observation.Protocol = ASMDataCPPProtocol
	}
	for ordinal, member := range members {
		value := ASMDataMember{Name: member.name, NameBytes: []byte(member.name), Ordinal: ordinal,
			Offset: member.offset, Size: int64(len(member.data))}
		if ordinal != 0 {
			flags := sdkCompilerObjectFlags(request.Target)
			if ordinal > 1 {
				if member.name != memberNames[ordinal-2] {
					return nil, contextError("SDK DATA archive/source ordinal or exact byte-truncated member name differs")
				}
				flags |= 4
			}
			value, err = observeASMDataObject(member.data, request.BuiltinSource, request.Target, flags, referenced)
			if err != nil {
				return nil, contextError(fmt.Sprintf("SDK DATA member=%s: %v", member.name, err))
			}
			value.Name, value.NameBytes, value.Ordinal, value.Offset, value.Size = member.name, []byte(member.name), ordinal, member.offset, int64(len(member.data))
			value.ObjectOffset += member.offset
		}
		observation.Members = append(observation.Members, value)
	}
	if err := validateASMDataArchiveNames(observation.Members); err != nil {
		return nil, err
	}
	for index, source := range request.Sources {
		expandedGrammar := source.Expanded
		if cpp && len(expandedGrammar) == 0 {
			// The lexer uses a nonempty physical stream. A newline represents
			// zero statements; it is not substituted into retained source bytes.
			expandedGrammar = []byte("\n")
		}
		originalGrammar := source.Original
		if cpp {
			originalGrammar = expandedGrammar
		}
		originalProgram, err := asmDataProgramFingerprint(originalGrammar)
		if err != nil {
			return nil, err
		}
		expandedProgram, err := asmDataProgramFingerprint(expandedGrammar)
		if err != nil || originalProgram != expandedProgram {
			return nil, contextError("whole original and expanded ASM token programs differ")
		}
		originalStates, err := parseASMDataSource(originalGrammar, request.PackagePath, request.Target)
		if err != nil {
			return nil, err
		}
		expandedStates, err := parseASMDataSource(expandedGrammar, request.PackagePath, request.Target)
		if err != nil {
			return nil, err
		}
		original, err := observeASMDataObject(source.OriginalObject, request.BuiltinSource, request.Target, sdkAssemblyObjectFlags(request.Target), referenced)
		if err != nil {
			return nil, contextError(fmt.Sprintf("SDK DATA original source=%s: %v", source.Name, err))
		}
		expanded, err := observeASMDataObject(source.ExpandedObject, request.BuiltinSource, request.Target, sdkAssemblyObjectFlags(request.Target), referenced)
		if err != nil {
			return nil, contextError(fmt.Sprintf("SDK DATA expanded source=%s: %v", source.Name, err))
		}
		textOrder, err := ASMSourceTextOrder(originalGrammar, request.PackagePath, original)
		if err != nil {
			return nil, err
		}
		expandedOrder, err := ASMSourceTextOrder(expandedGrammar, request.PackagePath, expanded)
		if err != nil || !reflect.DeepEqual(textOrder, expandedOrder) {
			if err == nil {
				err = contextError("original/expanded source TEXT physical associations differ")
			}
			return nil, err
		}
		generated, err := generatedASMFuncdataWithTextOrder(originalGrammar, request.PackagePath, original, textOrder)
		if err != nil {
			return nil, err
		}
		expandedGenerated, err := generatedASMFuncdataWithTextOrder(expandedGrammar, request.PackagePath, expanded, expandedOrder)
		if err != nil || !sameGeneratedFuncdata(generated, expandedGenerated) {
			return nil, contextError("original/expanded generated FUNCDATA roles differ")
		}
		pools, err := generatedASMFloatPools(originalGrammar, request.Target, original, textOrder)
		if err != nil {
			return nil, err
		}
		expandedPools, err := generatedASMFloatPools(expandedGrammar, request.Target, expanded, expandedOrder)
		if err != nil || !sameGeneratedFloatPools(pools, expandedPools) {
			return nil, contextError("original/expanded generated float-pool roles differ")
		}
		ordinary := asmDataWithoutGeneratedFloatPools(asmDataWithoutGeneratedFuncdata(original, generated), pools)
		layouts, err := joinASMDataLayouts(originalStates, ordinary)
		if err != nil {
			return nil, err
		}
		expandedOrdinary := asmDataWithoutGeneratedFloatPools(asmDataWithoutGeneratedFuncdata(expanded, expandedGenerated), expandedPools)
		expandedLayouts, err := joinASMDataLayouts(expandedStates, expandedOrdinary)
		if err != nil {
			return nil, err
		}
		if !sameASMDataObjects(original, observation.Members[index+2]) || !sameASMDataObjects(original, expanded) {
			return nil, contextError("whole original/expanded/compiler ASM DATA or TEXT object identities differ")
		}
		if cpp && (!reflect.DeepEqual(original.Texts, expanded.Texts) ||
			!reflect.DeepEqual(original.Texts, observation.Members[index+2].Texts)) {
			// A live CPP producer maps the actual source positions before
			// assembling. Unlike the older offline token-equal observation,
			// this role requires complete PC/filename/line metadata parity.
			return nil, contextError("complete CPP original/expanded/compiler TEXT positions differ")
		}
		// Ordinals and physical source lines stay in both retained source records;
		// compare the directive grammar separately from those original positions.
		normalize := func(values []ASMGlobalLayout) []ASMGlobalLayout {
			result := append([]ASMGlobalLayout(nil), values...)
			for index := range result {
				result[index].Ordinal, result[index].Line = 0, 0
				result[index].Definition.DataOffset = 0
				result[index].Fragments = append([]ASMDataFragment(nil), result[index].Fragments...)
				for ordinal := range result[index].Fragments {
					result[index].Fragments[ordinal].Ordinal, result[index].Fragments[ordinal].Line = 0, 0
				}
			}
			return result
		}
		if !reflect.DeepEqual(normalize(layouts), normalize(expandedLayouts)) {
			return nil, contextError("original and expanded DATA/GLOBL grammar differs")
		}
		if cpp {
			// No raw-source grammar certificate is inferred from an expanded
			// program or a matching machine object. CPP provenance is external
			// to this observation-only adapter.
			originalProgram, layouts = "", nil
		}
		observation.Sources = append(observation.Sources, ASMDataSourceObservation{Name: source.Name,
			OriginalSHA256: digest(source.Original), ExpandedSHA256: digest(source.Expanded),
			OriginalObjectSHA256: digest(source.OriginalObject), ExpandedObjectSHA256: digest(source.ExpandedObject),
			OriginalProgramSHA256: originalProgram, ExpandedProgramSHA256: expandedProgram,
			Layouts: layouts, ExpandedLayouts: expandedLayouts, Original: original, Expanded: expanded, TextOrder: textOrder,
			GeneratedFuncdata: generated, GeneratedFloatPools: pools})
	}
	return observation, nil
}
