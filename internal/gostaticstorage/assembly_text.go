package gostaticstorage

import (
	"path/filepath"
	"strconv"
	"strings"
)

// ObserveARM64AssemblyText is an offline original-object observation. It does
// not construct a live source, caller carrier, entry adapter or frame slot.
func ObserveARM64AssemblyText(data, builtinSource []byte, target string) ([]TextRecord, error) {
	if !arm64AssemblyObservationTarget(target) {
		return nil, contextError("unobserved ARM64 assembly target")
	}
	return observeAssemblyText(data, builtinSource, target)
}

// ObserveARM64AssemblyArchive retains original caller/callee records only.
// Neither selected source names nor a successful decode grant LLVM authority.
func ObserveARM64AssemblyArchive(data, builtinSource []byte, target string, sources []string) ([]TextMember, error) {
	if !arm64AssemblyObservationTarget(target) {
		return nil, contextError("unobserved ARM64 assembly archive target")
	}
	return observeAssemblyArchive(data, builtinSource, target, sources, false)
}

func arm64AssemblyObservationTarget(target string) bool {
	switch target {
	case "darwin/arm64", "linux/arm64", "windows/arm64", "freebsd/arm64", "openbsd/arm64":
		return true
	}
	return false
}

// ObserveX86AssemblyText decodes complete original Go assembler object bytes.
// It is an offline observation: neither these bytes nor its return value create
// an Observation, a live source lease or a memory/entry permission.
func ObserveX86AssemblyText(data, builtinSource []byte, target string) ([]TextRecord, error) {
	if !X86SDKTarget(target) {
		return nil, contextError("unobserved x86 assembly target")
	}
	return observeAssemblyText(data, builtinSource, target)
}

func observeAssemblyText(data, builtinSource []byte, target string) ([]TextRecord, error) {
	builtins, err := textBuiltins(builtinSource)
	if err != nil {
		return nil, err
	}
	body, err := objectBody(data, target)
	if err != nil {
		return nil, err
	}
	return readTextObject(body, target, 4, false, builtins)
}

// ObserveX86AssemblyArchive retains every member of a bounded owned-main Go
// archive. sources is selection metadata, not authority. A live factory must
// independently bind that actual selection, the SDK work/gc.go member route,
// original source and standalone assembler output before using any record.
func ObserveX86AssemblyArchive(data, builtinSource []byte, target string, sources []string) ([]TextMember, error) {
	return observeX86AssemblyArchive(data, builtinSource, target, sources, false)
}

func observeX86AssemblyArchive(data, builtinSource []byte, target string, sources []string, sdk bool) ([]TextMember, error) {
	if !X86SDKTarget(target) || !sdk && target != "linux/386" && target != "linux/amd64" {
		return nil, contextError("unobserved x86 assembly archive target")
	}
	return observeAssemblyArchive(data, builtinSource, target, sources, sdk)
}

func observeAssemblyArchive(data, builtinSource []byte, target string, sources []string, sdk bool) ([]TextMember, error) {
	return observeAssemblyArchiveReferences(data, builtinSource, target, sources, sdk, nil)
}

func observeAssemblyArchiveReferences(data, builtinSource []byte, target string, sources []string, sdk bool, referenced sdkReferencedSymbols) ([]TextMember, error) {
	builtins, err := textBuiltins(builtinSource)
	if err != nil {
		return nil, err
	}
	members, err := archiveMembers(data)
	if err != nil {
		return nil, err
	}
	if len(sources) == 0 || len(members) != len(sources)+2 || members[0].name != "__.PKGDEF" || members[1].name != "_go_.o" {
		return nil, contextError("assembly archive differs from selected member inventory")
	}
	var sdkNames []string
	if sdk {
		sdkNames, err = sdkAssemblyMemberNames(sources)
		if err != nil {
			return nil, err
		}
	}
	seenSources := make(map[string]bool)
	definitions := make(map[string]bool)
	storage := make(map[string]bool)
	sdkDefinitions := make(sdkAssemblyNamedDefinitions)
	// Preserve the independent archive role; direct tool asm observations
	// below still require their own exact flags instead of this profile.
	compilerFlags := sdkCompilerObjectFlags(target) &^ 16
	result := []TextMember{{Name: members[0].name, Offset: members[0].offset, Size: int64(len(members[0].data))}}
	for index, member := range members[1:] {
		flags := compilerFlags
		if sdk {
			flags |= 16 // ObjFlagStd in the independently pinned Go 1.27.1 format.
		}
		if index != 0 {
			name := sources[index-1]
			memberName := strings.TrimSuffix(name, ".s") + ".o"
			if sdk {
				memberName = sdkNames[index-1]
			}
			if filepath.Base(name) != name || !strings.HasSuffix(name, ".s") || seenSources[name] || member.name != memberName {
				return nil, contextError("assembly source/member route differs")
			}
			seenSources[name] = true
			flags |= 4
		}
		reader := objectBody
		if sdk && index == 0 {
			reader = sdkObjectBody
		}
		body, err := reader(member.data, target)
		if err != nil {
			return nil, err
		}
		var sdkObject *checkedGoObject
		if !sdk {
			records, err := assemblyArchiveDefinitions(body, flags)
			if err != nil {
				return nil, err
			}
			for _, record := range records {
				name := record.Name
				key := name + "\x00" + strconv.Itoa(int(record.ABI))
				if definitions[key] || storage[name] || index != 0 && record.Kind != 1 {
					return nil, contextError("duplicate same-ABI/storage or assembly DATA definition")
				}
				definitions[key] = true
				storage[name] = record.Kind != 1
			}
		} else {
			object, err := checkedSDKObject(body, flags, index != 0)
			if err != nil {
				return nil, err
			}
			sdkObject = object
			symbols, err := object.indexedSymbols()
			if err != nil {
				return nil, err
			}
			for _, symbol := range symbols {
				if err := sdkDefinitions.observe(symbol, index != 0); err != nil {
					return nil, err
				}
			}
		}
		var texts []TextRecord
		if sdk {
			texts, err = readCheckedTextObjectKinds(sdkObject, target, builtins, referenced, true)
		} else {
			texts, err = readTextObjectReferences(body, target, flags, false, builtins, referenced)
		}
		if err != nil {
			return nil, err
		}
		result = append(result, TextMember{Name: member.name, Offset: member.offset, Size: int64(len(member.data)), Flags: flags, Texts: texts})
	}
	return result, nil
}

// The legacy owned/DATA reader intentionally retains its strict named view.
// SDK indexed observation uses a separate path, never widening this one.
func assemblyArchiveDefinitions(data []byte, flags uint32) ([]dataRecord, error) {
	records, err := readObjectRole(data, flags, false)
	if err != nil {
		return nil, err
	}
	values := make([]dataRecord, 0, len(records))
	for _, record := range records {
		values = append(values, record)
	}
	return values, nil
}

// ObserveX86SDKAssemblyArchive observes an original SDK archive. This offline
// decoder does not establish SDK source provenance, storage or native entry
// authority; its caller must independently authenticate those roles.
func ObserveX86SDKAssemblyArchive(data, builtinSource []byte, target string, sources []string) ([]TextMember, error) {
	return observeX86AssemblyArchive(data, builtinSource, target, sources, true)
}

// SDKReferencedArchive is offline metadata input, not SDK provenance or a
// storage/entry certificate. A live producer separately seals its actual
// selected dependency path, member inventory and complete original bytes.
type SDKReferencedArchive struct {
	PackagePath string
	Sources     []string
	Archive     []byte
}

// ObserveX86SDKAssemblyArchiveReferences additionally observes indexed
// references through separately retained actual dependency archives.
func ObserveX86SDKAssemblyArchiveReferences(data, builtinSource []byte, target string, sources []string, referenced map[string]SDKReferencedArchive) ([]TextMember, error) {
	if !X86SDKTarget(target) {
		return nil, contextError("unobserved SDK indexed-reference target")
	}
	symbols, err := sdkReferencedArchiveSymbols(referenced, target)
	if err != nil {
		return nil, err
	}
	return observeAssemblyArchiveReferences(data, builtinSource, target, sources, true, symbols)
}
