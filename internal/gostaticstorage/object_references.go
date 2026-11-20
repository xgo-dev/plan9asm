package gostaticstorage

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

// Each slice is exactly the compiler object's SymbolDefs block. Hashed and
// nonpackage definitions cannot be reached by a foreign package SymbolIndex.
// The live SDK source producer separately authenticates the map's package,
// export path and whole archive bytes; these records alone grant no role.
type sdkReferencedSymbols map[string][]indexedObjectSymbol

func resolveSDKIndexedReference(ref TextReference, diagnostic string, present bool, referenced sdkReferencedSymbols) (TextReference, error) {
	symbols, exists := referenced[ref.Package]
	if !exists || uint64(ref.SymbolIndex) >= uint64(len(symbols)) {
		return ref, contextError("TEXT foreign reference lacks actual indexed compiler definition")
	}
	symbol := symbols[ref.SymbolIndex]
	if symbol.Namespace != TextSymbolSelf || symbol.Relative != ref.SymbolIndex || symbol.Index != ref.SymbolIndex ||
		symbol.Name == "" || symbol.ABI != 0 && symbol.ABI != 1 || symbol.Kind == 0 ||
		present && diagnostic != symbol.Name {
		return ref, contextError("TEXT foreign indexed definition or diagnostic identity differs")
	}
	ref.Name, ref.ABI, ref.ABIKnown = symbol.Name, symbol.ABI, true
	ref.Kind, ref.KindKnown = symbol.Kind, true
	return ref, nil
}

func sdkReferencedArchiveSymbols(archives map[string]SDKReferencedArchive, target string) (sdkReferencedSymbols, error) {
	if len(archives) > 4096 {
		return nil, contextError("excessive SDK referenced archive inventory")
	}
	paths := make([]string, 0, len(archives))
	for path := range archives {
		paths = append(paths, path)
	}
	sort.Strings(paths)

	result := make(sdkReferencedSymbols, len(archives))
	var totalBytes int
	for _, path := range paths {
		archive := archives[path]
		if path == "" || path != archive.PackagePath || !filepath.IsLocal(filepath.FromSlash(path)) ||
			filepath.ToSlash(filepath.Clean(filepath.FromSlash(path))) != path {
			return nil, contextError("SDK referenced package key/path differs")
		}
		totalBytes += len(archive.Archive)
		if totalBytes > 64<<20 {
			return nil, contextError("complete SDK referenced archives exceed their byte bound")
		}
		members, err := archiveMembers(archive.Archive)
		if err != nil {
			return nil, err
		}
		if len(members) != len(archive.Sources)+2 || members[0].name != "__.PKGDEF" || members[1].name != "_go_.o" {
			return nil, contextError("SDK referenced archive differs from selected member inventory")
		}
		names, err := sdkAssemblyMemberNames(archive.Sources)
		if err != nil {
			return nil, err
		}
		for index, member := range members[1:] {
			flags := sdkCompilerObjectFlags(target)
			if index != 0 {
				if member.name != names[index-1] {
					return nil, contextError("SDK referenced source/member route differs")
				}
				flags |= 4
			}
			reader := objectBody
			if index == 0 {
				reader = sdkObjectBody
			}
			body, err := reader(member.data, target)
			if err != nil {
				return nil, contextError(fmt.Sprintf("SDK referenced package=%s member=%s object header: %v", path, member.name, err))
			}
			object, err := checkedSDKIndexedMetadata(body, flags, index != 0)
			if err != nil {
				return nil, contextError("SDK referenced package=" + path + " member=" + member.name + ": " + err.Error())
			}
			if index == 0 {
				result[path], err = object.selfSymbols()
				if err != nil {
					return nil, err
				}
			}
		}
	}
	return result, nil
}

// Go 1.27.1 work/gc.go packInternal truncates the compiler's object filename
// to 16 bytes, including a possible partial UTF-8 rune. Match the complete
// selected sources in original order before observing any body. Prefix matches
// and truncated-name collisions never select a source or archive member.
func sdkAssemblyMemberNames(sources []string) ([]string, error) {
	seenSources := make(map[string]bool, len(sources))
	seenMembers := map[string]bool{"__.PKGDEF": true, "_go_.o": true}
	result := make([]string, 0, len(sources))
	for _, source := range sources {
		if filepath.Base(source) != source || !strings.HasSuffix(source, ".s") || seenSources[source] ||
			strings.ContainsAny(source, "\\\x00\r\n") {
			return nil, contextError("duplicate or noncanonical complete SDK assembly source")
		}
		name := strings.TrimSuffix(source, ".s") + ".o"
		if len(name) > 16 {
			name = name[:16]
		}
		if seenMembers[name] {
			return nil, contextError("SDK assembly source names collide after archive byte truncation")
		}
		seenSources[source], seenMembers[name] = true, true
		result = append(result, name)
	}
	return result, nil
}
