package plan9asm

import (
	"go/types"
	"path/filepath"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
)

// This pure association observes a compiler body only. It does not authenticate
// the caller's input, establish its SDK origin or close any assembly CALL.
type x86GoPanicTerminalCompilerBody struct {
	declaration x86GoPanicTerminalDeclaration
	text        gostaticstorage.TextRecord
	assemblyABI uint16
}

func x86GoPanicTerminalCompilerBodies(pkg GoPackage, symABI []byte, objects *gostaticstorage.SDKASMDataObservation, root string) ([]x86GoPanicTerminalCompilerBody, error) {
	declarations, err := x86GoPanicTerminalDeclarations(pkg)
	if err != nil {
		return nil, err
	}
	if objects == nil || objects.Protocol != gostaticstorage.ASMDataCPPProtocol || objects.PackagePath != pkg.Path ||
		objects.Target != "linux/386" || pkg.SourceSelection.Sizes.Sizeof(types.Typ[types.Uintptr]) != 4 ||
		len(objects.Sources) == 0 || len(objects.Sources) > gostaticstorage.ArchiveMemberInventoryLimit-2 ||
		len(objects.Members) != len(objects.Sources)+2 || objects.Members[0].Name != "__.PKGDEF" ||
		objects.Members[1].Name != "_go_.o" || objects.Members[1].Flags != 16 {
		return nil, sdkASMDataContext("panic body lacks its complete actual386 compiler/archive role")
	}
	seen := map[string]bool{"__.PKGDEF": true, "_go_.o": true}
	for ordinal, source := range objects.Sources {
		if filepath.Base(source.Name) != source.Name || !strings.HasSuffix(source.Name, ".s") || strings.ContainsAny(source.Name, "\\\x00\r\n") {
			return nil, sdkASMDataContext("panic body assembly selection has a noncanonical source")
		}
		// Match the actual SDK packInternal member route, including its exact
		// byte truncation. This observes a route, never a winning definition.
		name := strings.TrimSuffix(source.Name, ".s") + ".o"
		if len(name) > 16 {
			name = name[:16]
		}
		if seen[name] || objects.Members[ordinal+2].Name != name || objects.Members[ordinal+2].Flags != 20 {
			return nil, sdkASMDataContext("panic body assembly member differs from its full selected route")
		}
		seen[name] = true
	}
	definitions, references, err := x86GoPanicTerminalSymABI(symABI)
	if err != nil {
		return nil, err
	}
	texts := make(map[string][]gostaticstorage.TextRecord)
	storage := make(map[string]bool)
	for ordinal, member := range objects.Members {
		for _, definition := range member.Definitions {
			storage[definition.Name] = true
		}
		for _, text := range member.Texts {
			texts[text.Name] = append(texts[text.Name], text)
			if ordinal != 1 {
				storage[text.Name] = true // Any alternative ASM body is ambiguous.
			}
		}
	}
	var result []x86GoPanicTerminalCompilerBody
	for _, declaration := range declarations {
		name := declaration.nativeName
		if references[name] == 0 {
			continue // An unrelated ordinary Go function needs no ASM role.
		}
		candidates := texts[name]
		if definitions[name] || references[name] != 1 || storage[name] || len(candidates) != 1 {
			return nil, sdkASMDataContext("panic declaration has a missing or ambiguous actual compiler definition")
		}
		text := candidates[0]
		// ABIInternal remains ABI1. Only a distinct live selected-source query
		// can supply the pinned non-regabi386 linker's ABIToVersion join.
		if text.Namespace != gostaticstorage.TextSymbolSelf || text.Index != text.Relative || text.ABI != 1 || text.Kind != 1 ||
			text.Flags != 0 || text.Flags2 != 0 || len(text.Hash) != 0 || len(text.Code) == 0 || text.Size != int64(len(text.Code)) || len(text.Positions) == 0 {
			return nil, sdkASMDataContext("panic declaration differs from its original compiler TEXT identity")
		}
		end, panicPosition := int64(0), false
		for _, position := range text.Positions {
			filename, valid := originalGoObjectSourcePath(position.File, root)
			if !valid || filename != declaration.filename || position.Start != end || position.End <= position.Start || position.End > text.Size ||
				int(position.Line) < declaration.startLine || int(position.Line) > declaration.endLine {
				return nil, sdkASMDataContext("panic compiler body lost its complete selected declaration positions")
			}
			end, panicPosition = position.End, panicPosition || int(position.Line) == declaration.panicLine
		}
		if end != text.Size || !panicPosition {
			return nil, sdkASMDataContext("panic compiler body does not cover the actual typed panic statement")
		}
		result = append(result, x86GoPanicTerminalCompilerBody{declaration: declaration, text: x86GoPanicTerminalCloneText(text), assemblyABI: 0})
	}
	if len(declarations) != 0 && len(result) == 0 {
		return nil, sdkASMDataContext("panic declarations lack any actual ABI0 assembler reference")
	}
	return result, nil
}

// This is the selected compiler's complete def/ref grammar, not a noreturn
// report. Repeated references form an ABI set, exactly as ReadSymABIs does.
func x86GoPanicTerminalSymABI(data []byte) (map[string]bool, map[string]uint8, error) {
	definitions, references := make(map[string]bool), make(map[string]uint8)
	if len(data) > 16<<20 {
		return nil, nil, sdkASMDataContext("panic SymABI exceeds its complete object byte bound")
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 3 || fields[0] != "def" && fields[0] != "ref" || strings.HasPrefix(fields[1], `"".`) ||
			strings.ContainsRune(fields[1], '\x00') || fields[2] != "ABI0" && fields[2] != "ABIInternal" {
			return nil, nil, sdkASMDataContext("panic SymABI has an unknown compiler symbol grammar")
		}
		if fields[0] == "def" {
			definitions[fields[1]] = true
		} else if fields[2] == "ABI0" {
			references[fields[1]] |= 1
		} else {
			references[fields[1]] |= 2
		}
	}
	return definitions, references, nil
}

func x86GoPanicTerminalCloneText(text gostaticstorage.TextRecord) gostaticstorage.TextRecord {
	text.Hash = append([]byte(nil), text.Hash...)
	text.Code = append([]byte(nil), text.Code...)
	text.Relocations = append([]gostaticstorage.TextRelocation(nil), text.Relocations...)
	text.Auxiliary = append([]gostaticstorage.TextAuxiliary(nil), text.Auxiliary...)
	text.PCFile = append([]byte(nil), text.PCFile...)
	text.PCLine = append([]byte(nil), text.PCLine...)
	text.Positions = append([]gostaticstorage.TextPosition(nil), text.Positions...)
	return text
}
