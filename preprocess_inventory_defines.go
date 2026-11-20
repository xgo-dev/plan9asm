package plan9asm

import (
	"fmt"
	"strings"
	"text/scanner"
)

// AssemblyCPPDriverDefinition preserves an ordered supplied -D string and its
// object-macro token projection. Replacement positions are relative to the
// supplied value, not a physical assembly file or an actual command receipt.
type AssemblyCPPDriverDefinition struct {
	Text       string
	Definition AssemblyCPPMacroDefinition
}

// InspectAssemblyCPPDriverDefinitions is query-only. It does not establish
// that a driver consumed these definitions, execute CPP, or grant source/ABI
// authority. The caller must independently bind the exact ordered inputs.
// Repeated names are retained: stock Go's predefine loop overwrites in order.
func InspectAssemblyCPPDriverDefinitions(defines []string) ([]AssemblyCPPDriverDefinition, error) {
	if len(defines) > 4096 {
		return nil, fmt.Errorf("driver CPP query exceeds its definition bound")
	}
	definitions := make([]AssemblyCPPDriverDefinition, 0, len(defines))
	bytes, tokens := 0, 0
	for _, text := range defines {
		if len(text) > 1<<20-bytes {
			return nil, fmt.Errorf("driver CPP query exceeds its definition byte bound")
		}
		bytes += len(text)
		name, value := text, "1"
		if index := strings.IndexByte(text, '='); index > 0 {
			name, value = text[:index], text[index+1:]
		}
		// Keep the literal key used by Go's predefine map. A spelling with
		// surrounding whitespace/comments may tokenize as one Go identifier,
		// but is not a literal invocation name this raw query can close.
		if !validPPIdentifier(name) {
			return nil, fmt.Errorf("driver CPP query needs a literal macro name: %q", name)
		}
		definition := AssemblyCPPDriverDefinition{
			Text: text, Definition: AssemblyCPPMacroDefinition{
				Name: name, Replacement: []AssemblyCPPToken{},
			},
		}
		reader := newPPGoReader("<driver-definition>", value)
		for {
			physical, err := reader.next()
			if err != nil {
				return nil, err
			}
			if physical.kind == scanner.EOF {
				break
			}
			if tokens >= 1<<20 {
				return nil, fmt.Errorf("driver CPP query exceeds its replacement token bound")
			}
			definition.Definition.Replacement = append(definition.Definition.Replacement,
				assemblyCPPPhysicalToken(reader, physical))
			tokens++
		}
		definitions = append(definitions, definition)
	}
	return definitions, nil
}
