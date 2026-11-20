package plan9asm

import (
	"fmt"
	"text/scanner"
)

// InspectAssemblyCPPStringTokens queries physical String tokens and their Make
// recording projection with the same reader as the strict executor. A token is
// not an include invocation, an active input or an authenticated source. Raw
// strings are excluded because Go's include reader requires scanner.String.
func InspectAssemblyCPPStringTokens(source, file string) ([]AssemblyCPPToken, error) {
	if file == "" || len(source) > 64<<20 {
		return nil, fmt.Errorf("CPP String query requires bounded named original bytes")
	}
	result := []AssemblyCPPToken{}
	reader := newPPGoReader(file, source)
	for {
		token, err := reader.next()
		if err != nil {
			return nil, err
		}
		if token.kind == scanner.EOF {
			return result, nil
		}
		if token.kind != scanner.String {
			continue
		}
		if len(result) >= 4096 {
			return nil, fmt.Errorf("CPP String query exceeds its candidate token bound")
		}
		result = append(result, assemblyCPPPhysicalToken(reader, token))
	}
}
