package goasmoracle

import (
	"strings"
	"text/scanner"
)

// SourceDiagnosticLineWithTrailingListing handles a separate backend layout:
// asm: <PC> (<physical source>:<line>) <complete Prog>: <concrete error>.
// Unlike the ordinary listing route, this has no preceding error to bind.
// Only the selected matcher can authenticate both the Prog and trailing error;
// the default diagnostic checker retains its original strict behavior.
func SourceDiagnosticLineWithTrailingListing(source, output string, focus int,
	match func(original, listing []string, detail string) bool) bool {
	if focus < 0 || match == nil {
		return false
	}
	data, valid := ReadSource(source)
	if !valid {
		return false
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range strings.Split(output, "\n") {
		marker := strings.Index(line, "("+source+":")
		if marker < 0 {
			continue
		}
		prefix := strings.Fields(line[:marker])
		if len(prefix) != 2 || prefix[0] != "asm:" || !canonicalPC(prefix[1]) {
			continue
		}
		position := line[marker+1+len(source)+1:]
		end := strings.IndexByte(position, ')')
		if end < 0 {
			continue
		}
		number, valid := positivePosition(position[:end])
		if !valid || number > len(lines) || focus > 0 && number != focus ||
			statementOpcode(lines[number-1]) == "" {
			continue
		}
		instruction, message, found := strings.Cut(strings.TrimSpace(position[end+1:]), ": ")
		if !found || instruction == "" || message == "" {
			continue
		}
		original, sourceOK := diagnosticTokens(lines[number-1])
		listing, listingOK := diagnosticTokens(instruction)
		if sourceOK && listingOK && len(listing) > 0 &&
			listing[0].kind == scanner.Ident && match(tokenTexts(original), tokenTexts(listing), message) {
			return true
		}
	}
	return false
}
