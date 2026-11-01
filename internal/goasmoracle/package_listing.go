package goasmoracle

import (
	"reflect"
	"strings"
)

// PackageQualifiedListing joins Go's leading-middle-dot symbol spelling to
// the exact package prefix selected by the observing assembler command. It
// compares the complete token sequence; an arbitrary suffix match is not a
// source observation. This grants no instruction or execution permission.
func PackageQualifiedListing(original, listing []string, packagePrefix string) bool {
	if packagePrefix == "" {
		return false
	}
	var expected []string
	qualified := false
	for index, text := range original {
		if index == 0 || !strings.HasPrefix(text, "·") {
			expected = append(expected, text)
			continue
		}
		name := strings.NewReplacer("·", ".", "∕", "/").Replace(text)
		tokens, valid := diagnosticTokens(packagePrefix + name)
		if !valid {
			return false
		}
		expected = append(expected, tokenTexts(tokens)...)
		qualified = true
	}
	return qualified && reflect.DeepEqual(expected, listing)
}
