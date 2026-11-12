package goasmrules

import "encoding/json"

// Own a complete ordered source cohort, including every original field and
// fixed-array capacity. This is captured Go metadata, not an opcode registry.
func x86LegacySourceMembers(catalog X86LegacyCatalog, schema func(string) []string) ([]byte, error) {
	var members []X86LegacyOpcode
	for _, entry := range catalog.Optab {
		if schema(entry.Ytab) != nil {
			members = append(members, entry)
		}
	}
	return json.Marshal(struct {
		Capacity int
		Members  []X86LegacyOpcode
	}{catalog.OpBytesSize, members})
}
