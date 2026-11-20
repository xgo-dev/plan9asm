package plan9asm

import (
	"bytes"
	"reflect"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
)

// This is a private comparison model, not a source, declaration or ABI token.
// The live numerical factory must obtain both inventories from its existing
// complete SDK producer before a declaration may consume the comparison.
type numericalCompilerAliasInput struct {
	Native    string
	ABI       uint16
	Standard  bool
	SymABI    []byte
	Generated []gostaticstorage.TextRecord
	Selected  []gostaticstorage.TextRecord
}

func numericalCompilerAliasAssociation(input numericalCompilerAliasInput) error {
	index, err := numericalCompilerAliasIndex(input.SymABI, input.Generated, input.Selected)
	if err != nil {
		return err
	}
	return index.association(input.Native, input.ABI, input.Standard)
}

type numericalCompilerAliasDirectory struct {
	definitions map[string]uint16
	generated   map[string][]gostaticstorage.TextRecord
	selected    map[string][]gostaticstorage.TextRecord
}

// Index the complete retained inventories once. The live capture reuses this
// directory for all original TEXTs rather than rescanning SymABI per symbol.
func numericalCompilerAliasIndex(symABI []byte, generated, selected []gostaticstorage.TextRecord) (*numericalCompilerAliasDirectory, error) {
	if len(symABI) == 0 || len(symABI) > 16<<20 || len(generated) == 0 || len(selected) == 0 ||
		len(generated) > gostaticstorage.ObjectSymbolInventoryLimit || len(selected) > gostaticstorage.ObjectSymbolInventoryLimit {
		return nil, numericalSBContext("foreign declaration lacks its complete compiler objects/SymABI")
	}
	result := &numericalCompilerAliasDirectory{definitions: make(map[string]uint16),
		generated: make(map[string][]gostaticstorage.TextRecord), selected: make(map[string][]gostaticstorage.TextRecord)}
	for _, line := range strings.Split(string(symABI), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 3 || fields[0] != "def" && fields[0] != "ref" ||
			fields[2] != "ABI0" && fields[2] != "ABIInternal" {
			return nil, numericalSBContext("compiler SymABI has an unregistered complete row")
		}
		if fields[0] == "def" {
			if _, duplicate := result.definitions[fields[1]]; duplicate {
				return nil, numericalSBContext("compiler SymABI repeats its native definition")
			}
			abi := uint16(0)
			if fields[2] == "ABIInternal" {
				abi = 1
			}
			result.definitions[fields[1]] = abi
		}
	}
	for _, member := range []struct {
		texts []gostaticstorage.TextRecord
		index map[string][]gostaticstorage.TextRecord
	}{{generated, result.generated}, {selected, result.selected}} {
		for _, text := range member.texts {
			member.index[text.Name] = append(member.index[text.Name], text)
		}
	}
	return result, nil
}

func (index *numericalCompilerAliasDirectory) association(native string, abi uint16, standard bool) error {
	fail := func() error {
		return numericalSBContext("foreign declaration/compiler wrapper/native ABI association differs")
	}
	if index == nil || native == "" || len(native) > 4096 || strings.ContainsAny(native, "\x00\r\n\t ") || abi != 1 {
		return fail()
	}
	if observed, found := index.definitions[native]; !found || observed != abi {
		return fail()
	}
	flag := uint8(16) // The separately authenticated Go1.27 Flag2 schema.
	if standard {
		flag = 32
	}
	wrapper := func(records []gostaticstorage.TextRecord) (gostaticstorage.TextRecord, bool) {
		var result gostaticstorage.TextRecord
		found := false
		for _, record := range records {
			if record.ABI != 0 {
				continue
			}
			if found || record.Name != native || record.Namespace != gostaticstorage.TextSymbolNonpkgDefinition ||
				record.Kind != 1 || record.Flags2 != flag|64 || record.Size <= 0 || record.Size != int64(len(record.Code)) {
				return result, false
			}
			result, found = record, true
		}
		return result, found
	}
	first, firstOK := wrapper(index.generated[native])
	second, secondOK := wrapper(index.selected[native])
	if !firstOK || !secondOK || first.Flags != second.Flags || first.Flags2 != second.Flags2 ||
		first.Size != second.Size || !bytes.Equal(first.Code, second.Code) || !reflect.DeepEqual(first.Relocations, second.Relocations) {
		return fail()
	}
	refs := 0
	for _, relocation := range first.Relocations {
		if relocation.Target.Name == native {
			if !relocation.Target.ABIKnown || relocation.Target.ABI != abi {
				return fail()
			}
			refs++
		}
	}
	if refs != 1 {
		return fail()
	}
	return nil
}
