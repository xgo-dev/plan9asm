package gostaticstorage

import (
	"errors"
	"fmt"
	"reflect"
	"testing"
)

// This collision model supplies no storage/source certificate. The real SDK
// factory independently observes its compiler declaration and ASM initializer.
func asmDataDeclarationFixture() []ASMDataMember {
	return []ASMDataMember{
		{Name: "_go_.o", Definitions: []ASMDataDefinition{{Name: "fixture.table",
			Namespace: TextSymbolSelf, Index: 5, Relative: 5, Kind: 10, Size: 8}}},
		{Name: "values.o", Definitions: []ASMDataDefinition{{Name: "fixture.table",
			Namespace: TextSymbolNonpkgDefinition, Kind: 3, Size: 8,
			Data: []byte{0, 1, 2, 3, 4, 5, 6, 7}}}},
	}
}

func TestASMDataCompilerBSSDeclarationAndASMInitializer(t *testing.T) {
	t.Run("byte-truncated-ASM-member-name", func(t *testing.T) {
		members := asmDataDeclarationFixture()
		// The existing SDK archive protocol truncates the complete original
		// object filename to 16 bytes, which may remove its .o suffix.
		members[1].Name = "long-assembly-na"
		if err := validateASMDataArchiveNames(members); err != nil {
			t.Fatal("an exact observed SDK member needed a filename-suffix heuristic", err)
		}
	})
	for _, bss := range []uint8{9, 10} {
		for _, data := range []uint8{3, 5, 7} {
			for _, reverse := range []bool{false, true} {
				t.Run(fmt.Sprintf("BSS%d-DATA%d-reverse%t", bss, data, reverse), func(t *testing.T) {
					members, before := asmDataDeclarationFixture(), asmDataDeclarationFixture()
					for _, rows := range [][]ASMDataMember{members, before} {
						rows[0].Definitions[0].Kind, rows[1].Definitions[0].Kind = bss, data
						if reverse {
							rows[0], rows[1] = rows[1], rows[0]
						}
					}
					if err := validateASMDataArchiveNames(members); err != nil {
						t.Fatal("compiler empty BSS declaration rejected a complete ASM initializer", err)
					}
					if !reflect.DeepEqual(members, before) {
						t.Fatal("collision checking selected a body or normalized an original kind")
					}
				})
			}
		}
	}
}

func TestASMDataBSSDeclarationPairDoesNotAuthorizeConflicts(t *testing.T) {
	for _, mutation := range []string{"size", "ABI", "empty-initializer", "compiler-data", "compiler-reloc",
		"compiler-DUPok", "initializer-DUPok", "compiler-namespace", "initializer-namespace",
		"compiler-origin", "initializer-origin", "duplicate-declaration", "two-initializers",
		"TEXT-initializer", "TLS-declaration", "reserved-initializer-member", "empty-initializer-member"} {
		t.Run(mutation, func(t *testing.T) {
			members := asmDataDeclarationFixture()
			declaration, initializer := &members[0].Definitions[0], &members[1].Definitions[0]
			switch mutation {
			case "size":
				initializer.Size++
			case "ABI":
				initializer.ABI = 1
			case "empty-initializer":
				initializer.Data = nil
			case "compiler-data":
				declaration.Data = []byte{1}
			case "compiler-reloc":
				declaration.Relocations = []TextRelocation{{Size: 8}}
			case "compiler-DUPok":
				declaration.Flags = 1
			case "initializer-DUPok":
				initializer.Flags = 1
			case "compiler-namespace":
				declaration.Namespace = TextSymbolNonpkgDefinition
			case "initializer-namespace":
				initializer.Namespace = TextSymbolSelf
			case "compiler-origin":
				members[0].Name = "another.o"
			case "initializer-origin":
				members[1].Name = "_go_.o"
			case "reserved-initializer-member":
				members[1].Name = "__.PKGDEF"
			case "empty-initializer-member":
				members[1].Name = ""
			case "duplicate-declaration":
				copy := *declaration
				copy.Index, copy.Relative = 6, 6
				members[0].Definitions = append(members[0].Definitions, copy)
			case "two-initializers":
				copy := members[1]
				copy.Name = "another.o"
				members = append(members, copy)
			case "TEXT-initializer":
				initializer.Kind = 1
			case "TLS-declaration":
				declaration.Kind = 11
			}
			if err := validateASMDataArchiveNames(members); !errors.Is(err, ErrContext) {
				t.Fatal("unproved declaration/initializer pair acquired a body choice", err)
			}
		})
	}
}
