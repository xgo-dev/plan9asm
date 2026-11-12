package gostaticstorage

import (
	"errors"
	"fmt"
	"reflect"
	"testing"
)

// These models exercise the already-pinned current SDK collision role only.
// The actual archive/enum prior is TestGoSDKFIPSTextKindOriginalArchive; a raw
// number, name, namespace or successful collision check supplies no provenance.
func sdkTextKindFixture(kind uint8, abi uint16) indexedObjectSymbol {
	return indexedObjectSymbol{Namespace: TextSymbolNonpkgDefinition, Name: "fixture.Entry",
		ABI: abi, Kind: kind, Relative: uint32(abi), Index: uint32(abi), Size: 1}
}

func sdkTextKindMember(symbol indexedObjectSymbol) ASMDataMember {
	return ASMDataMember{Texts: []TextRecord{{Namespace: symbol.Namespace,
		Name: symbol.Name, ABI: symbol.ABI, Kind: symbol.Kind, Flags: symbol.Flags,
		Relative: symbol.Relative, Index: symbol.Index, Size: int64(symbol.Size), Code: []byte{0xc3}}}}
}

func TestSDKCurrentTextKindsKeepDistinctABIIdentities(t *testing.T) {
	for _, kind := range []uint8{1, 2} { // Go 1.27 STEXT and STEXTFIPS, not historical Kind2.
		t.Run(fmt.Sprintf("kind%d", kind), func(t *testing.T) {
			compiler, assembly := sdkTextKindFixture(kind, 1), sdkTextKindFixture(kind, 0)
			compiler.Namespace = TextSymbolSelf
			for _, order := range []bool{false, true} {
				t.Run(fmt.Sprintf("assemblyFirst=%t", order), func(t *testing.T) {
					inputs := []indexedObjectSymbol{compiler, assembly}
					if order {
						inputs[0], inputs[1] = inputs[1], inputs[0]
					}
					t.Run("archive", func(t *testing.T) {
						members := []ASMDataMember{sdkTextKindMember(inputs[0]), sdkTextKindMember(inputs[1])}
						before := []ASMDataMember{sdkTextKindMember(inputs[0]), sdkTextKindMember(inputs[1])}
						if err := validateASMDataArchiveNames(members); err != nil {
							t.Fatal("actual text kind was mistaken for multi-ABI storage", err)
						}
						if !reflect.DeepEqual(members, before) {
							t.Fatal("collision checking rewrote or selected an original text body")
						}
					})
					t.Run("named", func(t *testing.T) {
						observed := make(sdkAssemblyNamedDefinitions)
						for _, symbol := range inputs {
							if err := observed.observe(symbol, symbol.ABI == 0); err != nil {
								t.Fatal("actual text kind lost its separate compiler/assembly identity", err)
							}
						}
						if !reflect.DeepEqual(observed[compiler.Name], inputs) {
							t.Fatal("named text checking merged ABIs or normalized raw kind/namespace/index")
						}
					})
				})
			}
		})
	}
}

func TestSDKCurrentTextKindsKeepStorageAndNamespaceBoundaries(t *testing.T) {
	for _, kind := range []uint8{1, 2} {
		first := sdkTextKindFixture(kind, 0)
		for _, abi := range []uint16{0, 1} {
			for _, reverse := range []bool{false, true} {
				t.Run(fmt.Sprintf("kind%d/mixed-kind-ABI%d/reverse%t", kind, abi, reverse), func(t *testing.T) {
					second := sdkTextKindFixture(3-kind, abi)
					second.Flags = 1
					inputs := []indexedObjectSymbol{first, second}
					if reverse {
						inputs[0], inputs[1] = inputs[1], inputs[0]
					}
					// Classifying both kinds as current text does not choose
					// between differently typed definitions of the same name.
					members := []ASMDataMember{sdkTextKindMember(inputs[0]), sdkTextKindMember(inputs[1])}
					if err := validateASMDataArchiveNames(members); !errors.Is(err, ErrContext) {
						t.Fatal("mixed STEXT/STEXTFIPS bodies acquired an archive winner", err)
					}
					observed := make(sdkAssemblyNamedDefinitions)
					if err := observed.observe(inputs[0], false); err != nil {
						t.Fatal("original single text definition precondition", err)
					}
					if err := observed.observe(inputs[1], false); !errors.Is(err, ErrContext) {
						t.Fatal("mixed STEXT/STEXTFIPS bodies acquired a named winner", err)
					}
				})
			}
		}
		t.Run(fmt.Sprintf("kind%d/same-member-DUPok", kind), func(t *testing.T) {
			copy := first
			copy.Flags = 1
			member := sdkTextKindMember(copy)
			member.Texts = append(member.Texts, member.Texts[0])
			if err := validateASMDataArchiveNames([]ASMDataMember{member}); !errors.Is(err, ErrContext) {
				t.Fatal("DUPok collapsed two same-member text identities", err)
			}
		})
		duplicate, hashed64, hashed, static, reference := first, first, first, first, first
		duplicate.Flags = 1
		hashed64.Namespace = TextSymbolHashed64
		hashed.Namespace = TextSymbolHashed
		static.ABI = 65535
		reference.Namespace = TextSymbolNonpkgReference
		for _, test := range []struct {
			name   string
			second indexedObjectSymbol
			valid  bool
		}{
			{"same-ABI-non-DUPok", first, false},
			{"same-ABI-DUPok", duplicate, true},
			{"hashed64-local", hashed64, true},
			{"hashed-local", hashed, true},
			{"static-local", static, true},
			{"reference-not-definition", reference, true},
		} {
			t.Run(fmt.Sprintf("kind%d/%s", kind, test.name), func(t *testing.T) {
				observed := make(sdkAssemblyNamedDefinitions)
				if err := observed.observe(first, false); err != nil {
					t.Fatal("original current text precondition", err)
				}
				err := observed.observe(test.second, false)
				if test.valid && err != nil || !test.valid && !errors.Is(err, ErrContext) {
					t.Fatal("text classification changed a same-ABI or namespace boundary", err)
				}
				if test.valid {
					want := []indexedObjectSymbol{first}
					if test.second.Namespace == TextSymbolNonpkgDefinition && test.second.ABI != 65535 {
						want = append(want, test.second)
					}
					if !reflect.DeepEqual(observed[first.Name], want) {
						t.Fatal("object-local namespace became a named body winner")
					}
				}
			})
		}
		for storage := uint8(3); storage <= 11; storage++ { // Complete current RODATA/DATA/BSS/TLS kinds.
			t.Run(fmt.Sprintf("kind%d/storage%d", kind, storage), func(t *testing.T) {
				value := ASMDataDefinition{Namespace: TextSymbolSelf, Name: first.Name, Kind: storage, Flags: 1}
				other := value
				other.ABI = 1
				for _, members := range [][]ASMDataMember{
					{{Definitions: []ASMDataDefinition{value}}, {Definitions: []ASMDataDefinition{other}}},
					{{Definitions: []ASMDataDefinition{value}}, sdkTextKindMember(first)},
				} {
					if err := validateASMDataArchiveNames(members); !errors.Is(err, ErrContext) {
						t.Fatal("real storage acquired multiple ABIs or a text identity", err)
					}
				}
				changed := first
				changed.Kind = storage
				observed := make(sdkAssemblyNamedDefinitions)
				if err := observed.observe(first, false); err != nil {
					t.Fatal(err)
				}
				if err := observed.observe(changed, false); !errors.Is(err, ErrContext) {
					t.Fatal("storage collided with an actual text definition", err)
				}
				if err := make(sdkAssemblyNamedDefinitions).observe(changed, true); !errors.Is(err, ErrContext) {
					t.Fatal("assembly DATA bypassed its independent source/object role", err)
				}
			})
		}
	}
	t.Run("FIPS-kind-cannot-mint-GLOBL-storage", func(t *testing.T) {
		states, member := asmDataIndexedFixture(1)
		member.Definitions[0].Kind = 2
		if _, err := joinASMDataLayouts(states, member); !errors.Is(err, ErrContext) {
			t.Fatal("a forged text kind replaced actual typed DATA storage", err)
		}
	})
}

func TestSDKCurrentTextKindDoesNotRegisterHistoricalObjects(t *testing.T) {
	// Go 1.20 used 2 for SRODATA. The binary magic alone did not change. A
	// current-kind collision fix must not expand the authenticated producer set.
	for _, version := range []string{"go1.20.14", "go1.23.12", "go1.26.9", "go1.27.4"} {
		for _, arch := range []string{"386", "amd64"} {
			t.Run(version+"/"+arch, func(t *testing.T) {
				object := []byte("go object linux " + arch + " " + version + "\n!\n\x00go120ld")
				if _, err := objectBody(object, "linux/"+arch); !errors.Is(err, ErrContext) {
					t.Fatal("a current SymKind number registered a different object producer", err)
				}
			})
		}
	}
}
