package plan9asm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
)

// These are independent selector values, never a live SDK source/owner.
func sdkASMMetadataModel(t *testing.T) sdkASMDataLiveObservation {
	t.Helper()
	program, first := numericalNativeOrderFixture(t)
	first.Name = "mixed.s"
	second := gostaticstorage.ASMDataSourceObservation{Name: "empty.s",
		Original: gostaticstorage.ASMDataMember{Flags: 4}, Expanded: gostaticstorage.ASMDataMember{Flags: 4}}
	observation := sdkASMDataLiveObservation{Protocol: "actual_go_sdk_asm_data_live_observation_v1",
		Request: GoX86SDKASMDataCaptureRequest{PackagePath: "example", Target: "linux/amd64"},
		CPP:     []AssemblyCPPObservation{{Output: program}, {}}, Positions: make([]sdkCPPPositionObservation, 2),
		ObjectInputs: gostaticstorage.SDKASMDataObservationRequest{PackagePath: "example", Target: "linux/amd64", Archive: []byte("model archive")},
		Objects: &gostaticstorage.SDKASMDataObservation{Protocol: gostaticstorage.ASMDataCPPProtocol,
			PackagePath: "example", Target: "linux/amd64", Sources: []gostaticstorage.ASMDataSourceObservation{first, second},
			Members: []gostaticstorage.ASMDataMember{{Name: "__.PKGDEF"}, {Name: "_go_.o"}, first.Original, second.Original}}}
	observation.RawSelection, _ = json.Marshal(map[string]any{"ImportPath": "example", "Standard": true,
		"SFiles": []string{"mixed.s", "empty.s"}})
	digest := func(data []byte) string {
		value := sha256.Sum256(data)
		return hex.EncodeToString(value[:])
	}
	observation.Objects.ArchiveSHA256 = digest(observation.ObjectInputs.Archive)
	for index, source := range observation.Objects.Sources {
		input := gostaticstorage.SDKASMDataSource{Name: source.Name, Original: []byte("original model " + source.Name),
			Expanded: []byte(observation.CPP[index].Output), OriginalObject: []byte("original object " + source.Name),
			ExpandedObject: []byte("expanded object " + source.Name)}
		observation.ObjectInputs.Sources = append(observation.ObjectInputs.Sources, input)
		value := &observation.Objects.Sources[index]
		value.OriginalSHA256, value.ExpandedSHA256 = digest(input.Original), digest(input.Expanded)
		value.OriginalObjectSHA256, value.ExpandedObjectSHA256 = digest(input.OriginalObject), digest(input.ExpandedObject)
		member := &observation.Objects.Members[index+2]
		member.Ordinal, member.Name = index+2, source.Name[:len(source.Name)-2]+".o"
		member.NameBytes = []byte(member.Name)
	}
	return observation
}

func TestGoX86SDKASMMetadataSelectorCompletePairing(t *testing.T) {
	observation := sdkASMMetadataModel(t)
	before, _ := json.Marshal(observation)
	file, ordinal, err := sdkASMMetadataSelectedMember(observation, "mixed.s")
	if err != nil || ordinal != 0 || file == nil || len(file.Funcs) != 3 ||
		file.Funcs[0].Sym != "foreign·first<ABIInternal>" || file.Funcs[2].Sym != "helper<>" ||
		len(file.Data) != 0 || len(file.Globl) != 0 {
		t.Fatal("complete source-order member selection", ordinal, err)
	}
	if !reflect.DeepEqual(observation.Objects.Sources[0].TextOrder, []gostaticstorage.ASMSourceText{
		{SourceOrdinal: 0, ObjectOrdinal: 1, Name: "foreign.first", ABI: 1, Namespace: gostaticstorage.TextSymbolNonpkgDefinition, Index: 1},
		{SourceOrdinal: 1, ObjectOrdinal: 2, Name: "example.second", Namespace: gostaticstorage.TextSymbolNonpkgDefinition, Index: 2, Relative: 1},
		{SourceOrdinal: 2, ObjectOrdinal: 0, Name: "helper", ABI: 65535, Namespace: gostaticstorage.TextSymbolSelf},
	}) {
		t.Fatal("source/physical ordinal association was reordered")
	}
	empty, ordinal, err := sdkASMMetadataSelectedMember(observation, "empty.s")
	if err != nil || empty == nil || ordinal != 1 || len(empty.Funcs)+len(empty.Data)+len(empty.Globl) != 0 {
		t.Fatal("complete empty selected member was invented or omitted", ordinal, err)
	}
	after, _ := json.Marshal(observation)
	if !bytes.Equal(before, after) {
		t.Fatal("selector mutated original physical records")
	}
	if _, err := gostaticstorage.ReadonlyLiteralDataInitializers(observation.Objects); !errors.Is(err, gostaticstorage.ErrContext) {
		t.Fatal("metadata acquired a readonly initializer", err)
	}
}

func TestGoX86SDKASMMetadataSelectorRejectsIncompleteTuples(t *testing.T) {
	for name, mutate := range map[string]func(*sdkASMDataLiveObservation){
		"missing-source":          func(o *sdkASMDataLiveObservation) { o.Objects.Sources = o.Objects.Sources[:1] },
		"missing-CPP":             func(o *sdkASMDataLiveObservation) { o.CPP = o.CPP[:1] },
		"missing-positions":       func(o *sdkASMDataLiveObservation) { o.Positions = o.Positions[:1] },
		"missing-object-input":    func(o *sdkASMDataLiveObservation) { o.ObjectInputs.Sources = o.ObjectInputs.Sources[:1] },
		"missing-compiler-member": func(o *sdkASMDataLiveObservation) { o.Objects.Members = o.Objects.Members[:3] },
		"duplicate-selected-name": func(o *sdkASMDataLiveObservation) { o.Objects.Sources[1].Name = "mixed.s" },
		"reordered-members": func(o *sdkASMDataLiveObservation) {
			o.Objects.Members[2], o.Objects.Members[3] = o.Objects.Members[3], o.Objects.Members[2]
		},
		"reordered-CPP":   func(o *sdkASMDataLiveObservation) { o.CPP[0], o.CPP[1] = o.CPP[1], o.CPP[0] },
		"expanded-source": func(o *sdkASMDataLiveObservation) { o.ObjectInputs.Sources[0].Expanded[0] ^= 1 },
		"original-source": func(o *sdkASMDataLiveObservation) { o.ObjectInputs.Sources[0].Original[0] ^= 1 },
		"original-object": func(o *sdkASMDataLiveObservation) { o.ObjectInputs.Sources[0].OriginalObject[0] ^= 1 },
		"archive":         func(o *sdkASMDataLiveObservation) { o.ObjectInputs.Archive[0] ^= 1 },
		"compiler-code":   func(o *sdkASMDataLiveObservation) { o.Objects.Members[2].Texts[0].Code[0] ^= 1 },
		"compiler-PC":     func(o *sdkASMDataLiveObservation) { o.Objects.Members[2].Texts[0].PCLine = []byte{1} },
		"compiler-relocation": func(o *sdkASMDataLiveObservation) {
			o.Objects.Members[2].Texts[0].Relocations = []gostaticstorage.TextRelocation{{Offset: 0, Size: 1}}
		},
		"expanded-PC":   func(o *sdkASMDataLiveObservation) { o.Objects.Sources[0].Expanded.Texts[0].PCFile = []byte{1} },
		"physical-name": func(o *sdkASMDataLiveObservation) { o.Objects.Sources[0].Original.Texts[0].Name += "foreign" },
		"physical-ABI":  func(o *sdkASMDataLiveObservation) { o.Objects.Sources[0].Original.Texts[0].ABI = 0 },
		"physical-namespace": func(o *sdkASMDataLiveObservation) {
			o.Objects.Sources[0].Original.Texts[0].Namespace = gostaticstorage.TextSymbolHashed
		},
		"physical-index":   func(o *sdkASMDataLiveObservation) { o.Objects.Sources[0].TextOrder[0].Index++ },
		"physical-ordinal": func(o *sdkASMDataLiveObservation) { o.Objects.Sources[0].TextOrder[0].ObjectOrdinal = 0 },
		"unselected-sibling-PC": func(o *sdkASMDataLiveObservation) {
			o.Objects.Members[3].Texts = []gostaticstorage.TextRecord{{Name: "omitted"}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			original := sdkASMMetadataModel(t)
			raw, _ := json.Marshal(original)
			var changed sdkASMDataLiveObservation
			if err := json.Unmarshal(raw, &changed); err != nil {
				t.Fatal(err)
			}
			mutate(&changed)
			file, ordinal, err := sdkASMMetadataSelectedMember(changed, "mixed.s")
			if file != nil || ordinal != -1 || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("incomplete/mutated complete metadata was selected", ordinal, err)
			}
		})
	}
	for _, name := range []string{"missing.s", "../mixed.s", "mixed.s/child", "", "mixed.o"} {
		if file, ordinal, err := sdkASMMetadataSelectedMember(sdkASMMetadataModel(t), name); file != nil || ordinal != -1 || !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("unselected member acquired original-source metadata", name, ordinal, err)
		}
	}
}

func TestGoX86SDKASMMetadataCannotRestoreLiveSource(t *testing.T) {
	raw, err := json.Marshal(sdkASMMetadataModel(t))
	var restored GoX86SDKASMDataSource
	if err != nil || json.Unmarshal(raw, &restored) != nil {
		t.Fatal("diagnostic serialization", err)
	}
	for _, source := range []*GoX86SDKASMDataSource{nil, {}, {identity: &GoX86SDKASMDataSource{}}, &restored} {
		if file, err := source.Assembly(context.Background(), "mixed.s"); file != nil || !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("public values restored a live source", err)
		}
	}
}

func TestGoX86SDKASMMetadataArchiveCountBound(t *testing.T) {
	// Complete independent values test the existing bound; none is a live SDK.
	for _, count := range []int{gostaticstorage.ArchiveMemberInventoryLimit - 2, gostaticstorage.ArchiveMemberInventoryLimit - 1} {
		observation := sdkASMMetadataModel(t)
		var names []string
		for _, source := range observation.Objects.Sources {
			names = append(names, source.Name)
		}
		for index := len(names); index < count; index++ {
			name := fmt.Sprintf("empty-%d.s", index)
			names = append(names, name)
			observed := observation.Objects.Sources[1]
			observed.Name = name
			input := observation.ObjectInputs.Sources[1]
			input.Name = name
			member := observation.Objects.Members[3]
			member.Ordinal, member.Name = index+2, fmt.Sprintf("empty-%d.o", index)
			member.NameBytes = []byte(member.Name)
			observation.Objects.Sources = append(observation.Objects.Sources, observed)
			observation.ObjectInputs.Sources = append(observation.ObjectInputs.Sources, input)
			observation.Objects.Members = append(observation.Objects.Members, member)
			observation.CPP = append(observation.CPP, AssemblyCPPObservation{})
			observation.Positions = append(observation.Positions, sdkCPPPositionObservation{})
		}
		observation.RawSelection, _ = json.Marshal(map[string]any{"ImportPath": "example", "Standard": true, "SFiles": names})
		file, ordinal, err := sdkASMMetadataSelectedMember(observation, "mixed.s")
		if count == gostaticstorage.ArchiveMemberInventoryLimit-2 {
			if file == nil || ordinal != 0 || err != nil {
				t.Fatal("existing complete archive bound shrank", err)
			}
		} else if file != nil || ordinal != -1 || !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("complete archive member bound grew", err)
		}
	}
}
