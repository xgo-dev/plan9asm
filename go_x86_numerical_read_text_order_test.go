package plan9asm

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
)

func numericalNativeOrderFixture(t *testing.T) (string, gostaticstorage.ASMDataSourceObservation) {
	t.Helper()
	const program = "TEXT foreign·first<ABIInternal>(SB),4,$0-9\nRET\nTEXT ·second(SB),4,$0-8\nRET\nTEXT helper<>(SB),4,$0-0\nRET\n"
	member := gostaticstorage.ASMDataMember{Flags: 4, Texts: []gostaticstorage.TextRecord{
		{Name: "helper", ABI: 65535, Kind: 1, Namespace: gostaticstorage.TextSymbolSelf, Code: []byte{0xc3}, Size: 1},
		{Name: "foreign.first", ABI: 1, Kind: 1, Namespace: gostaticstorage.TextSymbolNonpkgDefinition, Index: 1, Code: []byte{0x90, 0xc3}, Size: 2},
		{Name: "example.second", Kind: 1, Namespace: gostaticstorage.TextSymbolNonpkgDefinition, Index: 2, Relative: 1, Code: []byte{0x90, 0x90, 0xc3}, Size: 3},
	}}
	order, err := gostaticstorage.ASMSourceTextOrder([]byte(program), "example", member)
	if err != nil {
		t.Fatal("independent metadata grammar fixture", err)
	}
	return program, gostaticstorage.ASMDataSourceObservation{Original: member, Expanded: member, TextOrder: order}
}

func TestGoX86NumericalNativeTextOrderCompleteIdentity(t *testing.T) {
	program, observed := numericalNativeOrderFixture(t)
	order, err := numericalSDKNativeTextOrder(program, "example", observed, observed.Original.Texts, observed.Expanded.Texts)
	if err != nil || !reflect.DeepEqual(order, []int{1, 2, 0}) {
		t.Fatal("native consumer needs an exact complete source-to-object association", order, err)
	}
	order[0] = 0
	if observed.TextOrder[0].ObjectOrdinal != 1 {
		t.Fatal("consumer aliases the original mapping")
	}
}

func TestGoX86NumericalNativeTextOrderRejectsChangedEvidence(t *testing.T) {
	for name, mutate := range map[string]func(*gostaticstorage.ASMDataSourceObservation){
		"missing source":    func(o *gostaticstorage.ASMDataSourceObservation) { o.TextOrder = o.TextOrder[:2] },
		"source ordinal":    func(o *gostaticstorage.ASMDataSourceObservation) { o.TextOrder[0].SourceOrdinal++ },
		"object ordinal":    func(o *gostaticstorage.ASMDataSourceObservation) { o.TextOrder[0].ObjectOrdinal = 0 },
		"duplicate ordinal": func(o *gostaticstorage.ASMDataSourceObservation) { o.TextOrder[1] = o.TextOrder[0] },
		"symbol":            func(o *gostaticstorage.ASMDataSourceObservation) { o.TextOrder[0].Name += ".other" },
		"ABI":               func(o *gostaticstorage.ASMDataSourceObservation) { o.TextOrder[0].ABI = 0 },
		"namespace": func(o *gostaticstorage.ASMDataSourceObservation) {
			o.TextOrder[0].Namespace = gostaticstorage.TextSymbolSelf
		},
		"relative index":    func(o *gostaticstorage.ASMDataSourceObservation) { o.TextOrder[0].Relative++ },
		"physical index":    func(o *gostaticstorage.ASMDataSourceObservation) { o.TextOrder[0].Index++ },
		"expanded code":     func(o *gostaticstorage.ASMDataSourceObservation) { o.Expanded.Texts[0].Code[0] ^= 1 },
		"expanded position": func(o *gostaticstorage.ASMDataSourceObservation) { o.Expanded.Texts[0].PCLine = []byte{1} },
		"expanded relocation": func(o *gostaticstorage.ASMDataSourceObservation) {
			o.Expanded.Texts[0].Relocations = []gostaticstorage.TextRelocation{{Offset: 0, Size: 1, Type: 1}}
		},
		"expanded namespace": func(o *gostaticstorage.ASMDataSourceObservation) {
			o.Expanded.Texts[0].Namespace = gostaticstorage.TextSymbolNonpkgDefinition
		},
		"not assembler":     func(o *gostaticstorage.ASMDataSourceObservation) { o.Original.Flags = 0 },
		"unknown namespace": func(o *gostaticstorage.ASMDataSourceObservation) { o.Original.Texts[0].Namespace = 255 },
		"wrong bank ABI":    func(o *gostaticstorage.ASMDataSourceObservation) { o.Original.Texts[0].ABI = 0 },
		"exchanged records": func(o *gostaticstorage.ASMDataSourceObservation) {
			o.Original.Texts[0], o.Original.Texts[1] = o.Original.Texts[1], o.Original.Texts[0]
		},
		"missing object TEXT": func(o *gostaticstorage.ASMDataSourceObservation) { o.Original.Texts = o.Original.Texts[:2] },
	} {
		t.Run(name, func(t *testing.T) {
			program, observed := numericalNativeOrderFixture(t)
			raw, err := json.Marshal(observed)
			var changed gostaticstorage.ASMDataSourceObservation
			if err != nil || json.Unmarshal(raw, &changed) != nil {
				t.Fatal("independent mutation snapshot", err)
			}
			mutate(&changed)
			order, err := numericalSDKNativeTextOrder(program, "example", changed, observed.Original.Texts, observed.Expanded.Texts)
			if order != nil || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("changed source/physical identity was accepted", order, err)
			}
		})
	}
	program, observed := numericalNativeOrderFixture(t)
	for _, changed := range []string{
		strings.Replace(program, "foreign·first", "foreign·other", 1),
		strings.Replace(program, "<ABIInternal>", "<ABI0>", 1),
		program + "TEXT missing<>(SB),4,$0-0\nRET\n",
	} {
		if order, err := numericalSDKNativeTextOrder(changed, "example", observed, observed.Original.Texts, observed.Expanded.Texts); order != nil || !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("changed complete source TEXT inventory was accepted", order, err)
		}
	}
}

func TestGoX86NumericalNativeTextOrderGrantsNoEntryRole(t *testing.T) {
	for _, symbol := range []string{"helper<>", "foreign·first<ABIInternal>"} {
		_, _, accepted := numericalFunctionSourceIdentity(symbol, "example", "amd64", numericalSBOwnedSource)
		if accepted {
			t.Fatal("source order metadata granted an owned/native entry", symbol)
		}
	}
	if _, _, accepted := numericalFunctionSourceIdentity("helper<>", "example", "amd64", numericalSBSDKSource); accepted {
		t.Fatal("static helper acquired a numerical entry declaration")
	}
}
