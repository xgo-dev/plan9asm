package main

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

const legacyEncoderReportFixture = `package x86
type opBytes [31]uint8
var operands = []ytab{
    {Zm_r, 0, argList{Yml, Yrl}},
    {Zm_r, 2, argList{Yml, Yrl}},
}
var optab = [...]Optab{
    {obj.AXXX, nil, 0, opBytes{}},
    {ATEST, operands, Px, opBytes{0x0f, 0x20, 0x30}},
    {AENTER, nil, 0, opBytes{}},
    {0, nil, 0, opBytes{}},
}
var ymovtab = []movtab{
    {AMOVW, Yml, Ynone, Ytask, movMemReg2op, [4]uint8{0x0f, 0, 3, 0}},
    {0, 0, 0, 0, 0, [4]uint8{}},
}
`

func TestLegacyEncoderReportRetainsRulesWithoutGrantingCoverage(t *testing.T) {
	root := t.TempDir()
	writeEncoderFixture(t, filepath.Join(root, "src/cmd/internal/obj/x86/asm6.go"), legacyEncoderReportFixture)
	for _, arch := range []string{"amd64", "386"} {
		t.Run(arch, func(t *testing.T) {
			rep := report{Corpus: "go-asm", Goarch: arch, SupportedForms: 7, ContextForms: 11,
				EncoderRules: 13, EncoderRuleFingerprint: "existing-avx", EncoderFingerprint: "existing-classes"}
			before := rep
			if err := attachLegacyEncoderCatalog(&rep, root); err != nil {
				t.Fatal(err)
			}
			legacy := rep.LegacyEncoder
			if legacy == nil || legacy.OperandRows != 2 || legacy.MoveRows != 1 || legacy.SpecialEntries != 1 ||
				len(legacy.Catalog.Optab) != 4 || len(legacy.Catalog.Movtab) != 2 || len(legacy.Fingerprint) != 64 {
				t.Fatalf("complete source inventory was lost: %+v", legacy)
			}
			data, err := json.Marshal(rep)
			if err != nil || !strings.Contains(string(data), `"legacy_encoder"`) ||
				!strings.Contains(string(data), `"from3":"Ynone"`) ||
				!strings.Contains(string(data), `"kind":"sentinel"`) {
				t.Fatalf("JSON omitted original roles or special rows: %v", err)
			}
			if text := string(renderMarkdown(rep)); !strings.Contains(text, "legacy encoding inventory") ||
				!strings.Contains(text, "not translation or execution evidence") {
				t.Fatal("Markdown failed to separate inventory and tested coverage")
			}
			rep.LegacyEncoder = nil
			if !reflect.DeepEqual(rep, before) {
				t.Fatal("legacy inventory changed an existing denominator or granted tested coverage")
			}
		})
	}
}

func TestLegacyEncoderReportFingerprintKeepsRetainedRowAttributes(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "src/cmd/internal/obj/x86/asm6.go")
	read := func(source string) string {
		writeEncoderFixture(t, path, source)
		rep := report{Corpus: "go-asm", Goarch: "amd64"}
		if err := attachLegacyEncoderCatalog(&rep, root); err != nil {
			t.Fatal(err)
		}
		return rep.LegacyEncoder.Fingerprint
	}
	before := read(legacyEncoderReportFixture)
	for _, change := range []struct{ old, new string }{
		{"0x30", "0x31"}, {"operands, Px", "operands, P32"},
		{"Zm_r, 0", "Zr_m, 0"}, {"Zm_r, 0", "Zm_r, 1"},
		{"Yml, Yrl", "Yxm, Yxr"}, {"Yml, Ynone, Ytask", "Yml, Yrl, Ytask"},
		{"movMemReg2op", "movRegMem2op"}, {"[31]uint8", "[32]uint8"},
	} {
		if got := read(strings.Replace(legacyEncoderReportFixture, change.old, change.new, 1)); got == before {
			t.Fatalf("fingerprint discarded %s", change.old)
		}
	}
	if got := read("// comment does not alter encoding\n" + legacyEncoderReportFixture); got != before {
		t.Fatal("comment changed normalized encoding fingerprint")
	}
	// The row hash preserves the symbolic Px reference, not its definition.
	// Do not let a consumer mistake it for whole-assembler semantic identity.
	for _, definition := range []string{"const Px = 1\n", "const Px = 2\n"} {
		if got := read(legacyEncoderReportFixture + definition); got != before {
			t.Fatal("table-row fingerprint unexpectedly depends on external constant definitions")
		}
	}
}

func TestLegacyEncoderReportMissingSourcesFailAndOtherArchitecturesStayIndependent(t *testing.T) {
	root := t.TempDir()
	for _, rep := range []report{
		{Corpus: "go-asm", Goarch: "amd64"}, {Corpus: "go-asm", Goarch: "386"},
	} {
		if err := attachLegacyEncoderCatalog(&rep, root); err == nil || rep.LegacyEncoder != nil {
			t.Fatal("missing official source was silently reported as an empty complete inventory")
		}
	}
	for _, rep := range []report{
		{Corpus: "std", Goarch: "amd64"}, {Corpus: "go-asm", Goarch: "arm"},
		{Corpus: "go-asm", Goarch: "arm64"}, {Corpus: "go-asm", Goarch: "wasm"},
	} {
		if err := attachLegacyEncoderCatalog(&rep, root); err != nil || rep.LegacyEncoder != nil {
			t.Fatal("unrelated corpus acquired x86 source requirements", err)
		}
	}
}

func TestLegacyEncoderReportActualSelectedSDK(t *testing.T) {
	rep := report{Corpus: "go-asm", Goarch: "amd64"}
	if err := attachLegacyEncoderCatalog(&rep, runtime.GOROOT()); err != nil {
		t.Fatal(err)
	}
	legacy := rep.LegacyEncoder
	if legacy == nil || legacy.OperandRows < 1000 || legacy.MoveRows < 100 || legacy.SpecialEntries == 0 {
		t.Fatalf("actual complete tables missing: %+v", legacy)
	}
	t.Logf("legacy inventory: %d operand rows, %d special entries, %d move rows; not translated coverage",
		legacy.OperandRows, legacy.SpecialEntries, legacy.MoveRows)
}

func TestLegacyEncoderReportCLIOutput(t *testing.T) {
	oldArgs, oldFlags := os.Args, flag.CommandLine
	defer func() {
		os.Args, flag.CommandLine = oldArgs, oldFlags
	}()
	for _, arch := range []string{"amd64", "386"} {
		t.Run(arch, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "report.json")
			flag.CommandLine = flag.NewFlagSet("plan9asmscan", flag.ContinueOnError)
			os.Args = []string{"plan9asmscan", "-corpus=go-asm", "-goos=linux",
				"-goarch=" + arch, "-format=json", "-repo-root=../..", "-out=" + path}
			main()
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var rep report
			if err := json.Unmarshal(data, &rep); err != nil {
				t.Fatal(err)
			}
			if rep.Goarch != arch || rep.LegacyEncoder == nil || rep.LegacyEncoder.OperandRows < 1000 ||
				rep.EncoderRules == 0 || rep.EncoderRuleFingerprint == "" {
				t.Fatal("official CLI output lost its independent legacy or AVX rule inventory")
			}
		})
	}
}
