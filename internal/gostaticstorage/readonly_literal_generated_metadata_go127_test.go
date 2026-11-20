//go:build go1.27

package gostaticstorage

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type readonlyMixedMetadataCase struct {
	name                          string
	floatPool, funcdata, ordinary bool
}

func readonlyMixedMetadataSource(test readonlyMixedMetadataCase) []byte {
	var source strings.Builder
	source.WriteString("TEXT ·Entry(SB),4,$0-0\n")
	if test.funcdata {
		source.WriteString("FUNCDATA $1,no_pointers_stackmap(SB)\n")
	}
	if test.floatPool {
		source.WriteString("MOVSS $-0.0,X0\nADDSD $1.25,X0\n")
	}
	if test.ordinary {
		source.WriteString("MOVL ordinary<>(SB),AX\n")
	}
	source.WriteString("RET\n")
	if test.ordinary {
		source.WriteString("DATA ordinary<>+2(SB)/2,$0xbeef\nGLOBL ordinary<>(SB),8,$16\n")
	}
	return []byte(source.String())
}

// These are actual complete compiler archives plus two independently assembled
// objects. Stock Go readers preserve all DATA/TEXT/auxiliary records; neither
// metadata nor the returned initializer plan is SDK or native-entry authority.
func readonlyMixedMetadataActual(t *testing.T, directory, driver, dataOracle, textOracle, target string, builtin []byte, test readonlyMixedMetadataCase) *SDKASMDataObservation {
	t.Helper()
	env := fixtureEnv(t, target)
	consumer := filepath.Join(directory, strings.ReplaceAll(target, "/", "-")+"-"+test.name)
	if err := os.Mkdir(consumer, 0700); err != nil {
		t.Fatal(err)
	}
	pkg := fixtureModule + "/" + filepath.Base(consumer)
	source := readonlyMixedMetadataSource(test)
	expanded := bytes.ReplaceAll(source, []byte(","), []byte(", "))
	declarations := []byte("package mixedfixture\nfunc Entry()\n")
	for name, data := range map[string][]byte{"mixed.go": declarations, "mixed.s": source, "expanded.asm": expanded} {
		if err := os.WriteFile(filepath.Join(consumer, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	selection := run(t, driver, consumer, env, "list", "-json", "-compiled", "-export", "-mod=readonly", "-gcflags=-std", "-asmflags=-std", ".")
	var selected struct {
		ImportPath, Export string
		SFiles             []string
		Standard           bool
	}
	if json.Unmarshal(selection, &selected) != nil || selected.ImportPath != pkg || selected.Standard ||
		!reflect.DeepEqual(selected.SFiles, []string{"mixed.s"}) {
		t.Fatal("actual complete mixed-metadata source inventory differs")
	}
	archive, err := os.ReadFile(selected.Export)
	if err != nil {
		t.Fatal(err)
	}
	data := run(t, dataOracle, consumer, env, selected.Export)
	text := run(t, textOracle, consumer, env, selected.Export)
	actual := asmGeneratedFloatPoolOriginal(t, data, text)
	if len(actual) != 3 || len(actual[2].Texts) != 1 || actual[2].Texts[0].Name != pkg+".Entry" {
		t.Fatal("the original mixed-metadata archive has an incomplete source/TEXT inventory")
	}
	request := SDKASMDataObservationRequest{PackagePath: pkg, Target: target, Archive: archive, BuiltinSource: builtin}
	input := SDKASMDataSource{Name: "mixed.s", Original: source, Expanded: expanded}
	artifacts := map[string][]byte{"source-mixed.s": source, "expanded.asm": expanded, "source-mixed.go": declarations,
		"original.a": archive, "selection.json": selection, "data-sdk.json": data, "text-sdk.json": text}
	for _, role := range []string{"original", "expanded"} {
		file := "mixed.s"
		if role == "expanded" {
			file = "expanded.asm"
		}
		arguments := []string{"tool", "asm", "-std"}
		if target == "darwin/amd64" {
			arguments = append(arguments, "-shared")
		}
		arguments = append(arguments, "-p", pkg, "-o", role+".o", file)
		run(t, driver, consumer, env, arguments...)
		object, err := os.ReadFile(filepath.Join(consumer, role+".o"))
		if err != nil {
			t.Fatal(err)
		}
		if role == "original" {
			input.OriginalObject = object
		} else {
			input.ExpandedObject = object
		}
		artifacts[role+".o"] = object
		artifacts[role+"-data-sdk.json"] = run(t, dataOracle, consumer, env, role+".o")
		artifacts[role+"-text-sdk.json"] = run(t, textOracle, consumer, env, role+".o")
		members := asmGeneratedFloatPoolOriginal(t, artifacts[role+"-data-sdk.json"], artifacts[role+"-text-sdk.json"])
		if len(members) != 1 || !sameASMDataObjects(members[0], actual[2]) {
			t.Fatal("complete independently assembled DATA/TEXT/auxiliary records differ", role)
		}
	}
	request.Sources = []SDKASMDataSource{input}
	observation, err := ObserveX86SDKASMData(request)
	if err != nil || observation == nil || !reflect.DeepEqual(observation.Members, actual) || len(observation.Sources) != 1 {
		t.Fatal("the complete actual mixed source/object observation differs", err)
	}
	observed := observation.Sources[0]
	expectedCounts := [3]int{}
	if test.floatPool {
		expectedCounts[0] = 2
	}
	if test.funcdata {
		expectedCounts[1] = 1
	}
	if test.ordinary {
		expectedCounts[2] = 1
	}
	if [3]int{len(observed.GeneratedFloatPools), len(observed.GeneratedFuncdata), len(observed.ExpandedLayouts)} != expectedCounts {
		t.Fatal("ordinary layouts and actual independent metadata classes were confused")
	}
	if test.floatPool {
		for _, pool := range observed.GeneratedFloatPools {
			if len(pool.Owners) != 1 || pool.Definition.Name != "$f32.80000000" && pool.Definition.Name != "$f64.3ff4000000000000" {
				t.Fatal("the actual two-width FCONST metadata lost its complete owner", pool)
			}
		}
	}
	if test.funcdata && (len(observed.GeneratedFuncdata[0].Owners) != 1 || observed.GeneratedFuncdata[0].Owners[0].Slot != 1) {
		t.Fatal("actual reserved FUNCDATA lost its source/auxiliary owner")
	}
	retainTextArtifact(t, target, "readonly-mixed-"+test.name, artifacts)
	return observation
}

func TestReadonlyLiteralDataActualGoMixedGeneratedMetadata(t *testing.T) {
	directory, driver, _ := fixture(t)
	dataOracle := officialReaderForSource(t, driver, sdkASMDataReaderSource)
	textOracle := officialReaderForSource(t, driver, sdkTextReaderSource)
	builtin, err := os.ReadFile(filepath.Join(filepath.Dir(filepath.Dir(driver)), builtinSourceRole))
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"linux/386", "linux/amd64", "darwin/amd64", "windows/386", "windows/amd64"} {
		t.Run(target, func(t *testing.T) {
			for _, test := range []readonlyMixedMetadataCase{
				{"float-pool", true, false, true},
				{"funcdata", false, true, true},
				{"both", true, true, true},
				{"metadata-only", true, true, false},
			} {
				t.Run(test.name, func(t *testing.T) {
					observation := readonlyMixedMetadataActual(t, directory, driver, dataOracle, textOracle, target, builtin, test)
					t.Run("ordinary-only-initializer", func(t *testing.T) {
						images, err := ReadonlyLiteralDataInitializers(observation)
						if !test.ordinary {
							if !errors.Is(err, ErrContext) || images != nil {
								t.Fatal("metadata-only source acquired an initialized image", images, err)
							}
							return
						}
						expected := make([]byte, 16)
						expected[2], expected[3] = 0xef, 0xbe
						if err != nil || len(images) != 1 || images[0].Definition.Name != "ordinary" ||
							images[0].Definition.Namespace != TextSymbolSelf || images[0].Definition.ABI != 65535 ||
							!bytes.Equal(images[0].Initial, expected) || len(images[0].Fragments) != 1 {
							t.Fatal("verified metadata blocked ordinary RODATA or entered the initializer directory", images, err)
						}
						before := readonlyLiteralClone(t, observation)
						images[0].Initial[2] = 0
						images[0].Definition.Data[2] = 0
						if !reflect.DeepEqual(before, observation) {
							t.Fatal("ordinary image mutated a complete metadata/source/object observation")
						}
					})
					if test.name == "both" {
						t.Run("complete-metadata-guards", func(t *testing.T) {
							readonlyMixedMetadataGuards(t, observation)
						})
					}
				})
			}
		})
	}
}
