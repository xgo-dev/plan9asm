//go:build go1.27

package gostaticstorage

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestGoStandaloneAMD64DataIndependentOriginalObjects(t *testing.T) {
	directory, driver, _ := fixture(t)
	dataOracle := officialReaderForSource(t, driver, sdkASMDataReaderSource)
	textOracle := officialReaderForSource(t, driver, sdkTextReaderSource)
	builtin, err := os.ReadFile(filepath.Join(filepath.Dir(filepath.Dir(driver)), builtinSourceRole))
	if err != nil {
		t.Fatal(err)
	}
	// The shared independent fixture exercises all integer/float/string
	// fragments, sparse/tail/BSS extents, flags and address relocations. Here
	// it is an ordinary standalone object, never an SDK archive or -std input.
	source := []byte(asmDataFixtureSource("amd64"))
	name := filepath.Join(directory, "standalone.asm")
	if err := os.WriteFile(name, source, 0600); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"linux/amd64", "darwin/amd64", "windows/amd64"} {
		t.Run(target, func(t *testing.T) {
			env := fixtureEnv(t, target)
			objectName := filepath.Join(t.TempDir(), "standalone.o")
			run(t, driver, directory, env, "tool", "asm", "-p", fixtureModule, "-o", objectName, name)
			object, err := os.ReadFile(objectName)
			if err != nil {
				t.Fatal(err)
			}
			var actual []ASMDataMember
			var texts []TextMember
			if err := json.Unmarshal(run(t, dataOracle, directory, env, objectName), &actual); err != nil || len(actual) != 1 {
				t.Fatal("actual SDK standalone DATA reader", err)
			}
			if err := json.Unmarshal(run(t, textOracle, directory, env, objectName), &texts); err != nil || len(texts) != 1 {
				t.Fatal("actual SDK standalone TEXT reader", err)
			}
			observed, err := ObserveAMD64AssemblyData(source, object, builtin, fixtureModule, target)
			if err != nil {
				t.Fatal(err)
			}
			if observed.Member.Flags != 4 || !reflect.DeepEqual(observed.Member.Definitions, actual[0].Definitions) ||
				!reflect.DeepEqual(observed.Member.Texts, texts[0].Texts) || len(observed.Layouts) < len(asmDataGrammarCases) {
				t.Fatal("standalone observation differs from complete independent SDK records")
			}
			for name, mutate := range map[string]func([]byte, []byte) ([]byte, []byte){
				"wrong-value": func(s, o []byte) ([]byte, []byte) {
					return bytes.Replace(s, []byte("0x12345"), []byte("0x12346"), 1), o
				},
				"missing-layout": func(s, o []byte) ([]byte, []byte) {
					return bytes.ReplaceAll(s, []byte("GLOBL mutable<>(SB),$32"), nil), o
				},
				"missing-TEXT": func(s, o []byte) ([]byte, []byte) {
					return bytes.Replace(s, []byte("TEXT ·Entry"), []byte("MISSING ·Entry"), 1), o
				},
				"unknown-CPP":       func(s, o []byte) ([]byte, []byte) { return append([]byte("#define VALUE 1\n"), s...), o },
				"object-tail":       func(s, o []byte) ([]byte, []byte) { return s, append(o, 0) },
				"object-truncation": func(s, o []byte) ([]byte, []byte) { return s, o[:len(o)-1] },
			} {
				t.Run(name, func(t *testing.T) {
					changedSource, changedObject := mutate(bytes.Clone(source), bytes.Clone(object))
					if bytes.Equal(changedSource, source) && bytes.Equal(changedObject, object) {
						t.Fatal("negative did not change an input")
					}
					if _, err := ObserveAMD64AssemblyData(changedSource, changedObject, builtin, fixtureModule, target); !errors.Is(err, ErrContext) {
						t.Fatal("unbound source/object acquired a standalone observation", err)
					}
				})
			}
			for _, wrongTarget := range []string{"linux/386", "linux/arm64", "js/wasm", "freebsd/amd64"} {
				if _, err := ObserveAMD64AssemblyData(source, object, builtin, fixtureModule, wrongTarget); !errors.Is(err, ErrContext) {
					t.Fatal("standalone AMD64 observer accepted another physical target", wrongTarget, err)
				}
			}
			if _, err := ObserveAMD64AssemblyData(source, object, nil, fixtureModule, target); !errors.Is(err, ErrContext) {
				t.Fatal("missing actual builtin source was accepted", err)
			}
		})
	}
}
