//go:build go1.27

package gostaticstorage

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestGoStaticStorageX86AssemblyCompleteOriginalSDKReader(t *testing.T) {
	directory, binary, _ := fixture(t)
	oracle := officialReaderForSource(t, binary, sdkTextReaderSource)
	consumer := filepath.Join(directory, "asmconsumer")
	if err := os.Mkdir(consumer, 0700); err != nil {
		t.Fatal(err)
	}
	goSource := `package asmconsumer
import owner "example.invalid/staticstorage"
var _ = owner.Keys
func Feature() byte
func Other() byte
`
	if err := os.WriteFile(filepath.Join(consumer, "value.go"), []byte(goSource), 0600); err != nil {
		t.Fatal(err)
	}
	builtin, err := os.ReadFile(filepath.Join(filepath.Dir(filepath.Dir(binary)), "src", "cmd", "internal", "goobj", "builtinlist.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			target := "linux/" + arch
			env := fixtureEnv(t, target)
			originalSource := "#include \"textflag.h\"\nTEXT ·Feature(SB),NOSPLIT,$0-1\n" +
				"CMPB internal∕cpu·X86+64(SB),$1\nMOVB internal∕cpu·X86+65(SB),AL\nMOVB AL,ret+0(FP)\nRET\n"
			otherSource := "#include \"textflag.h\"\nTEXT ·Other(SB),NOSPLIT,$0-1\n" +
				"MOVB example·invalid∕staticstorage·Keys+1(SB),AL\nMOVB AL,ret+0(FP)\nRET\n"
			first, second := "first_"+arch+".s", "second_"+arch+".s"
			for name, source := range map[string]string{first: originalSource, second: otherSource} {
				if err := os.WriteFile(filepath.Join(consumer, name), []byte(source), 0600); err != nil {
					t.Fatal(err)
				}
			}
			selection := run(t, binary, consumer, env, "list", "-json", "-compiled", "-export", "-mod=readonly", ".")
			var selected struct {
				Export string
				SFiles []string
			}
			if err := json.Unmarshal(selection, &selected); err != nil || len(selected.SFiles) != 2 {
				t.Fatal("actual selected assembler member inventory differs", err)
			}
			archive, err := os.ReadFile(selected.Export)
			if err != nil {
				t.Fatal(err)
			}
			raw := run(t, oracle, consumer, env, selected.Export)
			var official []TextMember
			if err := json.Unmarshal(raw, &official); err != nil || len(official) != 4 {
				t.Fatal("independent SDK all-member reader differs", err)
			}
			observed, err := ObserveX86AssemblyArchive(archive, builtin, target, selected.SFiles)
			if err != nil || !reflect.DeepEqual(observed, official) {
				t.Fatal("whole compiler/assembler archive differs from SDK reader", err)
			}
			for _, mutation := range []struct {
				name    string
				target  string
				sources []string
			}{
				{"unobserved target", "darwin/amd64", selected.SFiles},
				{"source order", target, []string{selected.SFiles[1], selected.SFiles[0]}},
				{"duplicate source", target, []string{selected.SFiles[0], selected.SFiles[0]}},
				{"missing member", target, selected.SFiles[:1]},
				{"source path alias", target, []string{"./" + selected.SFiles[0], selected.SFiles[1]}},
			} {
				t.Run(mutation.name, func(t *testing.T) {
					if _, err := ObserveX86AssemblyArchive(archive, builtin, mutation.target, mutation.sources); err == nil {
						t.Fatal("offline decoder accepted changed archive target/member/source role")
					}
				})
			}
			objectPath := filepath.Join(filepath.Dir(oracle), "assembly-"+arch+".o")
			listing := run(t, binary, consumer, env, "tool", "asm", "-S", "-p", fixtureModule+"/asmconsumer", "-I",
				filepath.Join(filepath.Dir(filepath.Dir(binary)), "pkg", "include"), "-o", objectPath, filepath.Join(consumer, first))
			object, err := os.ReadFile(objectPath)
			if err != nil {
				t.Fatal(err)
			}
			standaloneRaw := run(t, oracle, consumer, env, objectPath)
			var standalone []TextMember
			if err := json.Unmarshal(standaloneRaw, &standalone); err != nil || len(standalone) != 1 {
				t.Fatal("independent standalone SDK reader differs", err)
			}
			texts, err := ObserveX86AssemblyText(object, builtin, target)
			if err != nil || !reflect.DeepEqual(texts, standalone[0].Texts) {
				t.Fatal("complete original assembler object differs from SDK reader", err)
			}
			if len(texts) != 1 || len(texts[0].Relocations) != 2 || !strings.Contains(string(listing), "internal/cpu.X86") {
				t.Fatal("independent full CMP immediate/MOV relocation witness was not consumed")
			}
			for _, member := range observed {
				if member.Name == strings.TrimSuffix(first, ".s")+".o" && !reflect.DeepEqual(member.Texts, texts) {
					t.Fatal("actual original assembler object/archive member TEXT identity differs")
				}
			}
			encoded, err := json.Marshal(observed)
			if err != nil {
				t.Fatal(err)
			}
			retainTextArtifact(t, target, "numerical-read-assembly", map[string][]byte{
				"archive-original.a": archive, "archive-sdk.json": raw, "archive-observed.json": encoded,
				"object-original.o": object, "object-sdk.json": standaloneRaw, "object-listing.txt": listing,
				"selection.json": selection, "source-first.s": []byte(originalSource), "source-second.s": []byte(otherSource),
				"source-value.go": []byte(goSource), "builtin-source.go": builtin,
			})
			t.Logf("ACTUAL_NUMERICAL_READ_ARCHIVE target=%s archiveSHA256=%s objectSHA256=%s members=%d",
				target, digest(archive), digest(object), len(observed))
		})
	}
}
