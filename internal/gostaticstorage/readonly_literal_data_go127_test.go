//go:build go1.27

package gostaticstorage

import (
	"bytes"
	"debug/elf"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// This uses the real Go assembler/compiler and linker, not an SDK-origin
// token. Explicit -std flags exercise the offline object role only. Complete
// ELF bytes independently establish sparse and zero-tail materialization.
func TestReadonlyLiteralDataActualGoObjects(t *testing.T) {
	directory, binary, _ := fixture(t)
	oracle := officialReaderForSource(t, binary, sdkASMDataReaderSource)
	root := filepath.Dir(filepath.Dir(binary))
	builtin, err := os.ReadFile(filepath.Join(root, "src", "cmd", "internal", "goobj", "builtinlist.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			target := "linux/" + arch
			env := fixtureEnv(t, target)
			pkg := fixtureModule + "/readonly" + arch
			consumer := filepath.Join(directory, "readonly"+arch)
			if err := os.Mkdir(consumer, 0700); err != nil {
				t.Fatal(err)
			}
			var source strings.Builder
			source.WriteString("TEXT ·Entry(SB),4,$0-0\n")
			var directives strings.Builder
			for index, test := range asmDataGrammarCases {
				name := fmt.Sprintf("literal_%d", index)
				fmt.Fprintf(&source, "MOVL %s<>(SB),AX\n", name)
				fmt.Fprintf(&directives, "DATA %s<>+0(SB)/%d,$%s\nGLOBL %s<>(SB),8,$16\n",
					name, test.width, test.value, name)
			}
			for _, name := range []string{"sparse", "tail", "before", "zero_only"} {
				fmt.Fprintf(&source, "MOVL %s<>(SB),AX\n", name)
			}
			source.WriteString("RET\n")
			directives.WriteString("DATA sparse<>+2(SB)/1,$255\nDATA sparse<>+7(SB)/4,$0x12345678\nGLOBL sparse<>(SB),8|16,$24\n")
			directives.WriteString("DATA tail<>(SB)/1,$31\nGLOBL tail<>(SB),8,$32\n")
			directives.WriteString("GLOBL before<>(SB),8,$8\nDATA before<>+8(SB)/4,$0x88776655\n")
			directives.WriteString("GLOBL zero_only<>(SB),8,$24\n")
			source.WriteString(directives.String())
			assembly := []byte(source.String())
			goSource := []byte("package readonlyfixture\nfunc Entry()\n")
			for name, data := range map[string][]byte{"source.go": goSource, "table.s": assembly} {
				if err := os.WriteFile(filepath.Join(consumer, name), data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			selection := run(t, binary, consumer, env, "list", "-compiled", "-export", "-json", "-gcflags=-std", "-asmflags=-std", ".")
			var selected struct {
				ImportPath, Export string
				SFiles             []string
				Standard           bool
			}
			if json.Unmarshal(selection, &selected) != nil || selected.ImportPath != pkg || selected.Standard ||
				!reflect.DeepEqual(selected.SFiles, []string{"table.s"}) {
				t.Fatal("actual first-party selected source inventory differs")
			}
			read := func(file string) []byte {
				data, err := os.ReadFile(file)
				if err != nil {
					t.Fatal(err)
				}
				return data
			}
			archive := read(selected.Export)
			original := run(t, oracle, consumer, env, selected.Export)
			request := SDKASMDataObservationRequest{PackagePath: pkg, Target: target, Archive: archive, BuiltinSource: builtin}
			input := SDKASMDataSource{Name: "table.s", Original: assembly, Expanded: assembly}
			artifacts := map[string][]byte{"original.a": archive, "data-sdk.json": original,
				"source-table.s": assembly, "source.go": goSource, "selection.json": selection}
			for _, role := range []string{"original", "expanded"} {
				object := filepath.Join(consumer, role+".o")
				run(t, binary, consumer, env, "tool", "asm", "-std", "-p", pkg, "-o", object, "table.s")
				data := read(object)
				artifacts[role+".o"] = data
				artifacts[role+".sdk.json"] = run(t, oracle, consumer, env, object)
				if role == "original" {
					input.OriginalObject = data
				} else {
					input.ExpandedObject = data
				}
			}
			request.Sources = []SDKASMDataSource{input}
			observation, err := ObserveX86SDKASMData(request)
			if err != nil {
				t.Fatal("complete actual source/whole original objects", err)
			}
			var official []ASMDataMember
			if json.Unmarshal(original, &official) != nil || len(official) != len(observation.Members) ||
				!reflect.DeepEqual(official[2].Definitions, observation.Members[2].Definitions) {
				t.Fatal("private DATA namespace/index/bytes differ from independent Go reader")
			}
			caller := filepath.Join(directory, "caller"+arch)
			if err := os.Mkdir(caller, 0700); err != nil {
				t.Fatal(err)
			}
			callerSource := []byte(fmt.Sprintf("package main\nimport %q\nfunc main(){ readonlyfixture.Entry() }\n", pkg))
			if err := os.WriteFile(filepath.Join(caller, "main.go"), callerSource, 0600); err != nil {
				t.Fatal(err)
			}
			executable := filepath.Join(caller, "original-linked")
			run(t, binary, caller, env, "build", "-gcflags="+pkg+"=-std", "-asmflags="+pkg+"=-std", "-o", executable, ".")
			artifacts["linked-original.elf"] = read(executable)
			artifacts["caller.go"] = callerSource
			encoded, err := json.Marshal(observation)
			if err != nil {
				t.Fatal(err)
			}
			artifacts["observation.json"] = encoded
			retainTextArtifact(t, target, "readonly-literal", artifacts)
			images, err := ReadonlyLiteralDataInitializers(observation)
			if err != nil || len(images) != len(asmDataGrammarCases)+4 {
				t.Fatal("complete actual literal initializer family remains unclosed", err)
			}
			object, err := elf.Open(executable)
			if err != nil {
				t.Fatal(err)
			}
			defer object.Close()
			if arch == "386" && object.Machine != elf.EM_386 || arch == "amd64" && object.Machine != elf.EM_X86_64 {
				t.Fatal("actual ELF target differs")
			}
			symbols, err := object.Symbols()
			if err != nil {
				t.Fatal(err)
			}
			for _, image := range images {
				matches := 0
				for _, symbol := range symbols {
					if symbol.Name != image.Definition.Name {
						continue
					}
					matches++
					section := object.Sections[symbol.Section]
					data, err := section.Data()
					start := symbol.Value - section.Addr
					if err != nil || section.Name != ".rodata" || symbol.Size != uint64(len(image.Initial)) ||
						start > uint64(len(data)) || symbol.Size > uint64(len(data))-start ||
						!bytes.Equal(image.Initial, data[start:start+symbol.Size]) {
						t.Fatal("exact sparse/tail initializer differs from actual Go linked bytes", image.Definition.Name, err)
					}
				}
				if matches != 1 {
					t.Fatal("private first-party linked symbol is not unique", image.Definition.Name, matches)
				}
			}
			encoded, err = json.Marshal(images)
			if err != nil {
				t.Fatal(err)
			}
			retainTextArtifact(t, target, "readonly-literal", map[string][]byte{"initializers.json": encoded})
		})
	}
}
