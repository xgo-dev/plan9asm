package gotoolprofile

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm"
)

func TestInstrumentationOriginalGeneratedAssemblyByteBudget(t *testing.T) {
	const goLimit = 2 << 20
	const assemblyLimit = 8 << 20
	for _, test := range []struct {
		name  string
		sizes map[string]int
		valid bool
	}{
		{"assembly above Go bound", map[string]int{"probe.s": 3 << 20}, true},
		{"assembly exact bound", map[string]int{"probe.s": assemblyLimit}, true},
		{"assembly over bound", map[string]int{"probe.s": assemblyLimit + 1}, false},
		{"Go exact bound", map[string]int{"probe.go": goLimit}, true},
		{"Go over bound", map[string]int{"probe.go": goLimit + 1}, false},
		{"inventory exact bound", map[string]int{"a.s": assemblyLimit, "b.s": assemblyLimit}, true},
		{"inventory over bound", map[string]int{"a.s": assemblyLimit, "b.s": assemblyLimit, "probe.go": 16}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := &ConsumerInput{
				Module: "example.invalid/sourcebudget", SourceRoot: t.TempDir(),
				Sources: make(map[string]string), Directories: map[string][]string{".": {}},
			}
			for name, size := range test.sizes {
				data := strings.Repeat(" ", size)
				if err := os.WriteFile(filepath.Join(input.SourceRoot, name), []byte(data), 0600); err != nil {
					t.Fatal(err)
				}
				input.Sources[name] = bytesSHA256([]byte(data))
				input.Directories["."] = append(input.Directories["."], name)
			}
			sort.Strings(input.Directories["."])
			inventory, err := CaptureInstrumentationOriginalSourceInventory(input, ".")
			if !test.valid {
				if err == nil {
					t.Fatal("accepted an original source beyond its file or inventory byte bound")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			data, err := json.Marshal(inventory)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodeInstrumentationOriginalSourceInventory(bytes.NewReader(data), input, "."); err != nil {
				t.Fatal(err)
			}
			for name := range inventory.Contents {
				inventory.Contents[name] += "changed"
				if err := ValidateInstrumentationOriginalSourceInventory(input, ".", inventory); err == nil {
					t.Fatal("large-source allowance erased original byte binding")
				}
				break
			}
		})
	}
}

func TestInstrumentationCPPGeneratedAssemblyByteBudget(t *testing.T) {
	const file = "probe.s"
	source := strings.Repeat("NOP\n", 3<<18)
	expanded, err := plan9asm.PreprocessAssemblySource(source, plan9asm.AssemblyPreprocessOptions{FileName: "module/" + file})
	if err != nil || len(expanded) <= 2<<20 {
		t.Fatalf("fixture lost its large expanded source: %d bytes: %v", len(expanded), err)
	}
	digest := bytesSHA256([]byte(source))
	input := &InstrumentationConsumerInput{
		Original: &ConsumerInput{Sources: map[string]string{file: digest}},
		Sources:  &InstrumentationOriginalSourceInventory{Contents: map[string]string{file: source}},
	}
	proof := InstrumentationAssemblyFile{
		CPP:            CPPProof{File: file, Inputs: map[string]string{"module/" + file: digest}},
		ExpandedSource: expanded, TypedSource: expanded,
		InputContents: map[string]string{"module/" + file: source},
	}
	pkg := PackageProof{Macros: &AssemblerMacros{}}
	// This is only bounded CPP replay, not a package/export/object certificate.
	if err := replayInstrumentationCPP(input, pkg, nil, proof); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		id   string
		size int
	}{
		{"assembly over bound", "module/probe.s", 8<<20 + 1},
		{"module header keeps old bound", "module/include.h", 2<<20 + 1},
		{"tool header keeps old bound", "tool/textflag.h", 2<<20 + 1},
		{"generated header keeps old bound", "generated/example.invalid/pkg/go_asm.h", 2<<20 + 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			text := strings.Repeat(" ", test.size)
			changed := proof
			changed.InputContents = map[string]string{test.id: text}
			changed.CPP.Inputs = map[string]string{test.id: bytesSHA256([]byte(text))}
			if err := replayInstrumentationCPP(input, pkg, nil, changed); err == nil || !strings.Contains(err.Error(), "bound") {
				t.Fatalf("CPP input escaped its byte bound: %v", err)
			}
		})
	}
	t.Run("complete CPP inventory keeps total bound", func(t *testing.T) {
		large := strings.Repeat(" ", 8<<20)
		largeSHA := bytesSHA256([]byte(large))
		changed := proof
		changed.InputContents = map[string]string{
			"module/" + file: source, "module/second.s": large, "module/third.s": large,
		}
		changed.CPP.Inputs = map[string]string{
			"module/" + file: digest, "module/second.s": largeSHA, "module/third.s": largeSHA,
		}
		if err := replayInstrumentationCPP(input, pkg, nil, changed); err == nil || !strings.Contains(err.Error(), "bound") {
			t.Fatalf("large-source allowance erased the complete CPP byte bound: %v", err)
		}
	})
}
