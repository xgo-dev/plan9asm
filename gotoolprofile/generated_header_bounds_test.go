package gotoolprofile

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestGeneratedHeaderDefinitionsUseBytesNotDeclarationCount(t *testing.T) {
	definitions := largeGeneratedDefinitions(5000)
	var source strings.Builder
	for index := 0; index < 5000; index++ {
		fmt.Fprintf(&source, "#define const_Value%d %d\n", index, index)
	}
	actual, err := HeaderDefinitions([]byte(source.String()))
	if err != nil || !reflect.DeepEqual(actual, definitions) {
		t.Fatalf("complete bounded header was rejected or truncated: %v", err)
	}
	canonical, err := CanonicalGeneratedHeader(actual)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := HeaderDefinitions(canonical)
	if err != nil || !reflect.DeepEqual(parsed, definitions) {
		t.Fatalf("canonical header lost a late definition: %v", err)
	}
	encoded, err := json.Marshal(definitions)
	if err != nil {
		t.Fatal(err)
	}
	var replay map[string]string
	if err := json.Unmarshal(encoded, &replay); err != nil {
		t.Fatal(err)
	}
	if HeaderDefinitionSHA256(replay) != HeaderDefinitionSHA256(definitions) {
		t.Fatal("complete definition digest did not survive JSON replay")
	}
	for _, changed := range []map[string]string{largeGeneratedDefinitions(4999), largeGeneratedDefinitions(5001)} {
		if HeaderDefinitionSHA256(changed) == HeaderDefinitionSHA256(definitions) {
			t.Fatal("late definition presence was ignored")
		}
	}
	replay["const_Value4999"] = "changed"
	if HeaderDefinitionSHA256(replay) == HeaderDefinitionSHA256(definitions) {
		t.Fatal("late definition value was ignored")
	}
	for _, value := range []string{"4999", "different"} {
		duplicate := source.String() + "#define const_Value4999 " + value + "\n"
		if _, err := HeaderDefinitions([]byte(duplicate)); err == nil {
			t.Fatal("a duplicate beyond the former count bound was accepted")
		}
	}
}

func largeGeneratedDefinitions(count int) map[string]string {
	definitions := make(map[string]string, count)
	for index := 0; index < count; index++ {
		definitions[fmt.Sprintf("const_Value%d", index)] = fmt.Sprint(index)
	}
	return definitions
}

func TestGeneratedHeaderByteBoundsRejectBeforeCanonicalAllocation(t *testing.T) {
	if _, err := HeaderDefinitions(make([]byte, 64<<20+1)); err == nil {
		t.Fatal("oversized textual input was accepted")
	}
	// Individually bounded values can still exceed the shared full output
	// budget. Share the test value instead of allocating a giant output.
	value := strings.Repeat("1", 32<<20)
	definitions := map[string]string{"First": value, "Second": value}
	if _, err := generatedHeaderDefinitionsSize(definitions); err == nil {
		t.Fatal("aggregate canonical byte budget was ignored")
	}
	if _, err := CanonicalGeneratedHeader(definitions); err == nil {
		t.Fatal("oversized portable definitions became canonical source")
	}
	// The reader must apply the same budget before serializing an attacker-
	// supplied portable map for its digest. This negative reaches that check
	// before any successful module/tool provenance could be established.
	observation := &Observation{Target: "linux/amd64", GoVersion: "go1.27.1"}
	proof := GeneratedHeaderProof{
		Protocol: GeneratedHeaderProtocol, PackagePath: "example.invalid/header",
		Target: observation.Target, GoVersion: observation.GoVersion,
		HeaderSHA256: strings.Repeat("a", 64), ObjectSHA256: strings.Repeat("b", 64),
		Definitions: definitions,
	}
	err := validateGeneratedHeaderContext(&ConsumerInput{}, proof, PackageProof{PackagePath: proof.PackagePath},
		generatedHeaderValidationContext{
			protocol: GeneratedHeaderProtocol, observed: observation,
			validateMacros: func() error { return nil },
		})
	if err == nil || !strings.Contains(err.Error(), "canonical byte bound") {
		t.Fatalf("reader did not bound portable definitions before hashing: %v", err)
	}
	for name, value := range map[string]string{
		"newlines": "1\n#define Injected 2", "carriage return": "1\r2", "NUL": "1\x002",
		"empty": "", "leading space": " 1", "trailing space": "1 ", "continuation": "1\\",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := generatedHeaderDefinitionsSize(map[string]string{"Name": value}); err == nil {
				t.Fatal("invalid definition survived canonical budget validation")
			}
		})
	}
}

func TestGeneratedHeaderActualCompilerFullGrammarBeyond4096(t *testing.T) {
	// cmd/compile/internal/gc.dumpasmhdr emits object-like constants and
	// complete struct sizes/field offsets, not float/complex or blank names.
	var source strings.Builder
	source.WriteString(`package header
const Text = "x y\n\t世界"
const Truth = true
const Rune = '世'
const Signed = -7
const Huge = 123456789012345678901234567890
const Fraction = 1.25
const Complex = 1 + 2i
const _ = 1
type Layout struct { First byte; _ [3]byte; Word uintptr; Last uint64 }
type Alias = Layout
type NonStruct int
`)
	for index := 0; index < 5000; index++ {
		fmt.Fprintf(&source, "const Value%d = %d\n", index, index)
	}
	directory := t.TempDir()
	goFile := filepath.Join(directory, "layout.go")
	if err := os.WriteFile(goFile, []byte(source.String()), 0600); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"linux/386", "linux/amd64", "linux/arm", "linux/arm64", "js/wasm"} {
		t.Run(target, func(t *testing.T) {
			parts := strings.Split(target, "/")
			header := filepath.Join(t.TempDir(), "go_asm.h")
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			env := replaceEnv(os.Environ(), map[string]string{"GOOS": parts[0], "GOARCH": parts[1], "CGO_ENABLED": "0"})
			_, _, err := RunBounded(ctx, directory, env, "go", "tool", "compile",
				"-p", "example.invalid/header", "-asmhdr", header, "-o", filepath.Join(t.TempDir(), "go.o"), goFile)
			if err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(header)
			if err != nil {
				t.Fatal(err)
			}
			actual, err := HeaderDefinitions(data)
			if err != nil {
				t.Fatalf("actual %s compiler header (%d bytes): %v", target, len(data), err)
			}
			wanted := largeGeneratedDefinitions(5000)
			wanted["const_Text"] = `"x y\n\t世界"`
			wanted["const_Truth"], wanted["const_Rune"] = "true", "19990"
			wanted["const_Signed"], wanted["const_Huge"] = "-7", "123456789012345678901234567890"
			size, word, last := "24", "8", "16"
			if parts[1] == "386" || parts[1] == "arm" {
				size, word, last = "16", "4", "8"
			}
			for _, name := range []string{"Layout", "Alias"} {
				wanted[name+"__size"], wanted[name+"_First"] = size, "0"
				wanted[name+"_Word"], wanted[name+"_Last"] = word, last
			}
			if !reflect.DeepEqual(actual, wanted) {
				t.Fatalf("actual compiler definitions changed full values/presence: got %d, want %d", len(actual), len(wanted))
			}
			canonical, err := CanonicalGeneratedHeader(actual)
			if err != nil {
				t.Fatal(err)
			}
			replay, err := HeaderDefinitions(canonical)
			if err != nil || !reflect.DeepEqual(replay, wanted) {
				t.Fatalf("actual compiler grammar failed canonical replay: %v", err)
			}
		})
	}
}
