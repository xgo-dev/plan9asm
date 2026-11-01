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

func TestGoSDKAssemblyActualTruncatedMemberNames(t *testing.T) {
	directory, compiler, _ := fixture(t)
	oracle := officialReaderForSource(t, compiler, sdkNamespaceReaderSource)
	consumer := filepath.Join(directory, "longmember")
	if err := os.Mkdir(consumer, 0700); err != nil {
		t.Fatal(err)
	}
	name := "long_original_assembly_member.s"
	unicodeName := "zzzzzzzzzzzzzzz界.s"
	goSource := "package longmember\nfunc Entry()\nfunc Unicode()\n"
	assembly := "#include \"textflag.h\"\nTEXT ·Entry(SB),NOSPLIT,$0-0\nRET\n"
	unicodeAssembly := "#include \"textflag.h\"\nTEXT ·Unicode(SB),NOSPLIT,$0-0\nRET\n"
	for file, data := range map[string]string{"value.go": goSource, name: assembly, unicodeName: unicodeAssembly} {
		if err := os.WriteFile(filepath.Join(consumer, file), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	builtin, err := os.ReadFile(filepath.Join(filepath.Dir(filepath.Dir(compiler)), "src", "cmd", "internal", "goobj", "builtinlist.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			target := "linux/" + arch
			env := fixtureEnv(t, target)
			raw := run(t, compiler, consumer, env, "list", "-json", "-compiled", "-export", "-mod=readonly",
				"-gcflags=-std", "-asmflags=-std", ".")
			var selected struct {
				Export   string
				SFiles   []string
				Standard bool
			}
			if err := json.Unmarshal(raw, &selected); err != nil || selected.Standard ||
				!reflect.DeepEqual(selected.SFiles, []string{name, unicodeName}) {
				t.Fatal("actual first-party source role differs", err)
			}
			archive, err := os.ReadFile(selected.Export)
			if err != nil {
				t.Fatal(err)
			}
			originalRaw := run(t, oracle, consumer, env, selected.Export)
			var original []namespaceOracleMember
			if err := json.Unmarshal(originalRaw, &original); err != nil || len(original) != 4 {
				t.Fatal("official original archive inventory differs", err)
			}
			for ordinal, source := range selected.SFiles {
				wanted := (strings.TrimSuffix(source, ".s") + ".o")[:16]
				if !bytes.Equal(original[ordinal+2].NameBytes, []byte(wanted)) || original[ordinal+2].Flags != 20 {
					t.Fatal("official original byte-truncated member/flags differ", original[ordinal+2])
				}
			}
			retainTextArtifact(t, target, "indexed-long-member", map[string][]byte{
				"original.a": archive, "namespace-sdk.json": originalRaw, "selection.json": raw,
				"source-value.go": []byte(goSource), "source-assembly.s": []byte(assembly), "source-unicode.s": []byte(unicodeAssembly),
			})
			observed, err := ObserveX86SDKAssemblyArchive(archive, builtin, target, selected.SFiles)
			if err != nil || len(observed) != 4 {
				t.Fatal("exact actual SDK-format long source/member route was rejected", err)
			}
			for ordinal, source := range selected.SFiles {
				wanted := (strings.TrimSuffix(source, ".s") + ".o")[:16]
				member := observed[ordinal+2]
				if member.Name != wanted || member.Offset != original[ordinal+2].Offset || member.Size != original[ordinal+2].Size ||
					len(member.Texts) != 1 || member.Texts[0].ABI != 0 || len(member.Texts[0].Code) == 0 {
					t.Fatal("original ordinal/whole-body member identity differs", member)
				}
			}
			for _, files := range [][]string{
				{name}, {name, name}, {unicodeName, name}, {name, "long_original_assembly_foreign.s"},
				{name, "unknown.s"},
			} {
				if _, err := ObserveX86SDKAssemblyArchive(archive, builtin, target, files); !errors.Is(err, ErrContext) {
					t.Fatal("missing/duplicate/reordered/colliding/unknown source chose a long member", files, err)
				}
			}
		})
	}
}

func TestGoSDKAssemblyCompleteMemberNameInventory(t *testing.T) {
	for _, sources := range [][]string{
		{"long_original_assembly_member.s", "long_original_assembly_other.s"},
		{"same.s", "same.s"}, {"../foreign.s"}, {"foreign\\path.s"}, {"not-assembly.go"}, {"_go_.s"},
	} {
		if _, err := sdkAssemblyMemberNames(sources); !errors.Is(err, ErrContext) {
			t.Fatal("ambiguous/noncanonical SDK selected-source inventory acquired a member route", sources, err)
		}
	}
	wanted := []string{"short.o", "zzzzzzzzzzzzzzz\xe7"}
	actual, err := sdkAssemblyMemberNames([]string{"short.s", "zzzzzzzzzzzzzzz界.s"})
	if err != nil || !reflect.DeepEqual(actual, wanted) {
		t.Fatal("SDK packInternal byte width became a rune/prefix match", actual, err)
	}
}
