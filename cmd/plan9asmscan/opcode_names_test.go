package main

import (
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
)

func TestOfficialOpcodeNamesExcludeNonOpcodeArraysOnEveryArchitecture(t *testing.T) {
	for _, goarch := range []string{"386", "amd64", "arm", "arm64", "wasm"} {
		t.Run(goarch, func(t *testing.T) {
			goroot := t.TempDir()
			dir := goarch
			if goarch == "386" || goarch == "amd64" {
				dir = "x86"
			}
			base := filepath.Join(goroot, "src", "cmd", "internal", "obj", dir)
			writeEncoderFixture(t, filepath.Join(base, "anames.go"), `package arch
var Anames = []string{
	"ADD",
	"MOVD",
	"LAST",
	"ReservedFD01",
}
var fakeAnames = []string{"NOTANOPCODE"}
const unrelated = "NOTANOPCODEEITHER"
`)
			writeEncoderFixture(t, filepath.Join(base, "anames_classes.go"), `package arch
var cnames = []string{
	"REG",
	"ADDR",
	"TEXTSIZE",
}
var OtherAnames = []string{
	"NOTANOPCODETHREE",
}
`)
			writeEncoderFixture(t, filepath.Join(base, "anames_gen.go"), `package arch
var sveAnames = []string{
	"ZADD",
}
func init() { Anames = append(Anames, sveAnames...) }
`)
			want := []string{"ADD", "MOVD"}
			if goarch == "arm64" {
				want = append(want, "ZADD")
			}
			arch, err := toPlan9Arch(goarch)
			if err != nil {
				t.Fatal(err)
			}
			catalog, err := buildOpcodeCatalog(goroot, arch, goarch, nil, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, item := range catalog {
				got = append(got, item.Opcode)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("official opcode names = %v, want only the registered opcode arrays %v", got, want)
			}
		})
	}
}

func TestOfficialOpcodeNamesRequireRegisteredARM64Supplement(t *testing.T) {
	goroot := t.TempDir()
	base := filepath.Join(goroot, "src", "cmd", "internal", "obj", "arm64")
	writeEncoderFixture(t, filepath.Join(base, "anames.go"), "package arm64\nvar Anames = []string{\"ADD\"}\n")
	writeEncoderFixture(t, filepath.Join(base, "anames_gen.go"), "package arm64\nvar sveAnames = []string{\"NOTREGISTERED\"}\n")
	arch, err := toPlan9Arch("arm64")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := buildOpcodeCatalog(goroot, arch, "arm64", nil, nil, nil); err == nil {
		t.Fatal("an unregistered SVE array was accepted as an official opcode namespace")
	}
}

func TestOfficialOpcodeNamesFailClosedForMalformedNamespace(t *testing.T) {
	for _, source := range []string{
		"package arm\nvar cnames = []string{\"REG\"}\n",
		"package arm\nvar Anames = []int{1}\n",
		"package arm\nvar Anames = []string{unknown}\n",
		"package arm\nvar Anames = []string{\"ADD\"}\nvar Anames = []string{\"SUB\"}\n",
		"package arm\nvar Anames = []string{\n",
	} {
		t.Run(source, func(t *testing.T) {
			goroot := t.TempDir()
			writeEncoderFixture(t, filepath.Join(goroot, "src", "cmd", "internal", "obj", "arm", "anames.go"), source)
			arch, err := toPlan9Arch("arm")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := buildOpcodeCatalog(goroot, arch, "arm", nil, nil, nil); err == nil {
				t.Fatal("malformed or absent official opcode namespace was accepted")
			}
		})
	}
}

func TestOfficialOpcodeNamesMatchAuditedGoSourceNamespaces(t *testing.T) {
	for _, goarch := range namespaceArchitectures {
		t.Run(goarch, func(t *testing.T) {
			want := actualGoNamespaceCounts(t, goarch).official
			arch, err := toPlan9Arch(goarch)
			if err != nil {
				t.Fatal(err)
			}
			catalog, err := buildOpcodeCatalog(runtime.GOROOT(), arch, goarch, nil, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			if len(catalog) != want {
				t.Fatalf("%s %s opcode namespace = %d, want audited Anames entries %d", runtime.Version(), goarch, len(catalog), want)
			}
			for _, item := range catalog {
				if item.Opcode == "REG" || item.Opcode == "ADDR" || item.Opcode == "TEXTSIZE" || item.Opcode == "NCLASS" {
					t.Fatalf("operand class %q entered the official opcode namespace", item.Opcode)
				}
			}
		})
	}
}

func TestOfficialOpcodeNamesAcceptKeyedAndEscapedStringEntries(t *testing.T) {
	goroot := t.TempDir()
	path := filepath.Join(goroot, "src", "cmd", "internal", "obj", "x86", "anames.go")
	writeEncoderFixture(t, path, "package x86\nvar Anames = []string{obj.A_ARCHSPECIFIC: \"A\\x44D\", \"SUB\", \"ADD\"}\n")
	arch, err := toPlan9Arch("amd64")
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := buildOpcodeCatalog(goroot, arch, "amd64", nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(catalog) != 2 || catalog[0].Opcode != "ADD" || catalog[1].Opcode != "SUB" {
		t.Fatalf("literal AST opcode entries = %+v, want ADD and SUB once each", catalog)
	}
}
