package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
	"github.com/xgo-dev/plan9asm/internal/sourcepath"
)

func TestFeatureCPPToolRootAliasRetainsExactSource(t *testing.T) {
	module, err := sourcepath.Resolve(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root, err := sourcepath.Resolve(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "sdk")
	if err := os.Symlink(root, alias); err != nil {
		t.Fatal(err)
	}
	header := "pkg/include/value.h"
	filename := filepath.Join(root, filepath.FromSlash(header))
	if err := os.MkdirAll(filepath.Dir(filename), 0700); err != nil {
		t.Fatal(err)
	}
	contents := "#define VALUE 41\n"
	if err := os.WriteFile(filename, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	source := "#include \"value.h\"\nTEXT ·Value(SB),$0-0\nMOVQ $VALUE, AX\nRET\n"
	asm := filepath.Join(module, "value.s")
	if err := os.WriteFile(asm, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	input := &gotoolprofile.ConsumerInput{
		Module: "example.invalid/alias", Sources: map[string]string{"value.s": featureBytesSHA256([]byte(source))},
		ToolSources: map[string]string{header: featureBytesSHA256([]byte(contents))},
	}
	consumer := &featureConsumer{Input: input, Dir: module, Root: alias}
	for _, spelling := range []string{root, alias} {
		consumer.Root = spelling
		expanded, inputs, err := consumer.preprocessCPP(asm, input.Module, nil)
		if err != nil || !strings.Contains(string(expanded), "$41") || inputs["tool/"+header] != input.ToolSources[header] {
			t.Fatalf("original tool bytes through root alias: %s %v: %v", expanded, inputs, err)
		}
	}
	delete(input.ToolSources, header)
	if _, _, err := consumer.preprocessCPP(asm, input.Module, nil); err == nil {
		t.Fatal("unregistered tool header was accepted")
	}
	input.ToolSources[header] = featureBytesSHA256([]byte(contents))
	if err := os.WriteFile(filename, []byte("#define VALUE 99\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := consumer.preprocessCPP(asm, input.Module, nil); err == nil {
		t.Fatal("changed tool header was accepted")
	}
	outside := filepath.Join(t.TempDir(), "value.h")
	if err := os.WriteFile(outside, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filename); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filename); err != nil {
		t.Fatal(err)
	}
	if _, _, err := consumer.preprocessCPP(asm, input.Module, nil); err == nil {
		t.Fatal("identical bytes redirected outside the tool root were accepted")
	}
}
