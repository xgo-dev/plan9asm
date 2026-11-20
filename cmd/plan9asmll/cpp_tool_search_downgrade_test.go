package main

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

func TestFeatureCPPOutsidePackageSearchCannotDowngradeToLegacyToolPrefix(t *testing.T) {
	input, dir := generatedHeaderFixture(t, "linux/amd64")
	file := input.AsmFiles[0]
	source := "#include \"../../pkg/include/textflag.h\"\nTEXT ·Probe(SB),NOSPLIT,$0-0\nRET\n"
	if err := os.WriteFile(filepath.Join(dir, file), []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	input.Sources[file], input.Headers[file] = featureBytesSHA256([]byte(source)), source
	tool := "pkg/include/textflag.h"
	data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), tool))
	if err != nil {
		t.Fatal(err)
	}
	input.ToolSources = map[string]string{tool: featureBytesSHA256(data)}
	canonicalDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	consumer := &featureConsumer{Input: input, Context: ctx, Dir: canonicalDir, Root: runtime.GOROOT()}
	if _, _, err := consumer.preprocessCPP(filepath.Join(canonicalDir, file), input.Module, nil); err == nil {
		t.Fatal("missing outside-package absence was accepted because the tool retained a legacy prefix")
	}
	miss := gotoolprofile.CPPPackageSearchMiss{
		Protocol: gotoolprofile.CPPPackageSearchMissProtocol, Assembly: file, Source: "module/" + file,
		Include: "../../pkg/include/textflag.h", PackageCandidate: "../../pkg/include/textflag.h", ToolSource: tool,
	}
	input.CPPIncludeSearchMisses = []gotoolprofile.CPPPackageSearchMiss{miss}
	if _, _, err := consumer.preprocessCPP(filepath.Join(canonicalDir, file), input.Module, nil); err != nil {
		t.Fatalf("exact original pkg/include fallback contract was rejected: %v", err)
	}
	unused := "#include \"../../pkg/include/textflag.h\"\n"
	if err := os.WriteFile(filepath.Join(dir, "unused.h"), []byte(unused), 0600); err != nil {
		t.Fatal(err)
	}
	input.Sources["unused.h"] = featureBytesSHA256([]byte(unused))
	input.CPPIncludeSearchMisses[0].Source = "module/unused.h"
	if _, _, err := consumer.preprocessCPP(filepath.Join(canonicalDir, file), input.Module, nil); err == nil {
		t.Fatal("matching literal in an unconsumed source substituted for the actual include parent")
	}
}

func TestFeatureCPPUnboundOriginIsRejectedBeforeReading(t *testing.T) {
	input, dir := generatedHeaderFixture(t, "linux/amd64")
	file := input.AsmFiles[0]
	source := "#include \"unbound.h\"\nTEXT ·Probe(SB),$0-0\nRET\n"
	if err := os.WriteFile(filepath.Join(dir, file), []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	input.Sources[file] = featureBytesSHA256([]byte(source))
	// Opening a directory succeeds, but reading its data fails. The error must
	// instead originate from the missing source identity before that read.
	if err := os.Mkdir(filepath.Join(dir, "unbound.h"), 0700); err != nil {
		t.Fatal(err)
	}
	canonicalDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	consumer := &featureConsumer{Input: input, Dir: canonicalDir, Root: runtime.GOROOT()}
	_, _, err = consumer.preprocessCPP(filepath.Join(canonicalDir, file), input.Module, nil)
	if err == nil || !strings.Contains(err.Error(), "provenance") || strings.Contains(err.Error(), "read contract") {
		t.Fatalf("unbound source was not rejected before opening/reading it: %v", err)
	}
}
