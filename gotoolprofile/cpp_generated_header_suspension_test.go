package gotoolprofile

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestCPPOriginalActiveGeneratedHeaderHasTypedRequirement(t *testing.T) {
	for _, test := range []struct {
		name   string
		source string
		active bool
	}{
		{"active", "#include \"go_asm.h\"\nTEXT ·Probe(SB),4,$0-0\nRET\n", true},
		{"macro_generated", "#define INCLUDE(file) \\\n#include file \\\n\nINCLUDE(\"go_asm.h\")\nTEXT ·Probe(SB),4,$0-0\nRET\n", true},
		{"inactive", "#ifdef absent\n#include \"go_asm.h\"\n#endif\nTEXT ·Probe(SB),4,$0-0\nRET\n", false},
		{"candidate_only", "TEXT ·Probe(SB),4,$0-0\nRET\nDATA ·name(SB)/8,$\"go_asm.h\"\n", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := generatedHeaderSuspensionInput(test.source)
			_, _, _, err := ReplayCPPOriginal(input, "probe.s", "example.invalid/header", nil, nil)
			var requirement interface {
				CPPGeneratedHeaderRequirement() (assembly, operand string)
			}
			if !test.active {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), "active CPP operand has no independently registered original: go_asm.h") {
				t.Fatalf("missing real active-include failure: %v", err)
			}
			if !errors.As(err, &requirement) {
				t.Fatalf("actual active generated-header callback lacks a typed requirement: %v", err)
			}
			assembly, operand := requirement.CPPGeneratedHeaderRequirement()
			if assembly != "probe.s" || operand != "go_asm.h" {
				t.Fatalf("typed requirement lost actual assembly/operand: %q %q", assembly, operand)
			}
			if !CPPOriginalNeedsGeneratedHeader(err, "probe.s") || CPPOriginalNeedsGeneratedHeader(err, "other.s") ||
				CPPOriginalNeedsGeneratedHeader(errors.Join(err, fmt.Errorf("independent source guard failure")), "probe.s") {
				t.Fatal("generated-header suspension accepted a foreign or combined error")
			}
			_, _, _, err = ReplayCPPOriginal(input, "probe.s", "example.invalid/header", nil, []byte("#define Record__size 8\n"))
			if err != nil {
				t.Fatalf("actual supplied native-header control: %v", err)
			}
		})
	}
}

func TestCPPOriginalUnregisteredOperandIsNotGeneratedHeaderRequirement(t *testing.T) {
	for _, source := range []string{
		"#include \"unknown.h\"\n",
		"#include FILE\n",
		"#unknown control\n",
	} {
		input := generatedHeaderSuspensionInput(source)
		_, _, _, err := ReplayCPPOriginal(input, "probe.s", "example.invalid/header", nil, nil)
		var requirement interface {
			CPPGeneratedHeaderRequirement() (assembly, operand string)
		}
		if err == nil || errors.As(err, &requirement) {
			t.Fatalf("unrelated original CPP error acquired header suspension: %v", err)
		}
		if CPPOriginalNeedsGeneratedHeader(err, "probe.s") {
			t.Fatal("unregistered operand entered actual-header planning")
		}
	}
}

func generatedHeaderSuspensionInput(source string) *ConsumerInput {
	return &ConsumerInput{
		CPPSourceProtocol: CPPOriginalReplayProtocol,
		AsmFiles:          []string{"probe.s"},
		Sources:           map[string]string{"probe.s": bytesSHA256([]byte(source))},
		ToolSources:       map[string]string{},
		CPPOriginals: &CPPOriginalReplayInput{
			Sources: map[string]string{"module/probe.s": source},
			Units: map[string]CPPOriginalUnit{
				"probe.s": {Includes: map[string]string{}, GeneratedHeaders: []string{"go_asm.h"}},
			},
			RequiredExpandedOperands: map[string][]CPPPackageSearchMiss{},
		},
	}
}
