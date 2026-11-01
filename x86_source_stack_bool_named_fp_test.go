package plan9asm

import (
	"errors"
	"strings"
	"testing"
)

func TestX86PhysicalSourceStackBoolNamedFPStillNeedsCanonicalProof(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		word := int64(8)
		if target.arch == "386" {
			word = 4
		}
		for _, test := range []struct {
			name, body string
			accepted   bool
		}{
			{"identity", "MOVB x+0(FP),AX\nMOVB AX,ret+@WORD(FP)\nBYTE $0xc3", true},
			{"one", "MOVB $1,ret+@WORD(FP)\nBYTE $0xc3", true},
			{"intermediate", "MOVB $2,ret+@WORD(FP)\nMOVB ret+@WORD(FP),AX\nSHRB $1,AX\nANDB $1,AX\nMOVB AX,ret+@WORD(FP)\nBYTE $0xc3", true},
			{"two", "MOVB $2,ret+@WORD(FP)\nBYTE $0xc3", false},
			{"three", "MOVB $3,ret+@WORD(FP)\nBYTE $0xc3", false},
			{"unknown", "MOVB BX,ret+@WORD(FP)\nBYTE $0xc3", false},
			{"unwritten", "MOVB x+0(FP),AX\nBYTE $0xc3", false},
		} {
			source, sig, pkg := x86SourceStackTypedFixture(target.arch, "bool", I1, word, "MOVB", test.body)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(target.triple+"/"+test.name+"/"+api, func(t *testing.T) {
					err := x86PhysicalBoolTranslate(t, target.arch, target.triple, api, source, sig, pkg)
					if test.accepted && err != nil || !test.accepted && !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatalf("named FP/raw RET accepted=%t: %v", test.accepted, err)
					}
				})
			}
		}
	}
}

func TestX86PhysicalSourceStackBoolDefaultModeUsesPublicAMD64Role(t *testing.T) {
	for _, test := range []struct {
		body     string
		accepted bool
	}{
		{"MOVB x+0(FP),AX\nMOVB AX,ret+@WORD(FP)\nBYTE $0xc3", true},
		{"MOVB @WORD(SP),AX\nMOVB AX,@RESULT(SP)\nBYTE $0xc3", true},
		{"MOVB $2,ret+@WORD(FP)\nBYTE $0xc3", false},
		{"MOVB $2,@RESULT(SP)\nBYTE $0xc3", false},
		{"MOVB $2,ret+@WORD(FP)\nMOVB ret+@WORD(FP),AX\nSHRB $1,AX\nANDB $1,AX\nMOVB AX,ret+@WORD(FP)\nBYTE $0xc3", true},
	} {
		source, sig, pkg := x86SourceStackTypedFixture("amd64", "bool", I1, 8, "MOVB", test.body)
		for _, api := range []string{"text", "module"} {
			t.Run(api+"/"+test.body, func(t *testing.T) {
				err := x86PhysicalBoolTranslate(t, "", "x86_64-unknown-linux-gnu", api, source, sig, pkg)
				if test.accepted && err != nil || !test.accepted && !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("default-mode accepted=%t: %v", test.accepted, err)
				}
			})
		}
	}
	t.Run("Go still requires explicit architecture", func(t *testing.T) {
		source, sig, pkg := x86SourceStackTypedFixture("amd64", "bool", I1, 8, "MOVB", "MOVB $1,ret+@WORD(FP)\nBYTE $0xc3")
		if err := x86PhysicalBoolTranslate(t, "", "x86_64-unknown-linux-gnu", "Go", source, sig, pkg); err == nil || !strings.Contains(err.Error(), "empty GOARCH") {
			t.Fatal("Go API lost its independent explicit architecture requirement", err)
		}
	})
}
