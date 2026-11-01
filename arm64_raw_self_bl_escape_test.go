package plan9asm

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestARM64RawSelfBLGoAcceptedEscapeSources(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		for _, mutation := range arm64RawSelfBLGuardMutations() {
			if mutation.name != "escaping_loop" && mutation.name != "prefix_escape" {
				continue
			}
			t.Run(goos+"/"+mutation.name, func(t *testing.T) {
				base := arm64RawSelfBLFixture()
				source := strings.Replace(base, mutation.old, mutation.replacement, 1)
				if source == base {
					t.Fatal("escape mutation no longer modifies the original fixture")
				}
				original := arm64ImmediateOriginalGoBytes(t, source, goos)
				raw := "WORD $0x94000000"
				if mutation.name == "escaping_loop" {
					raw = "WORD $0x97fffffe"
				}
				named := strings.Replace(source, raw, "BL spin", 1)
				if named == source {
					t.Fatal("escape fixture is missing its independently checked raw branch")
				}
				// Compare the entire native TEXT bytes, including the Go
				// expansion of both MOVDs. No pseudo width or BL PC is guessed.
				want := arm64ImmediateOriginalGoBytes(t, named, goos)
				if len(original) == 0 || !bytes.Equal(original, want) {
					t.Fatalf("raw escape fixture differs from actual Go BL spin: got %x, want %x", original, want)
				}
				if mutation.name == "escaping_loop" {
					wrongPC := strings.Replace(source, raw, "WORD $0x97ffffff", 1)
					if bytes.Equal(arm64ImmediateOriginalGoBytes(t, wrongPC, goos), want) {
						t.Fatal("byte oracle failed to distinguish the old one-instruction branch displacement")
					}
				}
				t.Logf("actual Go %s TEXT bytes: %x", goos, original)
				sig := arm64RawZeroFrameSig()
				sig.Name = "terminal"
				c := arm64RawContextLowerer(t, source, sig)
				c.unexposedCallFrame = true
				if c.rawZeroContextControlPlan("outer") != nil {
					t.Fatal("Go-accepted SP-address escape acquired a terminal-sink control certificate")
				}
			})
		}
	}
}

func TestARM64RawSelfBLDirectSPStoreIsNotEscapeOracle(t *testing.T) {
	// Preserve the old source failure: direct SP-to-memory is not a legal
	// Go MOVD form and cannot serve as a meaningful whole-source negative.
	source := strings.Replace(arm64RawSelfBLFixture(), "spin:\nWORD $0x94000000",
		"spin:\nMOVD RSP,(R1)\nWORD $0x97ffffff", 1)
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "invalid.s")
			if err := os.WriteFile(path, []byte(source), 0600); err != nil {
				t.Fatal(err)
			}
			output, err := arm64MemoryAuditGoCommand(t, goos, "tool", "asm", "-o", filepath.Join(dir, "invalid.o"), path)
			if err == nil || !strings.Contains(string(output), "MOVD") || !strings.Contains(string(output), "RSP") {
				t.Fatalf("old direct-SP source lost its actual Go rejection: %v\n%s", err, output)
			}
			t.Logf("actual Go source rejection: %s", strings.TrimSpace(string(output)))
		})
	}
}
