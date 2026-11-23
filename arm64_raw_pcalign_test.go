package plan9asm

import (
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
)

const arm64RawAlignmentMarker = 0xaa0003e0 // MOVD R0,R0

func arm64RawAlignedBranchSource(name, textFlags, prefix, directive string, displacement int64) string {
	word := 0xb4000000 | (uint32(displacement/4)&0x7ffff)<<5 // CBZ X0
	return fmt.Sprintf(`TEXT %s(SB),%s,$0-16
%sMOVD data+0(FP),R8
MOVD 0(R8),R0
MOVD 8(R8),R1
WORD $%#08x
MOVD R1,R0
%s
branchTarget:
WORD $%#08x
MOVD R0,ret+8(FP)
RET
`, name, textFlags, prefix, word, directive, arm64RawAlignmentMarker)
}

func TestARM64RawPCAlignmentBindsGoObjectTarget(t *testing.T) {
	for alignment := int64(8); alignment <= 2048; alignment *= 2 {
		directive := fmt.Sprintf("PCALIGN $%d", alignment)
		t.Run(directive, func(t *testing.T) {
			target := (20 + alignment - 1) &^ (alignment - 1)
			checkARM64RawPCAlignment(t, directive, target)
		})
	}
	t.Run("known_anchor", func(t *testing.T) {
		source := arm64RawAlignedBranchSource("aligned", "4", "PCALIGN $64\n", "PCALIGN $32", 20)
		checkARM64RawAlignedGoTarget(t, source, 32)
	})
	t.Run("short_named_branch", func(t *testing.T) {
		source := arm64RawAlignedBranchSource("aligned", "516", "", "PCALIGN $32", 20)
		source = strings.Replace(source, "PCALIGN $32\n", "BEQ branchTarget\nPCALIGN $32\n", 1)
		checkARM64RawAlignedGoTarget(t, source, 32)
	})
}

func TestARM64RawPCAlignmentRetainsUnknownLayoutBoundaries(t *testing.T) {
	// An unresolved instruction width can conceal a literal pool or make
	// the distance of an adjacent conditional branch unprovable.
	for _, test := range []struct {
		name, change string
	}{
		{"literal materialization", "MOVD $0x123456789abcdef0,R10\n"},
		{"unbounded named branch", "BEQ branchTarget\nMOVD $0x123456789abcdef0,R10\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			source := arm64RawAlignedBranchSource("aligned", "516", "", "PCALIGN $32", 20)
			source = strings.Replace(source, "PCALIGN $32\n", test.change+"PCALIGN $32\n", 1)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := normalizeARM64RawPCRelative(file.Funcs[0]); err == nil || !strings.Contains(err.Error(), "proven instruction boundary") {
				t.Fatalf("unproved source layout acquired a branch destination: %v", err)
			}
		})
	}
}

func checkARM64RawPCAlignment(t *testing.T, directive string, target int64) {
	t.Helper()
	const branchPC = 12
	source := arm64RawAlignedBranchSource("aligned", "516", "", directive, target-branchPC)
	checkARM64RawAlignedGoTarget(t, source, target)
}

func checkARM64RawAlignedGoTarget(t *testing.T, source string, target int64) {
	t.Helper()
	native := assembleARM64StructureTestBytes(t, source)
	if len(native) < int(target)+4 {
		t.Fatalf("Go object too short for offset %d: %d bytes", target, len(native))
	}
	if word := binary.LittleEndian.Uint32(native[target:]); word != arm64RawAlignmentMarker {
		t.Fatalf("Go offset %d has word %#08x, want branch target %#08x", target, word, arm64RawAlignmentMarker)
	}
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	fn, err := normalizeARM64RawPCRelative(file.Funcs[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, ins := range fn.Instrs {
		if ins.Op == "CBZ" && len(ins.Args) == 2 && ins.Args[1].Ident == "branchTarget" {
			return
		}
	}
	t.Fatal("normalized branch missed the exact Go target")
}
