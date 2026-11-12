package plan9asm

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestARM64NativeScratchOriginActualGoCFG(t *testing.T) {
	fixtures := []struct {
		name, body string
		closed     bool
	}{
		{"full_x_definition", "MOVD $1,R27\nMOVD R27,R0", true},
		{"full_w_zero_extension", "MOVW $1,R27\nMOVD R27,R0", true},
		{"implicit_sb_scratch", "MOVBU ·cell(SB),R0", true},
		{"entry_read", "MOVD R27,R0", false},
		{"one_branch_lacks_definition", "CBZ R0,join\nMOVD $1,R27\njoin:\nMOVD R27,R1", false},
		{"both_branches_define", "CBZ R0,other\nMOVD $1,R27\nB join\nother:\nMOVD $2,R27\njoin:\nMOVD R27,R1", true},
		{"partial_movk", "MOVK $1,R27\nMOVD R27,R0", false},
		{"defined_movk", "MOVD $1,R27\nMOVK $2,R27\nMOVD R27,R0", true},
		{"call_kills_scratch_origin", "MOVD $1,R27\nCALL leaf(SB)\nMOVD R27,R0", false},
		{"redefine_after_call", "CALL leaf(SB)\nMOVD $1,R27\nMOVD R27,R0", true},
		{"dead_component_entry_read", "RET\nMOVD R27,R0", false},
		{"loop_with_dominating_definition", "MOVD $1,R27\nloop:\nADD $1,R27\nCBNZ R0,loop\nMOVD R27,R1", true},
		{"only_backedge_defines", "loop:\nMOVD R27,R1\nMOVD $1,R27\nCBNZ R0,loop", false},
		{"branch_enters_before_definition", "CBZ R0,read\nMOVD $1,R27\nread:\nMOVD R27,R1", false},
		{"unsupported_indirect_entry", "MOVD $1,R27\nJMP (R1)", false},
		{"unsupported_system_transfer", "SVC $0", false},
	}
	var source strings.Builder
	for _, fixture := range fixtures {
		fmt.Fprintf(&source, "TEXT %s(SB),516,$0-0\n%s\nRET\n", fixture.name, fixture.body)
	}
	source.WriteString("TEXT leaf(SB),516,$0-0\nRET\nDATA ·cell(SB)/8,$1\nGLOBL ·cell(SB),8,$8\n")
	directory := t.TempDir()
	input, object := filepath.Join(directory, "origin_arm64.s"), filepath.Join(directory, "original.o")
	if err := os.WriteFile(input, []byte(source.String()), 0600); err != nil {
		t.Fatal(err)
	}
	listing, err := arm64MemoryAuditGoCommand(t, "linux", "tool", "asm", "-S", "-p", "example.invalid/origin", "-o", object, input)
	if err != nil {
		t.Fatalf("unchanged original Go source: %v\n%s", err, listing)
	}
	disassembly, err := arm64MemoryAuditGoCommand(t, "linux", "tool", "objdump", object)
	if err != nil {
		t.Fatalf("actual native object decoder: %v\n%s", err, disassembly)
	}
	t.Logf("actual selected SDK assembly listing:\n%s\nfull native object/relocations:\n%s", listing, disassembly)
	bodies, err := arm64ScratchObjectBodies(disassembly)
	if err != nil {
		t.Fatal(err)
	}
	for _, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			body, present := bodies[fixture.name]
			if !present {
				t.Fatal("missing complete native object body")
			}
			if got := arm64ScratchNativeDoesNotAccess(body); got != fixture.closed {
				t.Fatalf("actual native scratch incoming-origin closure=%v, want %v", got, fixture.closed)
			}
		})
	}
}

func TestARM64NativeScratchSourceSnapshotDoesNotAliasData(t *testing.T) {
	file := &File{Arch: ArchARM64, Data: []DataStmt{{Sym: "·cell", Payload: []byte{1, 2, 3}}}}
	snapshot := arm64ScratchFileSnapshot(file)
	file.Data[0].Payload[1] = 9
	if snapshot.Data[0].Payload[1] != 2 {
		t.Fatal("a mutable public DATA payload changed the sealed original source")
	}
}

func TestARM64NativeScratchRelocationAndNativeCFGMutations(t *testing.T) {
	// Explicitly synthetic native byte/relocation mutations, not a claim that
	// stock Go emitted these malformed bodies. Actual original object producer
	// coverage above supplies the unchanged input/relocation reference.
	valid := arm64ScratchNativeBody{
		code:   []uint32{0x9000001b, 0x39400360, 0xd65f03c0},
		relocs: []arm64ScratchNativeRelocation{{0, 8, "R_ARM64_PCREL_LDST8", "pkg.cell", 0}},
	}
	if !arm64ScratchNativeDoesNotAccess(valid) {
		t.Fatal("complete native ADRP+LDRB origin control rejected")
	}
	for _, test := range []struct {
		name string
		edit func(*arm64ScratchNativeBody)
	}{
		{"unknown-relocation", func(body *arm64ScratchNativeBody) { body.relocs[0].kind = "R_UNKNOWN" }},
		{"wrong-relocation-width", func(body *arm64ScratchNativeBody) { body.relocs[0].width = 4 }},
		{"wrong-tuple-width", func(body *arm64ScratchNativeBody) { body.relocs[0].kind = "R_ARM64_PCREL_LDST64" }},
		{"overlapping-relocation", func(body *arm64ScratchNativeBody) { body.relocs = append(body.relocs, body.relocs[0]) }},
		{"wrong-address-base", func(body *arm64ScratchNativeBody) { body.code[1] = 0x39400340 }},
		{"call-without-relocation", func(body *arm64ScratchNativeBody) { body.code[0] = 0x94000000; body.relocs = nil }},
		{"call-target-addend", func(body *arm64ScratchNativeBody) {
			body.code = []uint32{0x94000000, 0xd65f03c0}
			body.calls = []string{"pkg.leaf"}
			body.relocs = []arm64ScratchNativeRelocation{{0, 4, "R_CALLARM64", "pkg.leaf", 4}}
		}},
		{"branch-outside-body", func(body *arm64ScratchNativeBody) { body.code[0] = 0x14000005 }},
		{"unknown-word", func(body *arm64ScratchNativeBody) { body.code[0] = 0xffffffff }},
		{"unknown-return-register", func(body *arm64ScratchNativeBody) { body.code[2] = 0xd65f0020 }},
		{"missing-real-return", func(body *arm64ScratchNativeBody) { body.code[2] = 0xd503201f }},
		{"work-budget", func(body *arm64ScratchNativeBody) {
			body.code = make([]uint32, 65537)
			for i := range body.code {
				body.code[i] = 0xd503201f
			}
			body.code[len(body.code)-1] = 0xd65f03c0
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := valid
			changed.code = append([]uint32(nil), valid.code...)
			changed.relocs = append([]arm64ScratchNativeRelocation(nil), valid.relocs...)
			test.edit(&changed)
			if arm64ScratchNativeDoesNotAccess(changed) {
				t.Fatal("malformed native component acquired an incoming-scratch summary")
			}
		})
	}
}
