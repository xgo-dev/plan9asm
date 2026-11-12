package plan9asm

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestARM64PrivateSourceAPINilAndOtherArchitectures(t *testing.T) {
	if file, err := CoalesceARM64PrivateRegisterHelpers(nil); err == nil || file != nil {
		t.Fatalf("nil source did not fail: file=%v error=%v", file, err)
	}
	for _, arch := range []Arch{ArchAMD64, ArchARM, ArchWASM} {
		file := &File{Arch: arch, Funcs: []Func{{Sym: "untouched"}}}
		prepared, err := CoalesceARM64PrivateRegisterHelpers(file)
		if err != nil || prepared != file {
			t.Fatalf("non-ARM64 source changed: arch=%v error=%v", arch, err)
		}
	}
}

func TestARM64PrivateSourceAPIOriginalFileImmutable(t *testing.T) {
	source := arm64PrivateRegisterHelperSource("4,$0-0", "CALL mix<>(SB)")
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	original, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := CoalesceARM64PrivateRegisterHelpers(file)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(file, original) || len(prepared.Funcs) != 1 || prepared == file {
		t.Fatal("continuation preparation mutated its complete original source")
	}
	if !prepared.Funcs[0].arm64PrivateRegisterEntry {
		t.Fatal("validated continuation lost its internal machine-state proof")
	}
	preparedAgain, err := CoalesceARM64PrivateRegisterHelpers(prepared)
	if err != nil || !reflect.DeepEqual(preparedAgain, prepared) {
		t.Fatalf("repeated preparation changed the closed source: %v", err)
	}
}

func TestARM64PrivateSourceAPIKeepsContextRejections(t *testing.T) {
	base := arm64PrivateRegisterHelperSource("4,$0-0", "CALL mix<>(SB)")
	for _, test := range []struct{ name, source string }{
		{"native_frame_memory_helper", strings.Replace(base, "ADC $0,R9,R20", "MOVD (RSP),R20", 1)},
		{"reserved_register", strings.Replace(base, "ADC $0,R9,R20", "MOVD R27,R20", 1)},
		{"framed_helper", strings.Replace(base, "TEXT mix<>(SB),4,$0-0", "TEXT mix<>(SB),4,$16-0", 1)},
		{"native_address", base + "TEXT ·Escape(SB),4,$0-0\nMOVD $mix<>(SB),R0\nRET\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			file, err := Parse(ArchARM64, test.source)
			if err != nil {
				t.Fatal(err)
			}
			original, err := Parse(ArchARM64, test.source)
			if err != nil {
				t.Fatal(err)
			}
			if prepared, err := CoalesceARM64PrivateRegisterHelpers(file); prepared != nil ||
				!errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("unproved source gained a continuation: file=%v error=%v", prepared, err)
			}
			if !reflect.DeepEqual(file, original) {
				t.Fatal("failed source proof mutated its input")
			}
		})
	}
}
