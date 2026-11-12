package plan9asm

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestARM64DCZVADataAddressesNeedNativeExtentContract(t *testing.T) {
	for _, test := range []struct {
		name    string
		body    string
		address string
	}{
		{"named-load", "MOVD holder<>(SB),R0\nDC ZVA,R0", "payload<>(SB)"},
		{"raw-store", "MOVD holder<>(SB),R0\nWORD $0xd50b7420", "payload<>(SB)"},
		{"offset-relocation", "MOVD holder<>(SB),R0\nDC ZVA,R0", "payload<>+1(SB)"},
		{"external-relocation", "MOVD holder<>(SB),R0\nDC ZVA,R0", "external(SB)"},
		{"indirect-load", "MOVD holder<>(SB),R2\nMOVD (R2),R0\nDC ZVA,R0", "payload<>(SB)"},
		{"unobserved-relocation", "DC ZVA,R0", "payload<>(SB)"},
		{"unreachable-load", "B clear\ndead:\nMOVD holder<>(SB),R0\nclear:\nDC ZVA,R0", "payload<>(SB)"},
	} {
		t.Run(test.name, func(t *testing.T) {
			source := arm64TypedNativeSource(test.body) +
				"DATA holder<>+0(SB)/8,$" + test.address + "\nGLOBL holder<>(SB),16,$8\n" +
				"DATA payload<>+0(SB)/8,$7\nGLOBL payload<>(SB),16,$8\n"
			// These are accepted source relocations, not invalid machine code.
			// Never execute a hardware-sized store to these small objects.
			arm64TypedNativeGoObject(t, source)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			if len(file.Data) != 2 || file.Data[0].Addr != test.address {
				t.Fatalf("source address provenance was not parsed: %+v", file.Data)
			}
			normalized, err := NormalizeRawFileForTranslation(file, "arm64")
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(file.Data, normalized.Data) {
				t.Fatal("public normalization discarded DATA address provenance")
			}
			fn := file.Funcs[0]
			if !errors.Is(validateARM64DCZVASource(fn, file.Data), ErrProbeNeedsContext) {
				t.Error("original source gate ignored the complete file's DATA relocation")
			}
			fn, err = normalizeARM64RawPCRelative(fn)
			if err != nil {
				t.Fatal(err)
			}
			if !errors.Is(validateARM64DCZVAAddressSources(arm64SourceGoFrame(fn), fn.FrameSize, arm64SplitBlocks(fn), file.Data), ErrProbeNeedsContext) {
				t.Error("normalized CFG gate ignored the complete file's DATA relocation")
			}
			lowerer, _ := newARM64CtxWithFuncForTest(t, fn, arm64TypedNativeOptions(t, arm64TypedNativeTargets[0]).Sigs["NativeEffects"], nil)
			lowerer.sourceData = file.Data
			if !errors.Is(lowerer.requireDCZVANoPrivateAddressSources(), ErrProbeNeedsContext) {
				t.Error("lowerer dropped source DATA before native store emission")
			}
			// On the original implementation this captures the false success:
			// holder is an eight-byte zero placeholder despite its Go relocation.
			// Once rejected, there is no returned IR to inspect or execute.
			ir, err := Translate(file, arm64TypedNativeOptions(t, arm64TypedNativeTargets[0]))
			if err == nil {
				for _, line := range strings.Split(ir, "\n") {
					if strings.Contains(line, "holder") && strings.Contains(line, "global") {
						t.Logf("unproven relocation translated successfully: %s", line)
					}
				}
			}
			arm64DCZVARequireContextAllAPIs(t, source)
		})
	}
}

func TestARM64DCZVAScalarDataIsNotAnAddressSource(t *testing.T) {
	source := arm64TypedNativeSource("MOVD block_size<>(SB),R2\nDC ZVA,R0") +
		"DATA block_size<>+0(SB)/8,$64\nGLOBL block_size<>(SB),16,$8\n"
	arm64TypedNativeGoObject(t, source)
	// A normal SB data read, including memclr's cached hardware block size,
	// neither takes a materialized object's address nor carries a relocation.
	arm64TypedNativeAllAPIsAndObjects(t, source, 0, 0)
}
