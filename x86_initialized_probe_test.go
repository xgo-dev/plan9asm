package plan9asm

import "testing"

func TestInitializedMaskLogicalProbeSourceBoundaries(t *testing.T) {
	for _, source := range []string{
		"KANDQ K0,K7", "KNOTQ K0,K7,K3", "KANDQ K8,K7,K3",
		"KANDQ (AX),K7,K3", "KANDQ.Z K0,K7,K3",
	} {
		t.Run(source, func(t *testing.T) {
			ins := x86ScalarLaneInstruction(t, source)
			if sequence, known, err := InitializedMaskLogicalProbeSequence("amd64", ins); !known || err == nil || sequence != nil {
				t.Fatal("malformed family acquired initialized source", sequence, known, err)
			}
		})
	}
	ins := x86ScalarLaneInstruction(t, "KANDQ K0,K7,K3")
	for _, origin := range []string{"encoded", "raw-source", "address-size", "segment"} {
		t.Run(origin, func(t *testing.T) {
			modified := ins
			switch origin {
			case "encoded":
				modified.x86Encoded = true
			case "raw-source":
				modified.x86SourceRaw = &x86SourceRawInstruction{op: ins.Op, args: ins.Args}
			case "address-size":
				modified.x86AddressBits = 32
			case "segment":
				modified.x86SegmentPrefix = 0x64
			}
			if sequence, known, err := InitializedMaskLogicalProbeSequence("amd64", modified); !known || err == nil || sequence != nil {
				t.Fatal("raw/override origin acquired named initialization", sequence, known, err)
			}
		})
	}
	if sequence, known, err := InitializedMaskLogicalProbeSequence("arm64", ins); !known || err == nil || sequence != nil {
		t.Fatal("foreign architecture acquired mask initialization", sequence, known, err)
	}
	other := x86ScalarLaneInstruction(t, "PSLLW X1,X0")
	if sequence, known, err := InitializedMaskLogicalProbeSequence("amd64", other); known || err != nil || sequence != nil {
		t.Fatal("profile expanded beyond its registered typed family", sequence, known, err)
	}
}
