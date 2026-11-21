package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

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

func TestInitializedX86RegisterProbeFamiliesAndBoundaries(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			scalar := []string{}
			for _, condition := range []string{"CC", "CS", "EQ", "GE", "GT", "HI", "LE", "LS", "LT", "MI", "NE", "OC", "OS", "PC", "PL", "PS"} {
				scalar = append(scalar, "SET"+condition+" AH")
			}
			widths := []string{"B", "W", "L"}
			if arch == "amd64" {
				widths = append(widths, "Q")
			}
			for _, stem := range []string{"DIV", "IDIV", "MUL", "IMUL"} {
				for _, width := range widths {
					for _, reg := range []string{"AX", "BX", "DX"} {
						scalar = append(scalar, stem+width+" "+reg)
					}
				}
				scalar = append(scalar, stem+"B AH", stem+"B BH")
			}
			if arch == "386" {
				scalar = append(scalar, "IDIVL BP")
			}
			for _, width := range widths {
				for _, stem := range []string{"ADC", "ADD", "CMP", "SBB", "SUB"} {
					scalar = append(scalar, stem+width+" BX,AX")
				}
				for _, stem := range []string{"RCL", "RCR", "ROL", "ROR", "SAR", "SAL", "SHL", "SHR"} {
					scalar = append(scalar, stem+width+" $1,AX", stem+width+" CX,AX")
				}
				if width != "B" {
					scalar = append(scalar, "IMUL"+width+" AX,BX", "IMUL"+width+" $4,CX",
						"SHL"+width+" $2,AX,BX", "SHR"+width+" CX,AX,BX")
				}
			}
			scalar = append(scalar, "CMOVLLE DI,SI", "ANDNL DX,CX,AX", "ADCXL AX,BX")
			checkInitializedRegisterFamily(t, arch, scalar, InitializedScalarRegisterProbeSequence)

			var vector []string
			for _, op := range []string{"CMPPD", "CMPPS", "CMPSD", "CMPSS"} {
				for _, predicate := range []int{-128, 4, 127} {
					vector = append(vector, fmt.Sprintf("%s X0,X1,%d", op, predicate))
				}
			}
			checkInitializedRegisterFamily(t, arch, vector, InitializedVectorRegisterProbeSequence)

			for _, test := range []struct {
				profile func(string, Instr) ([]Instr, bool, error)
				source  string
			}{
				{InitializedScalarRegisterProbeSequence, "SETCC symbol+4(SB)"},
				{InitializedScalarRegisterProbeSequence, "DIVB (BX)"},
				{InitializedScalarRegisterProbeSequence, "IDIVL SP"},
				{InitializedScalarRegisterProbeSequence, "IMULL (AX),BX"},
				{InitializedScalarRegisterProbeSequence, "MOVL AX,CR0"},
				{InitializedScalarRegisterProbeSequence, "RCRL X0,AX"},
				{InitializedScalarRegisterProbeSequence, "LOOP next"},
				{InitializedVectorRegisterProbeSequence, "CMPPD symbol+4(SB),X1,4"},
				{InitializedVectorRegisterProbeSequence, "CMPPD X0,X1,symbol"},
				{InitializedVectorRegisterProbeSequence, "CMPPD X0,X1,128"},
			} {
				original := x86ScalarLaneInstruction(t, test.source)
				if sequence, known, err := test.profile(arch, original); known || err != nil || sequence != nil {
					t.Errorf("unbound or invalid form %s acquired probe inputs: %v %v %v", test.source, sequence, known, err)
				}
				original.x86Encoded = true
				if sequence, known, err := test.profile(arch, original); known || err != nil || sequence != nil {
					t.Errorf("raw %s acquired named probe inputs: %v %v %v", test.source, sequence, known, err)
				}
			}
		})
	}
}

func checkInitializedRegisterFamily(t *testing.T, arch string, sources []string, profile func(string, Instr) ([]Instr, bool, error)) {
	t.Helper()
	var originalGo strings.Builder
	for i, source := range sources {
		original := x86ScalarLaneInstruction(t, source)
		sequence, known, err := profile(arch, original)
		if !known || err != nil || len(sequence) < 2 {
			t.Errorf("%s missing typed initialization: %v %v %v", source, sequence, known, err)
			continue
		}
		if !reflect.DeepEqual(sequence[len(sequence)-1], original) {
			t.Errorf("%s changed source form: %+v", source, sequence)
			continue
		}
		if err := ProbeInstructionSequence(ArchAMD64, arch, sequence); err != nil {
			t.Errorf("%s with initialized inputs: %v", source, err)
		}
		fmt.Fprintf(&originalGo, "TEXT ·Initialized%d(SB),4,$0-0\n", i)
		for _, ins := range sequence {
			originalGo.WriteString(ins.Raw + "\n")
		}
		originalGo.WriteString("RET\n")
	}
	requireX86GoAssemblerResult(t, arch, originalGo.String(), true)
}
