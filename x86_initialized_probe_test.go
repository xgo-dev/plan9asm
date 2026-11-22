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

func TestInitializedX86SharedVectorFamilyRegisters(t *testing.T) {
	checkInitializedRegisterFamily(t, "amd64", []string{
		"VPSRAW $79, X11, K4, X15",
		"VPSRLQ $67, Y14, K4, Y20",
		"VPBROADCASTD R14, K1, X15",
		"VPBROADCASTQ CX, K1, Z3",
		"VMAXPD.SAE Z3, Z2, K1, Z1",
		"VMAXPD X2, X9, X2",
		"VPMADDWD X22, X28, K3, X0",
		"VPACKUSWB Y9, Y8, K2, Y27",
		"VUNPCKHPD Z1, Z22, K5, Z8",
		"VMOVDDUP Y2, K5, Y21",
		"VCVTDQ2PD Y11, K2, Z31",
		"VSQRTPD X16, K4, X0",
		"VPERMB X26, X20, K1, X23",
		"VDBPSADBW $127, Z3, Z5, K2, Z19",
		"VPHADDD X2, X9, X2",
		"VPHADDD Y2, Y15, Y2",
		"KADDQ K4, K5, K0",
		"KSHIFTLB $0, K7, K0",
		"KUNPCKWD K7, K5, K3",
		"VPMOVB2M X0, K5",
		"VPMOVM2D K3, Z7",
		"VEXTRACTF32X4 $1, Z14, K7, X2",
		"VINSERTPS $7, X2, X9, X2",
		"VPEXTRQ $7, X2, AX",
		"VPINSRD $1, AX, X2, X3",
		"VMOVSD X2, X9, X2",
		"VMOVQ X2, X7",
	}, InitializedVectorRegisterProbeSequence)
}

func TestInitializedX86FourSourceMemoryUsesEncodedRegisterRange(t *testing.T) {
	for _, form := range []struct {
		op, bank string
	}{
		{"V4FMADDPS", "Z"}, {"V4FMADDSS", "X"},
		{"V4FNMADDPS", "Z"}, {"V4FNMADDSS", "X"},
		{"VP4DPWSSD", "Z"}, {"VP4DPWSSDS", "Z"},
	} {
		for _, mode := range []struct {
			arch, suffix, mask string
		}{
			{"386", "", ""}, {"amd64", "", ""},
			{"amd64", "", ",K3"}, {"amd64", ".Z", ",K3"},
		} {
			source := fmt.Sprintf("%s%s -17(BX)(SI*4),[%s1-%s4]%s,%s7",
				form.op, mode.suffix, form.bank, form.bank, mode.mask, form.bank)
			t.Run(mode.arch+"/"+source, func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, source)
				sequence, known, err := InitializedVectorMemoryProbeSequence(mode.arch, ins)
				if err != nil || !known || len(sequence) < 2 {
					t.Fatalf("missing initialized memory probe: %v, err=%v", known, err)
				}
				if !reflect.DeepEqual(sequence[len(sequence)-1], ins) {
					t.Fatal("probe changed the exact four-source instruction")
				}
				if _, width, valid := initializedVectorOperands(mode.arch, ins); !valid || width != 16 {
					t.Fatalf("memory tuple = %d bytes, valid=%v, want 16 bytes", width, valid)
				}
				writes := make(map[Reg]bool)
				for _, setup := range sequence[:len(sequence)-1] {
					if dst := setup.Args[len(setup.Args)-1]; dst.Kind == OpReg {
						writes[dst.Reg] = true
					}
				}
				// Go's encoding selects the aligned block [0-3], even
				// though the source lists [1-4]. The old destination
				// also supplies the accumulator on masked zeroing forms.
				for _, reg := range []string{"0", "1", "2", "3", "7"} {
					if !writes[Reg(form.bank+reg)] {
						t.Errorf("probe did not initialize %s%s", form.bank, reg)
					}
				}
				if writes[Reg(form.bank+"4")] || writes["K3"] != (mode.mask != "") || !writes[BX] || !writes[SI] {
					t.Fatalf("wrong written register set: %v", writes)
				}
			})
		}
	}
}

func TestInitializedX86VectorTransferMemoryWidths(t *testing.T) {
	for _, test := range []struct {
		arch, source string
		width        int64
	}{
		{"386", "VPEXTRQ $1, X2, (BX)", 4}, // WIG lane extraction writes a dword.
		{"386", "VMOVQ X2, (BX)", 4},       // Go selects W1 66 7E, whose W is ignored.
		{"386", "INSERTPS $7, (BX), X2", 4},
		{"amd64", "VPEXTRQ $1, X2, (BX)", 8},
		{"amd64", "VPINSRW $7, (BX), X2, X3", 2},
		{"amd64", "VINSERTF32X4 $1, (BX), Z14, K7, Z2", 16},
		{"amd64", "VINSERTF64X4.Z $1, (BX), Z14, K7, Z2", 32},
		{"amd64", "VEXTRACTF32X4 $1, Z14, K7, (BX)", 16},
		{"amd64", "VEXTRACTF64X4.Z $1, Z14, K7, (BX)", 0},
		{"amd64", "VMOVSD.Z (BX), K7, X2", 8},
		{"amd64", "VMOVSS X2, K7, (BX)", 4},
	} {
		t.Run(test.arch+"/"+test.source, func(t *testing.T) {
			ins := x86ScalarLaneInstruction(t, test.source)
			_, width, valid := initializedVectorOperands(test.arch, ins)
			if valid != (test.width > 0) || valid && width != test.width {
				t.Fatalf("initialized memory span = (%d, %v), want %d bytes", width, valid, test.width)
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
