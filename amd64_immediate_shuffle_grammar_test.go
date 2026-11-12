package plan9asm

import (
	"bytes"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestX86ImmediateShuffleCompleteImmediateDomains(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		t.Run(arch, func(t *testing.T) {
			var source strings.Builder
			source.WriteString("TEXT probe(SB),4,$0-0\n")
			count := 0
			for _, op := range []string{"PSHUFW", "PSHUFL", "PSHUFD", "PSHUFHW", "PSHUFLW", "VPSHUFD", "VPSHUFHW", "VPSHUFLW"} {
				for value := 0; value < 256; value++ {
					immediate, bank := value, "X"
					if op == "PSHUFW" {
						immediate, bank = value-128, "M"
					}
					row := fmt.Sprintf("%s $%d,%s0,%s1", op, immediate, bank, bank)
					fmt.Fprintln(&source, row)
					ins := x86YMMReadSource(t, row)
					before := fmt.Sprintf("%#v", ins)
					if _, known, err := x86ImmediateShuffleProperties(ins, arch); !known || err != nil {
						t.Fatalf("complete imm8 domain missing %s: %v", row, err)
					}
					if before != fmt.Sprintf("%#v", ins) {
						t.Fatal("pure grammar changed original source")
					}
					count++
				}
			}
			source.WriteString("RET\n")
			goAssemblerOracleOutput(t, arch, source.String(), "", true)
			if count != 2048 {
				t.Fatal("complete independent immediate denominator changed", count)
			}
		})
	}
}

func TestX86ImmediateShuffleRejectsSiblingInvalidFormats(t *testing.T) {
	var rows []string
	for _, op := range []string{"PSHUFL", "PSHUFD", "PSHUFHW", "PSHUFLW"} {
		for _, args := range []string{"$-1,X0,X1", "$256,X0,X1", "$0,X16,X1", "$0,X0,Y1", "$0,AX,X1", "$0,X0,(AX)", "$0,X0,K1,X1"} {
			rows = append(rows, op+" "+args)
		}
		rows = append(rows, op+".Z $0,X0,X1")
	}
	for _, args := range []string{"$128,M0,M1", "$-129,M0,M1", "$0,X0,M1", "$0,M0,X1", "$0,M8,M1", "$0,M0,(AX)"} {
		rows = append(rows, "PSHUFW "+args)
	}
	rows = append(rows, "PSHUFW.Z $0,M0,M1")
	for _, op := range []string{"VPSHUFD", "VPSHUFHW", "VPSHUFLW"} {
		for _, args := range []string{"$-129,X0,X1", "$256,X0,X1", "$-1,Z0,Z1", "$-1,X16,X1", "$-1,X0,K1,X1", "$0,X0,Y1", "$0,AX,X1", "$0,X0,(AX)", "$0,X0,K0,X1", "$0,X0,K8,X1", "$0,X0,X32"} {
			rows = append(rows, op+" "+args)
		}
		rows = append(rows, op+".Z $0,X0,X1", op+".BCST $0,X0,X1", op+".SAE $0,(AX),X1")
		if op != "VPSHUFD" {
			rows = append(rows, op+".BCST $0,(AX),X1")
		}
	}
	for _, row := range rows {
		t.Run(row, func(t *testing.T) {
			for _, arch := range []string{"amd64", "386"} {
				source := "TEXT f(SB),4,$0-0\n" + row + "\nRET\n"
				masklessZero := row == "VPSHUFD.Z $0,X0,X1" || row == "VPSHUFHW.Z $0,X0,X1" || row == "VPSHUFLW.Z $0,X0,X1"
				historicalReserved := masklessZero && !goToolchainAtLeast(runtime.Version(), 1, 21)
				goAssemblerOracleOutput(t, arch, source, "", historicalReserved)
				if masklessZero {
					// Before Go 1.21 the encoder emitted reserved EVEX.z/aaa=0.
					// Observe its exact original bytes; neither named nor raw
					// translation may acquire semantics from that old acceptance.
					pp := byte(1)
					if strings.HasPrefix(row, "VPSHUFHW") {
						pp = 2
					} else if strings.HasPrefix(row, "VPSHUFLW") {
						pp = 3
					}
					code := []byte{0x62, 0xf1, 0x7c | pp, 0x88, 0x70, 0xc8, 0}
					if historicalReserved {
						listing := x86InsertExtractGoListing(t, arch, source)
						var observed []byte
						for _, line := range strings.Split(string(listing), "\n") {
							observed = append(observed, x86InsertExtractListedBytes(line)...)
						}
						if !bytes.Equal(observed, append(append([]byte(nil), code...), 0xc3)) {
							t.Fatalf("historical reserved shuffle bytes changed: %x", observed)
						}
						t.Logf("%s/%s historical reserved z=1/aaa=0 observation; not a legal form", runtime.Version(), arch)
					}
					mode := 64
					if arch == "386" {
						mode = 32
					}
					if _, _, known, err := decodedX86PackedShuffleInstruction(code, mode); !known || err == nil {
						t.Fatal("reserved raw zeroing acquired shuffle semantics", err)
					}
					x86RequireZeroMaskAPIOutcome(t, arch, source, false)
					x86RequireZeroMaskAPIOutcome(t, arch, x86RawINSERTPSSource("f", code), false)
				}
				ins := x86YMMReadSource(t, row)
				if _, known, err := x86ImmediateShuffleProperties(ins, arch); !known || err == nil || errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("Go-rejected syntax became a valid/context form", row, arch, err)
				}
			}
		})
	}
}

func TestX86ImmediateShuffleMode32PhysicalAndMMXBoundaries(t *testing.T) {
	for _, op := range []string{"VPSHUFD", "VPSHUFHW", "VPSHUFLW"} {
		for _, row := range []string{op + " $0,X16,X31", op + " $0,Y16,Y31"} {
			goAssemblerOracleOutput(t, "386", "TEXT f(SB),4,$0-0\n"+row+"\nRET\n", "", true)
			if _, known, err := x86ImmediateShuffleProperties(x86YMMReadSource(t, row), "386"); !known || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("source-only high bank acquired physical binding", row, err)
			}
		}
		for _, row := range []string{op + " $0,Z8,Z0", op + " $0,X0,K1,X1"} {
			goAssemblerOracleOutput(t, "386", "TEXT f(SB),4,$0-0\n"+row+"\nRET\n", "", false)
			if _, known, err := x86ImmediateShuffleProperties(x86YMMReadSource(t, row), "386"); !known || err == nil || errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("Go-rejected mode32 form acquired physical binding", row, err)
			}
		}
	}
	for _, arch := range []string{"amd64", "386"} {
		ins := x86YMMReadSource(t, "PSHUFW $27,AX,M1")
		goAssemblerOracleOutput(t, arch, "TEXT f(SB),4,$0-0\n"+ins.Raw+"\nRET\n", "", true)
		form, known, err := x86ImmediateShuffleProperties(ins, arch)
		if !known || err != nil || form.source.Reg != "M0" || !form.spec.mmx {
			t.Fatal("original Go Ymm spelling lost its actual MMX bank", arch, form, err)
		}
		if !errors.Is(x86LegacyMMXReadEmitterContext(ins, arch), ErrProbeNeedsContext) || x86CallerVectorMoveKnown(ins) {
			t.Fatal("GP source spelling became initialized MMX data or caller permission")
		}
	}
}

func TestX86ImmediateShuffleNativeFeatureScope(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range []string{"PSHUFL $0,(AX),X1", "PSHUFD $0,(AX),X1", "PSHUFHW $0,(AX),X1", "PSHUFLW $0,(AX),X1"} {
			if got := inferFuncTargetFeaturesForGOARCH(ArchAMD64, arch, Func{Instrs: []Instr{x86YMMReadSource(t, row)}}); got != "+sse2" {
				t.Fatal("validated native legacy m128 needs its private SSE2 carrier", arch, row, got)
			}
		}
		for _, row := range []string{"PSHUFL $-1,(AX),X1", "PSHUFL $0,X0,X1", "VPSHUFD $0,(AX),X1", "PSHUFW $0,(AX),M1"} {
			if got := inferFuncTargetFeaturesForGOARCH(ArchAMD64, arch, Func{Instrs: []Instr{x86YMMReadSource(t, row)}}); got != "" {
				t.Fatal("non-native/malformed form acquired features", arch, row, got)
			}
		}
	}
}

func TestX86ImmediateShuffleNativeMemoryCannotBorrowVirtualBacking(t *testing.T) {
	for _, op := range []string{"PSHUFL", "PSHUFD", "PSHUFHW", "PSHUFLW"} {
		for _, operand := range []string{"a+0(FP)", "(SP)", "(BP)", "(AX)(BP*2)"} {
			row := op + " $0," + operand + ",X1"
			t.Run(row, func(t *testing.T) {
				goAssemblerOracleOutput(t, "amd64", "TEXT f(SB),4,$0-16\n"+row+"\nRET\n", "", true)
				ins := x86YMMReadSource(t, row)
				var output strings.Builder
				ctx := &amd64Ctx{goarch: "amd64", b: &output}
				if known, _, err := ctx.lowerPackedWordShuffle(ins.Op, ins); !known || !errors.Is(err, ErrProbeNeedsContext) || output.Len() != 0 {
					t.Fatal("virtual/native frame acquired backing before IR", row, err, output.String())
				}
			})
		}
		for _, bits := range []int{32, 64} {
			ins := x86YMMReadSource(t, op+" $0,(AX),X1")
			ins.x86AddressBits = bits
			var output strings.Builder
			ctx := &amd64Ctx{goarch: "amd64", b: &output}
			if known, _, err := ctx.lowerPackedWordShuffle(ins.Op, ins); !known || !errors.Is(err, ErrProbeNeedsContext) || output.Len() != 0 {
				t.Fatal("unbound address-size identity acquired native backing", bits, err)
			}
		}
	}
}
