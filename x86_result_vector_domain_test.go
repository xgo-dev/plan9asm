package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// These spellings are independent Go-table witnesses. The wide result domain
// must compose with existing typed effects, not merely accept one zero idiom.
func TestX86ResultVectorDomainWideComposition(t *testing.T) {
	for _, bank := range []string{"X", "Y", "Z"} {
		for _, operation := range []string{
			"VPANDQ %[1]s0,%[1]s1,%[1]s2",
			"VPCLMULQDQ $17,%[1]s0,%[1]s1,%[1]s2",
			"VPSRLQ $7,%[1]s0,%[1]s2",
			"VAESENC %[1]s0,%[1]s1,%[1]s2",
			"VADDPS %[1]s0,%[1]s1,%[1]s2",
		} {
			row := fmt.Sprintf(operation, bank)
			t.Run(bank+"/"+row, func(t *testing.T) {
				rows := []string{
					fmt.Sprintf("VPXORQ %[1]s0,%[1]s0,%[1]s0", bank),
					fmt.Sprintf("VPXORQ %[1]s1,%[1]s1,%[1]s1", bank), row,
				}
				state := x86ResultState{flags: x86ByteFlagsAll}
				for _, current := range rows {
					ins := x86ScalarLaneInstruction(t, current)
					if !x86ScalarFPResultTransfer(ins, &state, nil, 0, "amd64") {
						t.Fatalf("typed vector domain cannot compose %s", current)
					}
				}
				if state.xmm[2] != 0xffff || state.flags != x86ByteFlagsAll {
					t.Fatal("composed numerical result or flags lost")
				}
			})
		}
	}
}

func TestX86ResultVectorDomainWholeCFGDoesNotBorrowShapeState(t *testing.T) {
	for _, otherBranch := range []string{"VZEROUPPER", "NOP"} {
		source := `TEXT ·view(SB),4,$0-12
MOVL a+0(FP),AX
MOVL AX,X0
CMPL AX,$0
JE other
VZEROUPPER
JMP joined
other:
` + otherBranch + `
joined:
VADDPS Z0,Z0,Z1
PEXTRD $0,X1,AX
MOVL AX,ret+8(FP)
RET
`
		goAssemblerOracleOutput(t, "amd64", source, "", true)
		for _, api := range []string{"text", "module", "Go"} {
			_, err := x86ScalarFPBitViewAPI(t, source, "func view(a uint32) uint32\n", "amd64", "x86_64-unknown-linux-gnu", api)
			if otherBranch == "VZEROUPPER" && err != nil {
				t.Fatal("both-path upper initialization lost", api, err)
			}
			if otherBranch == "NOP" && !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("source-wide top or one predecessor defined the missing upper bytes", api, err)
			}
		}
	}
	const deadRead = `TEXT ·view(SB),4,$0-4
JMP finish
VPCLMULQDQ $0,(AX),Z0,Z1
finish:
MOVL $1,AX
MOVL AX,X0
PEXTRD $0,X0,AX
MOVL AX,ret+0(FP)
RET
`
	goAssemblerOracleOutput(t, "amd64", deadRead, "", true)
	for _, api := range []string{"text", "module", "Go"} {
		if _, err := x86ScalarFPBitViewAPI(t, deadRead, "func view() uint32\n", "amd64", "x86_64-unknown-linux-gnu", api); !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("dead wide native read bypassed source closure", api, err)
		}
	}
}

func TestX86ResultVectorDomainPhysicalAliasesAndJoins(t *testing.T) {
	for register := 0; register < 32; register++ {
		for width := 16; width <= 64; width *= 2 {
			for missing := 0; missing < 64; missing++ {
				for _, legacy := range []bool{false, true} {
					if legacy && width != 16 {
						continue
					}
					before := x86ResultState{flags: x86ByteFlagsAll}
					before.xmm[register] = 0xa55a
					before.vectorUpper[register] = 0xa55aa55aa55a0000
					state := before.clone()
					known := ^(uint64(1) << uint(missing))
					state.writeVector(register, width, known, legacy)
					var want uint64
					for byteIndex := 0; byteIndex < 64; byteIndex++ {
						defined := byteIndex != missing
						if byteIndex >= width {
							defined = !legacy || before.vectorBytes(register)>>uint(byteIndex)&1 != 0
						}
						if defined {
							want |= uint64(1) << uint(byteIndex)
						}
					}
					if state.vectorBytes(register) != want || state.vectorUpper[register]&0xffff != 0 {
						t.Fatalf("bank%d width%d missing%d legacy%t: %016x want %016x", register, width, missing, legacy, state.vectorBytes(register), want)
					}
					joined := state.intersect(before)
					if joined.vectorBytes(register) != want&before.vectorBytes(register) {
						t.Fatal("CFG join promoted unknown upper bytes")
					}
					joined.writeVector(register, 64, 0, false)
					if state.vectorBytes(register) != want || state.flags != before.flags {
						t.Fatal("clone/join shares mutable physical vector state")
					}
				}
			}
		}
	}
}

func TestX86ResultVectorDomainEveryExistingWriteEncoding(t *testing.T) {
	// Every existing low-X writer must explicitly preserve or clear aliases.
	// This list is independent of the implementation dispatch and registries.
	for _, row := range []string{
		"MOVL AX,X2", "VMOVD AX,X2", "MOVQ AX,X2", "VMOVQ AX,X2",
		"MOVSS X0,X2", "MOVSD X0,X2", "VMOVSS X0,X1,X2", "VMOVSD X0,X1,X2",
		"PINSRB $3,AX,X2", "VPINSRB $3,AX,X0,X2",
		"INSERTPS $35,X0,X2", "VINSERTPS $35,X0,X1,X2",
		"PXOR X0,X2", "VPXOR X0,X1,X2",
		"PCLMULQDQ $17,X0,X2", "VPCLMULQDQ $17,X0,X1,X2",
		"AESENC X0,X2", "VAESENC X0,X1,X2",
		"PSRLQ $1,X2", "VPSRLQ $1,X0,X2",
		"ADDSS X0,X2", "VADDSS X0,X1,X2", "MULPS X0,X2", "VMULPS X0,X1,X2",
		"VPBROADCASTD X0,X2",
	} {
		t.Run(row, func(t *testing.T) {
			state := x86ResultState{flags: x86ByteFlagsAll}
			for index := range state.xmm {
				state.xmm[index] = 0xffff
				state.vectorUpper[index] = 0xa5a55a5aa5a50000
			}
			state.gp[0] = 0xff
			before := state.clone()
			if !x86ScalarFPResultTransfer(x86ScalarLaneInstruction(t, row), &state, nil, 0, "amd64") {
				t.Fatal("existing typed writer lost its effect")
			}
			want := before.vectorUpper[2]
			if strings.HasPrefix(row, "V") {
				want = ^uint64(0xffff)
			}
			if state.vectorUpper[2] != want || state.xmm[2] != 0xffff || state.flags != before.flags {
				t.Fatalf("write encoding lost alias semantics: %016x", state.vectorBytes(2))
			}
			for index := range state.xmm {
				if index != 2 && state.vectorBytes(index) != before.vectorBytes(index) {
					t.Fatal("unrelated vector bank changed", index)
				}
			}
		})
	}
}

func TestX86ResultVectorDomainWideLogicalEveryByte(t *testing.T) {
	for _, bank := range []string{"X", "Y", "Z"} {
		width := map[string]int{"X": 16, "Y": 32, "Z": 64}[bank]
		for _, suffix := range []string{"", ".Z"} {
			row := fmt.Sprintf("VPANDQ%s %s0,%s1,K1,%s2", suffix, bank, bank, bank)
			ins := x86ScalarLaneInstruction(t, row)
			for missing := 0; missing < 64; missing++ {
				for input := 0; input < 3; input++ {
					state := x86ResultState{flags: x86ByteFlagsAll, masks: [8]bool{1: true}}
					for register := 0; register < 3; register++ {
						state.writeVector(register, 64, ^uint64(0), false)
					}
					state.writeVector(input, 64, ^(uint64(1) << uint(missing)), false)
					if !x86ScalarFPResultTransfer(ins, &state, nil, 0, "amd64") {
						t.Fatal("legal partial input was not represented", row)
					}
					want := ^uint64(0)
					if missing < width && (input < 2 || suffix == "") {
						want &^= uint64(1) << uint(missing)
					}
					if state.vectorBytes(2) != want {
						t.Fatalf("%s input%d missing%d: %016x want%016x", row, input, missing, state.vectorBytes(2), want)
					}
				}
			}
		}
	}
}

func TestX86ResultVectorDomainDoesNotPromoteLowXToWide(t *testing.T) {
	for _, row := range []string{"VPANDQ Z0,Z1,Z2", "VPCLMULQDQ $17,Z0,Z1,Z2", "VPSRLQ $1,Z0,Z2", "VAESENC Z0,Z1,Z2"} {
		state := x86ResultState{xmm: [32]uint16{0: 0xffff, 1: 0xffff}}
		if !x86ScalarFPResultTransfer(x86ScalarLaneInstruction(t, row), &state, nil, 0, "amd64") {
			t.Fatal("valid effect must retain the unknown upper bytes", row)
		}
		if state.vectorUpper[2] != 0 || state.xmm[2] != 0xffff {
			t.Fatal("a low-X witness falsely initialized a wider source", row)
		}
	}
}

func TestX86ResultVectorTransportNeverInitializesMissingUpperBytes(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc is required")
	}
	for _, arch := range []string{"amd64", "386"} {
		resultOffset, triple := 8, "x86_64-unknown-linux-gnu"
		if arch == "386" {
			resultOffset, triple = 4, "i386-unknown-linux-gnu"
		}
		for _, form := range []struct{ move, extract string }{
			{"VMOVUPS Y0,Y1", "VEXTRACTF128 $1,Y1,X2"},
			{"VMOVUPS Z0,Z1", "VEXTRACTF32X4 $1,Z1,X2"},
		} {
			for _, initialized := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/upper-initialized-%v", arch, form.move, initialized), func(t *testing.T) {
					upper := "NOP"
					if initialized {
						upper = "VZEROUPPER"
					}
					source := fmt.Sprintf(`TEXT ·view(SB),4,$0-%d
MOVL a+0(FP),AX
MOVL AX,X0
%s
%s
%s
PEXTRD $0,X2,AX
MOVL AX,ret+%d(FP)
RET
`, resultOffset+4, upper, form.move, form.extract, resultOffset)
					goAssemblerOracleOutput(t, arch, source, "", true)
					for _, api := range []string{"text", "module", "Go"} {
						ir, err := x86ScalarFPBitViewAPI(t, source, "func view(a uint32) uint32\n", arch, triple, api)
						if initialized && err != nil {
							t.Errorf("%s lost independently initialized upper bytes: %v", api, err)
						}
						if !initialized && !errors.Is(err, ErrProbeNeedsContext) {
							t.Errorf("%s promoted unknown upper bytes through register transport: %v", api, err)
						}
						if initialized && err == nil {
							compileLLVMToObject(t, llc, triple, "known-upper.ll", "known-upper.o", ir)
						}
					}
				})
			}
		}
	}
}

func TestX86ResultVectorDomainFiveTargetThreeAPIObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			var source, declarations strings.Builder
			count := 0
			for _, bank := range []string{"X", "Y", "Z"} {
				for _, operation := range []string{
					"VPANDQ %[1]s0,%[1]s1,%[1]s2", "VPCLMULQDQ $17,%[1]s0,%[1]s1,%[1]s2",
					"VPSRLQ $7,%[1]s0,%[1]s2", "VAESENC %[1]s0,%[1]s1,%[1]s2",
					"VADDPS %[1]s0,%[1]s1,%[1]s2", "VMULPD %[1]s0,%[1]s1,%[1]s2",
				} {
					if target.arch == "386" && strings.HasPrefix(operation, "VPCLMULQDQ") {
						continue // Go mode32 does not parse the four-operand row.
					}
					fmt.Fprintf(&declarations, "func wide%d() uint32\n", count)
					fmt.Fprintf(&source, "TEXT ·wide%d(SB),4,$0-4\nVPXORQ %s0,%s0,%s0\nVPXORQ %s1,%s1,%s1\n%s\nPEXTRD $0,X2,AX\nMOVL AX,ret+0(FP)\nRET\n",
						count, bank, bank, bank, bank, bank, bank, fmt.Sprintf(operation, bank))
					count++
				}
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
				if err != nil {
					t.Fatal(api, err)
				}
				compileLLVMToObject(t, llc, target.triple, "wide-results.ll", "wide-results.o", ir)
			}
		})
	}
}

func TestX86ResultVectorDomainZeroRegisterBoundaries(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, name := range []string{"VZEROUPPER", "VZEROALL"} {
			t.Run(arch+"/"+name, func(t *testing.T) {
				state := x86ResultState{flags: x86ByteFlagsAll}
				for register := range state.xmm {
					state.xmm[register] = 0x1234
					state.vectorUpper[register] = 0x1234123412340000
				}
				if !x86ScalarFPResultTransfer(x86ScalarLaneInstruction(t, name), &state, nil, 0, arch) {
					t.Fatal("complete zero-register family lacks result effects")
				}
				limit := 16
				if arch == "386" {
					limit = 8
				}
				for register := range state.xmm {
					want := uint64(0x1234123412341234)
					if register < limit {
						want |= ^uint64(0xffff)
						if name == "VZEROALL" {
							want = ^uint64(0)
						}
					}
					if state.vectorBytes(register) != want {
						t.Fatal("zero-register encoding changed wrong bank/bytes", register)
					}
				}
				if state.flags != x86ByteFlagsAll {
					t.Fatal("vector zero modified flags")
				}
			})
		}
		for _, malformed := range []string{"VZEROUPPER X0", "VZEROALL.Z"} {
			state := x86ResultState{}
			if x86ScalarFPResultTransfer(x86ScalarLaneInstruction(t, malformed), &state, nil, 0, arch) {
				t.Fatal("malformed zero form supplied defined bytes", malformed)
			}
		}
	}
}
