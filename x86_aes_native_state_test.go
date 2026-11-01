package plan9asm

import (
	"reflect"
	"strings"
	"testing"
)

func TestX86AESNativePreservesIndependentStateAndStandaloneBoundary(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, name := range x86AESOracleNames {
			row, destination := x86AESOracleRow(name, "(SI)", "X")
			ins := x86ScalarLaneInstruction(t, row)
			for flags := uint8(0); flags <= x86ByteFlagsAll; flags++ {
				state := x86ResultState{flags: flags, direction: x86ResultDirectionEither}
				state.pointerGP[6], state.gp[3], state.xmm[1] = true, 0x55, 0xffff
				state.masks[2], state.vectorUpper[1], state.vectorUpper[2] = true, 0x12340000, 0x56780000
				before := state.clone()
				if accepted, known := x86ResultAESStep(ins, &state, nil, arch); !known || accepted || !reflect.DeepEqual(state, before) {
					t.Fatal("standalone AES acquired native backing or mutated a failed proof", arch, name)
				}
				want := state.clone()
				want.writeVector(destination, 16, 0xffff, !strings.HasPrefix(name, "V"))
				if accepted, known := x86LoweredAESResultStep(ins, &state, nil, arch); !known || !accepted || !reflect.DeepEqual(state, want) {
					t.Fatal("AES continuation changed an independent GP, flag, mask or vector alias", arch, name, flags)
				}
			}
		}
	}
}

func TestX86AESKeyAssistRequiresOnlyItsNumericalRegisterSubwords(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, name := range []string{"AESKEYGENASSIST", "VAESKEYGENASSIST"} {
			row, _ := x86AESOracleRow(name, "X0", "X")
			ins := x86ScalarLaneInstruction(t, row)
			for missing := -1; missing < 16; missing++ {
				state := x86ResultState{flags: x86ByteFlagAF}
				state.xmm[0] = 0xf0f0 // Only source dwords one and three contribute.
				if missing >= 0 {
					state.xmm[0] &^= 1 << uint(missing)
				}
				before := state.clone()
				defined := uint64(0xffff)
				if missing >= 0 && missing%8 >= 4 {
					// Each used input byte contributes to the unrotated and
					// rotated output dwords in its eight-byte half.
					half, at := missing/8*8, missing%4
					defined &^= uint64(1)<<uint(half+at) | uint64(1)<<uint(half+4+(at+3)%4)
				}
				want := before.clone()
				want.writeVector(2, 16, defined, !strings.HasPrefix(name, "V"))
				accepted, known := x86LoweredAESResultStep(ins, &state, nil, arch)
				if !known || !accepted || !reflect.DeepEqual(state, want) {
					t.Fatal("key assist invented used bytes or required irrelevant register data", arch, name, missing, accepted)
				}
			}
		}
	}
}

func TestX86AESRawIdentityCannotBorrowPrivateControlOrInputs(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, name := range x86AESOracleNames {
			row, _ := x86AESOracleRow(name, "(SI)", "X")
			file, err := Parse(ArchAMD64, "TEXT Value(SB),4,$0-0\n"+x86RawNumericalInstruction(t, arch, row)+"RET\n")
			if err != nil {
				t.Fatal(err)
			}
			file, err = normalizeX86RawFile(file, arch)
			if err != nil {
				t.Fatal(err)
			}
			ins := file.Funcs[0].Instrs[1]
			if !x86RawAESSource(ins, arch) || !x86ResultPreservesPrivateStorage(ins, arch) ||
				x86PreservesNumericalSourceState(ins) {
				t.Fatal("exact data-changing AES source lost its distinct private-control role", arch, name)
			}
			for _, change := range []func(*Instr){
				func(ins *Instr) { ins.x86SourceRaw = nil },
				func(ins *Instr) { ins.Args[len(ins.Args)-1].Reg = "X3" },
				func(ins *Instr) { ins.x86AddressBits = 16 },
				func(ins *Instr) { ins.x86UnboundAddressOverride = true },
				func(ins *Instr) { ins.x86SegmentPrefix = 0x64 },
				func(ins *Instr) { ins.x86RIPLiteral = true },
			} {
				changed := ins
				changed.Args = append([]Operand(nil), ins.Args...)
				change(&changed)
				state := x86ResultState{flags: x86ByteFlagsAll}
				state.pointerGP[6], state.xmm[1] = true, 0xffff
				if x86ResultNamedPredicateInstruction(changed) {
					// Removing all legacy origin metadata is a fresh named
					// operation, not a forged raw marker. A numerical address
					// still cannot supply its missing incoming pointer.
					state.pointerGP[6], state.gp[6] = false, 0xff
				}
				before := state.clone()
				accepted, known := x86LoweredAESResultStep(changed, &state, nil, arch)
				if !known || accepted || !reflect.DeepEqual(state, before) || x86RawAESSource(changed, arch) ||
					!x86ResultNamedPredicateInstruction(changed) && (x86ResultPreservesPrivateStorage(changed, arch) ||
						x86ResultDirectionAfterSource(changed, x86ResultDirectionEither, arch) != x86ResultDirectionUnknown) {
					t.Fatal("changed AES source borrowed numerical inputs or private controls", arch, name)
				}
			}
		}
	}
}

func TestX86RawImmediateFirstDataRoleBindsTheWholeOriginalInstruction(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, name := range []string{"AESKEYGENASSIST", "VAESKEYGENASSIST"} {
			row, _ := x86AESOracleRow(name, "(SI)", "X")
			file, err := Parse(ArchAMD64, "TEXT Value(SB),4,$0-0\n"+x86RawNumericalInstruction(t, arch, row)+"RET\n")
			if err != nil {
				t.Fatal(err)
			}
			file, err = normalizeX86RawFile(file, arch)
			if err != nil {
				t.Fatal(err)
			}
			ins := file.Funcs[0].Instrs[1]
			if x86RawOrdinaryVectorSource(ins, arch) || !x86RawOrdinaryVectorSourceAt(ins, arch, 1) ||
				!x86RawAESSource(ins, arch) || x86RawOrdinaryVectorSourceAt(ins, arch, -1) ||
				x86RawOrdinaryVectorSourceAt(ins, arch, len(ins.Args)) {
				t.Fatal("immediate-first grammar rewrote the source or borrowed the selector as data", arch, name)
			}
			changed := ins
			changed.Args = append([]Operand(nil), ins.Args...)
			changed.Args[0].Imm++
			if x86RawAESSource(changed, arch) || x86RawOrdinaryVectorSourceAt(changed, arch, 1) {
				t.Fatal("unchanged data operand hid a changed original immediate", arch, name)
			}
		}
	}
}
