package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestX86ResultBlockTransferAliasedOperands(t *testing.T) {
	for _, row := range x86InsertExtractFormats() {
		if strings.HasSuffix(strings.Fields(row)[0], "PS") || strings.Contains(row, "(BX)") {
			continue
		}
		// The five equality partitions of source/base/destination. Extraction
		// has no base; retaining the partitions also checks an unrelated bank.
		for _, aliases := range [][3]int{{0, 1, 2}, {0, 0, 2}, {0, 1, 0}, {0, 1, 1}, {0, 0, 0}} {
			for _, immediate := range []int{0, 1, 2, 255} {
				ins := x86ScalarLaneInstruction(t, strings.Replace(row, "$255", fmt.Sprintf("$%d", immediate), 1))
				for index := range ins.Args {
					arg := &ins.Args[index]
					if arg.Kind == OpReg && amd64VectorByteWidth(arg.Reg) != 0 {
						bank, valid := amd64VectorRegisterIndex(arg.Reg, amd64VectorByteWidth(arg.Reg))
						if !valid || bank >= len(aliases) {
							t.Fatal("unexpected independent format bank", row)
						}
						arg.Reg = Reg(fmt.Sprintf("%s%d", string(arg.Reg)[:1], aliases[bank]))
					}
				}
				form, known, err := x86InsertExtractProperties(ins, "amd64")
				if !known || err != nil {
					t.Fatal(row, aliases, err)
				}
				state := x86ResultState{masks: [8]bool{1: true}, flags: x86ByteFlagsAll}
				for index, bytes := range []uint64{0xa5a5f0f00f0f5a5a, 0x123456789abcdef0, 0xfedcba9876543210} {
					state.writeVector(index, 64, bytes, false)
				}
				before := state.clone()
				destination, _ := amd64VectorRegisterIndex(ins.Args[form.destination].Reg, form.output)
				want := x86ResultBlockTransferReference(ins, form, before, immediate)
				if !x86ResultBlockTransfer(ins, form, &state, nil, 0, "amd64") || state.vectorBytes(destination) != want {
					t.Fatalf("%s aliases%v imm%d: %016x want %016x", row, aliases, immediate, state.vectorBytes(destination), want)
				}
				for index := range state.xmm {
					if index != destination && state.vectorBytes(index) != before.vectorBytes(index) {
						t.Fatal("aliased transfer modified an unrelated bank", row, index)
					}
				}
				if state.flags != before.flags {
					t.Fatal("aliased transfer modified flags", row)
				}
			}
		}
	}
}

func x86ResultBlockTransferReference(ins Instr, form x86InsertExtractForm, before x86ResultState, immediate int) uint64 {
	source, _ := amd64VectorRegisterIndex(ins.Args[form.source].Reg, amd64VectorByteWidth(ins.Args[form.source].Reg))
	destination, _ := amd64VectorRegisterIndex(ins.Args[form.destination].Reg, form.output)
	base := -1
	if form.spec.insert {
		base, _ = amd64VectorRegisterIndex(ins.Args[form.base].Reg, form.width)
	}
	selected := immediate % (form.width / form.spec.chunk) * form.spec.chunk
	var want uint64
	for output := 0; output < 64; output++ {
		defined := true
		if output < form.output {
			from, at := source, selected+output
			if form.spec.insert {
				from, at = base, output
				if output >= selected && output < selected+form.spec.chunk {
					from, at = source, output-selected
				}
			}
			defined = before.vectorBytes(from)>>uint(at)&1 != 0
			if form.mask >= 0 && !form.zeroing {
				defined = defined && before.vectorBytes(destination)>>uint(output)&1 != 0
			}
		}
		if defined {
			want |= uint64(1) << uint(output)
		}
	}
	return want
}

func TestX86ResultBlockTransferWholeCFGSelection(t *testing.T) {
	for _, otherBranch := range []string{"VZEROUPPER", "NOP"} {
		for _, selection := range []int{0, 1, 2, 3} {
			source := fmt.Sprintf(`TEXT ·view(SB),4,$0-12
MOVL a+0(FP),AX
MOVL AX,X0
CMPL AX,$0
JE other
VZEROUPPER
JMP joined
other:
%s
joined:
VEXTRACTF32X4 $%d,Z0,X1
PEXTRD $0,X1,AX
MOVL AX,ret+8(FP)
RET
`, otherBranch, selection)
			goAssemblerOracleOutput(t, "amd64", source, "", true)
			for _, api := range []string{"text", "module", "Go"} {
				_, err := x86ScalarFPBitViewAPI(t, source, "func view(a uint32) uint32\n", "amd64", "x86_64-unknown-linux-gnu", api)
				accepted := otherBranch == "VZEROUPPER" || selection == 0
				if accepted && err != nil {
					// Unknown unselected source bytes are not dependencies.
					t.Fatal("selected initialized chunk lost", api, otherBranch, selection, err)
				}
				if !accepted && !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("one predecessor or shape state defined the selected chunk", api, otherBranch, selection, err)
				}
			}
		}
	}
}

func TestX86ResultBlockTransferCompleteTypedForms(t *testing.T) {
	for _, row := range x86InsertExtractFormats() {
		if strings.HasSuffix(strings.Fields(row)[0], "PS") {
			continue // The four scalar forms have their own byte-lane suite.
		}
		t.Run(row, func(t *testing.T) {
			goAssemblerOracleOutput(t, "amd64", "TEXT f(SB),4,$0-0\n"+row+"\nRET\n", "", true)
			// FP here is an explicitly supplied numerical state, not native
			// backing for a real masked store or permission to skip its emitter.
			ins := x86ScalarLaneInstruction(t, strings.ReplaceAll(row, "(BX)", "a+0(FP)"))
			state := x86ResultState{fp: make([]bool, 64), flags: x86ByteFlagsAll}
			owned := make([]bool, 64)
			for index := range owned {
				owned[index], state.fp[index] = true, true
			}
			for register := range state.xmm {
				state.writeVector(register, 64, ^uint64(0), false)
			}
			for mask := range state.masks {
				state.masks[mask] = true
			}
			if !x86ScalarFPResultTransfer(ins, &state, owned, 0, "amd64") {
				t.Fatal("complete typed block format has no composable numerical effect")
			}
			if state.flags != x86ByteFlagsAll {
				t.Fatal("block transfer modified flags")
			}
		})
	}
}

func TestX86ResultBlockTransferEveryImmediateByteAndMerge(t *testing.T) {
	for _, row := range x86InsertExtractFormats() {
		if strings.HasSuffix(strings.Fields(row)[0], "PS") || strings.Contains(row, "(BX)") {
			continue
		}
		for immediate := 0; immediate < 256; immediate++ {
			ins := x86ScalarLaneInstruction(t, strings.Replace(row, "$255", fmt.Sprintf("$%d", immediate), 1))
			form, known, err := x86InsertExtractProperties(ins, "amd64")
			if !known || err != nil {
				t.Fatal(row, err)
			}
			source, _ := amd64VectorRegisterIndex(ins.Args[form.source].Reg, amd64VectorByteWidth(ins.Args[form.source].Reg))
			destination, _ := amd64VectorRegisterIndex(ins.Args[form.destination].Reg, form.output)
			base := -1
			if form.spec.insert {
				base, _ = amd64VectorRegisterIndex(ins.Args[form.base].Reg, form.width)
			}
			for input := 0; input < 3; input++ {
				register := []int{source, base, destination}[input]
				if register < 0 {
					continue
				}
				for missing := 0; missing < 64; missing++ {
					state := x86ResultState{masks: [8]bool{1: true}}
					for index := 0; index < 3; index++ {
						state.writeVector(index, 64, ^uint64(0), false)
					}
					state.writeVector(register, 64, ^(uint64(1) << uint(missing)), false)
					before := state.clone()
					want := x86ResultBlockTransferReference(ins, form, before, immediate)
					if !x86ResultBlockTransfer(ins, form, &state, nil, 0, "amd64") || state.vectorBytes(destination) != want {
						t.Fatalf("%s imm%d input%d byte%d: %016x want%016x", row, immediate, input, missing, state.vectorBytes(destination), want)
					}
				}
			}
		}
	}
}

func TestX86ResultBlockTransferMemoryAndMaskRemainBound(t *testing.T) {
	for _, chunk := range []int{16, 32} {
		suffix := map[int]string{16: "32X4", 32: "32X8"}[chunk]
		for _, insertion := range []bool{false, true} {
			row := "VINSERTF" + suffix + ".Z $0,a+0(FP),Z1,K1,Z2"
			if !insertion {
				row = "VEXTRACTF" + suffix + " $0,Z1,K1,a+0(FP)"
			}
			ins := x86ScalarLaneInstruction(t, row)
			for missing := -1; missing < 64; missing++ {
				for _, mask := range []bool{false, true} {
					state := x86ResultState{fp: make([]bool, 64), masks: [8]bool{1: mask}}
					state.writeVector(1, 64, ^uint64(0), false)
					owned := make([]bool, 64)
					for index := range owned {
						owned[index], state.fp[index] = true, index != missing
					}
					accepted := x86ResultTransfer(ins, &state, owned, 0, "amd64")
					if accepted != (mask && (missing < 0 || missing >= chunk)) {
						t.Fatal("mask/read/write erased a missing tuple byte", row, mask, missing)
					}
				}
			}
		}
	}
	for _, row := range []string{"VINSERTF32X4 $0,(AX),Z1,Z2", "VEXTRACTF32X8 $0,Z1,(AX)"} {
		state := x86ResultState{pointerGP: [16]bool{true}}
		state.writeVector(1, 64, ^uint64(0), false)
		if x86ResultTransfer(x86ScalarLaneInstruction(t, row), &state, nil, 0, "amd64") {
			t.Fatal("numerical transfer created a native read/write certificate", row)
		}
	}
}

func TestX86ResultBlockTransferMaskedStoreCannotBorrowReadAuthority(t *testing.T) {
	for _, chunk := range []int{16, 32} {
		for _, destination := range []string{"·data(SB)", "input+0(FP)", "result+32(FP)"} {
			for _, masked := range []bool{false, true} {
				mask := ""
				if masked {
					mask = "K1,"
				}
				row := fmt.Sprintf("VEXTRACTF32X%d $0,Z1,%s%s", chunk/4, mask, destination)
				ins := x86ScalarLaneInstruction(t, row)
				state := x86ResultState{fp: make([]bool, 64), masks: [8]bool{1: true}}
				state.writeVector(1, 64, ^uint64(0), false)
				owned := make([]bool, 64)
				for index := range owned {
					owned[index], state.fp[index] = true, true
				}
				operand := ins.Args[len(ins.Args)-1]
				if address, valid := x86StaticSBReadAddress(operand, "amd64"); valid {
					state.loweredStaticReads = map[x86StaticSBAddress]int64{address: int64(chunk)}
				}
				if !x86ResultRead(operand, int64(chunk), &state, owned, "amd64") {
					t.Fatal("fixture must supply complete numerical read authority", row)
				}
				accepted := x86ResultTransfer(ins, &state, owned, 32, "amd64")
				if accepted != (destination == "result+32(FP)") {
					t.Fatal("read authority changed the native or FP write envelope", row, accepted)
				}
			}
		}
	}
}

func TestX86ResultBlockTransferFiveTargetThreeAPIObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			var source, declarations strings.Builder
			count := 0
			for _, row := range x86InsertExtractFormats() {
				if strings.HasSuffix(strings.Fields(row)[0], "PS") || strings.Contains(row, "(BX)") {
					continue
				}
				if target.arch == "386" && (strings.HasPrefix(row, "VINSERT") || strings.Contains(row, "K1")) {
					continue // Go mode32 rejects four/five-operand named source.
				}
				ins := x86ScalarLaneInstruction(t, row)
				destination := ins.Args[len(ins.Args)-1].Reg
				fmt.Fprintf(&declarations, "func block%d() uint32\n", count)
				fmt.Fprintf(&source, "TEXT ·block%d(SB),4,$0-4\nVPXORQ Z0,Z0,Z0\nVPXORQ Z1,Z1,Z1\nVPXORQ Z2,Z2,Z2\nMOVL $7,AX\nKMOVW AX,K1\n%s\nPEXTRD $0,X%s,AX\nMOVL AX,ret+0(FP)\nRET\n", count, row, string(destination)[1:])
				count++
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
				if err != nil {
					t.Fatal(api, err)
				}
				compileLLVMToObject(t, llc, target.triple, "block-results.ll", "block-results.o", ir)
			}
		})
	}
}
