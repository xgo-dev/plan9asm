package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// This inventory is independent of the production opcode maps. Initialized
// dwords are deliberately narrower than X wherever the selected output permits.
type x86PackedShiftResultCase struct {
	row   string
	data  uint16
	count uint16
	lane  int
}

func x86PackedShiftResultRows() []x86PackedShiftResultCase {
	var rows []x86PackedShiftResultCase
	add := func(row string, data, count uint16, lane int) {
		rows = append(rows, x86PackedShiftResultCase{row, data, count, lane})
	}
	for _, op := range []string{"PSLLW", "PSLLL", "PSLLQ", "PSRLW", "PSRLL", "PSRLQ"} {
		add(op+" $7,X1", 0xffff, 0, 0)
		add(op+" X0,X1", 0xffff, 0x00ff, 0)
	}
	for _, op := range []string{"PSLLO", "PSLLDQ"} {
		add(op+" $12,X1", 0x000f, 0, 3)
	}
	for _, op := range []string{"PSRLO", "PSRLDQ"} {
		add(op+" $4,X1", 0x00f0, 0, 0)
	}
	for _, op := range []string{"VPSLLW", "VPSLLD", "VPSLLQ", "VPSRLW", "VPSRLD", "VPSRLQ"} {
		add(op+" $7,X1,X2", 0xffff, 0, 0)
		add(op+" X0,X1,X2", 0xffff, 0x00ff, 0)
	}
	for _, op := range []string{"VPSLLVW", "VPSLLVD", "VPSLLVQ", "VPSRLVW", "VPSRLVD", "VPSRLVQ"} {
		add(op+" X0,X1,X2", 0xffff, 0xffff, 0)
	}
	add("VPSLLDQ $12,X1,X2", 0x000f, 0, 3)
	add("VPSRLDQ $4,X1,X2", 0x00f0, 0, 0)
	add("PSRLQ $32,X1", 0x00f0, 0, 0)
	add("PSLLQ $32,X1", 0x000f, 0, 1)
	add("PSLLQ X0,X1", 0x000f, 0x00ff, 0)
	add("PSRLQ X0,X1", 0x00f0, 0x00ff, 1)
	add("VPSLLVQ X0,X1,X2", 0x000f, 0x00ff, 0)
	add("VPSRLVQ X0,X1,X2", 0x00f0, 0x00ff, 1)
	add("PSRLDQ $16,X1", 0, 0, 0)
	add("PSLLQ $64,X1", 0, 0, 0)
	return rows
}

func TestX86PackedShiftResultThreeAPIsFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	var source, declarations strings.Builder
	for index, row := range x86PackedShiftResultRows() {
		name := fmt.Sprint("shiftResult", index)
		fmt.Fprintf(&declarations, "func %s() uint32\n", name)
		fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-4\n%s\n", name,
			x86PackedShiftResultBody(row.row, row.data, row.count, row.lane, "ret+0(FP)"))
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
				if err != nil {
					t.Fatal(api, err)
				}
				compileLLVMToObject(t, llc, target.triple, "shift-result.ll", "shift-result.o", ir)
			}
		})
	}
}

func TestX86PackedShiftResultMemoryAndMaskBoundaries(t *testing.T) {
	for _, row := range []string{
		"PSRLQ (AX),X1", "PSRLQ a+0(FP),X1", "PSRLQ local-16(SP),X1",
		"VPSRLQ $255,(AX),X2", "VPSRLDQ $16,·data(SB),X2",
		"VPSRLVQ (AX),X1,X2", "VPSRLQ.BCST $64,(AX),X2",
		"PSRLQ $7,M1",
	} {
		ins := x86ScalarLaneInstruction(t, row)
		state := x86ResultState{fp: make([]bool, 16), auto: make([]bool, 16)}
		for i := range state.fp {
			state.fp[i], state.auto[i] = true, true
		}
		for i := range state.xmm {
			state.xmm[i] = 0xffff
		}
		owned := make([]bool, 16)
		for i := range owned {
			owned[i] = true
		}
		if x86ResultTransfer(ins, &state, owned, 16, "amd64") || len(ins.x86CallerMemory) != 0 {
			t.Fatal("numerical effect borrowed native/MMX permission", row)
		}
	}
	for _, row := range []string{"VPSRLQ $7,X1,K3,X2", "VPSRLQ.Z $7,X1,K3,X2"} {
		ins := x86ScalarLaneInstruction(t, row)
		for _, initialized := range []bool{false, true} {
			state := x86ResultState{}
			state.xmm[1], state.xmm[2], state.masks[3] = 0xffff, 0x5a5a, initialized
			accepted := x86ResultTransfer(ins, &state, nil, 0, "amd64")
			if accepted != initialized {
				t.Fatal("uninitialized mask was ignored", row)
			}
			if initialized {
				want := uint16(0x5a5a)
				if strings.Contains(row, ".Z") {
					want = 0xffff
				}
				if state.xmm[2] != want {
					t.Fatal("merge/zero effect", row, state.xmm[2], want)
				}
			}
		}
	}
	for _, body := range []string{
		"MOVL $7,AX\nPINSRD $0,AX,X1\nPSRLQ $1,X1\nPEXTRD $0,X1,AX\n",
		"MOVL $7,AX\nPINSRD $1,AX,X1\nPSRLDQ $3,X1\nPEXTRD $0,X1,AX\n",
		"MOVL $7,AX\nPINSRD $0,AX,X0\nPINSRD $0,AX,X1\nPSLLQ X0,X1\nPEXTRD $0,X1,AX\n",
	} {
		_, file, sig, source := x86ResultInitializationFixture(t, "amd64", "func Value() uint32", body+"MOVL AX,ret0+0(FP)\nRET")
		goAssemblerOracleOutput(t, "amd64", source, "", true)
		for _, check := range []func(Func, FuncSig, string) error{CheckX86ABI0ResultInitialization, checkX86ScalarFPResultInitialization} {
			if err := check(file.Funcs[0], sig, "amd64"); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("one missing dependency acquired a result", err)
			}
		}
	}
}

func TestX86PackedShiftResultOwnedMemoryStillNeedsFullNativeTuple(t *testing.T) {
	for _, fixture := range []struct {
		row   string
		width int
	}{
		{"VPSRLQ a+0(FP),X1,X2", 16},
		{"VPSRLVQ a+0(FP),X1,X2", 16},
		{"VPSRLVQ.BCST a+0(FP),X1,X2", 8},
		{"VPSRLQ $64,a+0(FP),X2", 16},
		{"VPSRLQ.BCST $64,a+0(FP),X2", 8},
		{"VPSRLDQ $16,a+0(FP),X2", 16},
	} {
		for _, auto := range []bool{false, true} {
			row := fixture.row
			if auto {
				row = strings.ReplaceAll(row, "a+0(FP)", "local-16(SP)")
			}
			goAssemblerOracleOutput(t, "amd64", "TEXT f(SB),4,$16-16\n"+row+"\nRET\n", "", true)
			ins := x86ScalarLaneInstruction(t, row)
			for missing := -1; missing < 16; missing++ {
				state := x86ResultState{fp: make([]bool, 16), auto: make([]bool, 16)}
				owned := make([]bool, 16)
				for i := range state.fp {
					state.fp[i], state.auto[i], owned[i] = i != missing, i != missing, true
				}
				state.xmm[1] = 0xffff
				accepted := x86ResultTransfer(ins, &state, owned, 16, "amd64")
				want := missing < 0 || missing >= fixture.width
				if accepted != want || accepted && state.xmm[2] != 0xffff || len(ins.x86CallerMemory) != 0 {
					t.Fatal("logical tuple/memory authority mismatch", row, missing, accepted, want)
				}
			}
		}
	}
}

func x86PackedShiftResultBody(row string, data, count uint16, lane int, result string) string {
	var body strings.Builder
	body.WriteString("MOVL $7,AX\n")
	for register, bytes := range []uint16{count, data} {
		for dword := 0; dword < 4; dword++ {
			if bytes&(15<<uint(dword*4)) != 0 {
				fmt.Fprintf(&body, "PINSRD $%d,AX,X%d\n", dword, register)
			}
		}
	}
	body.WriteString(row + "\n")
	destination := "X1"
	if strings.HasPrefix(row, "V") {
		destination = "X2"
	}
	fmt.Fprintf(&body, "PEXTRD $%d,%s,AX\nMOVL AX,%s\nRET", lane, destination, result)
	return body.String()
}

func TestX86PackedShiftResultIndependentWholeSources(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range x86PackedShiftResultRows() {
			t.Run(arch+"/"+row.row, func(t *testing.T) {
				body := x86PackedShiftResultBody(row.row, row.data, row.count, row.lane, "ret0+0(FP)")
				_, file, sig, source := x86ResultInitializationFixture(t, arch, "func Value() uint32", body)
				goAssemblerOracleOutput(t, arch, source, "", true)
				for _, check := range []func(Func, FuncSig, string) error{CheckX86ABI0ResultInitialization, checkX86ScalarFPResultInitialization} {
					if err := check(file.Funcs[0], sig, arch); err != nil {
						t.Error(err)
					}
				}
			})
		}
	}
}

func TestX86PackedShiftResultRejectsNonIntegerImmediate(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range []string{"PSRLQ $0.0,X1", "PSRLDQ $0.0,X1", "VPSRLQ $0.0,X1,X2", "VPSRLDQ $0.0,X1,X2", "PSRLQ $1.5,X1", "VPSRLQ $1.5,X1,X2"} {
			goAssemblerOracleOutput(t, arch, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n", "", false)
			ins := x86ScalarLaneInstruction(t, row)
			if _, known, err := x86PackedShiftProperties(ins.Op, ins, arch); !known || err == nil {
				t.Errorf("floating count accepted: %s %s", arch, row)
			}
		}
	}
}
