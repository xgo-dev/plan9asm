package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestX86TernaryTypedGrammarActualGoCompleteRows(t *testing.T) {
	var source strings.Builder
	count := 0
	for _, op := range []string{"VPTERNLOGD", "VPTERNLOGQ"} {
		for _, bank := range []string{"X", "Y", "Z"} {
			for _, memory := range []string{bank + "29", "-64(AX)(CX*4)", "data+0(FP)", "·data(SB)"} {
				for _, mode := range []string{"", "merge", "zero", "broadcast", "broadcast_zero"} {
					broadcast := strings.HasPrefix(mode, "broadcast")
					if broadcast && memory == bank+"29" {
						continue
					}
					suffix, mask := "", ""
					if broadcast {
						suffix = ".BCST"
					}
					if mode == "merge" || mode == "zero" || mode == "broadcast_zero" {
						mask = ",K7"
					}
					if strings.HasSuffix(mode, "zero") {
						suffix += ".Z"
					}
					row := fmt.Sprintf("%s%s $255,%s,%s30%s,%s31", op, suffix, memory, bank, mask, bank)
					ins := x86ScalarLaneInstruction(t, row)
					if _, recognized, err := x86TernaryLogicProperties(ins.Op, ins, "amd64"); !recognized || err != nil {
						t.Fatal(row, err)
					}
					fmt.Fprintf(&source, "TEXT form%d(SB),4,$0-64\n%s\nRET\n", count, row)
					count++
				}
			}
		}
	}
	for _, target := range x86RawReturnTargets {
		if target.arch == "amd64" {
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
		} else {
			goAssemblerOracleOutput(t, target.arch, source.String(), "", false)
		}
	}
	t.Logf("%d independent Go opcode/width/source/mask/broadcast witnesses", count)
}

func TestX86TernaryTypedGrammarRejectsFabricatedOperands(t *testing.T) {
	for _, mutate := range []func(*Instr){
		func(ins *Instr) { ins.Args[0].ImmRaw = "unresolved" },
		func(ins *Instr) { ins.Args[0].ImmIsFloat = true },
		func(ins *Instr) { ins.Args[1].Mem.OffRaw = "unresolved" },
		func(ins *Instr) { ins.Args[1].Mem.IndexExt = "UXTW" },
		func(ins *Instr) { ins.Args[1].Mem.Index, ins.Args[1].Mem.Scale = CX, 3 },
		func(ins *Instr) { ins.Args[1].Mem.Index, ins.Args[1].Mem.Scale = SP, 1 },
		func(ins *Instr) { ins.Args[1].Mem.Base = "R16" },
		func(ins *Instr) { ins.Args[1].Mem.Off = 1 << 32 },
		func(ins *Instr) { ins.x86AddressBits = 32 },
		func(ins *Instr) { ins.x86UnboundAddressOverride = true },
	} {
		ins := x86ScalarLaneInstruction(t, "VPTERNLOGD $150,(AX),X1,X2")
		mutate(&ins)
		if _, known, err := x86TernaryLogicProperties(ins.Op, ins, "amd64"); !known || err == nil {
			t.Fatalf("fabricated source accepted: %#v", ins)
		}
		state := x86ResultState{}
		if x86ResultTransfer(ins, &state, nil, 0, "amd64") {
			t.Fatal("malformed source received numerical credit")
		}
	}
}

func TestX86TernaryNativeSegmentsAndUnboundAddresses(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	var source strings.Builder
	source.WriteString("TEXT ·view(SB),4,$0-0\n")
	for _, op := range []string{"VPTERNLOGD", "VPTERNLOGQ"} {
		for _, bank := range []string{"X", "Y", "Z"} {
			for _, memory := range []string{"8(AX)(FS)", "8(AX)(GS)"} {
				fmt.Fprintf(&source, "%s.BCST.Z $255,%s,%s1,K1,%s2\n", op, memory, bank, bank)
			}
		}
	}
	source.WriteString("RET\n")
	for _, target := range x86RawReturnTargets {
		if target.arch != "amd64" {
			continue // Both actual Go mode32 rejection axes are covered above.
		}
		// Retain the original twelve source rows, actual Go objects, both
		// segment address spaces and emitter objects. This source has neither
		// an initialized K1 nor a bound segment address; it is not a public
		// numerical or ABI success. Complete initialized ordinary-memory
		// counterparts live in the independent 54-row public object matrix.
		file, signatures := x86UnboundVoidFormatSources(t, source.String(), target.arch, target.triple)
		ir := x86ScalarFormatObjectUnit(t, file, signatures, target.arch, target.triple, 0)
		for _, space := range []string{"ptr addrspace(256)", "ptr addrspace(257)"} {
			if !strings.Contains(ir, space) {
				t.Fatal("original segment format address space erased", space)
			}
		}
		for _, level := range []string{"-O0", "-O2"} {
			x86PackedStringCompileObject(t, llc, target.triple, ir, level)
		}
	}
	for _, unbound := range []bool{false, true} {
		ins := x86ScalarLaneInstruction(t, "VPTERNLOGD $0,(AX),X1,X2")
		ins.x86AddressBits = 32
		ins.x86UnboundAddressOverride = unbound
		var output strings.Builder
		ctx := amd64Ctx{goarch: "amd64", b: &output}
		if _, _, err := ctx.lowerTernaryLogic(ins.Op, ins); !errors.Is(err, ErrProbeNeedsContext) || output.Len() != 0 {
			t.Fatal("unbound native memory emitted IR", err)
		}
	}
}
