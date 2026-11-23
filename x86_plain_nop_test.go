package plan9asm

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func x86PlainNOPSourceForms(arch string) []string {
	rows := []string{
		"NOP", "NOP $value+0(FP)", "NOP $local-8(SP)",
		"NOP AX", "NOP SP", "NOP R8", "NOP F0", "NOP F7", "NOP X0", "NOP X15",
		"NOP SPB", "NOP CR15", "NOP MAXREG",
		"NOP (AX)", "NOP (X1)", "NOP (AX)(SP*2)", "NOP 0x100000000(AX)",
		"NOP 16", "NOP value+0(FP)", "NOP local-8(SP)", "NOP data+4(SB)",
		"NOP data(SB)(CX*2)",
	}
	if arch == "amd64" {
		rows = append(rows, "NOP $data+4(SB)")
	} else {
		rows = append(rows, "NOP BPB", "NOP R8B", "NOP Z8", "NOP (AX)(X8*2)")
	}
	return rows
}

func TestX86PlainNOPCompleteGoRowsAndInertState(t *testing.T) {
	count := 0
	for _, row := range x86OfficialDirectiveRows(t) {
		if row.Opcode == "NOP" {
			count++
		}
	}
	if count != 9 {
		t.Fatalf("expected all nine ordered Go NOP rows, got %d", count)
	}
	for _, arch := range []string{"amd64", "386"} {
		forms := x86PlainNOPSourceForms(arch)
		source := "TEXT f(SB),4,$0-0\n" + strings.Join(forms, "\n") + "\nRET\n"
		if code := assembleX87ControlBytes(t, arch, source); !bytes.Equal(code, []byte{0xc3}) {
			t.Fatalf("%s NOP hints emitted bytes before RET: %x", arch, code)
		}
		file, err := Parse(ArchAMD64, source)
		if err != nil {
			t.Fatal(err)
		}
		ctx := newX86Ctx(new(strings.Builder), file.Funcs[0], FuncSig{Ret: Void}, nil, nil, arch, "", false)
		ctx.scanUsedRegs()
		if len(ctx.usedRegs) != 1 || !ctx.usedRegs[AX] ||
			len(ctx.usedXRegs)+len(ctx.usedYRegs)+len(ctx.usedZRegs)+len(ctx.usedKRegs) != 0 || ctx.usedX87 {
			t.Error("NOP hints must not allocate registers")
		}
		if _, _, used := ctx.classicFrameRange(); used {
			t.Error("NOP FP hints must not allocate a classic frame")
		}
		if lo, hi := ctx.stackOffsetRange(); lo != 0 || hi != 0 {
			t.Error("NOP SP hints must not change the stack extent", lo, hi)
		}
		for _, row := range forms {
			t.Run(arch+"/"+row, func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, row)
				effect, known, err := x86TypedGPByteEffect(ins.Op, ins, arch)
				if !known || err != nil || len(effect.operands) != 0 || effect.dynamicMemory ||
					effect.flagsRead != 0 || effect.flagsDefined != 0 || effect.flagsKilled != 0 {
					t.Fatalf("hint must have a validated empty effect: %+v, %t, %v", effect, known, err)
				}
				state := x86ResultState{fp: []bool{true, false}, flags: x86ByteFlagsAll, direction: x86ResultDirectionBackward}
				state.gp[0], state.pointerGP[2], state.xmm[3] = 0x03, true, 0x55aa
				before := state.clone()
				if !x86ResultTransfer(ins, &state, nil, 0, arch) || !reflect.DeepEqual(state, before) {
					t.Fatal("hint consumed or changed numerical or address state")
				}
				if _, _, valid := x86InstructionMemoryShape(ins, 0, arch); valid {
					t.Fatal("hint supplied a memory access")
				}
			})
		}
	}
}

func TestX86PlainNOPThreeAPIsFiveTargets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc is required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			body := strings.Join(x86PlainNOPSourceForms(target.arch), "\n")
			source := "TEXT ·Hint(SB),4,$0-4\nMOVL $7,AX\n" + body + "\nMOVL AX,X0\nMOVL X0,ret+0(FP)\nRET\n"
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source, "func Hint() uint32\n", target.arch, target.triple, api)
				if err != nil {
					t.Fatal(api, err)
				}
				x86ResultInitializationObject(t, llc, target.triple, ir, api)
			}
		})
	}
}

func TestX86PlainNOPRejectsBadFormsAndKeepsPrefixContext(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		triple := "x86_64-unknown-linux-gnu"
		if arch == "386" {
			triple = "i386-unknown-linux-gnu"
		}
		rejected := []string{
			"NOP $0", "NOP $0(AX)", "NOP $0(FS)", "NOP AX,BX",
			"NOP.Q AX", "NOP AL", "NOP M0", "NOP X16", "NOP Y0", "NOP K1", "NOP (AX)(X0*2)",
		}
		if arch == "386" {
			rejected = append(rejected, "NOP $data(SB)", "NOP g")
		} else {
			rejected = append(rejected, "NOP R8B", "NOP Z8", "NOP (AX)(X8*2)")
		}
		for _, row := range rejected {
			t.Run(arch+"/"+row, func(t *testing.T) {
				source := "TEXT ·Hint(SB),4,$0-0\n" + row + "\nRET\n"
				goAssemblerOracleOutput(t, arch, source, "", false)
				for _, api := range []string{"text", "module", "Go"} {
					if _, err := x86ScalarFPBitViewAPI(t, source, "func Hint()\n", arch, triple, api); err == nil {
						t.Errorf("%s accepted a form Go rejects", api)
					}
				}
			})
		}
		t.Run(arch+"/segment-prefix", func(t *testing.T) {
			source := "TEXT ·Hint(SB),4,$0-0\nNOP 0(FS)\nMOVL (AX),CX\nRET\n"
			if code := assembleX87ControlBytes(t, arch, source); !bytes.Equal(code, []byte{0x64, 0x8b, 0x08, 0xc3}) {
				t.Fatalf("Go listing must retain the prefix on the next instruction: %x", code)
			}
			for _, api := range []string{"text", "module", "Go"} {
				if _, err := x86ScalarFPBitViewAPI(t, source, "func Hint()\n", arch, triple, api); !errors.Is(err, ErrProbeNeedsContext) ||
					!strings.Contains(err.Error(), "prefix") {
					t.Errorf("%s must report the unbound prefix effect: %v", api, err)
				}
			}
		})
	}
}
