package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// Independently encode all sixteen VEX memory forms: ModRM.reg is data,
// VEX.vvvv is the vector mask, and ModRM.r/m is the actual AX address.
func x86ExplicitMaskMoveIndependentBytes(row x86ExplicitMaskMoveCase) []byte {
	op := strings.Fields(row.instruction)[0]
	opcode := map[string]byte{"VMASKMOVPS": 0x2c, "VMASKMOVPD": 0x2d, "VPMASKMOVD": 0x8c, "VPMASKMOVQ": 0x8c}[op]
	prefix, modrm := byte(0x71), byte(0x10)
	if row.width == 32 {
		prefix |= 4
	}
	if op == "VPMASKMOVQ" {
		prefix |= 128
	}
	if row.memory == 2 {
		opcode |= 2
		modrm = 0
	}
	return []byte{0xc4, 0xe2, prefix, opcode, modrm}
}

func x86ExplicitMaskMoveRawProgram(row x86ExplicitMaskMoveCase, arch string) string {
	word, move := 8, "MOVQ"
	if arch == "386" {
		word, move = 4, "MOVL"
	}
	return fmt.Sprintf("TEXT ·%s(SB),4,$0-%d\n%s p+0(FP),AX\n%s data+%d(FP),BX\n"+
		"%s mask+%d(FP),CX\nVMOVDQU (BX),%s0\nVMOVDQU (CX),%s1\nSTC\n%sRET\n",
		row.name, word*3, move, move, word, move, word*2, row.bank, row.bank,
		x86RawDisplacementDirectives(x86ExplicitMaskMoveIndependentBytes(row)))
}

func TestX86ExplicitMaskMoveRawPhysicalIdentityAndWholeReplay(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range x86ExplicitMaskMoveIndependentCases() {
			t.Run(arch+"/"+row.name, func(t *testing.T) {
				code := x86ExplicitMaskMoveIndependentBytes(row)
				mode := map[string]int{"386": 32, "amd64": 64}[arch]
				ins, consumed, known, err := decodedX86ExplicitMaskMoveInstruction(code, mode)
				want := x86ScalarLaneInstruction(t, row.instruction)
				if !known || err != nil || consumed != len(code) || ins.Op != want.Op ||
					!reflect.DeepEqual(ins.Args, want.Args) || !ins.x86Encoded {
					t.Fatal("complete independently encoded VEX source lost its physical form", known, consumed, ins.Raw, err)
				}
				file, err := normalizeX86RawFile(mustParseX86RawReturn(t, x86ExplicitMaskMoveRawProgram(row, arch)), arch)
				if err != nil {
					t.Fatal(err)
				}
				fn := file.Funcs[0]
				ordinal := len(fn.Instrs) - 2
				if !x86RawExplicitMaskMoveSource(fn.Instrs[ordinal], arch) {
					t.Fatal("exact raw vector mask source lost its independent decoded identity")
				}
				word := x86ResultPointerWord(arch)
				sig := FuncSig{Name: row.name, Args: []LLVMType{Ptr, Ptr, Ptr}, Ret: Void}
				for index := 0; index < 3; index++ {
					sig.Frame.Params = append(sig.Frame.Params, FrameSlot{Offset: int64(index) * word, Type: Ptr, Index: index, Field: -1})
				}
				check := func(candidate Func) error {
					ctx := newX86Ctx(new(strings.Builder), candidate, sig, nil, nil,
						arch, map[string]string{"386": "i386-unknown-linux-gnu", "amd64": "x86_64-unknown-linux-gnu"}[arch], false)
					return ctx.checkLoweredScalarFPResultInitialization()
				}
				if err := check(fn); err != nil {
					t.Fatal("initialized raw source lost its exact paired original-opcode consumer", err)
				}
				for _, control := range []struct {
					name string
					edit func(*Func)
				}{
					{"origin-only", func(fn *Func) { fn.Instrs[ordinal].x86SourceRaw = nil }},
					{"encoded", func(fn *Func) { fn.Instrs[ordinal].x86Encoded = false }},
					{"snapshot", func(fn *Func) { fn.Instrs[ordinal].x86SourceRaw.explicitMaskMove = x86RawExplicitMaskMoveIdentity{} }},
					{"snapshot-mode", func(fn *Func) { fn.Instrs[ordinal].x86SourceRaw.explicitMaskMove.arch = "other" }},
					{"changed-mask", func(fn *Func) { fn.Instrs[ordinal].Args[1].Reg = Reg(row.bank + "3") }},
					{"producer", func(fn *Func) { fn.Instrs[1].Raw += " " }},
					{"missing-replay", func(fn *Func) { fn.x86RawReplay = nil }},
				} {
					changed := fn
					changed.Instrs = cloneX86ReplayInstrs(fn.Instrs)
					control.edit(&changed)
					if err := check(changed); !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("changed raw source bypassed the complete real lowering consumer", control.name, err)
					}
					if err := fn.x86RawReplay.validate(fn, arch); err != nil {
						t.Fatal("replay clone modified the sealed original source", err)
					}
				}
			})
		}
	}
}

func TestX86ExplicitMaskMoveInitializedRawFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("complete raw explicit mask move objects require LLVM22 llc")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			var source, declarations strings.Builder
			for _, row := range x86ExplicitMaskMoveIndependentCases() {
				source.WriteString(x86ExplicitMaskMoveRawProgram(row, target.arch))
				fmt.Fprintf(&declarations, "func %s(p,data,mask *byte)\n", row.name)
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("complete initialized raw vector-mask source lost its public paired consumer", err)
					}
					for _, pipeline := range []struct{ ir, level string }{
						{ir, "-O0"}, {ir, "-O2"}, {x86DwordProductIROptimize(t, ir), "-O2"},
					} {
						x86PackedStringCompileObject(t, llc, target.triple, pipeline.ir, pipeline.level)
					}
				})
			}
		})
	}
}
