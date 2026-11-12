package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

type x86FloatingMinMaxRawCase struct {
	name, instruction string
	code              []byte
	evex              bool
	width             int
}

func x86FloatingMinMaxRawCases() []x86FloatingMinMaxRawCase {
	var rows []x86FloatingMinMaxRawCase
	for _, member := range x86FloatingMinMaxCases {
		pp := byte(0)
		if member.bits == 64 {
			pp++
		}
		if member.scalar {
			pp += 2
		}
		opcode := byte(0x5d)
		if strings.Contains(member.op, "MAX") {
			opcode = 0x5f
		}
		if member.legacy {
			code := []byte{0x0f, opcode, 0xd0}
			if pp != 0 {
				code = append([]byte{map[byte]byte{1: 0x66, 2: 0xf3, 3: 0xf2}[pp]}, code...)
			}
			rows = append(rows, x86FloatingMinMaxRawCase{member.op, member.op + " X0,X2", code, false, 16})
			continue
		}
		for _, generation := range []string{"VEX2", "VEX3", "EVEX"} {
			for _, width := range []int{16, 32, 64} {
				if member.scalar && width != 16 || generation != "EVEX" && width == 64 {
					continue
				}
				bank := map[int]string{16: "X", 32: "Y", 64: "Z"}[width]
				code := encodeX86VEXBinaryFloat(opcode, pp, generation == "VEX3", width == 32, false, 2, 1, 0)
				if generation == "EVEX" {
					code = encodeX86EVEXBinaryFloat(opcode, pp, byte(map[int]int{16: 0, 32: 1, 64: 2}[width]), false, false, 0, 2, 1, 0)
				}
				rows = append(rows, x86FloatingMinMaxRawCase{
					fmt.Sprintf("%s_%s_%d", member.op, generation, width),
					member.op + " " + bank + "0," + bank + "1," + bank + "2", code, generation == "EVEX", width,
				})
			}
		}
	}
	return rows
}

func x86FloatingMinMaxRawSource(row x86FloatingMinMaxRawCase) string {
	var source strings.Builder
	fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-0\n", row.name)
	bank := map[int]string{16: "X", 32: "Y", 64: "Z"}[row.width]
	for register := 0; register < 3; register++ {
		if strings.HasPrefix(row.name, "V") {
			fmt.Fprintf(&source, "VXORPS %s%d,%s%d,%s%d\n", bank, register, bank, register, bank, register)
		} else {
			fmt.Fprintf(&source, "XORPS X%d,X%d\n", register, register)
		}
	}
	source.WriteString(x86RawDisplacementDirectives(row.code))
	source.WriteString("RET\n")
	return source.String()
}

func TestX86FloatingMinMaxPhysicalGenerationAndWholeReplay(t *testing.T) {
	rows := x86FloatingMinMaxRawCases()
	if len(rows) != 48 {
		t.Fatal("incomplete independent legacy/VEX2/VEX3/EVEX physical directory", len(rows))
	}
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range rows {
			t.Run(arch+"/"+row.name, func(t *testing.T) {
				file, err := normalizeX86RawFile(mustParseX86RawReturn(t, x86FloatingMinMaxRawSource(row)), arch)
				if err != nil {
					t.Fatal(row.name, err)
				}
				fn := file.Funcs[0]
				ordinal := len(fn.Instrs) - 2
				ins := fn.Instrs[ordinal]
				f, known, err := x86FloatMinMaxProperties(ins, arch)
				if !known || err != nil || !x86RawFloatMinMaxSource(ins, arch) ||
					ins.x86SourceRaw.floatMinMax.arch != arch || ins.x86FloatMinMaxEVEX != row.evex ||
					x86FloatMinMaxNativeEVEX(ins, f) != row.evex {
					t.Fatal("physical MIN/MAX lost its mode/generation snapshot", row.name, err)
				}
				features := inferFuncTargetFeaturesForGOARCH(ArchAMD64, arch, Func{Instrs: []Instr{ins}})
				if strings.Contains(features, "+avx512f") != row.evex ||
					strings.Contains(features, "+avx512vl") != (row.evex && !f.scalar && row.width < 64) {
					t.Fatal("raw MIN/MAX lost its isolated original native ISA", row.name, features)
				}
				check := func(fn Func) error {
					ctx := newX86Ctx(new(strings.Builder), fn, FuncSig{Name: row.name, Ret: Void}, nil, nil,
						arch, map[string]string{"386": "i386-unknown-linux-gnu", "amd64": "x86_64-unknown-linux-gnu"}[arch], false)
					return ctx.checkLoweredScalarFPResultInitialization()
				}
				if err := check(fn); err != nil {
					t.Fatal("complete initialized raw program lost its paired native owner", row.name, err)
				}
				for _, control := range []struct {
					name string
					edit func(*Func)
				}{
					{"origin only", func(fn *Func) { fn.Instrs[ordinal].x86SourceRaw = nil }},
					{"physical generation", func(fn *Func) { fn.Instrs[ordinal].x86FloatMinMaxEVEX = !row.evex }},
					{"snapshot generation", func(fn *Func) { fn.Instrs[ordinal].x86SourceRaw.floatMinMax.evex = !row.evex }},
					{"absent snapshot", func(fn *Func) { fn.Instrs[ordinal].x86SourceRaw.floatMinMax = x86RawFloatMinMaxIdentity{} }},
					{"producer", func(fn *Func) { fn.Instrs[1].Raw += " " }},
					{"missing replay", func(fn *Func) { fn.x86RawReplay = nil }},
				} {
					changed := fn
					changed.Instrs = cloneX86ReplayInstrs(fn.Instrs)
					control.edit(&changed)
					if err := check(changed); !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("changed physical source bypassed the real lowering consumer", row.name, control.name, err)
					}
					if err := fn.x86RawReplay.validate(fn, arch); err != nil {
						t.Fatal("mutable replay clone corrupted original generation", err)
					}
				}
				if !x86ResultPreservesPrivateStorage(ins, arch) ||
					x86ResultDirectionAfterSource(ins, x86ResultDirectionBackward, arch) != x86ResultDirectionBackward {
					t.Fatal("exact MIN/MAX confused numerical writes with independent private or DF state")
				}
				var addresses [16]bool
				addresses[7] = true
				if x86ResultCallerAddressesAfter(ins, addresses, nil, arch) != addresses {
					t.Fatal("MIN/MAX changed an independently proved GP identity")
				}
			})
		}
	}
}

func TestX86FloatingMinMaxUnmaskedRawGenerationFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("complete raw MIN/MAX generation objects require LLVM22 llc")
	}
	var source, declarations strings.Builder
	for _, row := range x86FloatingMinMaxRawCases() {
		source.WriteString(x86FloatingMinMaxRawSource(row))
		fmt.Fprintf(&declarations, "func %s()\n", row.name)
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("initialized raw generation lost public native translation", err)
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
