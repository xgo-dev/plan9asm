package plan9asm

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func x86BinaryFloatLiteralInput(t *testing.T, row x86RawVectorLiteralCase) (*File, Instr) {
	t.Helper()
	file, err := normalizeX86RawFile(mustParseX86RawReturn(t, x86RawVectorLiteralSource(row)), "amd64")
	if err != nil || len(file.Data) != 1 {
		t.Fatal("binary floating source lost its actual DATA pool", row.name, err)
	}
	for _, ins := range file.Funcs[0].Instrs {
		if ins.x86RIPLiteral {
			// These are intentionally distinct source coordinates: replay
			// owns the pre-relocation decoder operand; the module read owns
			// the actual allocated DATA symbol and complete source tuple.
			pending := Operand{Kind: OpSym, Sym: "·__plan9asm_raw_literal_pending(SB)"}
			if ins.x86SourceRaw == nil || !reflect.DeepEqual(ins.x86SourceRaw.args[0], pending) ||
				ins.Args[0].Sym == pending.Sym || ins.Args[0].Sym != ins.x86RIPMemoryRead.symbol {
				t.Fatal("decoder and module literal coordinates lost their independent binding", row.name)
			}
			return file, ins
		}
	}
	t.Fatal("missing original RIP operand", row.name)
	return nil, Instr{}
}

func TestX86RawBinaryFloatLiteralEveryInputByteAndTuple(t *testing.T) {
	for _, row := range x86RawBinaryFloatInitializedLiteralCases(t) {
		t.Run(row.name, func(t *testing.T) {
			_, ins := x86BinaryFloatLiteralInput(t, row)
			base := strings.Split(string(ins.Op), ".")[0]
			sqrt := strings.HasPrefix(base, "VSQRT")
			scalar := strings.HasSuffix(base, "SS") || strings.HasSuffix(base, "SD")
			bits := 32
			if strings.HasSuffix(base, "PD") || strings.HasSuffix(base, "SD") {
				bits = 64
			}
			width := amd64VectorByteWidth(ins.Args[len(ins.Args)-1].Reg)
			active, tuple := width, width
			if scalar {
				active = bits / 8
			}
			if scalar || strings.Contains(string(ins.Op), ".BCST") {
				tuple = bits / 8
			}
			address, valid := x86StaticSBReadAddress(ins.Args[0], "amd64")
			if !valid || !x86RawBinaryFloatLiteralForm(ins, "amd64") || x86RawBinaryFloatLiteralForm(ins, "386") ||
				ins.x86RIPMemoryRead.width != int64(tuple) {
				t.Fatal("typed literal lost its independent source or complete tuple", row.name)
			}
			for missing := -1; missing < 64; missing++ {
				state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionBackward,
					loweredStaticReads: map[x86StaticSBAddress]int64{address: int64(tuple)}}
				state.gp[5], state.pointerGP[7], state.callerAddressGP[7], state.masks[7] = 0x53, true, true, true
				input := ^uint64(0)
				if missing >= 0 {
					input &^= uint64(1) << uint(missing)
				}
				state.writeVector(0, 64, input, false)
				before := state // Keep this instruction's transient DATA scope, unlike a CFG clone.
				accepted := x86ScalarFPResultTransfer(ins, &state, nil, 0, "amd64")
				// SQRT's second source only transports scalar upper X bytes;
				// unknown passthrough stays unknown, not a missing arithmetic input.
				want := missing < 0 || sqrt || missing >= active
				if accepted != want {
					t.Fatal("literal invented a missing binary input byte", row.name, missing, accepted, want)
				}
				if want {
					value := x86CallerVectorByteMask(int64(width))
					if scalar {
						required := x86CallerVectorByteMask(int64(active))
						value = required | input&(0xffff&^required)
					}
					before.writeVector(0, width, value, false)
				}
				if !reflect.DeepEqual(state, before) {
					t.Fatal("literal changed FLAGS/addresses or invented passthrough bytes", row.name, missing)
				}
			}
			for _, control := range []string{"short DATA", "missing mask"} {
				if control == "missing mask" && len(ins.Args) != 4 {
					continue
				}
				state := x86ResultState{loweredStaticReads: map[x86StaticSBAddress]int64{address: int64(tuple)}}
				state.writeVector(0, 64, ^uint64(0), false)
				state.masks[7] = control != "missing mask"
				if control == "short DATA" {
					state.loweredStaticReads[address]--
				}
				if x86ScalarFPResultTransfer(ins, &state, nil, 0, "amd64") {
					t.Fatal("literal waived an actual DATA or mask input", row.name, control)
				}
			}
		})
	}
}

func TestX86RawBinaryFloatLiteralSourceAndPublicBoundaries(t *testing.T) {
	for _, row := range x86RawBinaryFloatInitializedLiteralCases(t) {
		t.Run(row.name, func(t *testing.T) {
			file, ins := x86BinaryFloatLiteralInput(t, row)
			for _, control := range []struct {
				name string
				edit func(*Instr)
			}{
				{"origin", func(ins *Instr) { ins.x86SourceRaw = nil }},
				{"original opcode", func(ins *Instr) { ins.x86SourceRaw.op = "VADDPS" }},
				{"original operand", func(ins *Instr) { ins.x86SourceRaw.args[0].Sym += "changed" }},
				{"width", func(ins *Instr) { ins.x86VectorBytes++ }},
				{"encoded", func(ins *Instr) { ins.x86Encoded = false }},
				{"tuple", func(ins *Instr) { ins.x86RIPMemoryRead.width-- }},
				{"address", func(ins *Instr) { ins.x86AddressBits = 32 }},
				{"segment", func(ins *Instr) { ins.x86SegmentPrefix = 0x64 }},
				{"return", func(ins *Instr) { ins.x86RawNearReturn = new(x86RawNearReturnForm) }},
			} {
				changed := cloneX86ReplayInstrs([]Instr{ins})[0]
				control.edit(&changed)
				if control.name == "original opcode" && ins.Op == "VADDPS" {
					changed.x86SourceRaw.op = "VMULPS"
				}
				if x86RawBinaryFloatLiteralForm(changed, "amd64") || !x86RawBinaryFloatLiteralForm(ins, "amd64") {
					t.Fatal("changed literal borrowed or corrupted original identity", row.name, control.name)
				}
			}
			if err := checkX86ScalarFPResultInitialization(file.Funcs[0], FuncSig{Name: row.name, Ret: Void}, "amd64"); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("standalone declaration acquired a same-module DATA owner", row.name, err)
			}
			source := x86RawVectorLiteralSource(row)
			changes := []string{
				strings.Replace(source, "$0-0", "$16-0", 1),
				strings.Replace(source, "BYTE ", "MOVQ $0,SP\nBYTE ", 1),
			}
			if !strings.HasPrefix(string(ins.Op), "VSQRT") {
				changes = append(changes, strings.Replace(source, "VPXORD Z0,Z0,Z0\n", "", 1))
			}
			if len(ins.Args) == 4 {
				changes = append(changes, strings.Replace(source, "KMOVD AX,K7\n", "", 1))
			}
			for _, changed := range changes {
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, changed, "func "+row.name+"()", "amd64", "x86_64-unknown-linux-gnu", api)
					if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("literal waived actual inputs or raw return/storage closure", row.name, api, err)
					}
				}
			}
			file.Data[0].Payload[0] ^= 1
			options := Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu",
				Sigs:       map[string]FuncSig{row.name: {Name: row.name, Ret: Void}},
				ResolveSym: func(name string) string { return strings.TrimPrefix(name, "·") }}
			if ir, err := Translate(file, options); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("literal accepted changed original DATA", row.name, err)
			}
		})
	}
}
