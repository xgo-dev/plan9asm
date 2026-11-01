package plan9asm

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

var x86LegacyIntegerArithmeticTestOpcodes = []byte{
	0xfc, 0xfd, 0xfe, 0xfe, 0xd4, 0xec, 0xed, 0xdc, 0xdd,
	0xf8, 0xf9, 0xfa, 0xfb, 0xe8, 0xe9, 0xd8, 0xd9,
}

func TestX86LegacyIntegerArithmeticGrammarEffectsAndNativeWidths(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, op := range x86LegacyIntegerArithmeticTestNames {
			for _, operands := range []string{"X0,X1", "X0,X0", "(AX),X1", "8(AX)(CX*4),X1", "a+0(FP),X1", "value-32(SP),X1", "·data(SB),X1", "(FS),X1", "(GS),X1"} {
				t.Run(arch+"/"+op+" "+operands, func(t *testing.T) {
					file, err := Parse(ArchAMD64, "TEXT ·Value(SB),4,$64-64\n"+op+" "+operands+"\nRET\n")
					if err != nil {
						t.Fatal(err)
					}
					ins := file.Funcs[0].Instrs[1]
					before := fmt.Sprintf("%#v", ins)
					form, recognized, err := x86LegacyIntegerArithmeticProperties(ins.Op, ins, arch)
					if !recognized || err != nil || form.byteWidth != 16 || form.mmx {
						t.Fatal("full accepted XMM row lost", form, err)
					}
					effect, recognized, err := x86TypedInstructionByteEffect(ins.Op, ins, arch)
					if !recognized || err != nil || len(effect.operands) != 2 || effect.flagsDefined != 0 || effect.flagsKilled != 0 {
						t.Fatal("legacy arithmetic lost its two inputs or unchanged flags", effect, err)
					}
					for index, role := range effect.operands {
						if role.index != index || role.width != 16 || !role.read || role.write != (index == 1) || !reflect.DeepEqual(role.operand, ins.Args[index]) {
							t.Fatalf("wrong ordered input/output bytes: %#v", role)
						}
						width, write, known := x86InstructionMemoryShape(ins, index, arch)
						if known != (form.memory == index) || known && (width != 16 || write) {
							t.Fatal("descriptor and native memory reader differ", width, write, known)
						}
						if ins.Args[index].Kind == OpFP {
							width, write, known = X86FPAccessBytes(ins, index, arch)
							if !known || width != 16 || write {
								t.Fatal("FP observer does not preserve full native read", width, write, known)
							}
						}
					}
					if strings.HasPrefix(op, "PADDS") || strings.HasPrefix(op, "PADDUS") {
						if x86CallerVectorMoveKnown(ins) || x86SourceStackInstructionKnown(ins, "MOVQ", "Q", arch) {
							t.Fatal("pure descriptor granted unproved saturating caller transport")
						}
					}
					if before != fmt.Sprintf("%#v", ins) {
						t.Fatal("shape observer changed original source")
					}
				})
			}
		}
	}
}

func TestX86LegacyIntegerArithmeticActualGoBytesAndMMXBank(t *testing.T) {
	for opIndex, op := range x86LegacyIntegerArithmeticTestNames {
		for _, arch := range []string{"amd64", "386"} {
			for _, operands := range []struct {
				text  string
				modrm byte
			}{
				{"X1,X0", 0xc1}, {"X0,X7", 0xf8}, {"(AX),X1", 0x08},
			} {
				t.Run(arch+"/"+op+" "+operands.text, func(t *testing.T) {
					source := "TEXT probe(SB),4,$0-0\n" + op + " " + operands.text + "\nRET\n"
					want := []byte{0x66, 0x0f, x86LegacyIntegerArithmeticTestOpcodes[opIndex], operands.modrm, 0xc3}
					if got := x86PackedShiftActualGoBytes(t, arch, source); !bytes.Equal(got, want) {
						t.Fatalf("original source width/opcode differs: %x want %x", got, want)
					}
				})
			}
		}
		if !strings.HasPrefix(op, "PADD") || op == "PADDQ" {
			continue
		}
		for index, spelling := range []string{"M0", "M1", "M2", "M3", "M4", "M5", "M6", "M7", "AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI", "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"} {
			t.Run("mmx/"+op+" "+spelling, func(t *testing.T) {
				source := "TEXT probe(SB),4,$0-0\n" + op + " " + spelling + ",M7\nRET\n"
				want := []byte{0x0f, x86LegacyIntegerArithmeticTestOpcodes[opIndex], 0xf8 | byte(index&7), 0xc3}
				if index >= 16 {
					want = append([]byte{0x41}, want...)
				}
				if got := x86PackedShiftActualGoBytes(t, "amd64", source); !bytes.Equal(got, want) {
					t.Fatalf("Go's GP spelling must name the physical MMX bank: %x want %x", got, want)
				}
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				ins := file.Funcs[0].Instrs[1]
				effect, recognized, err := x86TypedInstructionByteEffect(ins.Op, ins, "amd64")
				if !recognized || err != nil || effect.operands[0].width != 8 || effect.operands[0].operand.Reg != Reg(fmt.Sprintf("M%d", index&7)) {
					t.Fatal("pure effects confused a numeric GP with a physical MMX input", effect, err)
				}
				state := x86ResultState{flags: x86ByteFlagsAll}
				for i := range state.gp {
					state.gp[i] = 0xff
				}
				if x86ResultTransfer(ins, &state, nil, 0, "amd64") {
					t.Fatal("initialized GP bytes fabricated MMX input/output permission")
				}
			})
		}
	}
}

func TestX86ABI0ResultLegacyIntegerArithmeticPartialBytesAndFlags(t *testing.T) {
	for _, op := range x86LegacyIntegerArithmeticTestNames {
		ins := Instr{Op: Op(op), Args: []Operand{{Kind: OpReg, Reg: "X1"}, {Kind: OpReg, Reg: "X0"}}}
		for source := 0; source < 2; source++ {
			for missing := 0; missing < 16; missing++ {
				t.Run(fmt.Sprintf("%s/input%d/byte%d", op, source, missing), func(t *testing.T) {
					state := x86ResultState{flags: x86ByteFlagsAll}
					state.xmm[0], state.xmm[1] = 0xffff, 0xffff
					state.xmm[1-source] &^= uint16(1) << uint(missing)
					if x86ResultTransfer(ins, &state, nil, 0, "amd64") {
						t.Fatal("read-modify-write borrowed one missing input byte")
					}
				})
			}
		}
		for flags := uint8(0); flags <= x86ByteFlagsAll; flags++ {
			state := x86ResultState{flags: flags}
			state.xmm[0], state.xmm[1] = 0xffff, 0xffff
			if !x86ResultTransfer(ins, &state, nil, 0, "amd64") || state.flags != flags || state.xmm[0] != 0xffff || state.xmm[1] != 0xffff {
				t.Fatal("legacy lane arithmetic altered flags or byte aliases", op, flags, state)
			}
		}
		body := "MOVSS a+0(FP),X1\nMOVL $1,AX\nCMPL AX,$0\nJE partial\nMOVSD a+0(FP),X0\nJMP joined\npartial:\nMOVSS X1,X0\njoined:\n" + op + " X1,X0\nMOVSD X0,ret0+8(FP)\nRET"
		file, sig, _ := x86ResultAUTOFixture(t, "amd64", "func Value(a uint64) uint64", 64, body)
		if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, "amd64"); !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("partial destination path became initialized", op, err)
		}
	}
}

func TestX86LegacyIntegerArithmeticThreeAPIFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range []struct{ arch, triple string }{
		{"amd64", "x86_64-apple-darwin"}, {"amd64", "x86_64-unknown-linux-gnu"}, {"amd64", "x86_64-pc-windows-msvc"},
		{"386", "i386-unknown-linux-gnu"}, {"386", "i686-pc-windows-msvc"},
	} {
		for _, op := range x86LegacyIntegerArithmeticTestNames {
			t.Run(target.triple+"/"+op, func(t *testing.T) {
				body := "MOVSD a+0(FP),X0\nMOVSD c+16(FP),X1\n" + op + " X1,X0\n" + op + " X0,X0\nMOVSD X0,ret0+32(FP)\nRET"
				pkg, file, sig, source := x86ResultInitializationFixture(t, target.arch, "func Value(a,b,c,d uint64) uint64", body)
				goAssemblerOracleOutput(t, target.arch, source, "", true)
				if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, target.arch); err != nil {
					t.Fatal(err)
				}
				options := Options{Goarch: target.arch, TargetTriple: target.triple, Sigs: map[string]FuncSig{"Value": sig},
					ResolveSym: func(symbol string) string { return strings.TrimPrefix(symbol, "·") }}
				before := fmt.Sprintf("%#v %#v", file, sig)
				ir, err := Translate(file, options)
				if err != nil {
					t.Fatal(err)
				}
				x86ResultInitializationObject(t, llc, target.triple, ir, "text")
				ctx := llvm.NewContext()
				defer ctx.Dispose()
				module, err := TranslateModuleInContext(ctx, file, options)
				if !module.IsNil() {
					defer module.Dispose()
				}
				if err != nil {
					t.Fatal(err)
				}
				x86ResultInitializationObject(t, llc, target.triple, module.String(), "module")
				translated, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{
					GOARCH: target.arch, TargetTriple: target.triple, ResolveSym: options.ResolveSym,
				})
				if translated != nil && !translated.Module.IsNil() {
					defer translated.Module.Dispose()
				}
				if err != nil {
					t.Fatal(err)
				}
				x86ResultInitializationObject(t, llc, target.triple, translated.Module.String(), "typed-go")
				if before != fmt.Sprintf("%#v %#v", file, sig) {
					t.Fatal("API changed original inputs")
				}
			})
		}
	}
}

func TestX86LegacyIntegerArithmeticMalformedFormsAndIdentity(t *testing.T) {
	for _, op := range x86LegacyIntegerArithmeticTestNames {
		for _, operands := range []string{"$1,X0", "X0,(AX)", "Y0,Y1", "Z0,Z1", "X16,X0", "(AX),(BX)", "X0,K1,X1"} {
			file, err := Parse(ArchAMD64, "TEXT probe(SB),4,$0-0\n"+op+" "+operands+"\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			ins := file.Funcs[0].Instrs[1]
			if _, recognized, err := x86TypedInstructionByteEffect(ins.Op, ins, "amd64"); !recognized || err == nil {
				t.Fatal("malformed row acquired effects", ins, err)
			}
		}
		file, err := Parse(ArchAMD64, "TEXT probe(SB),4,$0-0\n"+op+" X0,X1\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		for _, identity := range []Op{"", Op(op), Op(strings.ToLower(op))} {
			ins := file.Funcs[0].Instrs[1]
			ins.Op = identity
			if _, recognized, err := x86LegacyIntegerArithmeticProperties(Op(op), ins, "amd64"); !recognized || err != nil {
				t.Fatal("matching dispatch lost compatibility", identity, err)
			}
		}
		ins := file.Funcs[0].Instrs[1]
		ins.Op = "MOVQ"
		if _, recognized, err := x86TypedInstructionByteEffect(Op(op), ins, "amd64"); !recognized || err == nil {
			t.Fatal("contradictory dispatch obtained effects", err)
		}
		ctx, output := newAMD64CtxWithFuncForTest(t, file.Funcs[0], FuncSig{Ret: Void}, nil)
		before := output.String()
		var known bool
		if strings.HasPrefix(op, "PADD") {
			known, _, err = ctx.lowerPackedIntegerAdd(Op(op), ins)
		} else {
			known, _, err = ctx.lowerPackedIntegerSubtract(Op(op), ins)
		}
		if !known || err == nil || output.String() != before {
			t.Fatal("contradictory dispatch changed IR before rejection", op, known, err)
		}
		for _, operands := range []string{"X8,X0", "X0,X15"} {
			source := "TEXT probe(SB),4,$0-0\n" + op + " " + operands + "\nRET\n"
			goAssemblerOracleOutput(t, "386", source, "", false)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			ins := file.Funcs[0].Instrs[1]
			if _, recognized, err := x86TypedInstructionByteEffect(ins.Op, ins, "386"); !recognized || err == nil {
				t.Fatal("mode32 acquired an unavailable physical X bank", op, err)
			}
		}
	}
}

func TestX86ABI0ResultLegacyIntegerArithmeticDoesNotBorrowPermission(t *testing.T) {
	for _, op := range x86LegacyIntegerArithmeticTestNames {
		for name, body := range map[string]string{
			"source unknown":          "MOVSD a+0(FP),X0\n" + op + " X2,X0\nMOVSD X0,ret0+32(FP)\nRET",
			"old destination unknown": "MOVSD a+0(FP),X1\n" + op + " X1,X0\nMOVSD X0,ret0+32(FP)\nRET",
			"native pointer":          "MOVSD a+0(FP),X0\nMOVQ a+0(FP),AX\n" + op + " (AX),X0\nMOVSD X0,ret0+32(FP)\nRET",
			"AUTO partial":            "MOVSD a+0(FP),X0\nMOVQ $1,value-32(SP)\n" + op + " value-32(SP),X0\nMOVSD X0,ret0+32(FP)\nRET",
			"FP gap or result":        "MOVSD a+0(FP),X0\n" + op + " b+28(FP),X0\nMOVSD X0,ret0+32(FP)\nRET",
			"call kills facts":        "MOVSD a+0(FP),X0\nMOVSD c+16(FP),X1\nCALL ·Other(SB)\n" + op + " X1,X0\nMOVSD X0,ret0+32(FP)\nRET",
			"dead unbound call":       "MOVSD a+0(FP),X0\nMOVSD c+16(FP),X1\n" + op + " X1,X0\nMOVSD X0,ret0+32(FP)\nRET\nCALL ·Unknown(SB)\nRET",
			"escape logical AUTO":     "MOVSD a+0(FP),X0\nMOVSD c+16(FP),X1\nLEAQ value-32(SP),AX\n" + op + " X1,X0\nMOVSD X0,ret0+32(FP)\nRET",
		} {
			t.Run(op+"/"+name, func(t *testing.T) {
				file, sig, _ := x86ResultAUTOFixture(t, "amd64", "func Value(a,b,c,d uint64) uint64", 64, body)
				if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, "amd64"); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("pure arithmetic effects fabricated initialization or backing", err)
				}
			})
		}
		t.Run(op+"/dead modeled timestamp", func(t *testing.T) {
			// RDTSC has a complete implicit-output effect now. Retain its
			// positive source-wide control instead of calling it unknown.
			body := "MOVSD a+0(FP),X0\nMOVSD c+16(FP),X1\n" + op +
				" X1,X0\nMOVSD X0,ret0+32(FP)\nRET\nRDTSC\nRET"
			file, sig, _ := x86ResultAUTOFixture(t, "amd64", "func Value(a,b,c,d uint64) uint64", 64, body)
			if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, "amd64"); err != nil {
				t.Fatal("modeled dead timestamp lost its closed source effect", err)
			}
		})
	}
}
