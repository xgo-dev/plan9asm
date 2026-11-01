package plan9asm

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func TestX86ResultNumericalLEAIndexOnlyThreeAPIs(t *testing.T) {
	const source = "TEXT ·view<ABIInternal>(SB),4,$0-0\nLEAQ 0(BX*8),CX\nCMPQ CX,$0\nSETEQ AX\nRET\n"
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			_, err := x86ScalarFPBitViewAPI(t, source, "func view(x,y uint64) bool\n", "amd64", "x86_64-unknown-linux-gnu", api)
			if err != nil {
				t.Fatal("initialized NUM-only index LEA rejected:", err)
			}
		})
	}
}

func x86NumericalLEAWidths(arch string) []string {
	if arch == "386" {
		return []string{"W", "L"}
	}
	return []string{"W", "L", "Q"}
}

func x86NumericalLEAAddresses() []string {
	return []string{"(AX)", "-129(AX)", "127(AX)", "128(AX)", "2147483647(AX)", "-2147483648(AX)",
		"17(AX)(BX*1)", "17(AX)(BX*2)", "17(AX)(BX*4)", "17(AX)(BX*8)",
		"0(BX*1)", "-7(BX*2)", "128(BX*4)", "0(BX*8)", "17", "-7", "(1<<7)"}
}

func TestX86ResultNumericalLEACompleteIndependentGoRows(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	table := string(data)
	if !regexp.MustCompile(`(?s)var ym_rl = \[\]ytab\{\s*\{Zm_r, 1, argList\{Ym, Yrl\}\},\s*\}`).MatchString(table) {
		t.Fatal("complete Go LEA zcase/zoffset/classes changed")
	}
	rows := regexp.MustCompile(`\{A(LEA[WLQ]), ([^,]+), ([^,]+), opBytes\{([^}]+)\}\}`).FindAllStringSubmatch(table, -1)
	if len(rows) != 3 {
		t.Fatal("complete Go LEA family changed", len(rows))
	}
	for _, row := range rows {
		prefix := map[string]string{"LEAW": "Pe", "LEAL": "Px", "LEAQ": "Pw"}[row[1]]
		if row[2] != "ym_rl" || row[3] != prefix || row[4] != "0x8d" {
			t.Fatal("complete Go LEA attributes changed", row)
		}
	}
}

func TestX86ResultNumericalLEACompleteGoShapesAndEffects(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, width := range x86NumericalLEAWidths(arch) {
			for _, address := range x86NumericalLEAAddresses() {
				t.Run(arch+"/"+width+"/"+address, func(t *testing.T) {
					body := "LEA" + width + " " + address + ",CX"
					goAssemblerOracleOutput(t, arch, "TEXT f(SB),4,$0-0\n"+body+"\nRET\n", "", true)
					ins := x86PureGPUnknownInstruction(t, body)
					effect, known, err := x86TypedInstructionByteEffect(ins.Op, ins, arch)
					if !known || err != nil || effect.dynamicMemory || effect.flagsRead|effect.flagsDefined|effect.flagsKilled != 0 {
						t.Fatal("numerical LEA byte effect/unchanged FLAGS missing", known, err, effect)
					}
					last := effect.operands[len(effect.operands)-1]
					if !last.write || last.read || !reflect.DeepEqual(last.operand, Operand{Kind: OpReg, Reg: CX}) || last.width != x86LEAWidth(ins.Op, arch) {
						t.Fatal("LEA reads old destination or writes wrong bytes", last)
					}
					for _, input := range effect.operands[:len(effect.operands)-1] {
						if !input.read || input.write || input.operand.Kind != OpReg || input.width != last.width {
							t.Fatal("LEA effective address is not a numerical register dependency", input)
						}
					}
				})
			}
		}
	}
}

func TestX86ResultNumericalLEADefinedBytesFlagsAndAliases(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, width := range x86NumericalLEAWidths(arch) {
			for _, destination := range []string{"AX", "BX", "CX"} {
				ins := x86PureGPUnknownInstruction(t, "LEA"+width+" -7(AX)(BX*8),"+destination)
				for _, flags := range []uint8{0, x86ByteFlagCF, x86ByteFlagAF | x86ByteFlagPF, x86ByteFlagsAll} {
					state := x86ResultState{flags: flags}
					state.gp[0], state.gp[3] = 0xff, 0xff
					before := state.clone()
					if !x86ResultTransfer(ins, &state, nil, 0, arch) || state.flags != flags {
						t.Fatal("initialized LEA or preserved FLAGS rejected", arch, width, destination, state.flags)
					}
					root, mask, _ := x86ResultGP(Reg(destination), x86LEAWidth(ins.Op, arch), arch)
					if width == "L" || width == "Q" {
						mask = 0xff
					}
					before.gp[root] |= mask
					if !reflect.DeepEqual(before, state) {
						t.Fatal("LEA gained a non-numerical fact", arch, width, destination, state)
					}
				}
			}
		}
		word, move, typ := x86ResultPointerWord(arch), "MOVQ", "uint64"
		if arch == "386" {
			move, typ = "MOVL", "uint32"
		}
		for _, test := range []struct {
			name, body string
			accept     bool
		}{
			{"W low inputs", "MOVW $7,AX\nMOVW $9,BX\nLEAW -7(AX)(BX*8),CX\nMOVW CX,DX", true},
			{"W unknown upper", "MOVW $7,AX\nLEAW 0(AX*8),CX\n" + move + " CX,DX", false},
			{"L missing input", "MOVW $7,BX\nLEAL 0(BX*8),CX\nMOVL CX,DX", false},
			{"L clears old pointer", move + " p+0(FP),CX\nMOVL $7,BX\nLEAL 0(BX*8),CX\n" + move + " CX,DX", true},
			{"W old pointer remainder", move + " p+0(FP),CX\nMOVL $7,BX\nLEAW 0(BX*8),CX\n" + move + " CX,DX", false},
			{"unknown index", "LEAL 0(BX*8),CX\nMOVL CX,DX", false},
			{"unknown base", "MOVL $7,BX\nLEAL 0(AX)(BX*8),CX\nMOVL CX,DX", false},
			{"pointer index", move + " p+0(FP),BX\nLEAL 0(BX*8),CX\nMOVL CX,DX", false},
			{"pointer base as data", move + " p+0(FP),BX\nLEAL 0(BX),CX\nMOVL CX,DX", false},
		} {
			t.Run(arch+"/"+test.name, func(t *testing.T) {
				body := test.body + fmt.Sprintf("\nMOVW DX,ret0+%d(FP)\nRET", word)
				if strings.Contains(test.name, "unknown upper") || strings.Contains(test.name, "pointer remainder") {
					body = test.body + fmt.Sprintf("\n%s DX,ret0+%d(FP)\nRET", move, word)
				}
				result := "uint16"
				if strings.Contains(test.name, "unknown upper") || strings.Contains(test.name, "pointer remainder") {
					result = typ
				}
				_, file, sig, source := x86ResultInitializationFixture(t, arch, "func Value(p *byte) "+result, body)
				goAssemblerOracleOutput(t, arch, source, "", true)
				for _, check := range []func(Func, FuncSig, string) error{CheckX86ABI0ResultInitialization, checkX86ScalarFPResultInitialization} {
					err := check(file.Funcs[0], sig, arch)
					if test.accept && err != nil || !test.accept && !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("NUM-only/opaque/partial-byte boundary differs", test.accept, err)
					}
				}
			})
		}
	}
}

func TestX86ResultNumericalLEACanonicalBoolAndCompleteCFG(t *testing.T) {
	for _, test := range []struct {
		name, body string
		accept     bool
	}{
		{"canonical untouched", "MOVB $1,AX\nLEAQ 0(BX*8),CX", true},
		{"flags preserved", "CMPQ AX,BX\nLEAQ 0(BX*8),CX\nSETEQ AX", true},
		{"canonical overwritten W", "MOVB $1,AX\nLEAW 0(BX*8),AX", false},
		{"canonical overwritten L", "MOVB $1,AX\nLEAL 0(BX*8),AX", false},
		{"canonical overwritten Q", "MOVB $1,AX\nLEAQ 0(BX*8),AX", false},
		{"unknown dead LEA", "LEAQ 0(DX*8),CX\nMOVB $1,AX", false},
		{"unknown joined input", "CMPQ AX,BX\nJE one\nMOVQ $7,DX\nJMP joined\none:\nMOVW $7,DX\njoined:\nLEAQ 0(DX*8),CX\nSETEQ AX", false},
		{"complete joined input", "CMPQ AX,BX\nJE one\nMOVQ $7,DX\nJMP joined\none:\nMOVQ BX,DX\njoined:\nLEAQ 0(DX*8),CX\nSETEQ AX", true},
		{"no implicit FLAGS", "LEAQ 0(BX*8),CX\nSETEQ AX", false},
		{"no native memory", "LEAQ 0(BX*8),CX\nMOVQ (CX),DX\nCMPQ DX,$0\nSETEQ AX", false},
		{"no g fact", "LEAQ 0(R14*8),CX\nCMPQ CX,$0\nSETEQ AX", false},
		{"no physical SP fact", "LEAQ 0(SP),CX\nMOVB $1,AX", false},
		{"no physical BP fact", "LEAQ 0(BP),CX\nMOVB $1,AX", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			source := "TEXT ·view<ABIInternal>(SB),4,$0-0\n" + test.body + "\nRET\n"
			for _, api := range []string{"text", "module", "Go"} {
				_, err := x86ScalarFPBitViewAPI(t, source, "func view(x,y uint64) bool\n", "amd64", "x86_64-unknown-linux-gnu", api)
				if test.accept && err != nil || !test.accept && !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal(api, test.accept, err)
				}
			}
		})
	}
}

func TestX86ResultNumericalLEACompletePhysicalRegisterBank(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		registers := strings.Fields("AX CX DX BX SP BP SI DI")
		if arch == "amd64" {
			registers = append(registers, strings.Fields("R8 R9 R10 R11 R12 R13 R14 R15")...)
		}
		for _, width := range x86NumericalLEAWidths(arch) {
			for _, register := range registers {
				for _, body := range []string{
					"LEA" + width + " 7(" + register + "),CX",
					"LEA" + width + " 7(" + register + "*8),CX",
					"LEA" + width + " 7(AX)(BX*8)," + register,
				} {
					if register == "SP" && strings.Contains(body, "SP*8") {
						goAssemblerOracleOutput(t, arch, "TEXT f(SB),4,$0-0\n"+body+"\nRET\n", "", false)
						continue
					}
					goAssemblerOracleOutput(t, arch, "TEXT f(SB),4,$0-0\n"+body+"\nRET\n", "", true)
					ins := x86PureGPUnknownInstruction(t, body)
					_, known, err := x86TypedInstructionByteEffect(ins.Op, ins, arch)
					ordinary := register != "SP" && (register != "BP" || arch == "386")
					if ordinary && (!known || err != nil) || !ordinary && (known || err != nil) {
						t.Fatal("registered bank vs physical stack-role boundary", arch, body, known, err)
					}
				}
			}
		}
	}
}

func TestX86ResultNumericalLEARejectsOtherRolesAndUnknownInputs(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, width := range x86NumericalLEAWidths(arch) {
			for _, source := range []string{"slot+0(FP)", "tmp-8(SP)", "table(SB)", "0(FS)", "0(GS)", "0(TLS)", "1(PC)", "CONST(AX)"} {
				ins := x86PureGPUnknownInstruction(t, "LEA"+width+" "+source+",CX")
				if _, known, err := x86TypedInstructionByteEffect(ins.Op, ins, arch); source == "tmp-8(SP)" {
					if known || err != nil {
						t.Fatal("named NUM registration intercepted a specialized stack role", arch, known, err)
					}
				} else if !known || err == nil {
					t.Fatal("LEA granted another address/storage domain", arch, source, known, err)
				}
				if _, _, known := X86FPAccessBytes(ins, 0, arch); known {
					t.Fatal("LEA acquired an FP memory access width", arch, source)
				}
			}
			for _, args := range []string{"$1,CX", "AX,CX", "(AX),AL", "(AX),AH", "(AX),X0", "(AX),M0", "(AX),TLS", "(AX),(BX)", "(AX)", "(AX),BX,CX", "(AX)(BX*3),CX"} {
				body := "LEA" + width + " " + args
				goAssemblerOracleOutput(t, arch, "TEXT f(SB),4,$0-0\n"+body+"\nRET\n", "", false)
				file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+body+"\nRET\n")
				if err != nil {
					continue // Actual source rejected by both parsers, not a pass.
				}
				ins := file.Funcs[0].Instrs[1]
				if _, known, err := x86TypedInstructionByteEffect(ins.Op, ins, arch); !known || err == nil {
					t.Fatal("Go-rejected LEA row admitted", arch, body, known, err)
				}
			}
			// asmidx emits no source position. Reuse its exact tuple-bound
			// observer, never widen the generic actual-Go rejection oracle.
			unscaled := "LEA" + width + " 0(AX)(CX),DX"
			x86UnnamedScale0OriginalGoRejection(t, arch, "TEXT addr(SB),4,$0-0\n"+unscaled+"\nRET\n")
			ins := x86PureGPUnknownInstruction(t, unscaled)
			if _, known, err := x86TypedInstructionByteEffect(ins.Op, ins, arch); !known || err == nil {
				t.Fatal("unencodable missing scale became numerical LEA", known, err)
			}
		}
	}
	ins := x86PureGPUnknownInstruction(t, "LEAQ 0(BX*8),CX")
	for _, change := range []func(*Instr){
		func(i *Instr) { i.x86Encoded = true },
		func(i *Instr) { i.x86AddressBits = 32 },
		func(i *Instr) { i.x86UnboundAddressOverride = true },
		func(i *Instr) { i.x86SegmentPrefix = 0x64 },
		func(i *Instr) { i.x86RawNearReturn = &x86RawNearReturnForm{} },
	} {
		changed := ins
		change(&changed)
		if _, known, err := x86TypedInstructionByteEffect(changed.Op, changed, "amd64"); known || err != nil {
			t.Fatal("named NUM LEA intercepted a physical/source override", known, err)
		}
		bare := x86PureGPUnknownInstruction(t, "LEAQ 17,CX")
		change(&bare)
		if !reflect.DeepEqual(x86LEASourceInstruction(bare), bare) {
			t.Fatal("bare source displacement laundered a physical/source override")
		}
	}
	for _, op := range []Op{"LEAQ.Z", "LEAQ.SAE"} {
		changed := ins
		changed.Op = op
		if _, known, err := x86TypedInstructionByteEffect(op, changed, "amd64"); !known || err == nil {
			t.Fatal("LEA acquired a suffix", known, err)
		}
	}
	state := x86ResultState{}
	state.pointerGP[3], state.callerAddressGP[3] = true, true
	if x86ResultTransfer(ins, &state, nil, 0, "amd64") {
		t.Fatal("opaque/caller address index became numerical bytes")
	}
	for _, source := range []string{"LEAQ 0(DX*8),CX", "LEAW 0(AX),CX"} {
		unknown := x86PureGPUnknownInstruction(t, source)
		if x86LoweredPureGPUnknownTransfer(unknown, &state, "amd64") {
			t.Fatal("unknown-value fallback acquired LEA/address authority")
		}
	}
}

func TestX86ResultNumericalLEAOriginalIdentityAndPointerRuleIndependent(t *testing.T) {
	for _, source := range []string{"LEAQ 17,CX", "LEAL (1<<7),CX", "LEAQ (AX)(BX*8),CX"} {
		ins := x86PureGPUnknownInstruction(t, source)
		before := fmt.Sprintf("%#v", ins)
		state := x86ResultState{}
		state.gp[0], state.gp[3] = 0xff, 0xff
		if !x86ResultTransfer(ins, &state, nil, 0, "amd64") || before != fmt.Sprintf("%#v", ins) {
			t.Fatal("LEA effect changed original source/operand identity", source)
		}
	}
	ins := x86PureGPUnknownInstruction(t, "LEAQ 7(AX)(BX*8),CX")
	state := x86ResultState{}
	state.pointerGP[0], state.callerAddressGP[0], state.gp[3] = true, true, 0xff
	if !x86ResultTransfer(ins, &state, nil, 0, "amd64") || !state.pointerGP[1] || state.gp[1] != 0 {
		t.Fatal("separate caller address LEA became numerical or was disabled")
	}
	state = x86ResultState{}
	state.pointerGP[3], state.gp[0] = true, 0xff
	if x86ResultTransfer(ins, &state, nil, 0, "amd64") {
		t.Fatal("numerical base and opaque pointer index became a valid address")
	}
}

func TestX86ResultNumericalLEASharedCarryAndCanonicalConsumers(t *testing.T) {
	for _, op := range []string{"LEAW", "LEAL", "LEAQ"} {
		ins := x86PureGPUnknownInstruction(t, op+" -7(BX*8),CX")
		ctx := &amd64Ctx{goarch: "amd64"}
		carry := x86LockCarryState{carry: true}
		carry.gp[3] = 0xff
		next := ctx.lockCarryTransfer(ins, carry)
		if !next.carry || next.stackUnbound || next.gp[1] == 0 {
			t.Fatal("LEA lost known carry or numerical output", op, next)
		}
		carry.gp[3] = 0
		next = ctx.lockCarryTransfer(ins, carry)
		if !next.carry || next.gp[1]&15 != 0 {
			t.Fatal("LEA invented known numerical low bytes or changed carry", op, next)
		}
		canonical := [16]uint8{255, 255, 255, 255}
		nextCanonical := x86RegisterCanonicalBytesAfter(ins, canonical, "amd64")
		written := uint8(3)
		if op == "LEAL" {
			written = 15
		} else if op == "LEAQ" {
			written = 255
		}
		canonical[1] &^= written
		if !reflect.DeepEqual(nextCanonical, canonical) {
			t.Fatal("LEA canonicality did not kill exactly its computed bytes", op, nextCanonical, canonical)
		}
	}
}

func TestX86ResultNumericalLEAExistingStackFlagsConsumer(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		word, move, suffix := int64(8), Op("MOVQ"), "Q"
		if arch == "386" {
			word, move, suffix = 4, "MOVL", "L"
		}
		ins := x86PureGPUnknownInstruction(t, fmt.Sprintf("LEA%s -%d(BP),SP", suffix, 2*word))
		state := x86SourceStackState{callers: map[Reg]x86CallerPointerValue{}, known: map[Reg]uint8{}}
		state.bp = x86SourceStackAddress{offset: 0}
		x86SourceStackSetNumericFlags(&state, x86ByteFlagsAll)
		// These are the existing consumers in their actual order. The exact
		// stack address is proved first, not by the numerical descriptor.
		if !x86SourceStackAddressStep(&ins, &state, move, suffix, word) || state.sp != -2*word {
			t.Fatal("independent existing stack-address role was not exercised", arch)
		}
		if _, valid := x86CallerScalarStep(&ins, &state, &x86GoCallerRegionProof{}); !valid {
			t.Fatal("preceding stack proof lost its caller transfer", arch)
		}
		if !x86SourceStackFlagsStepForArch(ins, &state, arch) || x86SourceStackNumericFlagMask(&state) != x86ByteFlagsAll {
			t.Fatal("named numerical registration stole exact stack FLAGS delegation", arch)
		}
		numbers := x86ResultState{}
		if x86ResultTransfer(ins, &numbers, nil, 0, arch) {
			t.Fatal("specialized stack delegation became an unbound numerical fact", arch)
		}
	}
}
