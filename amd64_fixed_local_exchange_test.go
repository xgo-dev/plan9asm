package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func fixedLocalExchangeState() x86FixedLocalState {
	return x86FixedLocalState{
		pointers: map[Reg]int64{SP: 0}, opaque: make(map[Reg]x86FixedLocalOrigins),
		opaqueCells: make(map[int64]x86FixedLocalOrigins), addresses: make(map[int64]int64),
		known: make(map[Reg]uint8), constants: make(map[Reg]int64),
		booleans: make(map[Reg]uint8), vectors: make(map[Reg]uint64),
		masks: make(map[Reg]bool), results: make(map[int]bool),
		bytes: newFixedLocalByteSet(64), booleanBytes: newFixedLocalByteSet(64),
		flags: x86ByteFlagsAll,
	}
}

func TestGoAMD64FixedLocalExchangeRegisters(t *testing.T) {
	registers := append(x86CommutedPointerAddRegisters("amd64"), BP)
	var source strings.Builder
	source.WriteString("TEXT ·Value(SB),4,$0-0\n")
	for _, width := range []struct {
		suffix string
		bytes  int64
	}{{"B", 1}, {"W", 2}, {"L", 4}, {"Q", 8}} {
		for _, first := range registers {
			for _, last := range registers {
				body := fmt.Sprintf("XCHG%s %s,%s", width.suffix, first, last)
				fmt.Fprintln(&source, body)
				t.Run(body, func(t *testing.T) {
					ins := x86ScalarLaneInstruction(t, body)
					if !fixedLocalInstructionShape(ins) {
						t.Fatal("existing typed exchange family is absent from fixed-frame shapes")
					}
					state := fixedLocalExchangeState()
					state.known[first], state.known[last] = 255, 255
					state.booleans[first], state.booleans[last] = 0x55, 0xaa
					oldFirst, oldLast := state.booleans[first], state.booleans[last]
					if err := fixedLocalStep(&ins, &state, FuncSig{}, &x86FixedLocalProof{frame: 64}, 0); err != nil {
						t.Fatal("initialized exchange rejected", err)
					}
					mask := uint8((1 << uint(width.bytes)) - 1)
					wantFirst, wantLast := oldFirst&^mask|oldLast&mask, oldLast&^mask|oldFirst&mask
					if width.bytes == 4 && !(first == AX && last == AX) {
						wantFirst, wantLast = wantFirst|240, wantLast|240
					}
					if state.booleans[first] != wantFirst || state.booleans[last] != wantLast ||
						state.known[first] != 255 || state.known[last] != 255 || state.flags != x86ByteFlagsAll {
						t.Fatal("swap lost byte identity, dword zero extension or FLAGS", state)
					}
				})
			}
		}
	}
	source.WriteString("RET\n")
	requireX86GoAssemblerResult(t, "amd64", source.String(), true)
}

func TestGoAMD64FixedLocalExchangeByteAliasesAndValues(t *testing.T) {
	for _, width := range []struct {
		suffix string
		bytes  int64
	}{{"B", 1}, {"W", 2}, {"L", 4}, {"Q", 8}} {
		for _, reg := range []Reg{AX, BX} {
			for missing := int64(0); missing < width.bytes; missing++ {
				t.Run(fmt.Sprintf("missing/%s/%s/%d", width.suffix, reg, missing), func(t *testing.T) {
					state := fixedLocalExchangeState()
					state.known[AX], state.known[BX] = 255, 255
					state.known[reg] &^= 1 << uint(missing)
					before := cloneFixedLocalState(state)
					ins := x86ScalarLaneInstruction(t, "XCHG"+width.suffix+" AX,BX")
					if err := fixedLocalStep(&ins, &state, FuncSig{}, &x86FixedLocalProof{frame: 64}, 0); !errors.Is(err, ErrProbeNeedsContext) || !reflect.DeepEqual(state, before) {
						t.Fatal("incomplete input mutated state or acquired initialized bytes", err)
					}
				})
			}
		}
	}
	for _, operands := range []string{"AH,AL", "AL,AH", "CH,CL", "CL,CH", "AH,BH", "AL,BL", "R11,R12", "SI,DI"} {
		t.Run(operands, func(t *testing.T) {
			ins := x86ScalarLaneInstruction(t, "XCHGB "+operands)
			state := fixedLocalExchangeState()
			for _, reg := range []Reg{AX, BX, CX, SI, DI, "R11", "R12"} {
				state.known[reg], state.booleans[reg] = 255, 0x55
				state.constants[reg] = 0x1234
				state.setRange(reg, x86UnsignedRange{1, 2})
			}
			before := cloneFixedLocalState(state)
			first, last := ins.Args[0], ins.Args[1]
			firstRoot, _ := x86CallerGP(first.Reg)
			lastRoot, _ := x86CallerGP(last.Reg)
			firstBits := fixedLocalBooleanRead(first, 1, &before)
			lastBits := fixedLocalBooleanRead(last, 1, &before)
			if err := fixedLocalStep(&ins, &state, FuncSig{}, &x86FixedLocalProof{frame: 64}, 0); err != nil {
				t.Fatal(err)
			}
			fixedLocalWriteBooleans(&before, first.Reg, 1, lastBits)
			fixedLocalWriteBooleans(&before, last.Reg, 1, firstBits)
			delete(before.constants, firstRoot)
			delete(before.constants, lastRoot)
			if !reflect.DeepEqual(state, before) {
				t.Fatal("overlapping aliases did not snapshot both inputs or revoke fullword facts", state, before)
			}
		})
	}
	for _, width := range []string{"W", "L", "Q"} {
		t.Run("accumulator NOP/"+width, func(t *testing.T) {
			state := fixedLocalExchangeState()
			state.opaque[AX] = fixedLocalOrigin(x86FixedLocalOrigin{parameter: 8})
			state.comparison = x86FixedLocalComparison{register: AX, constant: 7}
			before := cloneFixedLocalState(state)
			ins := x86ScalarLaneInstruction(t, "XCHG"+width+" AX,AX")
			if err := fixedLocalStep(&ins, &state, FuncSig{}, &x86FixedLocalProof{frame: 64}, 0); err != nil || !reflect.DeepEqual(state, before) {
				t.Fatal("Go opcode 90 is a NOP even for opaque or undefined bytes", err)
			}
		})
	}
}

func TestGoAMD64FixedLocalExchangeValueDomains(t *testing.T) {
	roles := []string{"number", "private", "incoming", "readonly"}
	for _, first := range roles {
		for _, last := range roles {
			t.Run(first+"/"+last, func(t *testing.T) {
				state := fixedLocalExchangeState()
				seed := func(reg Reg, role string, value int64) {
					switch role {
					case "number":
						state.known[reg], state.constants[reg], state.booleans[reg] = 255, value, 0xfe
						state.setRange(reg, x86UnsignedRange{uint64(value), uint64(value)})
					case "private":
						state.pointers[reg] = value
					case "incoming":
						state.opaque[reg] = fixedLocalOrigin(x86FixedLocalOrigin{parameter: value})
					case "readonly":
						state.opaque[reg] = fixedLocalOrigin(x86FixedLocalOrigin{literal: x86StaticSBAddress{symbol: "table<>(SB)", offset: value}})
					}
				}
				seed(AX, first, 8)
				seed(BX, last, 24)
				state.comparison = x86FixedLocalComparison{register: AX, constant: 31}
				before := cloneFixedLocalState(state)
				ins := x86ScalarLaneInstruction(t, "XCHGQ AX,BX")
				if err := fixedLocalStep(&ins, &state, FuncSig{}, &x86FixedLocalProof{frame: 64}, 0); err != nil {
					t.Fatal(err)
				}
				for _, pair := range [][2]Reg{{AX, BX}, {BX, AX}} {
					to, from := pair[0], pair[1]
					if state.known[to] != before.known[from] || state.booleans[to] != before.booleans[from] ||
						state.pointers[to] != before.pointers[from] || state.opaque[to] != before.opaque[from] ||
						state.constants[to] != before.constants[from] || state.ranges[to] != before.ranges[from] {
						t.Fatal("exchange lost a complete typed value or retained an old value", to, state, before)
					}
				}
				if state.comparison != (x86FixedLocalComparison{register: BX, constant: 31}) || state.flags != before.flags {
					t.Fatal("FLAGS must follow the same compared value after a full-word exchange", state.comparison)
				}
			})
		}
	}
}

func TestGoAMD64FixedLocalExchangeCompleteRoles(t *testing.T) {
	rows := []struct {
		name, body string
		input, ok  bool
	}{
		{"private pointers", "LEAQ 8(SP),R14\nLEAQ 24(SP),R15\nXCHGQ R15,R14\nMOVQ AX,(R14)\nMOVQ 24(SP),AX", false, true},
		{"private and NUM", "LEAQ 8(SP),CX\nMOVQ AX,DX\nXCHGQ CX,DX\nMOVQ CX,(DX)\nMOVQ 8(SP),AX", false, true},
		{"NUM and private", "LEAQ 8(SP),CX\nMOVQ AX,DX\nXCHGQ DX,CX\nMOVQ CX,(DX)\nMOVQ 8(SP),AX", false, true},
		{"old roles cannot survive swap", "LEAQ 8(SP),CX\nMOVQ AX,DX\nXCHGQ DX,CX\nMOVQ DX,(CX)\nMOVQ 8(SP),AX", false, false},
		{"private spill and NUM", "LEAQ 24(SP),CX\nMOVQ CX,8(SP)\nXCHGQ AX,8(SP)\nMOVQ 8(SP),DX\nMOVQ DX,(AX)\nMOVQ 24(SP),AX", false, true},
		{"NUM spill and private", "LEAQ 24(SP),CX\nXCHGQ 0(SP),CX\nMOVQ 0(SP),DX\nMOVQ CX,(DX)\nMOVQ 24(SP),AX", false, true},
		{"memory address uses old register", "MOVQ AX,8(SP)\nLEAQ 8(SP),CX\nXCHGQ CX,(CX)\nMOVQ 8(SP),DX\nMOVQ CX,(DX)\nMOVQ 8(SP),AX", false, true},
		{"native pointers", "XCHGQ SI,DI\nMOVQ (DI),AX", true, true},
		{"native and NUM", "XCHGQ SI,AX\nMOVQ (AX),AX", true, true},
		{"native spill", "MOVQ SI,8(SP)\nXCHGQ 8(SP),AX\nMOVQ (AX),AX", true, true},
		{"native private swap", "LEAQ 16(SP),CX\nXCHGQ SI,CX\nMOVQ (CX),AX\nMOVQ AX,(SI)\nMOVQ 16(SP),AX", true, true},
		{"constant index", "MOVQ $8,CX\nMOVQ $16,DX\nXCHGQ CX,DX\nMOVQ AX,(SP)(CX*1)\nMOVQ 16(SP),AX", false, true},
		{"flags preserved", "MOVQ AX,CX\nSTC\nXCHGQ AX,CX\nADCQ $0,AX", false, true},
		{"unknown register", "XCHGQ AX,CX", false, false},
		{"unknown memory", "XCHGQ AX,8(SP)", false, false},
		{"crossing frame", "XCHGQ AX,60(SP)", false, false},
		{"partial pointer", "MOVQ SP,CX\nXCHGW AX,CX", false, false},
		{"partial opaque", "XCHGL SI,AX", true, false},
		{"partial spill", "MOVQ SI,8(SP)\nXCHGL AX,8(SP)", true, false},
		{"pointer cannot escape", "LEAQ 8(SP),CX\nXCHGQ CX,(SI)", true, false},
		{"NUM not address", "XCHGQ AX,0(SP)\nMOVQ (AX),AX", false, false},
		{"pointer not NUM", "LEAQ 8(SP),CX\nXCHGQ AX,CX", false, false},
		{"stack register", "XCHGQ AX,SP", false, false},
		{"flags not invented", "MOVQ AX,CX\nXCHGQ AX,CX\nADCQ $0,AX", false, false},
	}
	for _, width := range []string{"B", "W", "L", "Q"} {
		for _, memory := range []string{"0(SP)", "3(SI)"} {
			for _, reverse := range []bool{false, true} {
				first, last := "AX", memory
				if reverse {
					first, last = last, first
				}
				rows = append(rows, struct {
					name, body string
					input, ok  bool
				}{"XCHG" + width + " " + first + "," + last, "XCHG" + width + " " + first + "," + last, memory == "3(SI)", true})
			}
		}
	}
	var source strings.Builder
	for index, row := range rows {
		fixture := fixedLocalGPFixture
		if row.input {
			fixture = fixedLocalInputFixture
		}
		fn, sig, original := fixture(t, row.body)
		source.WriteString(strings.Replace(original, "·Value", fmt.Sprintf("·Value%d", index), 1))
		t.Run(row.name, func(t *testing.T) {
			_, err := proveX86FixedLocal(fn, sig)
			if row.ok && err != nil || !row.ok && !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("complete typed exchange valid=%t: %v", row.ok, err)
			}
		})
	}
	requireX86GoAssemblerResult(t, "amd64", source.String(), true)
}

func TestGoAMD64FixedLocalExchangeCandidates(t *testing.T) {
	for _, row := range []struct {
		body string
		want bool
	}{
		{"MOVQ SP,CX\nXCHGQ DX,CX\nMOVQ (DX),AX", true},
		{"MOVQ SP,CX\nXCHGQ CX,DX\nMOVQ (DX),AX", true},
		{"MOVQ SP,CX\nXCHGQ CX,DX\nXCHGQ DX,R15\nMOVQ (R15),AX", true},
		{"XCHGQ CX,0(SP)", true},
		{"XCHGQ 0(SP),CX", true},
		{"XCHGB CX,0(SP)", true},
		{"XCHGW 0(SP),CX", true},
		{"XCHGL CX,0(SP)", true},
		{"MOVQ SP,CX\nXCHGL CX,DX\nMOVQ (DX),AX", false},
		{"MOVQ SI,CX\nXCHGQ CX,DX\nMOVQ (DX),AX", false},
		{"MOVQ SP,CX\nXCHGQ CX,DX", false},
		{"XCHGQ CX,scratch-8(SP)", false},
	} {
		t.Run(row.body, func(t *testing.T) {
			file, err := Parse(ArchAMD64, "TEXT ·Value(SB),4,$64-0\n"+row.body+"\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			if got := GoAMD64FixedLocalFrameBindingNeeded(file, "amd64"); got != row.want {
				t.Fatalf("candidate=%t, want %t", got, row.want)
			}
		})
	}
}

func TestX86ExchangeCallerOrigins(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		word, suffix := x86ResultPointerWord(arch), "Q"
		if arch == "386" {
			suffix = "L"
		}
		t.Run(arch+"/complete same-origin difference", func(t *testing.T) {
			body := fmt.Sprintf("MOV%s p+0(FP),AX\nMOV%s n+%d(FP),BX\nXCHG%s AX,BX\nADD%s AX,BX\nSUB%s p+0(FP),BX\nMOV%s BX,ret+%d(FP)\nRET", suffix, suffix, word, suffix, suffix, suffix, suffix, 2*word)
			_, file, sig, source := x86ResultInitializationFixture(t, arch, "func Value(p *byte,n uintptr) uintptr", body)
			requireX86GoAssemblerResult(t, arch, source, true)
			for _, check := range []func(Func, FuncSig, string) error{CheckX86ABI0ResultInitialization, checkX86ScalarFPResultInitialization} {
				if err := check(file.Funcs[0], sig, arch); err != nil {
					t.Fatal("swapped incoming pointer lost its complete original-source origin", err)
				}
			}
		})
		for _, operands := range []string{"AX,BX", "BX,AX", "AX,AX"} {
			t.Run(arch+"/"+operands, func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, "XCHG"+suffix+" "+operands)
				state := x86ResultState{callerAddressFP: map[int64]bool{0: true, word: true}}
				first, _, _ := x86ResultGP(AX, word, arch)
				last, _, _ := x86ResultGP(BX, word, arch)
				state.pointerGP[first], state.pointerGP[last] = true, true
				state.callerAddressGP[first], state.callerAddressGP[last] = true, true
				state.callerAddressOrigin[first], state.callerAddressOrigin[last] = 1, uint16(word+1)
				before := state.clone()
				if !x86ScalarFPResultTransfer(ins, &state, nil, 0, arch) {
					t.Fatal("existing typed whole-word swap rejected")
				}
				state.callerAddressGP = x86ResultCallerAddressesAfterTransfer(ins, before.callerAddressGP, state.callerAddressGP, state.callerAddressFP, arch)
				state.callerAddressOrigin = x86ResultCallerOriginsAfter(ins, before.callerAddressOrigin, state.callerAddressGP, state.callerAddressFP, arch)
				if operands != "AX,AX" {
					before.callerAddressOrigin[first], before.callerAddressOrigin[last] = before.callerAddressOrigin[last], before.callerAddressOrigin[first]
				}
				if state.callerAddressGP != before.callerAddressGP || state.callerAddressOrigin != before.callerAddressOrigin {
					t.Fatal("whole-word swap lost or invented incoming-pointer identity", state, before)
				}
			})
		}
	}
}

func TestX86ExchangeCanonicalBytes(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range []struct {
			body   string
			ax, bx uint8
		}{
			{"XCHGB AH,AL", 0x56, 0xaa},
			{"XCHGB AL,AH", 0x56, 0xaa},
			{"XCHGB AX,BX", 0x54, 0xab},
			{"XCHGW AX,BX", 0x56, 0xa9},
			{"XCHGL AX,BX", 0x5a, 0xa5},
			{"XCHGL AX,AX", 0x55, 0xaa},
			{"XCHGL BX,BX", 0x55, 0xaa},
			{"XCHGB AX,(SI)", 0x54, 0xaa},
			{"XCHGB (SI),AX", 0x54, 0xaa},
		} {
			t.Run(arch+"/"+row.body, func(t *testing.T) {
				before := [16]uint8{0: 0x55, 3: 0xaa, 6: 0x81}
				want := before
				want[0], want[3] = row.ax, row.bx
				if arch == "amd64" && strings.HasPrefix(row.body, "XCHGL") && row.body != "XCHGL AX,AX" {
					want[3] |= 240
					if row.body != "XCHGL BX,BX" {
						want[0] |= 240
					}
				}
				if got := x86RegisterCanonicalBytesAfter(x86ScalarLaneInstruction(t, row.body), before, arch); got != want {
					t.Fatal("independent canonical-byte domain did not follow the same typed swap", got, want)
				}
			})
		}
	}
}

func TestGoAMD64FixedLocalExchangeReadonlyAndRange(t *testing.T) {
	for _, row := range []struct {
		name, body string
		valid      bool
	}{
		{"readonly origin moves", "LEAQ literal<>(SB),CX\nMOVQ AX,DX\nXCHGQ CX,DX\nMOVQ (DX),AX", true},
		{"readonly remains readonly", "LEAQ literal<>(SB),CX\nMOVQ AX,DX\nXCHGQ CX,DX\nXCHGQ AX,(DX)", false},
		{"readonly extent unchanged", "LEAQ literal<>+240(SB),CX\nMOVQ AX,DX\nXCHGQ CX,DX\nMOVQ (DX),AX", false},
		{"range moves", fixedLocalRangePrefix + "MOVQ $0,CX\nXCHGQ R9,CX\n" + strings.ReplaceAll(fixedLocalRangeLoad, "R9", "CX"), true},
		{"comparison follows value", "MOVQ AX,R9\nMOVQ AX,CX\nCMPQ R9,$16\nXCHGQ R9,CX\nJAE done\nTESTQ CX,CX\nJE done\n" + strings.ReplaceAll(fixedLocalRangeLoad, "R9", "CX"), true},
	} {
		t.Run(row.name, func(t *testing.T) {
			fn, sig, _ := fixedLocalRangeFixture(t, row.body)
			_, err := proveX86FixedLocal(fn, sig)
			if row.valid && err != nil || !row.valid && !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("readonly/range value valid=%t: %v", row.valid, err)
			}
		})
	}
}
