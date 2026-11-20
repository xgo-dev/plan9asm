package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"testing"
)

func TestX86NarrowPoppedWordCannotDefineUnwrittenHighBits(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		word, move := 8, "MOVQ"
		if target.arch == "386" {
			word, move = 4, "MOVL"
		}
		for _, control := range []struct {
			name, before string
			pass         bool
		}{
			{"unknown-high", "", false},
			{"narrow-high", "MOVW $0,AX\n", false},
			{"known-high", move + " $0,AX\n", true},
			{"zero-extended-high", "MOVL $0,AX\n", true},
		} {
			source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%sMOVL $1,DX\nCMPL DX,DX\nBTW $0,DX\nPUSHFW\nPOPW AX\nAND%s $65536,AX\n%s AX,ret+0(FP)\nRET\n", word, control.before, move[3:], move)
			goAssemblerOracleOutput(t, target.arch, source, "", true)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(target.triple+"/"+control.name+"/"+api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, "func Value() uintptr", target.arch, target.triple, api)
					if control.pass && (err != nil || ir == "") || !control.pass && (!errors.Is(err, ErrProbeNeedsContext) || ir != "") {
						t.Fatal("narrow POP invented or revoked unwritten GP bits", control.pass, err)
					}
				})
			}
		}
	}
}

func TestX86NativeBitTestExactStateAndIndependentAuthorities(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range x86BitTestOracleNames(arch) {
			for _, index := range []string{"$-128", "$127", "CX"} {
				ins := x86ScalarLaneInstruction(t, op+" "+index+",-1(DX)(BX*2)")
				for flags := uint8(0); flags <= x86ByteFlagsAll; flags++ {
					state := x86ResultState{flags: flags, direction: x86ResultDirectionBackward}
					state.gp[1], state.gp[3], state.pointerGP[2] = 0xff, 0xff, true
					want := state.clone()
					want.flags = flags&x86ByteFlagZF | x86ByteFlagCF
					if accepted, known := x86LoweredNativeBitTest(ins, &state, nil, arch); !accepted || !known || !reflect.DeepEqual(state, want) {
						t.Fatal("native BIT invented memory/GP/flags facts", arch, ins, state, want)
					}
				}
				for _, mutation := range []string{"unknown-base", "numerical-base", "unknown-index", "commuted-pointer", "physical", "address", "raw"} {
					if index != "CX" && mutation == "unknown-index" {
						continue
					}
					changed := ins
					state := x86ResultState{flags: x86ByteFlagsAll}
					state.gp[1], state.gp[3], state.pointerGP[2] = 0xff, 0xff, true
					switch mutation {
					case "unknown-base":
						state.pointerGP[2] = false
					case "numerical-base":
						state.pointerGP[2], state.gp[2] = false, 0xff
					case "unknown-index":
						state.gp[1] = 0
					case "commuted-pointer":
						state.pointerGP[2], state.gp[2], state.pointerGP[3], state.gp[3] = false, 0xff, true, 0
					case "physical":
						changed.x86Encoded = true
					case "address":
						changed.x86AddressBits = 16
					case "raw":
						changed.x86SourceRaw = new(x86SourceRawInstruction)
					}
					before := state.clone()
					if accepted, _ := x86LoweredNativeBitTest(changed, &state, nil, arch); accepted || !reflect.DeepEqual(state, before) {
						t.Fatal("native BIT accepted an unproved reaching role or changed rejected state", arch, op, index, mutation)
					}
				}
			}
		}
	}
}

func TestX86PoppedFlagWordImmediateMaskThreeAPIs(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, row := range []struct {
			suffix, typ string
			width       int
		}{
			{"W", "uint16", 2}, {"L", "uint32", 4}, {"Q", "uint64", 8},
		} {
			if target.arch == "amd64" && row.suffix == "L" || target.arch == "386" && row.suffix == "Q" {
				continue // These stack-width spellings are Go-rejected in this mode.
			}
			for _, control := range []struct {
				name, between string
				mask          int
				pass          bool
			}{
				{"CF-ZF", "", 65, true}, {"CF", "", 1, true}, {"ZF", "", 64, true}, {"zero", "", 0, true},
				{"unknown-PF", "", 69, false}, {"unknown-DF", "", 1024, false}, {"unknown-OF", "", 2048, false},
				{"overwritten", "MOV" + row.suffix + " BX,AX\n", 65, false},
			} {
				body := fmt.Sprintf("MOVL $1,DX\nCMPL DX,DX\nBTW $0,DX\nPUSHF%s\nPOP%s AX\n%sAND%s $%d,AX\nMOV%s AX,ret+0(FP)\nRET\n", row.suffix, row.suffix, control.between, row.suffix, control.mask, row.suffix)
				source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s", row.width, body)
				goAssemblerOracleOutput(t, target.arch, source, "", true)
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(target.triple+"/"+row.suffix+"/"+control.name+"/"+api, func(t *testing.T) {
						ir, err := x86ScalarFPBitViewAPI(t, source, "func Value() "+row.typ, target.arch, target.triple, api)
						if control.pass && (err != nil || ir == "") || !control.pass && (!errors.Is(err, ErrProbeNeedsContext) || ir != "") {
							t.Fatal("captured status mask lost or invented defined bits", control.pass, err)
						}
					})
				}
			}
		}
	}
}

func TestX86NativeBitTestCompleteReachingInputsThreeAPIs(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		word, move := 8, "MOVQ"
		if target.arch == "386" {
			word, move = 4, "MOVL"
		}
		for _, op := range x86BitTestOracleNames(target.arch) {
			for _, index := range []string{"$-128", "$127", "CX"} {
				body := fmt.Sprintf("%s p+0(FP),DX\n%s index+%d(FP),CX\n%s %s,(DX)\nSETCS AL\nMOVB AL,ret+%d(FP)\nRET\n", move, move, word, op, index, word*2)
				for _, control := range []struct {
					name, body string
					pass       bool
				}{
					{"complete", body, true},
					{"unknown-base", "NOP\n" + body[len(move+" p+0(FP),DX\n"):], false},
				} {
					source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s", word*2+1, control.body)
					goAssemblerOracleOutput(t, target.arch, source, "", true)
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(target.triple+"/"+op+"/"+index+"/"+control.name+"/"+api, func(t *testing.T) {
							ir, err := x86ScalarFPBitViewAPI(t, source, "func Value(p *byte,index uintptr) uint8", target.arch, target.triple, api)
							if control.pass && (err != nil || ir == "") || !control.pass && (!errors.Is(err, ErrProbeNeedsContext) || ir != "") {
								t.Fatal("native BIT reaching input class mismatch", control.pass, err)
							}
							if control.pass {
								llc := findLLVM22Tool("llc")
								if llc == "" {
									t.Fatal("LLVM22 llc required")
								}
								for _, level := range []string{"-O0", "-O2"} {
									x86PackedStringCompileObject(t, llc, target.triple, ir, level)
								}
							}
						})
					}
				}
			}
		}
	}
}
