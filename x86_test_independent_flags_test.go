package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// Independent inventory of the non-memory Go TEST rows. The existing compare
// grammar still owns mode, immediate direction, register classes and memory.
func x86TESTIndependentFlagCases(arch string) []string {
	var cases []string
	for _, suffix := range []string{"B", "W", "L", "Q"} {
		if arch == "386" && suffix == "Q" {
			continue
		}
		a, b := "AX", "DX"
		if suffix == "B" {
			a, b = "AL", "DL"
		}
		for _, operands := range []string{a + "," + a, b + "," + a, "$0," + a, "$-1," + a} {
			cases = append(cases, "TEST"+suffix+" "+operands)
		}
	}
	return append(cases, "TESTB AH,AL")
}

func TestX86TESTIndependentFlagsExactAvailability(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, body := range x86TESTIndependentFlagCases(arch) {
			for _, flags := range []uint8{0, x86ByteFlagsAll} {
				t.Run(fmt.Sprintf("%s/%s/flags%x", arch, body, flags), func(t *testing.T) {
					ins := x86PureGPUnknownInstruction(t, body)
					state := x86ResultState{flags: flags}
					// Unrelated partial numerical bytes must survive exactly;
					// TEST does not initialize even its own operand registers.
					state.gp[3] = 0x5a
					before := state.clone()
					strict := state.clone()
					if x86ScalarFPResultTransfer(ins, &strict, nil, 0, arch) {
						t.Fatal("strict observer accepted unavailable TEST data")
					}
					if !x86LoweredPureGPUnknownTransfer(ins, &state, arch) {
						t.Fatal("TEST lost its data-independent CF/OF writes")
					}
					before.flags = x86ByteFlagCF | x86ByteFlagOF
					if !reflect.DeepEqual(state, before) {
						t.Fatalf("TEST manufactured numerical/data-dependent availability: got GP=%x flags=%x, want GP=%x flags=%x",
							state.gp, state.flags, before.gp, before.flags)
					}
				})
			}
		}
	}
}

func TestX86TESTIndependentFlagsKeepStrictBoundaries(t *testing.T) {
	for _, body := range []string{
		"CMPB AL,AL", "CMPW AX,AX", "CMPL AX,AX", "CMPQ AX,AX",
		"TESTB AL,(DX)", "TESTW AX,(DX)", "TESTL AX,(DX)", "TESTQ AX,(DX)",
		"TESTB $0,(DX)", "TESTW $0,(DX)", "TESTL $0,(DX)", "TESTQ $0,(DX)",
		"TESTL x+0(FP),AX", "TESTL $MISSING,AX", "TESTL $1.0,AX",
	} {
		t.Run(body, func(t *testing.T) {
			state := x86ResultState{flags: x86ByteFlagsAll}
			before := state.clone()
			if x86LoweredPureGPUnknownTransfer(x86PureGPUnknownInstruction(t, body), &state, "amd64") ||
				!reflect.DeepEqual(state, before) {
				t.Fatal("TEST fallback skipped memory/grammar or accepted a data-dependent CMP")
			}
		})
	}
	for _, arch := range []string{"amd64", "386"} {
		for _, body := range x86TESTIndependentFlagCases(arch) {
			ins := x86PureGPUnknownInstruction(t, body)
			for _, mutation := range []string{"known", "pointer", "raw", "origin", "address", "segment"} {
				t.Run(arch+"/"+body+"/"+mutation, func(t *testing.T) {
					copy := ins
					state := x86ResultState{flags: x86ByteFlagsAll}
					switch mutation {
					case "known":
						for i := range state.gp {
							state.gp[i] = 0xff
						}
					case "pointer":
						state.pointerGP[0] = true
					case "raw":
						copy.x86Encoded = true
					case "origin":
						copy.x86SourceRaw = &x86SourceRawInstruction{}
					case "address":
						copy.x86AddressBits = 32
					case "segment":
						copy.x86SegmentPrefix = 0x64
					}
					before := state.clone()
					if x86LoweredPureGPUnknownTransfer(copy, &state, arch) || !reflect.DeepEqual(state, before) {
						t.Fatal("unpaired TEST or opaque pointer acquired fallback", mutation)
					}
				})
			}
			_, file, sig, _ := x86ResultInitializationFixture(t, arch, "func Value() uint32",
				body+"\nMOVL $37,ret0+0(FP)\nRET")
			for _, check := range []func(Func, FuncSig, string) error{
				CheckX86ABI0ResultInitialization, checkX86ScalarFPResultInitialization,
			} {
				if err := check(file.Funcs[0], sig, arch); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("declaration-only observer acquired lowering permission", arch, body, err)
				}
			}
		}
	}
}

// Read all four CF/OF predicates before any packing arithmetic changes FLAGS.
// CF=OF=0 therefore gives the independently specified result 0x01010000.
const x86TESTIndependentFlagPack = `SETCS AL
SETOS BL
SETCC CL
SETOC DL
MOVBLZX AL,AX
MOVBLZX BL,BX
MOVBLZX CL,CX
MOVBLZX DL,DX
SHLL $8,BX
SHLL $16,CX
SHLL $24,DX
ORL BX,AX
ORL CX,AX
ORL DX,AX
`

func x86TESTIndependentFlagSource(arch string) (string, string) {
	var source, declarations strings.Builder
	for index, body := range x86TESTIndependentFlagCases(arch) {
		fmt.Fprintf(&declarations, "func testFlags%d(seed uint64) uint64\n", index)
		// The actual scalar bit view selects the paired whole-source observer;
		// the seed is deliberately not imported as AX/DX numerical authority.
		fmt.Fprintf(&source, "TEXT ·testFlags%d(SB),4,$0-16\nMOVSS seed+0(FP),X0\n%s\n%sMOVL AX,ret+8(FP)\nMOVSS X0,ret+12(FP)\nRET\n",
			index, body, x86TESTIndependentFlagPack)
	}
	return source.String(), declarations.String()
}

func TestX86TESTIndependentFlagsThreeAPIs(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			source, declaration := x86TESTIndependentFlagSource(target.arch)
			goAssemblerOracleOutput(t, target.arch, source, "", true)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, api)
					if err != nil {
						t.Fatal(err)
					}
					compileLLVMToObject(t, llc, target.triple, "test-flags.ll", "test-flags.o", ir)
				})
			}
		})
	}
}

func TestX86TESTIndependentFlagsDoNotGrantDependentInputs(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for name, body := range map[string]string{
			"numerical": "MOVL AX,CX",
			"address":   "MOVL (AX),CX",
			"store":     "MOVL AX,(DX)",
			"memory":    "TESTL $0,(AX)",
			"ZF":        "SETEQ CL",
			"SF":        "SETMI CL",
			"PF":        "SETPS CL",
			"AF":        "LAHF",
			"branchZF":  "JE done\ndone:",
		} {
			t.Run(target.triple+"/"+name, func(t *testing.T) {
				source := "TEXT ·view(SB),4,$0-12\nMOVSS seed+0(FP),X0\nTESTL AX,AX\n" +
					body + "\nMOVSS X0,ret+8(FP)\nRET\n"
				for _, api := range []string{"text", "module", "Go"} {
					if _, err := x86ScalarFPBitViewAPI(t, source, "func view(seed uint64) uint32\n",
						target.arch, target.triple, api); !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("TEST supplied unavailable data/flags", api, err)
					}
				}
			})
		}
		for _, body := range x86TESTIndependentFlagCases(target.arch) {
			t.Run(target.triple+"/pointer/"+body, func(t *testing.T) {
				word, move := 8, "MOVQ"
				if target.arch == "386" {
					word, move = 4, "MOVL"
				}
				// A genuine incoming caller address already has a separate,
				// legal TEST predicate role. That is not NUM: even an output
				// subsequently overwritten must not import its pointer bits.
				source := fmt.Sprintf("TEXT ·view(SB),4,$0-%d\nMOVSS seed+%d(FP),X0\n%s p+0(FP),AX\n%s\nSETCS CL\nMOVL AX,ret+%d(FP)\nMOVSS X0,ret+%d(FP)\nRET\n",
					word+12, word, move, body, word+8, word+8)
				for _, api := range []string{"text", "module", "Go"} {
					if _, err := x86ScalarFPBitViewAPI(t, source, "func view(p *uint32,seed uint64) uint32\n",
						target.arch, target.triple, api); !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("TEST treated incoming pointer bits as a numerical input", api, err)
					}
				}
			})
		}
	}
}
