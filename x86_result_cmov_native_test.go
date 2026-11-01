package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestX86CMOVNativeExactByteFlagsAndSourceState(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, name := range x86CMOVOracleNames(arch) {
			t.Run(arch+"/"+name, func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, name+" -1(SI)(BX*2),AX")
				width := map[byte]int64{'W': 2, 'L': 4, 'Q': 8}[name[4]]
				required := uint8(0)
				for _, row := range x86CMOVOracleConditions {
					if name[5:] == row.name {
						required = row.flags
					}
				}
				if required == 0 {
					t.Fatal("independent condition inventory lost a predicate")
				}
				seed := func() x86ResultState {
					state := x86ResultState{flags: x86ByteFlagsAll}
					state.gp[0], state.gp[3], state.pointerGP[6] = 0xff, 0xff, true
					return state
				}
				check := func(changed Instr, state x86ResultState, want bool) {
					t.Helper()
					before := state.clone()
					accepted, known := x86LoweredCMOVResultStep(changed, &state, nil, 0, arch)
					if accepted != want || !known || !reflect.DeepEqual(state, before) {
						t.Fatal("native CMOV changed an unrelated byte, FLAGS, address or failed state", accepted, want, known)
					}
					if x86ResultTransfer(changed, &before, nil, 0, arch) {
						t.Fatal("standalone result observer borrowed a paired native read")
					}
				}
				for flags := uint8(0); flags <= x86ByteFlagsAll; flags++ {
					state := seed()
					state.flags = flags
					check(ins, state, flags&required == required)
				}
				for missing := int64(0); missing < 8; missing++ {
					state := seed()
					state.gp[0] &^= 1 << uint(missing)
					// A successful L write independently clears the upper half.
					if width == 4 && missing >= 4 {
						if accepted, known := x86LoweredCMOVResultStep(ins, &state, nil, 0, arch); !known || !accepted || state.gp[0] != 0xff {
							t.Fatal("dword CMOV failed to zero-extend even on a false predicate")
						}
						continue
					}
					check(ins, state, missing >= width)
				}
				for _, origin := range []string{"raw", "decoded", "raw-return", "address-size", "unbound-address", "segment", "pointer-destination"} {
					changed, state := ins, seed()
					switch origin {
					case "raw":
						changed.x86SourceRaw = new(x86SourceRawInstruction)
					case "decoded":
						changed.x86Encoded = true
					case "raw-return":
						changed.x86RawNearReturn = new(x86RawNearReturnForm)
					case "address-size":
						changed.x86AddressBits = 32
					case "unbound-address":
						changed.x86UnboundAddressOverride = true
					case "segment":
						changed.x86SegmentPrefix = 0x64
					case "pointer-destination":
						state.pointerGP[0] = true
					}
					check(changed, state, false)
				}
			})
		}
	}
}

// The original initialized CMOV producer is shared with official byte rows.
// A different destination only selects a nonaliasing FLAGS observation scratch;
// it grants no predicate, pointer or source-memory permission.
func x86ConditionalMoveInitializedFunction(name, operation, destination, arch string) (string, string) {
	word, suffix := goWordSize(arch), "Q"
	if word == 4 {
		suffix = "L"
	}
	scratch := "BX"
	if destination == scratch {
		scratch = "DX"
	}
	source := fmt.Sprintf("TEXT ·%s(SB),4,$0-%d\nMOV%s p+0(FP),SI\n"+
		"MOV%s old+%d(FP),%s\nMOV%s out+%d(FP),DI\nMOV%s $11,CX\nPUSH%s flags+%d(FP)\nPOPF%s\n%s\n"+
		"PUSHF%s\nPOP%s %s\nMOV%s %s,(DI)\nMOV%s %s,ret+%d(FP)\nRET\n", name, 5*word, suffix,
		suffix, word, destination, suffix, 3*word, suffix, suffix, 2*word, suffix, operation, suffix, suffix, scratch, suffix, scratch, suffix, destination, 4*word)
	declaration := fmt.Sprintf("func %s(p *byte,old,flags uintptr,out *uintptr) uintptr\n", name)
	return source, declaration
}

func TestX86CMOVNativeCompleteFamilyFiveTargetObjects(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			word := goWordSize(target.arch)
			for _, raw := range []bool{false, true} {
				var source, declarations strings.Builder
				count := 0
				for _, name := range x86CMOVOracleNames(target.arch) {
					for _, operand := range []string{"(SI)", "CX"} {
						operation := name + " " + operand + ",AX"
						if raw {
							operation = x86RawNumericalInstruction(t, target.arch, operation)
						}
						function := fmt.Sprint("ConditionalRead", count)
						body, declaration := x86ConditionalMoveInitializedFunction(function, operation, "AX", target.arch)
						source.WriteString(body)
						declarations.WriteString(declaration)
						count++
					}
				}
				want := 96
				if word == 4 {
					want = 64
				}
				if count != want {
					t.Fatal("complete conditional register/memory data inventory changed", count)
				}
				x86RawNumericalFamilyObjects(t, source.String(), declarations.String(), target.arch, target.triple)
			}
		})
	}
}

func TestX86CMOVNativeCannotInventPotentialInputs(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		word, suffix := goWordSize(target.arch), "Q"
		if word == 4 {
			suffix = "L"
		}
		for _, name := range x86CMOVOracleNames(target.arch) {
			for _, role := range []string{"unknown-pointer", "numerical-pointer", "unknown-old", "unknown-flags", "unknown-index"} {
				setup := fmt.Sprintf("MOV%s p+0(FP),SI\nMOV%s old+%d(FP),AX\n"+
					"PUSH%s flags+%d(FP)\nPOPF%s\n", suffix, suffix, word, suffix, 2*word, suffix)
				memory := "(SI)"
				switch role {
				case "unknown-pointer":
					setup = strings.Replace(setup, fmt.Sprintf("MOV%s p+0(FP),SI\n", suffix), "", 1)
				case "numerical-pointer":
					setup = strings.Replace(setup, "p+0(FP)", fmt.Sprintf("old+%d(FP)", word), 1)
				case "unknown-old":
					setup = strings.Replace(setup, fmt.Sprintf("MOV%s old+%d(FP),AX\n", suffix, word), "", 1)
				case "unknown-flags":
					setup = strings.Replace(setup, fmt.Sprintf("PUSH%s flags+%d(FP)\nPOPF%s\n", suffix, 2*word, suffix), "", 1)
				case "unknown-index":
					memory = "(SI)(BX*2)"
				}
				source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s%s %s,AX\nRET\n", 3*word, setup, name, memory)
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, source, "func Value(p *byte,old,flags uintptr)", target.arch, target.triple, api)
					if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("native CMOV invented a potential input, including for Void", name, role, target.triple, api, err)
					}
				}
			}
		}
	}
}
