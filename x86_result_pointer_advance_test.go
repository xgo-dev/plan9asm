package plan9asm

import (
	"errors"
	"fmt"
	"testing"
)

func TestX86IncomingPointerUnaryAdvanceWholeSourceThreeAPIs(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		word, move, suffix := goWordSize(target.arch), "MOVQ", "Q"
		if target.arch == "386" {
			move, suffix = "MOVL", "L"
		}
		for _, stem := range []string{"INC", "DEC"} {
			for _, scenario := range []string{"projection", "native-read", "unknown", "unknown-CF", "partial", "result-address"} {
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(target.triple+"/"+stem+"/"+scenario+"/"+api, func(t *testing.T) {
						body := move + " p+0(FP),AX\n"
						if scenario == "unknown" {
							body = ""
						}
						if scenario == "result-address" {
							body = fmt.Sprintf("LEA%s ret+%d(FP),AX\n", suffix, word)
						}
						actualSuffix := suffix
						if scenario == "partial" {
							actualSuffix = "W"
						}
						body += stem + actualSuffix + " AX\n"
						if scenario == "native-read" {
							body += move + " AX,SI\nMOVL $0,AX\nCRC32B (SI),AX\n"
						} else {
							if scenario == "unknown-CF" {
								body += "JCS unknown_cf\nunknown_cf:\n"
							}
							body += "AND" + suffix + " $7,AX\n"
						}
						body += fmt.Sprintf("MOVL AX,ret+%d(FP)\nRET\n", word)
						source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s", word+4, body)
						ir, err := x86ScalarFPBitViewAPI(t, source, "func Value(p *byte) uint32", target.arch, target.triple, api)
						positive := scenario == "projection" || scenario == "native-read"
						if positive && (err != nil || ir == "") {
							t.Fatal("actual caller native-word unary advance lost its pointer", err)
						}
						if !positive && (!errors.Is(err, ErrProbeNeedsContext) || ir != "") {
							t.Fatal("unary address advance borrowed unknown/partial bytes or incoming CF", err)
						}
					})
				}
			}
		}
	}
}

func TestX86IncomingPointerUnaryAdvanceRolesFlagsAndOrigins(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		word, suffix := x86ResultPointerWord(arch), "Q"
		if arch == "386" {
			suffix = "L"
		}
		for _, stem := range []string{"INC", "DEC"} {
			for _, register := range []Reg{AX, CX, DX, BX, BP, SI, DI, "R8", "R15"} {
				index, _, valid := x86ResultGP(register, word, arch)
				if !valid {
					continue
				}
				for _, flags := range []uint8{0, x86ByteFlagCF, x86ByteFlagsAll} {
					for _, caller := range []bool{false, true} {
						ins := x86ScalarLaneInstruction(t, stem+suffix+" "+string(register))
						state := x86ResultState{flags: flags, direction: x86ResultDirectionBackward}
						state.pointerGP[index], state.callerAddressGP[index], state.callerAddressOrigin[index] = true, caller, 1
						accepted := x86ScalarFPResultTransfer(ins, &state, nil, 0, arch)
						if accepted != caller {
							t.Fatal("unary advance conflated opaque and actual caller roles", arch, ins.Raw, caller, accepted)
						}
						if !caller {
							continue
						}
						wantFlags := flags&x86ByteFlagCF | x86ByteFlagsAll&^x86ByteFlagCF
						if state.flags != wantFlags || state.gp[index] != 0 || !state.pointerGP[index] || state.direction != x86ResultDirectionBackward {
							t.Fatal("unary address advance changed CF/NUM/DF", arch, ins.Raw, state)
						}
						after := x86ResultCallerAddressesAfter(ins, state.callerAddressGP, nil, arch)
						origin := x86ResultCallerOriginsAfter(ins, state.callerAddressOrigin, after, map[int64]bool{0: true}, arch)
						if !after[index] || origin[index] != 1 {
							t.Fatal("post-transfer lost actual pointer/origin after a checked affine advance", arch, ins.Raw)
						}
						var unknown [16]bool
						if x86ResultCallerAddressesAfter(ins, unknown, nil, arch) != unknown {
							t.Fatal("unary shape created caller address identity")
						}
					}
				}
			}
		}
	}
}
