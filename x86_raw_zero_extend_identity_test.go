package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"testing"
)

func TestX86RawZeroExtendSourceIdentityAndPreservedDomains(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for opcode := byte(0x30); opcode <= 0x35; opcode++ {
			decoded, err := decodeX86RawDirectives(rawX86Function([]byte{0xc4, 0xe2, 0x79, opcode, 0x08}), arch)
			if err != nil || len(decoded.Instrs) != 1 {
				t.Fatal("independent complete widening row did not decode", err)
			}
			original := decoded.Instrs[0]
			if !x86RawZeroExtendSource(original, arch) {
				t.Fatal("original typed/raw widening identity disappeared")
			}
			t.Run(fmt.Sprintf("%s/%x/domains", arch, opcode), func(t *testing.T) {
				var addresses [16]bool
				addresses[0], addresses[7] = true, true
				if x86ResultDirectionAfterSource(original, x86ResultDirectionBackward, arch) != x86ResultDirectionBackward ||
					!x86ResultPreservesPrivateStorage(original, arch) ||
					x86ResultCallerAddressesAfter(original, addresses, nil, arch) != addresses {
					t.Fatal("bound widening revoked an independent DF/private-storage/GP-address fact")
				}
			})
			for _, mutation := range []string{"origin", "mode", "encoded", "opcode", "operand", "vector width", "address size"} {
				t.Run(fmt.Sprintf("%s/%x/%s", arch, opcode, mutation), func(t *testing.T) {
					changed, mode := original, arch
					changed.Args = append([]Operand(nil), original.Args...)
					switch mutation {
					case "origin":
						changed.x86SourceRaw = nil
					case "mode":
						mode = map[string]string{"386": "amd64", "amd64": "386"}[arch]
					case "encoded":
						changed.x86Encoded = !changed.x86Encoded
					case "opcode":
						changed.Op = "VPMOVZXWQ"
						if changed.Op == original.Op {
							changed.Op = "VPMOVZXBD"
						}
					case "operand":
						changed.Args[0].Mem.Base = DX
					case "vector width":
						changed.x86VectorBytes ^= 16
					case "address size":
						changed.x86AddressBits = 16
					}
					if x86RawZeroExtendSource(changed, mode) {
						t.Fatal("mutated instruction acquired another raw producer's identity")
					}
					if mutation == "origin" {
						// A VEX origin-only mutation can look exactly like a
						// genuine named instruction. The immutable whole-source
						// replay below, not a standalone step, must reject it.
						return
					}
					state := x86FMA3ResultInputState()
					before := state.clone()
					if accepted, _ := x86ResultPackedZeroExtendStep(changed, &state, nil, mode, true); accepted || !reflect.DeepEqual(state, before) {
						t.Fatal("unbound physical widening changed numerical state")
					}
				})
			}
		}
	}
}

func TestX86RawZeroExtendWholeProducerAndStandaloneBoundaries(t *testing.T) {
	const body = "MOVQ p+0(FP),AX\nVZEROALL\nBYTE $0xc4; BYTE $0xe2; BYTE $0x79; BYTE $0x31; BYTE $0x08\nPEXTRD $0,X1,AX\nMOVL AX,ret0+8(FP)\nRET"
	_, file, sig, source := x86ResultInitializationFixture(t, "amd64", "func Value(p *[32]byte) uint32", body)
	x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", source)
	file, err := normalizeX86RawFile(file, "amd64")
	if err != nil || len(file.Funcs) != 1 {
		t.Fatal("complete initialized widening producer did not normalize", err)
	}
	for _, mutation := range []string{"original", "origin only", "producer", "replay"} {
		t.Run(mutation, func(t *testing.T) {
			function := file.Funcs[0]
			function.Instrs = append([]Instr(nil), function.Instrs...)
			switch mutation {
			case "origin only":
				for index := range function.Instrs {
					if function.Instrs[index].Op == "VPMOVZXBD" {
						function.Instrs[index].x86SourceRaw = nil
						function.Instrs[index].x86Encoded = false
					}
				}
			case "producer":
				function.Instrs[2].Op = "VZEROUPPER"
			case "replay":
				function.x86RawReplay = nil
			}
			ctx := amd64Ctx{fpScalarSource: function, fpSourceSig: sig, sig: sig,
				goarch: "amd64", targetTriple: "x86_64-unknown-linux-gnu"}
			err := ctx.checkLoweredScalarFPResultInitialization()
			if mutation == "original" {
				if err != nil {
					t.Fatal("complete original source lost its paired widening consumer", err)
				}
			} else if !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("changed whole producer inherited the original source proof", err)
			}
			if err := checkX86ScalarFPResultInitialization(function, sig, "amd64"); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("standalone declaration query acquired paired native memory", err)
			}
		})
	}
}
