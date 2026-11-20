package plan9asm

import (
	"errors"
	"strings"
	"testing"
)

func x86X87RawClearBody(masked bool) string {
	if masked {
		// Unlike FINIT followed by clear, this cannot pass if DB E2 is
		// replaced with NOP: entry exception bits are initially unknown.
		return "BYTE $0xdb; BYTE $0xe2\nFSTSW AX\nANDW $0x80ff,AX\nMOVW AX,ret+0(FP)\nFINIT\nRET"
	}
	return "FINIT\nBYTE $0xdb; BYTE $0xe2\nFSTSW AX\nMOVW AX,ret+0(FP)\nRET"
}

func TestX86X87RawClearBoundedInitializedAndMaskedThreeAPIs(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, masked := range []bool{false, true} {
			name := "initialized-word"
			if masked {
				name = "only-cleared-bits"
			}
			_, _, _, source := x86ResultInitializationFixture(t, target.arch, "func Value() uint16", x86X87RawClearBody(masked))
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(target.triple+"/"+name+"/"+api, func(t *testing.T) {
					ir, err := x86X87InitializedWordAPI(t, source, "func Value() uint16", target.arch, target.triple, api, X87Software)
					if err != nil || ir == "" {
						t.Fatal("raw clear was rejected before its numerical oracle; no value observation executed", err)
					}
					x86ScalarFPNamedConstantResult(t, ir, "Value", []uint64{0})
				})
			}
		}
	}
}

func TestX86X87RawClearCannotInventWordOrValueFacts(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, row := range []struct{ name, body string }{
			{"NOP-is-not-clear", strings.Replace(x86X87RawClearBody(true), "BYTE $0xdb; BYTE $0xe2", "BYTE $0x90", 1)},
			{"clear-is-not-whole-status", strings.Replace(x86X87RawClearBody(true), "ANDW $0x80ff,AX\n", "", 1)},
			{"clear-does-not-create-F0", "FINIT\nBYTE $0xdb; BYTE $0xe2\nFTST\nMOVW $0,ret+0(FP)\nRET"},
			{"clear-does-not-empty-stack", "FINIT\nFLD1\nBYTE $0xdb; BYTE $0xe2\nMOVW $0,ret+0(FP)\nRET"},
		} {
			_, _, _, source := x86ResultInitializationFixture(t, target.arch, "func Value() uint16", row.body)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(target.triple+"/"+row.name+"/"+api, func(t *testing.T) {
					ir, err := x86X87InitializedWordAPI(t, source, "func Value() uint16", target.arch, target.triple, api, X87Software)
					if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
						t.Fatal("raw clear granted an unknown status/value/stack fact", err)
					}
					t.Logf("FIRST_CONTEXT %s: %v", row.name, err)
				})
			}
		}
	}
}

func TestX86X87RawClearRequiresWholeReplayIdentity(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		_, file, sig, _ := x86ResultInitializationFixture(t, arch, "func Value() uint16", x86X87RawClearBody(true))
		normalized, err := normalizeX86RawFile(file, arch)
		if err != nil || normalized == nil || len(normalized.Funcs) != 1 {
			t.Fatal("raw fixture normalization failed", err)
		}
		fn := normalized.Funcs[0]
		clear := -1
		for ordinal, ins := range fn.Instrs {
			if ins.Op == "FCLEX" && ins.x86SourceRaw != nil {
				clear = ordinal
			}
		}
		if clear < 0 || fn.x86RawReplay == nil {
			t.Fatal("fixture lacks the actual complete raw decoder replay")
		}
		t.Run(arch+"/standalone-query", func(t *testing.T) {
			if err := CheckX86ABI0ResultInitialization(fn, sig, arch); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("standalone declaration query acquired the private raw-clear role", err)
			}
		})
		for _, change := range []string{"none", "missing-replay", "wrong-mode", "raw-source", "original-instruction", "decoded-instruction",
			"normalized-snapshot", "normalized-op", "original-op", "original-args", "ordinal", "copied-token", "address-size", "raw-return"} {
			t.Run(arch+"/"+change, func(t *testing.T) {
				candidate := fn
				candidate.Instrs = cloneX86ReplayInstrs(fn.Instrs)
				replay := *fn.x86RawReplay
				replay.original = cloneX86ReplayInstrs(replay.original)
				replay.decoded = cloneX86ReplayInstrs(replay.decoded)
				replay.normalized = cloneX86ReplayInstrs(replay.normalized)
				candidate.x86RawReplay = &replay
				mode := arch
				switch change {
				case "missing-replay":
					candidate.x86RawReplay = nil
				case "wrong-mode":
					mode = "386"
					if arch == "386" {
						mode = "amd64"
					}
				case "raw-source":
					replay.source = strings.Replace(replay.source, "BYTE $0xe2", "BYTE $0xe3", 1)
				case "original-instruction":
					replay.original[1].Raw = "BYTE $0x90"
				case "decoded-instruction":
					replay.decoded[clear].Op = "NOP"
				case "normalized-snapshot":
					replay.normalized[clear].Op = "NOP"
				case "normalized-op":
					candidate.Instrs[clear].Op = "NOP"
				case "original-op":
					candidate.Instrs[clear].x86SourceRaw.op = "NOP"
				case "original-args":
					candidate.Instrs[clear].x86SourceRaw.args = []Operand{{Kind: OpReg, Reg: AX}}
				case "ordinal":
					candidate.Instrs[clear], candidate.Instrs[clear+1] = candidate.Instrs[clear+1], candidate.Instrs[clear]
				case "copied-token":
					candidate.Sym += "Copy"
				case "address-size":
					candidate.Instrs[clear].x86AddressBits = 32
				case "raw-return":
					candidate.Instrs[clear].x86RawNearReturn = new(x86RawNearReturnForm)
				}
				consumer := &amd64Ctx{fpScalarSource: candidate, sig: sig, fpSourceSig: sig, goarch: mode, x87Mode: X87Software}
				err := consumer.checkLoweredScalarFPResultInitialization()
				if change == "none" {
					if err != nil {
						t.Fatal("authentic raw clear never reached a positive paired proof", err)
					}
					return
				}
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("changed source/mode/ordinal borrowed a raw-clear replay", err)
				}
				t.Logf("FIRST_CONTEXT %s: %v", change, err)
			})
		}
	}
}
