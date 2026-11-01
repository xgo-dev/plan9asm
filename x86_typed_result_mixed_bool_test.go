package plan9asm

import (
	"errors"
	"fmt"
	"testing"
)

func TestX86TypedNumericalMixedBoolCanonicalCompositionThreeAPIs(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		operations := []string{"CRC32B BX,AX", "CRC32W BX,AX", "CRC32L BX,AX", "MULL BX", "BSWAPL AX"}
		inputType, inputMove, inputOffset := "uint32", "MOVL", 4
		if target.arch == "amd64" {
			operations = append(operations, "CRC32Q BX,AX", "BSWAPQ AX")
			inputType, inputMove, inputOffset = "uint64", "MOVQ", 8
		}
		for _, boolFirst := range []bool{false, true} {
			declaration := fmt.Sprintf("func Value(crc,value %s) (uint32,bool)", inputType)
			if boolFirst {
				declaration = fmt.Sprintf("func Value(crc,value %s) (bool,uint32)", inputType)
			}
			_, _, sig, _ := x86ResultInitializationFixture(t, target.arch, declaration, "RET")
			var boolean, number int64
			for _, slot := range sig.Frame.Results {
				if slot.Type == I1 {
					boolean = slot.Offset
				} else {
					number = slot.Offset
				}
			}
			for _, operation := range operations {
				scenarios := []string{"canonical-mask", "raw-two", "unmasked-number", "unknown-accumulator", "missing-number"}
				if operation == "BSWAPQ AX" {
					// A prior MOVL makes the high half zero; BSWAPQ then
					// legitimately produces a canonical low byte without AND.
					scenarios = append(scenarios, "zero-extended-input")
				}
				for _, scenario := range scenarios {
					body := fmt.Sprintf("%s value+%d(FP),BX\n", inputMove, inputOffset)
					if scenario != "unknown-accumulator" {
						move := inputMove
						if scenario == "zero-extended-input" {
							move = "MOVL"
						}
						body += move + " crc+0(FP),AX\n"
					}
					body += operation + "\n"
					if scenario != "missing-number" {
						body += fmt.Sprintf("MOVL AX,ret+%d(FP)\n", number)
					}
					switch scenario {
					case "raw-two":
						body += "MOVL $2,AX\n"
					case "unmasked-number", "zero-extended-input":
						// Initialized arithmetic bytes alone never witness zero/one.
					default:
						body += "ANDL $1,AX\n"
					}
					body += fmt.Sprintf("MOVB AX,ret+%d(FP)\nRET", boolean)
					_, _, _, source := x86ResultInitializationFixture(t, target.arch, declaration, body)
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(fmt.Sprintf("%s/bool-first=%t/%s/%s/%s", target.triple, boolFirst, operation, scenario, api), func(t *testing.T) {
							ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, api)
							if scenario == "canonical-mask" || scenario == "zero-extended-input" {
								if err != nil || ir == "" {
									t.Fatalf("complete typed NUM/canonical tuple rejected: output=%t error=%v", ir != "", err)
								}
							} else if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
								t.Fatalf("unproved arithmetic bool tuple accepted: output=%t error=%v", ir != "", err)
							}
						})
					}
				}
			}
		}
	}
}

func TestX86TypedNumericalMixedBoolRequiresLiveCachedCanonicalRole(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, raw := range []int{1, 2} {
			t.Run(fmt.Sprintf("%s/raw=%d", arch, raw), func(t *testing.T) {
				_, file, sig, _ := x86ResultInitializationFixture(t, arch,
					"func Value() (bool,uint32)",
					fmt.Sprintf("MOVL $7,AX\nBSWAPL AX\nMOVL AX,ret+4(FP)\nMOVB $%d,ret+0(FP)\nRET", raw))
				fn := file.Funcs[0]
				fn.x86ResultFlowBudget = &x86ResultFlowBudget{}
				consumer := &amd64Ctx{goarch: arch, sig: sig, fpResults: sig.Frame.Results, fpScalarSource: fn}
				if raw == 2 {
					// A stale private role bit cannot turn a failed complete proof
					// into a canonical result or physical-I8 storage permission.
					consumer.fpMixedBoolBytes = true
					if err := consumer.integerEffectResultInitialized("test"); !errors.Is(err, ErrProbeNeedsContext) || consumer.abi0BoolResultByteStorage() {
						t.Fatal("failed canonical proof borrowed a role bit", err)
					}
					return
				}
				if err := consumer.scalarFPResultInitialized(); err != nil {
					t.Fatal("independent whole canonical proof failed", err)
				}
				used := *fn.x86ResultFlowBudget
				if err := consumer.integerEffectResultInitialized("test"); !errors.Is(err, ErrProbeNeedsContext) || consumer.abi0BoolResultByteStorage() {
					t.Fatal("initialization alone created a live canonical storage role", err)
				}
				if err := consumer.validateMixedBoolResultRole(); err != nil || !consumer.fpMixedBoolBytes || !consumer.abi0BoolResultByteStorage() {
					t.Fatal("actual canonical tuple did not acquire its existing role", err)
				}
				if err := consumer.integerEffectResultInitialized("test"); err != nil {
					t.Fatal("generic NUM consumer discarded the proved canonical role", err)
				}
				if used != *fn.x86ResultFlowBudget {
					t.Fatal("composition repeated or bypassed the shared whole-proof budget")
				}
			})
		}
	}
}
