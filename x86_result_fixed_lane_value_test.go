package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// Independent Go optab/attribute inventory, never the production registry.
type x86FixedLaneValueOracle struct {
	name                        string
	immediate, unary, broadcast bool
}

var x86GFNIResultOracle = []x86FixedLaneValueOracle{
	{"VGF2P8MULB", false, false, false},
	{"VGF2P8AFFINEQB", true, false, true},
	{"VGF2P8AFFINEINVQB", true, false, true},
}

var x86BitCountResultOracle = []x86FixedLaneValueOracle{
	{"VPOPCNTB", false, true, false}, {"VPOPCNTW", false, true, false},
	{"VPOPCNTD", false, true, true}, {"VPOPCNTQ", false, true, true},
	{"VPLZCNTD", false, true, true}, {"VPLZCNTQ", false, true, true},
}

func x86FixedLaneValueResultFixture(member x86FixedLaneValueOracle, bank, mode, input string, immediate int) string {
	op, mask, second, control := member.name, "", bank+"1,", ""
	if input == "broadcast" {
		op, input = op+".BCST", "table<>(SB)"
	}
	if mode != "plain" {
		mask = "K1,"
	}
	if mode == "zero" {
		op += ".Z"
	}
	if member.unary {
		second = ""
	}
	if member.immediate {
		control = fmt.Sprintf("$%d,", immediate)
	}
	return fmt.Sprintf("TEXT ·Value(SB),4,$0-4\nMOVL $7,AX\nKMOVD AX,K1\n"+
		"VPXORD Z0,Z0,Z0\nVPXORD Z1,Z1,Z1\nVPXORD Z2,Z2,Z2\nVPXORD Z3,Z3,Z3\n"+
		"%s %s%s,%s%s%s2\nVPCOMPRESSQ Z2,K1,Z3\nPEXTRD $0,X3,AX\nMOVL AX,ret+0(FP)\nRET\n",
		op, control, input, second, mask, bank)
}

func x86FixedLaneValueResultMatrix(t *testing.T, members []x86FixedLaneValueOracle, amd64Count, mode32Count int) {
	t.Helper()
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			var source, declarations strings.Builder
			source.WriteString("GLOBL table<>(SB),8,$64\n")
			var names []string
			for _, member := range members {
				if target.arch == "386" && member.immediate {
					continue // Named affine instructions require at least four operands.
				}
				for _, bank := range []string{"X", "Y", "Z"} {
					for _, mode := range []string{"plain", "merge", "zero"} {
						if target.arch == "386" && !member.unary && mode != "plain" {
							continue
						}
						inputs := []string{bank + "0", "table<>(SB)"}
						if member.broadcast {
							inputs = append(inputs, "broadcast")
						}
						controls := []int{0}
						if member.immediate {
							controls = append(controls, 255)
						}
						for _, input := range inputs {
							for _, immediate := range controls {
								body := x86FixedLaneValueResultFixture(member, bank, mode, input, immediate)
								name := fmt.Sprintf("Value%d", len(names))
								names = append(names, name)
								source.WriteString(strings.ReplaceAll(body, "Value", name))
								declarations.WriteString("func " + name + "() uint32\n")
							}
						}
					}
				}
			}
			want := amd64Count
			if target.arch == "386" {
				want = mode32Count
			}
			if len(names) != want {
				t.Fatal("independent value-family denominator changed", len(names), want)
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("initialized complete fixed-lane family rejected", err)
					}
					x86CompactExpandRequireAllDefinitions(t, ir, names)
				})
			}
		})
	}
}

func TestX86GFNIInitializedResultWholeFamily(t *testing.T) {
	x86FixedLaneValueResultMatrix(t, x86GFNIResultOracle, 126, 6)
}

func TestX86PackedBitCountInitializedResultWholeFamily(t *testing.T) {
	x86FixedLaneValueResultMatrix(t, x86BitCountResultOracle, 144, 144)
}

func TestX86FixedLaneValueResultInputsStayIndependent(t *testing.T) {
	members := append(append([]x86FixedLaneValueOracle(nil), x86GFNIResultOracle...), x86BitCountResultOracle...)
	for _, member := range members {
		for _, bank := range []string{"X", "Y", "Z"} {
			for _, mode := range []string{"plain", "merge", "zero"} {
				source := x86FixedLaneValueResultFixture(member, bank, mode, bank+"0", 255)
				missing := []string{"Z0", "result"}
				if !member.unary {
					missing = append(missing, "Z1")
				}
				if mode != "plain" {
					missing = append(missing, "mask")
				}
				if mode == "merge" {
					missing = append(missing, "Z2")
				}
				for _, omit := range missing {
					body := strings.Replace(source, fmt.Sprintf("VPXORD %s,%s,%s", omit, omit, omit), "NOP", 1)
					if omit == "result" {
						body = strings.Replace(source, "MOVL AX,ret+0(FP)", "NOP", 1)
					} else if omit == "mask" {
						body = strings.Replace(source, "KMOVD AX,K1", "NOP", 1)
					}
					t.Run(member.name+"/"+bank+"/"+mode+"/"+omit, func(t *testing.T) {
						goAssemblerOracleOutput(t, "amd64", body, "", true)
						for _, api := range []string{"text", "module", "Go"} {
							if _, err := x86ScalarFPBitViewAPI(t, body, "func Value() uint32", "amd64", "x86_64-unknown-linux-gnu", api); !errors.Is(err, ErrProbeNeedsContext) {
								t.Fatal("value family acquired an unknown input/result", api, err)
							}
						}
					})
				}
			}
		}
	}
}
