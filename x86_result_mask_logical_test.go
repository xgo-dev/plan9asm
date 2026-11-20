package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

// Independent source inventory: five binary, one unary and two FLAGS families,
// each with B/W/D/Q widths. Go's rows are _ykaddb and _yknotb respectively.
func x86MaskLogicalOracle() []struct{ op, operands string } {
	var rows []struct{ op, operands string }
	for _, stem := range []string{"KAND", "KANDN", "KOR", "KXNOR", "KXOR", "KNOT", "KTEST", "KORTEST"} {
		operands := "K0,K7,K3"
		if stem == "KNOT" {
			operands = "K0,K3"
		} else if stem == "KTEST" || stem == "KORTEST" {
			operands = "K0,K7"
		}
		for _, suffix := range []string{"B", "W", "D", "Q"} {
			rows = append(rows, struct{ op, operands string }{stem + suffix, operands})
		}
	}
	return rows
}

func TestX86MaskLogicalCompleteInputAndState(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range x86MaskLogicalOracle() {
			t.Run(arch+"/"+row.op, func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, row.op+" "+row.operands)
				for seed := 0; seed < 256; seed++ {
					state := x86ResultState{flags: x86ByteFlagCF}
					state.gp[1], state.pointerGP[2], state.callerAddressGP[2] = 0x53, true, true
					state.xmm[3] = 0x1234
					for index := range state.masks {
						state.masks[index] = seed&(1<<index) != 0
					}
					before := state.clone()
					want := state.masks[0] && (strings.HasPrefix(row.op, "KNOT") || state.masks[7])
					accepted := x86ScalarFPResultTransfer(ins, &state, nil, 0, arch)
					if accepted != want {
						t.Fatalf("seed=%02x accepted=%v want=%v", seed, accepted, want)
					}
					if want {
						if strings.Contains(row.op, "TEST") {
							before.flags = x86ByteFlagsAll
						} else {
							before.masks[3] = true
						}
					}
					if !reflect.DeepEqual(state, before) {
						t.Fatal("mask operation changed unrelated state or partially accepted missing inputs")
					}
					if accepted && x86ResultCallerAddressesAfter(ins, before.callerAddressGP, nil, arch) != before.callerAddressGP {
						t.Fatal("mask-only operation revoked unrelated GP address identities")
					}
				}
			})
		}
	}
}

func TestX86MaskLogicalUnknownVoidInputs(t *testing.T) {
	for _, row := range x86MaskLogicalOracle() {
		t.Run(row.op, func(t *testing.T) {
			for _, arch := range []string{"amd64", "386"} {
				triple := "x86_64-unknown-linux-gnu"
				if arch == "386" {
					triple = "i386-unknown-linux-gnu"
				}
				source := "TEXT ·Value(SB),4,$0\n" + row.op + " " + row.operands + "\nRET\n"
				x86LEAActualTargetGoObject(t, arch, triple, source)
				for _, declaration := range []string{"func Value()", "func Value(unused bool)"} {
					for _, api := range []string{"text", "module", "Go"} {
						ir, err := x86ScalarFPBitViewAPI(t, source, declaration, arch, triple, api)
						if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("dead output or unused bool invented source mask values", arch, declaration, api, err)
						}
					}
				}
			}
		})
	}
}

func TestX86MaskLogicalSameSourceConstants(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, stem := range []string{"KXOR", "KXNOR", "KANDN"} {
			for _, suffix := range []string{"B", "W", "D", "Q"} {
				for source := 0; source < 8; source++ {
					for destination := 0; destination < 8; destination++ {
						ins := x86ScalarLaneInstruction(t, fmt.Sprintf("%s%s K%d,K%d,K%d", stem, suffix, source, source, destination))
						state := x86ResultState{flags: x86ByteFlagAF}
						want := state.clone()
						want.masks[destination] = true
						if !x86ScalarFPResultTransfer(ins, &state, nil, 0, arch) || !reflect.DeepEqual(state, want) {
							t.Fatal("same-source constant required an irrelevant input or changed FLAGS", arch, ins.Raw)
						}
					}
				}
			}
		}
	}
}

func x86MaskLogicalCompleteFixture(arch string) (string, string) {
	var source, declarations strings.Builder
	for _, row := range x86MaskLogicalOracle() {
		fmt.Fprintf(&declarations, "func %s(a,b uint64) uint64\n", row.op)
		fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-24\nKMOVQ a+0(FP),K0\nKMOVQ b+8(FP),K7\n%s %s\n",
			row.op, row.op, row.operands)
		if strings.Contains(row.op, "TEST") {
			word := "Q"
			if arch == "386" {
				word = "L"
			}
			fmt.Fprintf(&source, "PUSHF%s\nPOP%s AX\nAND%s $0x8d5,AX\nMOV%s AX,ret+16(FP)\n", word, word, word, word)
			if arch == "386" {
				source.WriteString("MOVL $0,ret+20(FP)\n")
			}
		} else {
			source.WriteString("KMOVQ K3,ret+16(FP)\n")
		}
		source.WriteString("RET\n")
	}
	return source.String(), declarations.String()
}

func TestX86MaskLogicalInitializedFiveTargetObjects(t *testing.T) {
	x86MaskLogicalFiveTargetObjects(t, false)
}

func TestX86MaskLogicalRawInitializedFiveTargetObjects(t *testing.T) {
	x86MaskLogicalFiveTargetObjects(t, true)
}

func x86MaskLogicalFiveTargetObjects(t *testing.T, raw bool) {
	t.Helper()
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			source, declarations := x86MaskLogicalCompleteFixture(target.arch)
			if raw {
				source = x86MaskLogicalRawFixture(t, source)
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source, declarations, target.arch, target.triple, api)
				if err != nil {
					t.Fatal("complete initialized mask family rejected", api, err)
				}
				for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
					for _, level := range []string{"-O0", "-O2"} {
						x86PackedStringCompileObject(t, llc, target.triple, text, level)
					}
				}
			}
		})
	}
}

func TestX86MaskLogicalPortableValuesAndFlags(t *testing.T) {
	x86MaskLogicalPortableValuesAndFlags(t, false)
}

func TestX86MaskLogicalRawPortableValuesAndFlags(t *testing.T) {
	x86MaskLogicalPortableValuesAndFlags(t, true)
}

func x86MaskLogicalPortableValuesAndFlags(t *testing.T, raw bool) {
	t.Helper()
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM 22 llc/clang required")
	}
	source, declarations := x86MaskLogicalCompleteFixture("amd64")
	if raw {
		source = x86MaskLogicalRawFixture(t, source)
	}
	var prototypes, checks strings.Builder
	for index, row := range x86MaskLogicalOracle() {
		bits := []int{8, 16, 32, 64}[index%4]
		fmt.Fprintf(&prototypes, "extern uint64_t %s(uint64_t,uint64_t);\n", row.op)
		fmt.Fprintf(&checks, "if (check(%s,\"%s\",%d,%d)) return 1;\n", row.op, row.op, index/4, bits)
	}
	oracle := "#include <stdint.h>\n#include <stdio.h>\n" + prototypes.String() + `
static int check(uint64_t (*fn)(uint64_t,uint64_t), const char *name, unsigned op, unsigned bits) {
    const uint64_t values[] = {0, 1, UINT64_MAX, UINT64_C(0x89abcdef01234567),
        UINT64_C(0x8000000000000000), UINT64_C(0x55555555aaaaaaaa)};
    uint64_t mask = bits == 64 ? UINT64_MAX : (UINT64_C(1) << bits) - 1;
    for (unsigned i = 0; i < 6; i++) {
        for (unsigned j = 0; j < 6; j++) {
            uint64_t a = values[i] & mask, b = values[j] & mask, expected = 0;
            switch (op) {
            case 0: expected = a & b; break;
            case 1: expected = a & ~b; break;
            case 2: expected = a | b; break;
            case 3: expected = ~(a ^ b) & mask; break;
            case 4: expected = a ^ b; break;
            case 5: expected = ~a & mask; break;
            case 6: expected = ((a & b) == 0 ? 64 : 0) | ((a & ~b) == 0 ? 1 : 0); break;
            case 7: expected = ((a | b) == 0 ? 64 : 0) | ((a | b) == mask ? 1 : 0); break;
            }
            uint64_t actual = fn(values[i], values[j]);
            if (actual != expected) {
                fprintf(stderr, "%s a=%llx b=%llx got=%llx want=%llx\n", name,
                    (unsigned long long)values[i], (unsigned long long)values[j],
                    (unsigned long long)actual, (unsigned long long)expected);
                return 1;
            }
        }
    }
    return 0;
}
int main(void) {
` + checks.String() + "return 0;\n}\n"
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source, declarations, "amd64", triple, api)
			if err != nil {
				t.Fatal("complete mask value/status program rejected", api, err)
			}
			for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
				for _, level := range []int{0, 2} {
					compileAndRunRuntimeTestWithCompiler(t, llc, []string{clang}, "mask-logical", triple, text, oracle, nil, level)
				}
			}
		})
	}
}
