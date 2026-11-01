package plan9asm

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// Independent Intel input inventory, in little-endian byte order. Memory
// operands still read the complete m128 even where register words are unused.
var x86SHAOracleInputs = []struct {
	name                  string
	source, old, implicit uint16
}{
	{"SHA1NEXTE", 0xffff, 0xf000, 0},
	{"SHA1MSG1", 0xff00, 0xffff, 0},
	{"SHA1MSG2", 0x0fff, 0xffff, 0},
	{"SHA1RNDS4", 0xffff, 0xffff, 0},
	{"SHA256MSG1", 0x000f, 0xffff, 0},
	{"SHA256MSG2", 0xff00, 0xffff, 0},
	{"SHA256RNDS2", 0xffff, 0xffff, 0x00ff},
}

func x86SHAOracleRow(name, source, destination string, immediate int) string {
	args := source + "," + destination
	if name == "SHA1RNDS4" {
		args = fmt.Sprintf("$%d,", immediate) + args
	} else if name == "SHA256RNDS2" {
		args = "X0," + args
	}
	return name + " " + args
}

func TestX86SHAIndependentCompleteGoRows(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	rows := regexp.MustCompile(`\{ASHA(?:1|256)[A-Z0-9]+, [^\n]+`).FindAllString(string(data), -1)
	if len(rows) != 7 {
		t.Fatal("complete legacy SHA opcode inventory changed", len(rows))
	}
	for index, row := range x86SHAOracleInputs {
		table, prefix := "yaes", "Px"
		code := []string{"0x0f, 0x38, 0xc8", "0x0f, 0x38, 0xc9", "0x0f, 0x38, 0xca", "0x3a, 0xcc", "0x0f, 0x38, 0xcc", "0x0f, 0x38, 0xcd", "0x0f, 0x38, 0xcb"}[index]
		if row.name == "SHA1RNDS4" {
			table, prefix = "ysha1rnds4", "Pm"
		} else if row.name == "SHA256RNDS2" {
			table = "ysha256rnds2"
		}
		want := fmt.Sprintf("{A%s, %s, %s, opBytes{%s, 0}}", row.name, table, prefix, code)
		if !strings.Contains(string(data), want) {
			t.Fatal("complete SHA encoding row changed", want)
		}
	}
	for table, want := range map[string]string{
		"yaes":         "{Zlitm_r, 2, argList{Yxm, Yxr}},",
		"ysha1rnds4":   "{Zibm_r, 2, argList{Yu2, Yxm, Yxr}},",
		"ysha256rnds2": "{Zlit_m_r, 0, argList{Yxr0, Yxm, Yxr}},",
	} {
		match := regexp.MustCompile(`(?s)var ` + table + ` = \[\]ytab\{(.*?)\n\}`).FindSubmatch(data)
		if len(match) != 2 || strings.Join(strings.Fields(string(match[1])), " ") != want {
			t.Fatal("complete SHA argument classes changed", table, match)
		}
	}
}

func TestX86SHASelectedInputsSharedConsumers(t *testing.T) {
	for _, row := range x86SHAOracleInputs {
		for _, source := range []string{"X1", "X2", "X0"} {
			operation := x86SHAOracleRow(row.name, source, "X2", 3)
			t.Run(operation, func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, operation)
				_, sig, _ := fixedLocalVEXFixture(t, operation)
				needed := map[Reg]uint16{"Z2": row.old, "Z0": row.implicit}
				needed[x86CallerVectorRoot(Reg(source))] |= row.source
				for input, mask := range needed {
					for missing := -1; missing < 16; missing++ {
						local := x86FixedLocalState{vectors: map[Reg]uint64{}, flags: x86ByteFlagsAll}
						result := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionEither}
						for root, known := range needed {
							if root == input && missing >= 0 {
								known &^= uint16(1) << uint(missing)
							}
							local.vectors[root] = uint64(known) | 1<<60
							index := int(root[1] - '0')
							result.writeVector(index, 64, local.vectors[root], false)
						}
						wantFull := missing < 0 || mask&(uint16(1)<<uint(missing)) == 0
						proof := &x86FixedLocalProof{}
						if err := fixedLocalStep(&ins, &local, sig, proof, 0); err != nil {
							t.Fatal("nontrapping SHA register transfer lacks shared effect", operation, err)
						}
						for _, transfer := range []func(Instr, *x86ResultState, []bool, int64, string) bool{x86ResultTransfer, x86ScalarFPResultTransfer} {
							copy := result.clone()
							if !transfer(ins, &copy, nil, 0, "amd64") || copy.vectorBytes(2) != local.vectors["Z2"] {
								t.Fatal("result and private-frame SHA numerical bytes differ", operation, input, missing)
							}
							if copy.flags != result.flags || copy.direction != result.direction {
								t.Fatal("SHA changed independent flags/direction")
							}
						}
						if (local.vectors["Z2"]&0xffff == 0xffff) != wantFull || local.vectors["Z2"]>>16 != 1<<44 || local.flags != x86ByteFlagsAll {
							t.Fatal("unused SHA bytes became mandatory or missing state became defined", operation, input, missing, local.vectors)
						}
					}
				}
			})
		}
	}
}

func TestX86SHAFullMemoryAndGrammarGuards(t *testing.T) {
	for _, row := range x86SHAOracleInputs {
		for missing := -1; missing < 16; missing++ {
			operation := x86SHAOracleRow(row.name, "a+0(FP)", "X2", 3)
			t.Run(fmt.Sprintf("%s/missing%d", row.name, missing), func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, operation)
				state := x86ResultState{fp: make([]bool, 16), flags: x86ByteFlagsAll}
				state.xmm[0], state.xmm[2] = row.implicit, row.old
				owned := make([]bool, 16)
				for i := range owned {
					owned[i], state.fp[i] = true, i != missing
				}
				before := state.clone()
				got := x86ResultTransfer(ins, &state, owned, 16, "amd64")
				if got != (missing < 0) || got && state.xmm[2] != 0xffff || !got && !reflect.DeepEqual(state, before) {
					t.Fatal("SHA numerical word mask replaced its complete memory envelope", got, state)
				}
			})
		}
	}
	for _, operation := range []string{
		"SHA256RNDS2 X1,X2,X3", "SHA256RNDS2 X0,X1", "SHA1RNDS4 $-1,X1,X2", "SHA1RNDS4 $4,X1,X2",
		"SHA1RNDS4 $0.5,X1,X2", "SHA1MSG1 Y1,X2", "SHA1MSG1 X16,X2", "SHA1MSG1 X1,(AX)", "SHA1MSG1.Z X1,X2",
	} {
		t.Run(operation, func(t *testing.T) {
			ins := x86ScalarLaneInstruction(t, operation)
			_, known, err := x86TypedInstructionByteEffect(ins.Op, ins, "amd64")
			if !known || err == nil {
				t.Fatal("invalid SHA form was not rejected by its shared grammar", known, err)
			}
		})
	}
}

func fixedLocalSHACases() []string {
	var rows []string
	for _, family := range x86SHAOracleInputs {
		selectors := []int{0}
		if family.name == "SHA1RNDS4" {
			selectors = []int{0, 1, 2, 3}
		}
		for _, selector := range selectors {
			for _, source := range []string{"X0", "X1", "X2", "64(BP)", "(SI)"} {
				rows = append(rows, x86SHAOracleRow(family.name, source, "X2", selector))
			}
		}
	}
	return rows
}

func TestGoAMD64FixedLocalSHACompleteFamily(t *testing.T) {
	rows := fixedLocalSHACases()
	if len(rows) != 50 {
		t.Fatal("SHA complete selector/alias/memory inventory changed", len(rows))
	}
	var source strings.Builder
	for index, row := range rows {
		source.WriteString(strings.Replace(fixedLocalVEXAssembly(row), "·Value", fmt.Sprintf("·Value%d", index), 1))
	}
	requireX86GoAssemblerResult(t, "amd64", source.String(), true)
	for _, row := range rows {
		t.Run(row, func(t *testing.T) {
			fn, sig, _ := fixedLocalVEXFixture(t, row)
			if _, err := proveX86FixedLocal(fn, sig); err != nil {
				t.Fatal("initialized original Go SHA function lacks fixed-local support", err)
			}
		})
	}
	for _, source := range []string{"65(BP)", "256(BP)", "(AX)"} {
		for _, family := range x86SHAOracleInputs {
			fn, sig, _ := fixedLocalVEXFixture(t, x86SHAOracleRow(family.name, source, "X2", 0))
			if _, err := proveX86FixedLocal(fn, sig); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("SHA acquired unaligned, uninitialized or unauthenticated memory", family.name, source, err)
			}
		}
	}
}

func TestX86SHAOriginalPhysicalBoundaries(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		var rows []string
		for _, family := range x86SHAOracleInputs {
			for _, source := range []string{"X1", "X7", "16(AX)(CX*2)", "16(BP)", "·data(SB)"} {
				rows = append(rows, x86SHAOracleRow(family.name, source, "X2", 3))
			}
		}
		code, pcs := x86NumericalBoundaryGoBytes(t, arch, strings.Join(rows, "\n")+"\nRET")
		mode := 64
		if arch == "386" {
			mode = 32
		}
		for index, row := range rows {
			t.Run(arch+"/"+row, func(t *testing.T) {
				physical := code[pcs[index]:pcs[index+1]]
				boundaries, _, err := x86NumericalNativeBoundaries(physical, mode)
				if err != nil || len(boundaries) != 1 || boundaries[0].Length != len(physical) {
					t.Fatal("original Go SHA bytes lack exact whole-TEXT boundary", fmt.Sprintf("%x", physical), err)
				}
				for end := 1; end < len(physical); end++ {
					if _, _, err := x86NumericalNativeBoundaries(physical[:end], mode); err == nil {
						t.Fatal("truncated SHA instruction acquired a complete boundary", end)
					}
				}
			})
		}
	}
}
