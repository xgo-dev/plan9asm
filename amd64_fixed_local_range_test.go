package plan9asm

import (
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"testing"
)

const fixedLocalRangeData = "DATA literal<>+0(SB)/8,$0x0102030405060708\n" +
	"DATA literal<>+232(SB)/8,$0x3132333435363738\nGLOBL literal<>(SB),8,$240\n"

const fixedLocalRangePrefix = "MOVQ AX,R9\nCMPQ R9,$16\nJAE done\nTESTQ R9,R9\nJE done\n"
const fixedLocalRangeLoad = "MOVQ R9,R11\nSHLQ $4,R11\nLEAQ literal<>(SB),R10\n" +
	"MOVOU -16(R10)(R11*1),X0\nMOVQ X0,AX\ndone:"

type fixedLocalRangeCase struct{ name, body string }

func fixedLocalRangeCases() []fixedLocalRangeCase {
	var cases []fixedLocalRangeCase
	aliases := x86ConditionalBranchAliasOracle()
	var names []string
	for alias := range aliases {
		names = append(names, alias)
	}
	sort.Strings(names)
	for _, alias := range names {
		var guard string
		switch aliases[alias] {
		case "JCS":
			guard = "CMPQ R9,$16\n" + alias + " bounded\nJMP done\nbounded:\n"
		case "JCC":
			guard = "CMPQ R9,$16\n" + alias + " done\n"
		case "JLS":
			guard = "CMPQ R9,$15\n" + alias + " bounded\nJMP done\nbounded:\n"
		case "JHI":
			guard = "CMPQ R9,$15\n" + alias + " done\n"
		case "JEQ":
			guard = "CMPQ R9,$16\nJAE done\nTESTQ R9,R9\n" + alias + " done\n"
		case "JNE":
			guard = "CMPQ R9,$16\nJAE done\nTESTQ R9,R9\n" + alias + " nonzero\nJMP done\nnonzero:\n"
		default:
			continue
		}
		if aliases[alias] != "JEQ" && aliases[alias] != "JNE" {
			guard += "TESTQ R9,R9\nJE done\n"
		}
		cases = append(cases, fixedLocalRangeCase{"condition/" + alias, "MOVQ AX,R9\n" + guard + fixedLocalRangeLoad})
	}
	for _, register := range strings.Fields("AX BX CX DX DI SI BP R8 R9 R10 R11 R12 R13 R14 R15") {
		body := strings.ReplaceAll(fixedLocalRangePrefix+fixedLocalRangeLoad, "R9", register)
		cases = append(cases, fixedLocalRangeCase{"index/" + register, body})
	}
	for _, scale := range []int{1, 2, 4, 8} {
		body := fixedLocalRangePrefix + fmt.Sprintf("LEAQ literal<>(SB),R10\nMOVOU -%d(R10)(R9*%d),X0\nMOVQ X0,AX\ndone:", scale, scale)
		cases = append(cases, fixedLocalRangeCase{fmt.Sprintf("scale/%d", scale), body})
	}
	cases = append(cases,
		fixedLocalRangeCase{"compare lower endpoint", strings.Replace(fixedLocalRangePrefix, "TESTQ R9,R9\nJE done", "CMPQ R9,$1\nJB done", 1) + fixedLocalRangeLoad},
		fixedLocalRangeCase{"flags preserved before branch", strings.Replace(fixedLocalRangePrefix, "JAE done", "MOVQ AX,R8\nNOP\nJAE done", 1) + fixedLocalRangeLoad},
		fixedLocalRangeCase{"range survives later flags", fixedLocalRangePrefix + "CMPQ AX,$12\nJE join\nNOP\njoin:\n" + fixedLocalRangeLoad},
		fixedLocalRangeCase{"unrelated partial write", fixedLocalRangePrefix + "MOVB $0,CL\n" + fixedLocalRangeLoad},
		fixedLocalRangeCase{"two bounded incoming paths", "MOVQ AX,R9\nTESTQ AX,AX\nJE small\nCMPQ R9,$16\nJAE done\nJMP bounded\nsmall:\nCMPQ R9,$8\nJAE done\nbounded:\nTESTQ R9,R9\nJE done\n" + fixedLocalRangeLoad},
		fixedLocalRangeCase{"generic loop before bound", "MOVQ AX,R9\nagain:\nCMPQ R9,$16\nJB tail\nSUBQ $16,R9\nJMP again\ntail:\nTESTQ R9,R9\nJE done\n" + fixedLocalRangeLoad},
		fixedLocalRangeCase{"wide numerical shift count", fixedLocalRangePrefix + strings.Replace(fixedLocalRangeLoad, "SHLQ $4", "SHLQ $68", 1)},
		fixedLocalRangeCase{"equivalent arithmetic shift spelling", fixedLocalRangePrefix + strings.Replace(fixedLocalRangeLoad, "SHLQ", "SALQ", 1)},
	)
	return cases
}

func fixedLocalRangeFixture(t *testing.T, body string) (Func, FuncSig, string) {
	t.Helper()
	fn, sig, source := fixedLocalGPFixture(t, body)
	// This is an internal replay fixture, not a public source binding. The
	// separate three-API object matrix captures the complete original DATA.
	sig.x86FixedLocal = &x86FixedLocalBinding{literalData: map[string]x86FixedLocalData{
		"literal<>": {size: 240, alignment: 16},
	}}
	return fn, sig, source
}

func TestGoAMD64FixedLocalReadonlyRangeComplete(t *testing.T) {
	var original strings.Builder
	original.WriteString(fixedLocalRangeData)
	rows := fixedLocalRangeCases()
	if len(rows) != 48 {
		t.Fatal("unsigned/equality aliases, complete GP bank and scale inventory changed", len(rows))
	}
	for index, row := range rows {
		fn, sig, source := fixedLocalRangeFixture(t, row.body)
		original.WriteString(strings.Replace(source, "·Value", fmt.Sprintf("·Value%d", index), 1))
		t.Run(row.name, func(t *testing.T) {
			proved, err := proveX86FixedLocal(fn, sig)
			if err != nil {
				t.Fatal("complete numerical range lost its readonly DATA access", err)
			}
			found := false
			for _, instruction := range proved.Instrs {
				if instruction.Op != "MOVOU" {
					continue
				}
				found = true
				access, present := instruction.x86FixedLocalMemory[0]
				if !present || access.owner != proved.x86FixedLocal || access.width != 16 || access.write || !access.nativeInput {
					t.Fatal("readonly numerical envelope acquired private storage or lost its complete tuple", access)
				}
			}
			if !found {
				t.Fatal("fixture has no complete indexed vector read")
			}
		})
	}
	requireX86GoAssemblerResult(t, "amd64", original.String(), true)
}

func TestGoAMD64FixedLocalReadonlyRangeGuards(t *testing.T) {
	valid := fixedLocalRangePrefix + fixedLocalRangeLoad
	rows := []fixedLocalRangeCase{
		{"zero not excluded", strings.Replace(valid, "TESTQ R9,R9\nJE done\n", "", 1)},
		{"upper edge reversed", strings.Replace(valid, "JAE done", "JB done", 1)},
		{"sixteen admitted", strings.Replace(valid, "CMPQ R9,$16", "CMPQ R9,$17", 1)},
		{"stale unsigned flags", strings.Replace(valid, "JAE done", "CMPQ AX,$32\nJAE done", 1)},
		{"stale zero flags", strings.Replace(valid, "JE done", "CMPQ AX,$32\nJE done", 1)},
		{"compared value overwritten", strings.Replace(valid, "JAE done", "MOVQ 0(SP),R9\nJAE done", 1)},
		{"partial comparison", strings.Replace(valid, "CMPQ R9,$16", "CMPL R9,$16", 1)},
		{"partial index overwrite", fixedLocalRangePrefix + "MOVB $0,R9\n" + fixedLocalRangeLoad},
		{"loaded index loses range", fixedLocalRangePrefix + "MOVQ 0(SP),R9\n" + fixedLocalRangeLoad},
		{"numerical arithmetic loses range", fixedLocalRangePrefix + "ADDQ $16,R9\n" + fixedLocalRangeLoad},
		{"shift overflow", strings.Replace(valid, "SHLQ $4", "SHLQ $63", 1)},
		{"lower bound before object", strings.Replace(valid, "MOVOU -16(", "MOVOU -17(", 1)},
		{"complete vector after object", strings.Replace(valid, "MOVOU -16(", "MOVOU -15(", 1)},
		{"wider complete tuple", strings.Replace(valid, "MOVOU -16(R10)(R11*1),X0", "VMOVDQU -16(R10)(R11*1),Y0", 1)},
		{"alignment not inferred from interval", strings.Replace(valid, "SHLQ $4,R11", "SHLQ $0,R11", 1)},
		{"unbounded incoming path", strings.Replace(valid, "CMPQ R9,$16", "CMPQ AX,$0\nJE unchecked\nCMPQ R9,$16", 1)},
		{"private base is not literal", strings.Replace(valid, "LEAQ literal<>(SB),R10", "MOVQ SP,R10", 1)},
		{"pointer cannot be numerical index", strings.Replace(valid, "MOVQ AX,R9", "MOVQ SP,R9", 1)},
		{"missing upper numerical bytes", strings.Replace(valid, "MOVQ AX,R9", "MOVW AX,R9", 1)},
		{"foreign readonly owner", strings.Replace(valid, "LEAQ literal<>(SB),R10", "LEAQ other<>(SB),R10", 1)},
		{"readonly write", strings.Replace(valid, "MOVOU -16(R10)(R11*1),X0", "PXOR X0,X0\nMOVOU X0,-16(R10)(R11*1)", 1)},
	}
	var original strings.Builder
	original.WriteString(fixedLocalRangeData + "GLOBL other<>(SB),8,$240\n")
	// Dynamic native reads retain their original effective address. Their
	// translation does not assert that every possible caller index is safe.
	// Private relocation, initialization and storage ownership remain required.
	rejected := map[string]bool{
		"private base is not literal":       true,
		"pointer cannot be numerical index": true,
		"missing upper numerical bytes":     true,
		"foreign readonly owner":            true,
		"readonly write":                    true,
	}
	for index, row := range rows {
		if row.name == "unbounded incoming path" {
			row.body = strings.Replace(row.body, "MOVQ R9,R11", "unchecked:\nMOVQ R9,R11", 1)
		}
		if row.name == "alignment not inferred from interval" {
			row.body = strings.Replace(row.body, "MOVOU -16(", "MOVO 0(", 1)
		}
		fn, sig, source := fixedLocalRangeFixture(t, row.body)
		original.WriteString(strings.Replace(source, "·Value", fmt.Sprintf("·Value%d", index), 1))
		t.Run(row.name, func(t *testing.T) {
			_, err := proveX86FixedLocal(fn, sig)
			if !rejected[row.name] {
				if err != nil {
					t.Fatal("dynamic machine address incorrectly required a caller bounds proof", err)
				}
				return
			}
			if !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("private, undefined or readonly storage acquired permission", err)
			}
			for _, instruction := range fn.Instrs {
				if len(instruction.x86FixedLocalMemory) != 0 {
					t.Fatal("failed range proof published provisional accesses")
				}
			}
		})
	}
	requireX86GoAssemblerResult(t, "amd64", original.String(), true)
}

func TestGoX86SDKLiteralUnsignedRangeEdges(t *testing.T) {
	// A small exhaustive value oracle is independent of the interval formulas.
	// It includes zero, interior exclusions and the unsigned overflow endpoint.
	for alias, canonical := range x86ConditionalBranchAliasOracle() {
		if canonical != "JCS" && canonical != "JCC" && canonical != "JLS" && canonical != "JHI" && canonical != "JEQ" && canonical != "JNE" {
			continue
		}
		t.Run(alias, func(t *testing.T) {
			for _, extent := range [][2]uint64{{0, 0}, {1, 1}, {15, 15}, {16, 16}, {0, 15}, {0, 31}, {1, 15}, {math.MaxUint64 - 2, math.MaxUint64}} {
				for _, bound := range []uint64{0, 1, 15, 16, math.MaxUint64} {
					for _, taken := range []bool{false, true} {
						minimum, maximum, feasible := uint64(0), uint64(0), false
						for value := extent[0]; ; value++ {
							var result bool
							switch canonical {
							case "JCS":
								result = value < bound
							case "JCC":
								result = value >= bound
							case "JLS":
								result = value <= bound
							case "JHI":
								result = value > bound
							case "JEQ":
								result = value == bound
							case "JNE":
								result = value != bound
							}
							if result == taken {
								if !feasible {
									minimum = value
								}
								maximum, feasible = value, true
							}
							if value == extent[1] {
								break
							}
						}
						state := x86SDKLiteralState{comparison: 0, compared: true, constant: bound}
						state.gp[0] = x86SDKLiteralValue{width: 8, minimum: extent[0], maximum: extent[1]}
						actual := x86SDKLiteralRefineEdge(Op(alias), taken, &state)
						if actual != feasible || feasible && (state.gp[0].minimum != minimum || state.gp[0].maximum != maximum) {
							t.Fatal("unsigned edge differs from enumerated values", extent, bound, taken, state.gp[0], actual, minimum, maximum, feasible)
						}
					}
				}
			}
		})
	}
}

func TestGoAMD64FixedLocalReadonlyRangeWriteRevocation(t *testing.T) {
	for _, row := range []string{
		"MOVB $0,R9", "MOVQ AX,R9", "MOVL AX,R9", "ADDQ $1,R9",
		"LEAQ 16(SP),R9", "LEAQ literal<>(SB),R9", "CMOVQEQ AX,R9",
		"SETNE R9", "KMOVQ K1,R9", "VPEXTRQ $0,X0,R9", "MOVQ X0,R9",
	} {
		t.Run(row, func(t *testing.T) {
			state := x86FixedLocalState{
				pointers: map[Reg]int64{SP: 0}, opaque: make(map[Reg]x86FixedLocalOrigins),
				constants: map[Reg]int64{AX: 7, "R9": 3}, booleans: make(map[Reg]uint8),
				known: map[Reg]uint8{AX: 255, "R9": 255}, vectors: map[Reg]uint64{"Z0": ^uint64(0)},
				masks: map[Reg]bool{"K1": true}, flags: x86ByteFlagsAll,
				ranges: map[Reg]x86UnsignedRange{"R9": {1, 15}}, comparison: x86FixedLocalComparison{register: "R9", constant: 16},
			}
			proof := &x86FixedLocalProof{frame: 64, binding: &x86FixedLocalBinding{
				literalData: map[string]x86FixedLocalData{"literal<>": {size: 240, alignment: 16}},
			}}
			ins := x86ScalarLaneInstruction(t, row)
			if err := fixedLocalStep(&ins, &state, FuncSig{}, proof, 0); err != nil {
				t.Fatal("registered write fixture rejected", err)
			}
			if _, stale := state.ranges["R9"]; stale || state.comparison.register != "" {
				t.Fatal("GP writer retained a stale numerical range or FLAGS relation", state.ranges, state.comparison)
			}
		})
	}
}

func TestGoAMD64FixedLocalUnsignedRangeDeadBackedge(t *testing.T) {
	// TEST clears CF regardless of the input, so JB cannot revisit the store.
	// The previous CMP must neither force three iterations nor reject this
	// actual one-pass function merely because its source contains a backedge.
	const body = "MOVQ $0,SI\nloop:\nMOVQ AX,16(SP)(SI*8)\nADDQ $1,SI\n" +
		"CMPQ SI,$3\nTESTQ AX,AX\nJB loop\nMOVQ AX,AX"
	fn, sig, source := fixedLocalCountedLoopFixture(t, body)
	requireX86GoAssemblerResult(t, "amd64", source, true)
	if _, err := proveX86FixedLocal(fn, sig); err != nil {
		t.Fatal("a provably dead backedge rejected an ordinary one-pass private access", err)
	}
}
