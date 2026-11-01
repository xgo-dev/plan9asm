package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// These are independent source cases, not a production opcode registry or a
// native-memory certificate. Existing family oracles supply their special rows.
type x86GPFaultingReadCase struct {
	family, instruction string
	bytes               int
	partner, carry      bool
	accumulator, index  bool
	native, write       bool
	flagsResult         bool
}

func x86GPFaultingReadCases(arch string) []x86GPFaultingReadCase {
	var rows []x86GPFaultingReadCase
	for i, suffix := range "BWLQ" {
		if arch == "386" && suffix == 'Q' {
			continue
		}
		width := []int{1, 2, 4, 8}[i]
		for _, stem := range []string{"ADD", "SUB", "ADC", "SBB", "AND", "OR", "XOR"} {
			rows = append(rows, x86GPFaultingReadCase{
				family: "alu", instruction: stem + string(suffix) + " MEM,BX", bytes: width,
				partner: true, carry: stem == "ADC" || stem == "SBB",
			})
		}
		rows = append(rows, x86GPFaultingReadCase{
			family: "load", instruction: "MOV" + string(suffix) + " MEM,BX", bytes: width,
		})
		for _, stem := range []string{"XCHG", "XADD"} {
			rows = append(rows, x86GPFaultingReadCase{
				family: "exchange", instruction: stem + string(suffix) + " BX,MEM",
				bytes: width, partner: true, native: true, write: true,
			})
			if stem == "XCHG" {
				reverse := rows[len(rows)-1]
				reverse.instruction = stem + string(suffix) + " MEM,BX"
				rows = append(rows, reverse)
			}
		}
	}
	for _, row := range x86ExtensionNativeOracle {
		if arch == "386" && row.amd64Only {
			continue
		}
		rows = append(rows, x86GPFaultingReadCase{
			family: "extension", instruction: row.op + " MEM,BX", bytes: row.source,
		})
	}
	for _, op := range x86BitTestOracleNames(arch) {
		width := map[byte]int{'W': 2, 'L': 4, 'Q': 8}[op[len(op)-1]]
		for _, index := range []string{"$0", "CX"} {
			rows = append(rows, x86GPFaultingReadCase{
				family: "bit-test", instruction: op + " " + index + ",MEM", bytes: width,
				index: index == "CX", write: op[:len(op)-1] != "BT",
				flagsResult: true,
			})
		}
	}
	for _, suffix := range "WLQ" {
		if arch == "386" && suffix == 'Q' {
			continue
		}
		for _, row := range x86CallerExplicitIMULRows {
			if !strings.Contains(row.instruction, "(DI)") {
				continue
			}
			instruction := strings.ReplaceAll(row.instruction, "@", string(suffix))
			rows = append(rows, x86GPFaultingReadCase{
				family: "imul", instruction: strings.Replace(instruction, "(DI)", "MEM", 1),
				bytes: map[rune]int{'W': 2, 'L': 4, 'Q': 8}[suffix], partner: !row.three,
			})
		}
	}
	for _, row := range x86CMPXCHGOriginalRows {
		if row.pair || arch == "386" && row.bits == 64 {
			continue
		}
		rows = append(rows, x86GPFaultingReadCase{
			family: "cmpxchg", instruction: row.op + " BX,MEM", bytes: row.bits / 8,
			partner: true, accumulator: true, native: true, write: true,
		})
	}
	return rows
}

type x86GPFaultingFixture struct {
	name, source, declaration string
	label                     string
	row                       x86GPFaultingReadCase
	accept                    bool
}

func x86GPFaultingSource(row x86GPFaultingReadCase, arch, name, omission string, indexed, live bool) x86GPFaultingFixture {
	word, move := 8, "MOVQ"
	if arch == "386" {
		word, move = 4, "MOVL"
	}
	var body strings.Builder
	if omission == "numeric-base" {
		fmt.Fprintf(&body, "%s $1,DX\n", move)
	} else if omission != "base" {
		fmt.Fprintf(&body, "%s p+0(FP),DX\n", move)
	}
	if row.partner && omission != "partner" {
		fmt.Fprintf(&body, "%s $3,BX\n", move)
	}
	if row.accumulator && omission != "accumulator" {
		fmt.Fprintf(&body, "%s $5,AX\n", move)
	}
	if row.index && omission != "bit-index" {
		fmt.Fprintf(&body, "%s $1,CX\n", move)
	}
	address := "(DX)"
	if indexed {
		address = "-1(DX)(SI*2)"
		if omission != "address-index" {
			fmt.Fprintf(&body, "%s $1,SI\n", move)
		}
	}
	if row.carry && omission != "carry" {
		body.WriteString("CLC\n")
	}
	body.WriteString(strings.Replace(row.instruction, "MEM", address, 1) + "\n")
	declaration := fmt.Sprintf("func %s(p *[32]byte)", name)
	args := word
	if live {
		result := "BX"
		if row.flagsResult {
			body.WriteString("SETCS BL\n")
		}
		if row.accumulator {
			result = "AX"
		}
		fmt.Fprintf(&body, "MOVB %s,ret+%d(FP)\n", result, word)
		declaration += " uint8"
		args++
	}
	body.WriteString("RET\n")
	label := omission
	if label == "" {
		label = "complete"
	}
	return x86GPFaultingFixture{
		name: name, source: fmt.Sprintf("TEXT ·%s(SB),4,$0-%d\n%s", name, args, body.String()),
		declaration: declaration, label: fmt.Sprintf("live=%t/indexed=%t/%s", live, indexed, label),
		row: row, accept: omission == "",
	}
}

func x86GPFaultingRename(fixture x86GPFaultingFixture, name string) x86GPFaultingFixture {
	fixture.source = strings.Replace(fixture.source, "·"+fixture.name+"(SB)", "·"+name+"(SB)", 1)
	fixture.declaration = strings.Replace(fixture.declaration, "func "+fixture.name+"(", "func "+name+"(", 1)
	fixture.name = name
	return fixture
}

// At most 32 complete functions share one original-Go listing/object. Each
// fixture keeps its own declaration and tests still translate negatives alone.
func x86GPFaultingGoBatches(t *testing.T, arch string, fixtures []x86GPFaultingFixture) {
	t.Helper()
	for start := 0; start < len(fixtures); start += 32 {
		end := start + 32
		if end > len(fixtures) {
			end = len(fixtures)
		}
		var source strings.Builder
		for _, fixture := range fixtures[start:end] {
			source.WriteString(fixture.source)
		}
		listing, err := x86ScalarLiteralGoListing(t, arch, source.String())
		if err != nil || listing == "" {
			t.Fatal("actual Go must accept every complete source before input classification", err)
		}
	}
	t.Logf("GP_FAULTING_READ_ORIGINAL_GO arch=%s complete_functions=%d", arch, len(fixtures))
}

func x86GPFaultingInputFixtures(row x86GPFaultingReadCase, arch string, live bool) []x86GPFaultingFixture {
	var fixtures []x86GPFaultingFixture
	omissions := []string{"", "base", "numeric-base"}
	if row.partner {
		omissions = append(omissions, "partner")
	}
	if row.carry {
		omissions = append(omissions, "carry")
	}
	if row.accumulator {
		omissions = append(omissions, "accumulator")
	}
	if row.index {
		omissions = append(omissions, "bit-index")
	}
	for _, omission := range omissions {
		fixtures = append(fixtures, x86GPFaultingSource(row, arch, "Value", omission, false, live))
	}
	fixtures = append(fixtures,
		x86GPFaultingSource(row, arch, "Value", "", true, live),
		x86GPFaultingSource(row, arch, "Value", "address-index", true, live))
	return fixtures
}

func TestX86GPFaultingReadWholeFunctionInputs(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		t.Run(arch, func(t *testing.T) {
			rows := x86GPFaultingReadCases(arch)
			want := map[string]int{"amd64": 95, "386": 67}[arch]
			if len(rows) != want {
				t.Fatal("complete A–G source-mode directory changed", len(rows), want)
			}
			var originals []x86GPFaultingFixture
			for _, row := range rows {
				for _, live := range []bool{false, true} {
					for _, fixture := range x86GPFaultingInputFixtures(row, arch, live) {
						name := fmt.Sprintf("Input%d", len(originals))
						originals = append(originals, x86GPFaultingRename(fixture, name))
					}
				}
			}
			x86GPFaultingGoBatches(t, arch, originals)
			for _, fixture := range originals {
				t.Run(fixture.row.family+"/"+fixture.row.instruction+"/"+fixture.label, func(t *testing.T) {
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(api, func(t *testing.T) {
							ir, err := x86ScalarFPBitViewAPI(t, fixture.source, fixture.declaration, arch, testTargetTriple("linux", arch), api)
							if fixture.accept {
								if err != nil || ir == "" {
									t.Fatal("INITIALIZED_POSITIVE_REJECTED", err, fixture.source)
								}
							} else if err == nil && ir != "" {
								t.Fatal("MISSING_INPUT_ACCEPTED", fixture.label, fixture.source)
							} else if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
								t.Fatal("WRONG_REJECTION_CLASS", err, fixture.source)
							}
						})
					}
				})
			}
		})
	}
}

func TestX86GPFaultingReadCompleteObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			var fixtures []x86GPFaultingFixture
			for _, row := range x86GPFaultingReadCases(target.arch) {
				for _, live := range []bool{false, true} {
					for _, indexed := range []bool{false, true} {
						name := fmt.Sprintf("Read%d", len(fixtures))
						fixtures = append(fixtures, x86GPFaultingSource(row, target.arch, name, "", indexed, live))
					}
				}
			}
			for start := 0; start < len(fixtures); start += 32 {
				end := start + 32
				if end > len(fixtures) {
					end = len(fixtures)
				}
				t.Run(fmt.Sprintf("batch%02d", start/32), func(t *testing.T) {
					batch := fixtures[start:end]
					x86GPFaultingGoBatches(t, target.arch, batch)
					var source, declarations strings.Builder
					var names []string
					for _, fixture := range batch {
						source.WriteString(fixture.source)
						declarations.WriteString(fixture.declaration + "\n")
						names = append(names, fixture.name)
					}
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(api, func(t *testing.T) {
							ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
							if err != nil || ir == "" {
								t.Fatal("INITIALIZED_BATCH_REJECTED", err)
							}
							for _, view := range []string{ir, x86MulDivRoundOptimize(t, ir)} {
								bodies := x86StringMemoryFunctions(t, view, names)
								for _, fixture := range batch {
									body := bodies[fixture.name]
									read := fmt.Sprintf("load volatile i%d,", fixture.row.bytes*8)
									if fixture.row.native {
										read = "asm sideeffect"
										opcode := strings.ToLower(strings.Fields(fixture.row.instruction)[0])
										if !strings.Contains(body, opcode) || !strings.Contains(body, "*m") {
											t.Fatal("complete function lost its original native memory opcode", fixture.name, body)
										}
									}
									if !strings.Contains(body, read) || fixture.row.write && !fixture.row.native && !strings.Contains(body, "store volatile") {
										t.Fatal("complete function lost its actual observable read/write", fixture.name, fixture.row.instruction, body)
									}
								}
							}
							for _, level := range []string{"-O0", "-O2"} {
								x86PackedStringCompileObject(t, llc, target.triple, ir, level)
							}
						})
					}
				})
			}
		})
	}
}

func TestX86GPFaultingReadNonMemoryControls(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		lea := "LEAQ 3(AX)(CX*2),BX"
		if target.arch == "386" {
			lea = "LEAL 3(AX)(CX*2),BX"
		}
		var fixtures []x86GPFaultingFixture
		for index, instruction := range []string{"ADDL CX,BX", "MOVBLZX AX,BX", "IMUL3L $7,AX,BX", "BSWAPL AX", lea, "NOPW (AX)", "NOP"} {
			name := fmt.Sprintf("Control%d", index)
			fixtures = append(fixtures, x86GPFaultingFixture{
				name: name, label: instruction,
				source:      fmt.Sprintf("TEXT ·%s(SB),4,$0-0\n%s\nRET\n", name, instruction),
				declaration: "func " + name + "()",
			})
		}
		x86GPFaultingGoBatches(t, target.arch, fixtures)
		for _, fixture := range fixtures {
			t.Run(target.triple+"/"+fixture.label, func(t *testing.T) {
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(api, func(t *testing.T) {
						ir, err := x86ScalarFPBitViewAPI(t, fixture.source, fixture.declaration, target.arch, target.triple, api)
						if err != nil || ir == "" {
							t.Fatal("NONFAULTING_CONTROL_REJECTED", err)
						}
					})
				}
			})
		}
	}
}

func TestX86GPFaultingReadProjectionBoundaries(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range x86GPFaultingReadCases(arch) {
			t.Run(arch+"/"+row.instruction, func(t *testing.T) {
				ins := x86YMMReadSource(t, strings.Replace(row.instruction, "MEM", "(DX)", 1))
				original := ins
				original.Args = append([]Operand(nil), ins.Args...)
				gp, gpKnown, gpErr := x86TypedGPByteEffect(ins.Op, ins, arch)
				universal, known, err := x86TypedInstructionByteEffect(ins.Op, ins, arch)
				if gpKnown {
					if gpErr != nil || !known || err != nil {
						t.Fatal("complete source changed its typed effect domain", gpErr, err)
					}
					want := gp
					want.requiresResultProof = true
					if !reflect.DeepEqual(universal, want) {
						t.Fatal("routing projection changed more than its local mandatory bit", gp, universal)
					}
				} else if known || err != nil {
					t.Fatal("private MOV/atomic routing registered a new general effect", known, err)
				}
				after, afterKnown, afterErr := x86TypedGPByteEffect(ins.Op, ins, arch)
				if !reflect.DeepEqual(gp, after) || gpKnown != afterKnown || (gpErr == nil) != (afterErr == nil) ||
					!reflect.DeepEqual(ins, original) {
					t.Fatal("routing mutated the GP directory or original operands")
				}
			})
		}
		for _, instruction := range []string{"ADDL AX,BX", "LEAL 3(AX)(CX*2),BX", "NOPW (AX)"} {
			ins := x86YMMReadSource(t, instruction)
			gp, known, err := x86TypedGPByteEffect(ins.Op, ins, arch)
			universal, universalKnown, universalErr := x86TypedInstructionByteEffect(ins.Op, ins, arch)
			if !known || err != nil || !universalKnown || universalErr != nil || !reflect.DeepEqual(gp, universal) {
				t.Fatal("non-memory GP/LEA/NOP summary changed", arch, instruction)
			}
		}
		ins := x86YMMReadSource(t, "MOVUPS (DX),X1")
		vector, known, err := x86TypedLegacyPackedMoveByteEffect(ins.Op, ins, arch)
		universal, universalKnown, universalErr := x86TypedInstructionByteEffect(ins.Op, ins, arch)
		if !known || err != nil || !universalKnown || universalErr != nil || !reflect.DeepEqual(vector, universal) ||
			x86GPFaultingReadNeedsProof(ins, arch) {
			t.Fatal("GP routing expanded the vector effect domain", arch)
		}
	}
}

func TestX86GPFaultingReadUintptrRolePolicy(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		var fixtures []x86GPFaultingFixture
		seen := make(map[string]bool)
		for _, row := range x86GPFaultingReadCases(target.arch) {
			if seen[row.family] {
				continue
			}
			seen[row.family] = true
			for _, live := range []bool{false, true} {
				name := fmt.Sprintf("Numeric%d", len(fixtures))
				fixture := x86GPFaultingSource(row, target.arch, name, "", false, live)
				fixture.declaration = strings.Replace(fixture.declaration, "*[32]byte", "uintptr", 1)
				fixtures = append(fixtures, fixture)
			}
		}
		x86GPFaultingGoBatches(t, target.arch, fixtures)
		for _, fixture := range fixtures {
			t.Run(target.triple+"/"+fixture.row.family+"/"+fixture.label, func(t *testing.T) {
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(api, func(t *testing.T) {
						ir, err := x86ScalarFPBitViewAPI(t, fixture.source, fixture.declaration, target.arch, target.triple, api)
						if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
							t.Fatal("UINTPTR_ROLE_POLICY_ACCEPTED: NUM input gained a pointer role", err)
						}
					})
				}
			})
		}
	}
}

func TestX86GPFaultingReadIMULAddressAlias(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		var fixtures []x86GPFaultingFixture
		for _, row := range x86GPFaultingReadCases(target.arch) {
			if row.family != "imul" {
				continue
			}
			three := strings.HasPrefix(row.instruction, "IMUL3")
			name := fmt.Sprintf("Alias%d", len(fixtures))
			fixture := x86GPFaultingSource(row, target.arch, name, "partner", false, false)
			fixture.source = strings.ReplaceAll(fixture.source, "DX", "BX")
			fixture.accept = three
			fixtures = append(fixtures, fixture)
		}
		x86GPFaultingGoBatches(t, target.arch, fixtures)
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(target.triple+"/"+api, func(t *testing.T) {
				var source, declarations strings.Builder
				for _, fixture := range fixtures {
					if !fixture.accept {
						ir, err := x86ScalarFPBitViewAPI(t, fixture.source, fixture.declaration, target.arch, target.triple, api)
						if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
							t.Fatal("two-operand IMUL obtained old-destination NUM from its pointer role", err)
						}
						continue
					}
					source.WriteString(fixture.source)
					declarations.WriteString(fixture.declaration + "\n")
				}
				ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
				if err != nil || ir == "" {
					t.Fatal("three-operand IMUL overwrites its pointer destination after reading its address", err)
				}
				for _, level := range []string{"-O0", "-O2"} {
					x86PackedStringCompileObject(t, llc, target.triple, ir, level)
				}
			})
		}
	}
}
