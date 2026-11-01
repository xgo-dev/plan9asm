package plan9asm

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// These are the four two-source floating shuffles, not the eight single-source
// PSHUFW/PSHUFD/PSHUFHW/PSHUFLW spellings already covered independently.
var x86PackedFloatShuffleOracleMembers = []string{"SHUFPS", "SHUFPD", "VSHUFPS", "VSHUFPD"}

type x86PackedFloatShuffleOracleRow struct {
	op, bank, input, mode string
}

func x86PackedFloatShuffleOracleRows(arch string) []x86PackedFloatShuffleOracleRow {
	var rows []x86PackedFloatShuffleOracleRow
	for _, op := range x86PackedFloatShuffleOracleMembers {
		for _, bank := range []string{"X", "Y", "Z"} {
			if !strings.HasPrefix(op, "V") && bank != "X" || arch == "386" && strings.HasPrefix(op, "V") {
				continue // Go's named mode32 frontend cannot encode four operands.
			}
			for _, input := range []string{"register", "full", "broadcast"} {
				for _, mode := range []string{"plain", "merge", "zero"} {
					if !strings.HasPrefix(op, "V") && (input == "broadcast" || mode != "plain") {
						continue
					}
					rows = append(rows, x86PackedFloatShuffleOracleRow{op, bank, input, mode})
				}
			}
		}
	}
	return rows
}

func (row x86PackedFloatShuffleOracleRow) instruction(selector, destination int) string {
	op, first, mask := row.op, row.bank+"0", ""
	if row.input != "register" {
		first = "(AX)"
	}
	if row.input == "broadcast" {
		op += ".BCST"
	}
	if row.mode != "plain" {
		mask = "K1,"
	}
	if row.mode == "zero" {
		op += ".Z"
	}
	operands := fmt.Sprintf(" $%d,%s,", selector, first)
	if strings.HasPrefix(row.op, "V") {
		operands += row.bank + "1," + mask
	}
	return op + operands + fmt.Sprint(row.bank, destination)
}

func (row x86PackedFloatShuffleOracleRow) program(arch, name string) (string, string) {
	word, move := 8, "MOVQ"
	if arch == "386" {
		word, move = 4, "MOVL"
	}
	destination := 2
	if !strings.HasPrefix(row.op, "V") {
		destination = 1
	}
	source := fmt.Sprintf("TEXT ·%s(SB),4,$0-%d\n%s out+0(FP),DI\n%s a+%d(FP),AX\n%s b+%d(FP),BX\n"+
		"VMOVUPS (AX),Z0\nVMOVUPS (BX),Z1\nVMOVUPS (DI),Z2\nKMOVQ mask+%d(FP),K1\n"+
		"MOVL $5,DX\nCMPL DX,$3\nSTD\n%s\nVMOVUPS Z%d,(DI)\nSETCS 64(DI)\nSETOS 65(DI)\nCLD\nRET\n",
		name, 3*word+8, move, move, word, move, 2*word, 3*word, row.instruction(27, destination), destination)
	return source, "func " + name + "(out,a,b *byte,mask uint64)\n"
}

func TestX86PackedFloatShuffleOriginalInitializedConformanceObjects(t *testing.T) {
	data, err := os.ReadFile("testdata/conformance/amd64/conformance_amd64.s")
	if err != nil {
		t.Fatal(err)
	}
	start := strings.Index(string(data), "TEXT ·packedFloatShuffleSemantics(SB)")
	if start < 0 {
		t.Fatal("original packed-float-shuffle entry missing")
	}
	end := strings.Index(string(data[start:]), "\n\tRET\n")
	if end < 0 {
		t.Fatal("original complete packed-float-shuffle return missing")
	}
	body := string(data[start : start+end+len("\n\tRET\n")])
	if fmt.Sprintf("%x", sha256.Sum256([]byte(body))) != "d23a93536d2e70b7c8c5367d1778bb95d6ae79495f3e5de22014e9d92d3f0323" {
		t.Fatal("original complete shuffle ASM/source observations changed")
	}
	data, err = os.ReadFile("amd64_conformance_test.go")
	if err != nil {
		t.Fatal(err)
	}
	reference, err := x86SegmentMOVSourceFunction(data, "amd64ConformanceRuntimeC")
	if err != nil || fmt.Sprintf("%x", sha256.Sum256(reference)) != "41b0fc284d1aea9a9d24d613f84a6f4ad416d25a84dfa9664f81c7f1a9eef1b4" {
		t.Fatal("original whole conformance C/reference changed", err)
	}
	x86PackedFaultProgramObjects(t, "#include \"textflag.h\"\n"+body,
		"func packedFloatShuffleSemantics(out *[96]byte,a,b *[32]byte)")
}

func TestX86PackedFloatShuffleInitializedFamilyFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("complete floating-shuffle objects require LLVM22")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			rows := x86PackedFloatShuffleOracleRows(target.arch)
			want := 58
			if target.arch == "386" {
				want = 4
			}
			if len(rows) != want {
				t.Fatal("orthogonal family/width/memory/mask denominator changed", len(rows), want)
			}
			var source, declarations strings.Builder
			for index, row := range rows {
				program, declaration := row.program(target.arch, fmt.Sprint("FloatShuffle", index))
				source.WriteString(program)
				declarations.WriteString(declaration)
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("complete initialized floating-shuffle source lost its typed consumer", err)
					}
					for _, pipeline := range []struct{ text, level string }{
						{ir, "-O0"}, {ir, "-O2"}, {x86DwordProductIROptimize(t, ir), "-O2"},
					} {
						x86PackedStringCompileObject(t, llc, target.triple, pipeline.text, pipeline.level)
					}
				})
			}
		})
	}
}

// Intel's selector is independent of the production form: Go's first operand
// supplies the high PS pair / odd PD lane, and the second supplies low/even.
func x86PackedFloatShuffleSelectedByte(op string, output, selector int) (input, at int) {
	laneBytes := 4
	if strings.HasSuffix(op, "PD") {
		laneBytes = 8
	}
	lane := output / laneBytes
	input = 1
	selected := selector >> (2 * (lane % 4)) & 3
	if laneBytes == 4 {
		if lane%4 >= 2 {
			input = 0
		}
	} else {
		input = 1 - lane%2
		selected = selector >> lane & 1
	}
	return input, output/16*16 + selected*laneBytes + output%laneBytes
}

func TestX86PackedFloatShuffleSelectorsEveryByteAliasesAndFlags(t *testing.T) {
	for _, row := range x86PackedFloatShuffleOracleRows("amd64") {
		if row.input != "register" {
			continue // Memory requires its separately paired physical source.
		}
		destinations := []int{0, 1, 2}
		if !strings.HasPrefix(row.op, "V") {
			destinations = []int{1}
		}
		for _, destination := range destinations {
			t.Run(row.instruction(27, destination), func(t *testing.T) {
				instruction := x86ScalarLaneInstruction(t, row.instruction(27, destination))
				effect, known, err := x86TypedInstructionByteEffect(instruction.Op, instruction, "amd64")
				if !known || err != nil || !effect.requiresResultProof || effect.flagsRead|effect.flagsDefined|effect.flagsKilled != 0 {
					t.Fatal("complete double-source shuffle lacks a typed result/FLAGS effect", known, err)
				}
				width := amd64VectorByteWidth(Reg(row.bank + "0"))
				check := func(selector, missingInput, missingByte int) {
					state := x86FMA3ResultInputState()
					if missingByte >= 0 {
						state.writeVector(missingInput, 64, state.vectorBytes(missingInput)&^(uint64(1)<<uint(missingByte)), false)
					}
					before := state.clone()
					var defined uint64
					for output := 0; output < width; output++ {
						input, at := x86PackedFloatShuffleSelectedByte(row.op, output, selector)
						available := before.vectorBytes(input)>>uint(at)&1 != 0
						if row.mode == "merge" {
							available = available && before.vectorBytes(destination)>>uint(output)&1 != 0
						}
						if available {
							defined |= uint64(1) << uint(output)
						}
					}
					want := before.clone()
					want.writeVector(destination, width, defined, !strings.HasPrefix(row.op, "V"))
					ins := x86ScalarLaneInstruction(t, row.instruction(selector, destination))
					if !x86ResultTransfer(ins, &state, nil, 0, "amd64") || !reflect.DeepEqual(state, want) {
						t.Fatal("selector borrowed a byte, lost an alias or changed GP/FLAGS/DF/storage state", selector, missingInput, missingByte)
					}
					caller := x86SourceStackState{
						bp: x86SourceStackAddress{original: true}, gOriginal: true, numericFlags: true,
						known: map[Reg]uint8{AX: 0xff}, callers: map[Reg]x86CallerPointerValue{DI: {argument: 0}},
						vectors: map[Reg]uint64{"Z0": before.vectorBytes(0), "Z1": before.vectorBytes(1), "Z2": before.vectorBytes(2)},
						masks:   map[Reg]bool{"K1": true},
					}
					wantCaller := x86CloneCallerState(caller)
					wantCaller.vectors[Reg(fmt.Sprint("Z", destination))] = want.vectorBytes(destination)
					if !x86CallerVectorMoveStep(&ins, &caller, nil) || !reflect.DeepEqual(caller, wantCaller) {
						t.Fatal("caller selector disagreed with exact result-byte dependencies or changed independent state", selector, missingInput, missingByte)
					}
				}
				for selector := 0; selector < 256; selector++ {
					check(selector, 0, -1)
				}
				for input := 0; input < 3; input++ {
					for missing := 0; missing < 64; missing++ {
						check(27, input, missing)
					}
				}
				if row.mode != "plain" {
					state := x86FMA3ResultInputState()
					state.masks[1] = false
					before := state.clone()
					if x86ResultTransfer(instruction, &state, nil, 0, "amd64") || !reflect.DeepEqual(state, before) {
						t.Fatal("unknown mask acquired a result or partly mutated state")
					}
				}
			})
		}
	}
}

func TestX86PackedFloatShuffleMissingNativeInputsAndDeadAccess(t *testing.T) {
	for _, row := range x86PackedFloatShuffleOracleRows("amd64") {
		if row.input == "register" {
			continue
		}
		t.Run(row.instruction(27, 1), func(t *testing.T) {
			destination := 2
			if !strings.HasPrefix(row.op, "V") {
				destination = 1
			}
			operation := row.instruction(27, destination)
			prefix := "TEXT ·Read(SB),4,$0-16\nMOVQ input+0(FP),AX\nKMOVQ mask+8(FP),K1\nPXOR X1,X1\nVXORPS X2,X2,X2\n"
			if row.bank != "X" {
				prefix = strings.Replace(prefix, "PXOR X1,X1\n", "VPXORD Z1,Z1,Z1\n", 1)
			}
			baseline := prefix + operation + "\nRET\n"
			x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", baseline)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, baseline, "func Read(input *byte,mask uint64)", "amd64", "x86_64-unknown-linux-gnu", api)
					if err != nil || ir == "" {
						t.Fatal("genuine initialized dead native shuffle lost its paired read", err)
					}
					width := amd64VectorByteWidth(Reg(row.bank + "0"))
					if row.input == "broadcast" {
						width = 4
						if strings.HasSuffix(row.op, "PD") {
							width = 8
						}
					}
					for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
						body := x86StringMemoryFunction(t, text, "Read")
						if strings.HasPrefix(row.op, "V") {
							tuple := fmt.Sprintf("<%d x i8>", width)
							if width == 4 || width == 8 {
								tuple = fmt.Sprintf("(?:%s|i%d)", tuple, width*8)
							}
							read := regexp.MustCompile(`(?m)load volatile ` + tuple + `, [^\n]*align 1(?:\D|$)`)
							if len(read.FindAllString(body, -1)) != 1 || strings.Count(body, "load volatile ") != 1 ||
								strings.Contains(body, "@llvm.masked.load") {
								var accesses []string
								for _, line := range strings.Split(body, "\n") {
									if strings.Contains(line, "load volatile ") || strings.Contains(line, "@llvm.masked.load") {
										accesses = append(accesses, strings.TrimSpace(line))
									}
								}
								t.Fatal("dead E4NF access lost its one unconditional full/broadcast tuple", width, accesses)
							}
						} else if !strings.Contains(body, "asm sideeffect") || !strings.Contains(body, strings.ToLower(row.op)) || !strings.Contains(body, "~{memory}") {
							t.Fatal("legacy m128 lost its original Type4 alignment/access opcode", body)
						}
					}
					mutations := []struct{ name, before, after string }{
						{"pointer", "MOVQ input+0(FP),AX\n", ""},
						{"numeric-address", "MOVQ input+0(FP),AX\n", "MOVQ $1,AX\n"},
						{"index", "(AX)", "(AX)(CX*2)"},
					}
					// A memory operand supplies only the first source, never the
					// selected register source or an independently merging destination.
					registerSeed := "PXOR X1,X1\n"
					if row.bank != "X" {
						registerSeed = "VPXORD Z1,Z1,Z1\n"
					}
					mutations = append(mutations, struct{ name, before, after string }{"register-source", registerSeed, ""})
					if row.mode == "merge" {
						mutations = append(mutations, struct{ name, before, after string }{"old-destination", "VXORPS X2,X2,X2\n", ""})
					}
					if row.mode != "plain" {
						mutations = append(mutations, struct{ name, before, after string }{"mask", "KMOVQ mask+8(FP),K1\n", ""})
					}
					for _, mutation := range mutations {
						changed := strings.Replace(baseline, mutation.before, mutation.after, 1)
						if changed == baseline {
							t.Fatal("independent negative did not change its input", mutation.name)
						}
						if output, err := x86ScalarFPBitViewAPI(t, changed, "func Read(input *byte,mask uint64)", "amd64", "x86_64-unknown-linux-gnu", api); output != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("dead shuffle acquired an absent pointer/index/mask", mutation.name, err)
						}
					}
				})
			}
		})
	}
}

func TestX86PackedFloatShuffleMissingSelectedBytesCannotReachStore(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		word, move := 8, "MOVQ"
		if arch == "386" {
			word, move = 4, "MOVL"
		}
		for _, row := range x86PackedFloatShuffleOracleRows(arch) {
			if row.input != "register" || row.mode != "plain" || row.bank != "X" {
				continue
			}
			for _, seed := range []string{"", "PXOR X0,X0\n", "PXOR X1,X1\n"} {
				destination := 2
				if !strings.HasPrefix(row.op, "V") {
					destination = 1
				}
				source := fmt.Sprintf("TEXT ·Missing(SB),4,$0-%d\n%s out+0(FP),DI\n%s%s\nMOVOU X%d,(DI)\nRET\n",
					word, move, seed, row.instruction(27, destination), destination)
				x86LEAActualTargetGoObject(t, arch, testTargetTriple("linux", arch), source)
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(fmt.Sprintf("%s/%s/seed=%q/%s", arch, row.op, seed, api), func(t *testing.T) {
						ir, err := x86ScalarFPBitViewAPI(t, source, "func Missing(out *byte)", arch, testTargetTriple("linux", arch), api)
						if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("a missing selected source byte reached an observable store", err)
						}
					})
				}
			}
		}
	}
}

func TestX86PackedFloatShuffleWholeRawOriginReplay(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range x86PackedFloatShuffleOracleRows(arch) {
			if row.input != "register" || row.mode != "plain" {
				continue
			}
			t.Run(arch+"/"+row.instruction(27, 1), func(t *testing.T) {
				destination := 2
				if !strings.HasPrefix(row.op, "V") {
					destination = 1
				}
				operation := row.instruction(27, destination)
				code, pcs := x86NumericalBoundaryGoBytes(t, arch, operation+"\nRET")
				if len(pcs) != 2 || pcs[1] != int64(len(code)-1) || code[len(code)-1] != 0xc3 {
					t.Fatal("independent original Go shuffle boundary missing", pcs, code)
				}
				prefix := "TEXT ·Value(SB),4,$0-4\n"
				zero := "PXOR"
				if strings.HasPrefix(row.op, "V") {
					zero = "VPXORD"
				}
				for register := 0; register < 3; register++ {
					if zero == "PXOR" {
						prefix += fmt.Sprintf("PXOR X%d,X%d\n", register, register)
					} else {
						prefix += fmt.Sprintf("VPXORD %s%d,%s%d,%s%d\n", row.bank, register, row.bank, register, row.bank, register)
					}
				}
				suffix := fmt.Sprintf("MOVL X%d,ret+0(FP)\nRET\n", destination)
				namedSource := prefix + operation + "\n" + suffix
				strict, check := x86RegisterReplayConsumers(t, arch, namedSource)
				named := mustParseX86RawReturn(t, namedSource).Funcs[0]
				if strict(named) != nil || check(named) != nil {
					t.Fatal("genuine complete named source failed before the raw restriction under review")
				}
				rawSource := prefix + x86RawDisplacementDirectives(code[:pcs[1]]) + suffix
				file, err := normalizeX86RawFile(mustParseX86RawReturn(t, rawSource), arch)
				if err != nil {
					t.Fatal("complete original raw normalization prior failed", err)
				}
				original, ordinal := file.Funcs[0], -1
				for index, instruction := range original.Instrs {
					if instruction.Op == Op(row.op) && instruction.x86SourceRaw != nil {
						if ordinal >= 0 {
							t.Fatal("ambiguous whole raw producer")
						}
						ordinal = index
					}
				}
				if ordinal < 0 || original.x86RawReplay == nil || original.x86RawReplay.validate(original, arch) != nil {
					t.Fatal("original raw producer lost its immutable complete source")
				}
				if err := check(original); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("raw instruction unexpectedly acquired a named producer permission", err)
				}
				changed := original
				changed.Instrs = cloneX86ReplayInstrs(original.Instrs)
				changed.Instrs[ordinal].x86SourceRaw = nil
				if original.x86RawReplay.validate(original, arch) != nil || !errors.Is(changed.x86RawReplay.validate(changed, arch), ErrProbeNeedsContext) {
					t.Fatal("origin-only mutation did not preserve the original immutable replay restriction")
				}
				if err := check(changed); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("erasing only the raw origin bypassed the real whole-source consumer", err)
				}
			})
		}
	}
}
