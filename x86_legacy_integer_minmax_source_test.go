package plan9asm

import (
	"crypto/sha256"
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

// Independent Go legacy directory: yxm/Pe has four SSE2 members; yxm_q4/Pq4
// has eight SSE4.1 members. Neither table admits MMX or a legacy qword name.
var x86LegacyIntegerMinMaxMembers = []struct {
	op     string
	bits   int
	map38  bool
	opcode byte
}{
	{"PMINUB", 8, false, 0xda}, {"PMAXUB", 8, false, 0xde},
	{"PMINSW", 16, false, 0xea}, {"PMAXSW", 16, false, 0xee},
	{"PMINSB", 8, true, 0x38}, {"PMAXSB", 8, true, 0x3c},
	{"PMINUW", 16, true, 0x3a}, {"PMAXUW", 16, true, 0x3e},
	{"PMINSD", 32, true, 0x39}, {"PMAXSD", 32, true, 0x3d},
	{"PMINUD", 32, true, 0x3b}, {"PMAXUD", 32, true, 0x3f},
}

func TestX86LegacyIntegerMinMaxCompleteOfficialRowsAndBytes(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	pattern := regexp.MustCompile(`\{A(P(?:MIN|MAX)[SU][BWD]), (\w+), (\w+), opBytes\{([^}]+)\}\}`)
	rows := pattern.FindAllStringSubmatch(string(data), -1)
	if len(rows) != 12 {
		t.Fatal("complete legacy integer min/max official denominator changed", len(rows))
	}
	for _, table := range []struct{ name, definition string }{
		{"yxm", "{Zm_r_xm,1,argList{Yxm,Yxr}},"},
		{"yxm_q4", "{Zm_r,1,argList{Yxm,Yxr}},"},
	} {
		definition := regexp.MustCompile(`(?s)var ` + table.name + ` = \[\]ytab\{(.*?)\n\}`).FindStringSubmatch(string(data))
		if len(definition) != 2 || strings.Join(strings.Fields(definition[1]), "") != table.definition {
			t.Fatal("original Go X-only table changed", table.name)
		}
	}
	for _, member := range x86LegacyIntegerMinMaxMembers {
		found := 0
		for _, row := range rows {
			if row[1] != member.op {
				continue
			}
			table, prefix := "yxm", "Pe"
			if member.map38 {
				table, prefix = "yxm_q4", "Pq4"
			}
			if row[2] != table || row[3] != prefix || strings.TrimSpace(row[4]) != fmt.Sprintf("0x%02x", member.opcode) {
				t.Fatal("original opcode/table/prefix changed", row)
			}
			found++
		}
		if found != 1 {
			t.Fatal("missing or duplicate original member", member.op, found)
		}
		for _, arch := range []string{"386", "amd64"} {
			t.Run(arch+"/"+member.op, func(t *testing.T) {
				for _, memory := range []bool{false, true} {
					operand, modrm := "X1", byte(0xc1)
					if memory {
						operand, modrm = "(AX)", 0
					}
					code, pcs := x86NumericalBoundaryGoBytes(t, arch, member.op+" "+operand+",X0\nRET")
					want := []byte{0x66, 0x0f}
					if member.map38 {
						want = append(want, 0x38)
					}
					want = append(want, member.opcode, modrm, 0xc3)
					if !reflect.DeepEqual(code, want) || len(pcs) != 2 || pcs[1] != int64(len(want)-1) {
						t.Fatal("complete actual Go opcode/register/m128 boundary changed", code, want, pcs)
					}
					mode := 64
					if arch == "386" {
						mode = 32
					}
					x86NumericalNativeRequireMC(t, code, mode, 2, "+sse2,+sse4.1")
				}
				goAssemblerOracleOutput(t, arch, "TEXT Invalid(SB),4,$0-0\n"+member.op+" M0,M1\nRET\n", "", false)
			})
		}
	}
}

func TestX86LegacyIntegerMinMaxOriginalExpandedConformanceObjects(t *testing.T) {
	data, err := os.ReadFile("testdata/conformance/amd64/conformance_amd64.s")
	if err != nil {
		t.Fatal(err)
	}
	start := strings.Index(string(data), "TEXT ·expandedEcosystemVectors(SB)")
	if start < 0 {
		t.Fatal("complete original expanded conformance entry missing")
	}
	end := strings.Index(string(data[start:]), "\n\tRET\n")
	if end < 0 {
		t.Fatal("complete original expanded conformance return missing")
	}
	body := string(data[start : start+end+len("\n\tRET\n")])
	if fmt.Sprintf("%x", sha256.Sum256([]byte(body))) != "97161386bd3a63d52dbd3a40aa758b4165e9b98f023eecac1449d594900750e3" {
		t.Fatal("original complete 174-line ASM program changed")
	}
	data, err = os.ReadFile("amd64_conformance_test.go")
	if err != nil {
		t.Fatal(err)
	}
	reference, err := x86SegmentMOVSourceFunction(data, "amd64ConformanceRuntimeC")
	if err != nil || fmt.Sprintf("%x", sha256.Sum256(reference)) != "41b0fc284d1aea9a9d24d613f84a6f4ad416d25a84dfa9664f81c7f1a9eef1b4" {
		t.Fatal("original complete C/reference observations changed", err)
	}
	x86PackedFaultProgramObjects(t, "#include \"textflag.h\"\n"+body,
		"func expandedEcosystemVectors(out *[816]byte,a,b *[16]byte)")
}

func TestX86LegacyIntegerMinMaxEveryByteAliasAndFlags(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		var original strings.Builder
		for _, member := range x86LegacyIntegerMinMaxMembers {
			fmt.Fprintf(&original, "TEXT Prior%s(SB),4,$0-0\n%s X1,X0\n%s X0,X0\nRET\n", member.op, member.op, member.op)
		}
		goAssemblerOracleOutput(t, arch, original.String(), "", true)
		for _, member := range x86LegacyIntegerMinMaxMembers {
			for _, source := range []int{0, 1} {
				row := fmt.Sprintf("%s X%d,X0", member.op, source)
				t.Run(arch+"/"+row, func(t *testing.T) {
					instruction := x86ScalarLaneInstruction(t, row)
					effect, known, err := x86TypedInstructionByteEffect(instruction.Op, instruction, arch)
					if !known || err != nil || !effect.requiresResultProof || effect.flagsRead|effect.flagsDefined|effect.flagsKilled != 0 || len(effect.operands) != 2 {
						t.Fatal("complete legacy family lacks its two-input RMW/FLAGS owner", known, err)
					}
					for index, operand := range effect.operands {
						if operand.index != index || operand.width != 16 || !operand.read || operand.write != (index == 1) ||
							!reflect.DeepEqual(operand.operand, instruction.Args[index]) {
							t.Fatal("legacy byte effect lost its source or RMW destination", operand)
						}
					}
					for input := 0; input < 3; input++ {
						for missing := -1; missing < 64; missing++ {
							state := x86FMA3ResultInputState()
							if missing >= 0 {
								state.writeVector(input, 64, state.vectorBytes(input)&^(uint64(1)<<uint(missing)), false)
							}
							before := state.clone()
							known := uint64(0xffff)
							if missing >= 0 && missing < 16 && (input == 0 || input == source) {
								lane := member.bits / 8
								known &^= x86CallerVectorByteMask(int64(lane)) << uint(missing/lane*lane)
							}
							want := before.clone()
							want.writeVector(0, 16, known, true)
							if !x86ResultTransfer(instruction, &state, nil, 0, arch) || !reflect.DeepEqual(state, want) {
								t.Fatal("min/max invented an input lane or changed upper aliases/GP/FLAGS/DF", input, missing)
							}
							if arch == "amd64" {
								caller := x86SourceStackState{numericFlags: true,
									bp: x86SourceStackAddress{original: true}, gOriginal: true,
									known: map[Reg]uint8{AX: 0xff}, callers: map[Reg]x86CallerPointerValue{DI: {argument: 0}},
									vectors: map[Reg]uint64{"Z0": before.vectorBytes(0), "Z1": before.vectorBytes(1), "Z2": before.vectorBytes(2)},
									masks:   map[Reg]bool{"K1": true},
								}
								wantCaller := x86CloneCallerState(caller)
								wantCaller.vectors["Z0"] = want.vectorBytes(0)
								local := instruction
								if !x86CallerVectorMoveStep(&local, &caller, nil) || !reflect.DeepEqual(caller, wantCaller) {
									t.Fatal("caller and result lane dependencies disagree", input, missing)
								}
							}
						}
					}
				})
			}
		}
	}
}

func TestX86LegacyIntegerMinMaxInitializedFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("complete legacy min/max objects require LLVM22")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			word, move := goWordSize(target.arch), "MOVQ"
			if target.arch == "386" {
				move = "MOVL"
			}
			var source, declarations strings.Builder
			count := 0
			for _, member := range x86LegacyIntegerMinMaxMembers {
				for _, memory := range []bool{false, true} {
					first := "X1"
					if memory {
						first = "(AX)"
					}
					name := fmt.Sprint("LegacyMinMax", count)
					fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n%s out+0(FP),DI\n%s a+%d(FP),AX\n%s b+%d(FP),BX\n"+
						"VMOVUPS (DI),Z0\nMOVOU (AX),X1\nMOVOU (BX),X0\nMOVL $5,DX\nCMPL DX,$3\nSTD\n"+
						"%s %s,X0\nVMOVUPS Z0,(DI)\nSETCS 64(DI)\nSETOS 65(DI)\nCLD\nRET\n",
						name, 3*word, move, move, word, move, 2*word, member.op, first)
					fmt.Fprintf(&declarations, "func %s(out,a,b *byte)\n", name)
					count++
				}
			}
			if count != 24 {
				t.Fatal("orthogonal twelve-member register/memory denominator changed", count)
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("complete initialized legacy min/max program lost its public owner", err)
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

func TestX86LegacyIntegerMinMaxDeadNativeInputsAndOriginalAccess(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		word, move := goWordSize(arch), "MOVQ"
		if arch == "386" {
			move = "MOVL"
		}
		triple := testTargetTriple("linux", arch)
		for _, member := range x86LegacyIntegerMinMaxMembers {
			source := fmt.Sprintf("TEXT ·Read(SB),4,$0-%d\n%s input+0(FP),AX\nPXOR X0,X0\n%s (AX),X0\nRET\n", word, move, member.op)
			x86LEAActualTargetGoObject(t, arch, triple, source)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(arch+"/"+member.op+"/"+api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, "func Read(input *byte)", arch, triple, api)
					if err != nil || ir == "" {
						t.Fatal("initialized legacy min/max lost its paired dead access", err)
					}
					for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
						body := x86StringMemoryFunction(t, text, "Read")
						if strings.Count(body, "asm sideeffect \""+strings.ToLower(member.op)+" ($2), $0\"") != 1 ||
							!strings.Contains(body, "\"=x,0,r,~{memory}\"") || strings.Contains(body, "load volatile <16 x i8>") {
							t.Fatal("dead m128 lost its one original RMW Type4/alignment access", member.op)
						}
					}
					for _, mutation := range []struct{ name, before, after string }{
						{"pointer", move + " input+0(FP),AX\n", ""},
						{"numeric-address", move + " input+0(FP),AX\n", move + " $1,AX\n"},
						{"old-destination", "PXOR X0,X0\n", ""},
						{"index", "(AX),X0", "(AX)(CX*2),X0"},
					} {
						changed := strings.Replace(source, mutation.before, mutation.after, 1)
						if changed == source {
							t.Fatal("missing-input control was not applied", mutation.name)
						}
						if output, err := x86ScalarFPBitViewAPI(t, changed, "func Read(input *byte)", arch, triple, api); output != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("dead native min/max invented an old input/address", mutation.name, err)
						}
					}
				})
			}
		}
	}
}

func TestX86LegacyIntegerMinMaxWholeSourceRawRestrictions(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, member := range x86LegacyIntegerMinMaxMembers {
			t.Run(arch+"/"+member.op, func(t *testing.T) {
				operation := member.op + " X1,X0"
				code, pcs := x86NumericalBoundaryGoBytes(t, arch, operation+"\nRET")
				if len(pcs) != 2 || pcs[1] != int64(len(code)-1) || code[len(code)-1] != 0xc3 {
					t.Fatal("complete independent original Go boundary missing", pcs)
				}
				prefix := "TEXT ·Value(SB),4,$0-4\nPXOR X0,X0\nPXOR X1,X1\n"
				suffix := "MOVL X0,ret+0(FP)\nRET\n"
				namedSource := prefix + operation + "\n" + suffix
				strict, check := x86RegisterReplayConsumers(t, arch, namedSource)
				named := mustParseX86RawReturn(t, namedSource).Funcs[0]
				if strict(named) != nil || check(named) != nil {
					t.Fatal("genuine initialized named source failed before the raw boundary under review")
				}
				file, err := normalizeX86RawFile(mustParseX86RawReturn(t,
					prefix+x86RawDisplacementDirectives(code[:pcs[1]])+suffix), arch)
				if err != nil {
					t.Fatal("complete actual Go bytes could not normalize", err)
				}
				original, ordinal := file.Funcs[0], -1
				for index, ins := range original.Instrs {
					if ins.Op == Op(member.op) && ins.x86SourceRaw != nil {
						if ordinal >= 0 || ins.x86Encoded {
							t.Fatal("origin-only fixture lost its exact legacy producer")
						}
						ordinal = index
					}
				}
				if ordinal < 0 || original.x86RawReplay == nil || original.x86RawReplay.validate(original, arch) != nil {
					t.Fatal("whole original source lost its sealed raw replay")
				}
				if err := check(original); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("legacy raw instruction borrowed a named numerical role", err)
				}
				changed := original
				changed.Instrs = cloneX86ReplayInstrs(original.Instrs)
				changed.Instrs[ordinal].x86SourceRaw = nil
				if !errors.Is(changed.x86RawReplay.validate(changed, arch), ErrProbeNeedsContext) || original.x86RawReplay.validate(original, arch) != nil {
					t.Fatal("origin-only mutation lost the independent immutable source restriction")
				}
				if err := check(changed); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("erased raw origin bypassed the actual whole-source consumer", err)
				}
			})
		}
	}
}
