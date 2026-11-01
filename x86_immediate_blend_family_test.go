package plan9asm

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

// Independent Go/SDM directory: three legacy X rows and four VEX X/Y pairs.
// A register/memory choice expands each of these eleven encoding rows twice.
// None has EVEX, masks, broadcast, SAE, or a floating-point exception effect.
type x86ImmediateBlendCase struct {
	op     string
	lane   int
	width  int
	legacy bool
	memory bool
	opcode byte
}

func x86ImmediateBlendCases() []x86ImmediateBlendCase {
	var rows []x86ImmediateBlendCase
	for _, member := range []struct {
		op     string
		lane   int
		opcode byte
	}{
		{"PBLENDW", 2, 0x0e}, {"BLENDPS", 4, 0x0c}, {"BLENDPD", 8, 0x0d},
		{"VPBLENDW", 2, 0x0e}, {"VPBLENDD", 4, 0x02},
		{"VBLENDPS", 4, 0x0c}, {"VBLENDPD", 8, 0x0d},
	} {
		legacy := !strings.HasPrefix(member.op, "V")
		widths := []int{16}
		if !legacy {
			widths = append(widths, 32)
		}
		for _, width := range widths {
			for _, memory := range []bool{false, true} {
				rows = append(rows, x86ImmediateBlendCase{member.op, member.lane, width, legacy, memory, member.opcode})
			}
		}
	}
	return rows
}

func (row x86ImmediateBlendCase) bank() string {
	if row.width == 32 {
		return "Y"
	}
	return "X"
}

func (row x86ImmediateBlendCase) instruction(immediate string) string {
	first := row.bank() + "0"
	if row.memory {
		first = "(BX)"
	}
	if row.legacy {
		return fmt.Sprintf("%s $%s,%s,X2", row.op, immediate, first)
	}
	return fmt.Sprintf("%s $%s,%s,%s1,%s2", row.op, immediate, first, row.bank(), row.bank())
}

// Capture all complete original instruction bytes in one independent Go
// listing. Mode32 VEX uses these actual low-bank bytes, not Go386's rejected
// four-operand named spelling, and receives a separate LLVM32 physical prior.
func x86ImmediateBlendOriginalCodes(t *testing.T) [][]byte {
	t.Helper()
	rows := x86ImmediateBlendCases()
	var body strings.Builder
	for _, row := range rows {
		fmt.Fprintln(&body, row.instruction("0xa5"))
	}
	body.WriteString("RET")
	code, pcs := x86NumericalBoundaryGoBytes(t, "amd64", body.String())
	if len(rows) != 22 || len(pcs) != 23 || pcs[22] != int64(len(code)-1) || code[len(code)-1] != 0xc3 {
		t.Fatal("independent complete Go blend byte/PC directory changed", len(rows), pcs, code)
	}
	var result [][]byte
	for index := range rows {
		result = append(result, append([]byte(nil), code[pcs[index]:pcs[index+1]]...))
	}
	for _, mode := range []int{32, 64} {
		x86NumericalNativeRequireMC(t, code[:pcs[22]], mode, 22, "+sse4.1,+avx2")
	}
	return result
}

func TestX86ImmediateBlendCompleteGoEncodingRowsAndPhysicalPriors(t *testing.T) {
	root := filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86")
	legacy, err := os.ReadFile(filepath.Join(root, "asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	vector, err := os.ReadFile(filepath.Join(root, "avx_optabs.go"))
	if err != nil {
		t.Fatal(err)
	}
	compact := func(source []byte) string { return strings.Join(strings.Fields(string(source)), "") }
	a, v := compact(legacy), compact(vector)
	if !strings.Contains(a, "varyxshuf=[]ytab{{Zibm_r,2,argList{Yu8,Yxm,Yxr}},}") {
		t.Fatal("complete Go legacy immediate/X-memory/X yxshuf row changed")
	}
	if !strings.Contains(v, "var_yvblendpd=[]ytab{"+
		"{zcase:Zvex_i_rm_v_r,zoffset:2,args:argList{Yu8,Yxm,Yxr,Yxr}},"+
		"{zcase:Zvex_i_rm_v_r,zoffset:2,args:argList{Yu8,Yym,Yyr,Yyr}},}") {
		t.Fatal("complete ordered Go X/Y immediate blend rows changed")
	}
	for _, row := range x86ImmediateBlendCases() {
		if row.memory || row.width != 16 {
			continue
		}
		if row.legacy {
			want := fmt.Sprintf("{A%s,yxshuf,Pq,opBytes{0x3a,0x%02x,0}}", row.op, row.opcode)
			if !strings.Contains(strings.ToLower(a), strings.ToLower(want)) {
				t.Fatal("independent legacy SSE4.1 registration changed", row.op)
			}
		} else {
			want := fmt.Sprintf("{as:A%s,ytab:_yvblendpd,prefix:Pavx,op:opBytes{"+
				"avxEscape|vex128|vex66|vex0F3A|vexW0,0x%02x,"+
				"avxEscape|vex256|vex66|vex0F3A|vexW0,0x%02x,}},", row.op, row.opcode, row.opcode)
			if !strings.Contains(strings.ToLower(v), strings.ToLower(want)) {
				t.Fatal("independent complete VEX-only encoding attributes changed", row.op)
			}
		}
	}
	codes := x86ImmediateBlendOriginalCodes(t)
	var legacySource, physicalSource strings.Builder
	legacySource.WriteString("TEXT named(SB),4,$0-0\n")
	physicalSource.WriteString("TEXT physical(SB),4,$0-0\n")
	for index, row := range x86ImmediateBlendCases() {
		if row.legacy {
			fmt.Fprintln(&legacySource, row.instruction("0xa5"))
		} else if !row.memory && row.width == 16 {
			requireX86GoAssemblerResult(t, "386", "TEXT bad(SB),4,$0-0\n"+row.instruction("0xa5")+"\nRET\n", false)
		}
		physicalSource.WriteString(x86RawDisplacementDirectives(codes[index]))
	}
	legacySource.WriteString("RET\n")
	physicalSource.WriteString("RET\n")
	x86LEAActualTargetGoObject(t, "386", "i386-unknown-linux-gnu", legacySource.String()+physicalSource.String())
}

func TestX86ImmediateBlendOriginalInitializedConformanceObjects(t *testing.T) {
	data, err := os.ReadFile("testdata/conformance/amd64/conformance_amd64.s")
	if err != nil {
		t.Fatal(err)
	}
	const header = "TEXT ·immediatePackedBlendSemantics(SB), NOSPLIT, $0-24\n"
	start := strings.Index(string(data), header)
	if start < 0 {
		t.Fatal("complete original eleven-form immediate blend function missing")
	}
	end := strings.Index(string(data[start:]), "\n\tRET\n")
	if end < 0 {
		t.Fatal("complete original immediate blend return missing")
	}
	source := "#include \"textflag.h\"\n" + string(data[start:start+end+len("\n\tRET\n")])
	x86PackedFaultProgramObjects(t, source,
		"func immediatePackedBlendSemantics(out *[240]byte, a,b *[32]byte)")
}

func x86ImmediateBlendInitializedProgram(row x86ImmediateBlendCase, code []byte, arch, name string) (string, string) {
	word, move := 8, "MOVQ"
	if arch == "386" {
		word, move = 4, "MOVL"
	}
	var source strings.Builder
	fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n%s out+0(FP),DI\n%s a+%d(FP),BX\n%s b+%d(FP),CX\n",
		name, 3*word, move, move, word, move, 2*word)
	// Explicit numerical producers are independent of the blend itself.
	fmt.Fprintf(&source, "VMOVUPS (BX),%s0\nVMOVUPS (CX),%s1\nVMOVUPS (CX),%s2\n", row.bank(), row.bank(), row.bank())
	source.WriteString("MOVL $5,DX\nCMPL DX,$3\nSTD\n")
	if code == nil {
		fmt.Fprintln(&source, row.instruction("0xa5"))
	} else {
		source.WriteString(x86RawDisplacementDirectives(code))
	}
	fmt.Fprintf(&source, "VMOVUPS %s2,(DI)\nSETCS 32(DI)\nSETOS 33(DI)\nCLD\nRET\n", row.bank())
	return source.String(), fmt.Sprintf("func %s(out *[34]byte, a,b *[32]byte)\n", name)
}

func TestX86ImmediateBlendInitializedNamedAndRawFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	rows, codes := x86ImmediateBlendCases(), x86ImmediateBlendOriginalCodes(t)
	for _, target := range x86RawReturnTargets {
		for _, raw := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/raw=%t", target.triple, raw), func(t *testing.T) {
				var source, declarations strings.Builder
				count := 0
				for index, row := range rows {
					if target.arch == "386" && !raw && !row.legacy {
						continue // The independent Go frontend rejects genuine named four-operand rows.
					}
					var code []byte
					if raw {
						code = codes[index]
					}
					body, declaration := x86ImmediateBlendInitializedProgram(row, code, target.arch, fmt.Sprint("Blend", count))
					source.WriteString(body)
					declarations.WriteString(declaration)
					count++
				}
				want := 22
				if target.arch == "386" && !raw {
					want = 6
				}
				if count != want {
					t.Fatal("initialized complete family directory changed", count, want)
				}
				x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(api, func(t *testing.T) {
						ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
						if err != nil || ir == "" {
							t.Fatal("complete initialized immediate blend family rejected", err)
						}
						for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
							x86PackedStringCompileObject(t, llc, target.triple, text, "-O0")
						}
					})
				}
			})
		}
	}
}

func TestX86ImmediateBlendSelectedBytesUpperAliasesAndIndependentState(t *testing.T) {
	var directory strings.Builder
	directory.WriteString("TEXT effects(SB),4,$0-0\n")
	for _, row := range x86ImmediateBlendCases() {
		if !row.memory {
			fmt.Fprintln(&directory, row.instruction("0xa5"))
		}
	}
	directory.WriteString("RET\n")
	x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", directory.String())
	for _, row := range x86ImmediateBlendCases() {
		if row.memory {
			continue
		}
		t.Run(fmt.Sprintf("%s/%d", row.op, row.width), func(t *testing.T) {
			for immediate := 0; immediate < 256; immediate++ {
				ins := x86ScalarLaneInstruction(t, row.instruction(fmt.Sprint(immediate)))
				effect, known, err := x86TypedInstructionByteEffect(ins.Op, ins, "amd64")
				if !known || err != nil || len(effect.operands) < 2 || !effect.requiresResultProof ||
					effect.flagsRead|effect.flagsDefined|effect.flagsKilled != 0 {
					t.Fatal("complete typed immediate blend effect is absent or changes FLAGS", immediate, err)
				}
				for _, sparse := range []bool{false, true} {
					state := x86FloatingHelperInitializedState()
					second := 1
					if row.legacy {
						second = 2
					}
					if sparse {
						state.writeVector(0, 64, 0x5151515151515151, false)
						state.writeVector(second, 64, 0xa2a2a2a2a2a2a2a2, false)
					}
					before := state.clone()
					var defined uint64
					for output := 0; output < row.width; output++ {
						source := second
						if immediate>>(uint(output/row.lane)%8)&1 != 0 {
							source = 0
						}
						defined |= (before.vectorBytes(source) >> uint(output) & 1) << uint(output)
					}
					want := before.clone()
					want.writeVector(2, row.width, defined, row.legacy)
					if !x86ResultTransfer(ins, &state, nil, 0, "amd64") || !reflect.DeepEqual(state, want) {
						t.Fatal("selector lost actual byte dependencies, aliases, FLAGS, DF, pointers or storage", immediate, sparse)
					}
				}
			}
		})
	}
}

func TestX86ImmediateBlendDeadReadsRetainNativeAccessAndMissingInputs(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		word, move, triple := 8, "MOVQ", "x86_64-unknown-linux-gnu"
		if arch == "386" {
			word, move, triple = 4, "MOVL", "i386-unknown-linux-gnu"
		}
		for _, row := range x86ImmediateBlendCases() {
			if !row.memory || arch == "386" && !row.legacy {
				continue
			}
			for _, missing := range []string{"none", "pointer", "index"} {
				t.Run(fmt.Sprintf("%s/%s/%d/%s", arch, row.op, row.width, missing), func(t *testing.T) {
					prefix := move + " p+0(FP),BX\n"
					if missing == "pointer" {
						prefix = ""
					}
					operation := row.instruction("0") // No selected memory bytes, but original access still occurs.
					if missing == "index" {
						operation = strings.Replace(operation, "(BX)", "(BX)(SI*2)", 1)
					}
					for register := 0; register < 3; register++ {
						prefix += fmt.Sprintf("VPXOR %s%d,%s%d,%s%d\n", row.bank(), register, row.bank(), register, row.bank(), register)
					}
					source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s%s\nRET\n", word, prefix, operation)
					x86LEAActualTargetGoObject(t, arch, triple, source)
					for _, api := range []string{"text", "module", "Go"} {
						ir, err := x86ScalarFPBitViewAPI(t, source, "func Value(p *[32]byte)", arch, triple, api)
						if missing != "none" {
							if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
								t.Fatal("dead blend invented missing native address/index input", api, err)
							}
							continue
						}
						if err != nil || ir == "" {
							t.Fatal("dead initialized original memory blend rejected", api, err)
						}
						body := x86StringMemoryFunction(t, x86DwordProductIROptimize(t, ir), "Value")
						if row.legacy {
							// Type4 legacy m128 alignment faults require the real opcode;
							// an LLVM load with align16 is only a promise, not a check.
							if !strings.Contains(body, "asm sideeffect") || !strings.Contains(body, strings.ToLower(row.op)) ||
								!strings.Contains(body, "~{memory}") {
								t.Fatal("dead legacy blend lost actual opcode/alignment/fault/cache-independent memory access", api)
							}
						} else if !strings.Contains(body, "load volatile ") &&
							(!strings.Contains(body, "asm sideeffect") || !strings.Contains(body, strings.ToLower(row.op)) || !strings.Contains(body, "~{memory}")) {
							t.Fatal("dead VEX blend lost its exact full native read", api)
						}
					}
				})
			}
		}
	}
}

func TestX86ImmediateBlendSelectedRegisterInputsCannotBeInvented(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		word, move, triple := 8, "MOVQ", "x86_64-unknown-linux-gnu"
		if arch == "386" {
			word, move, triple = 4, "MOVL", "i386-unknown-linux-gnu"
		}
		for _, row := range x86ImmediateBlendCases() {
			if row.memory || arch == "386" && !row.legacy {
				continue
			}
			for _, missing := range []int{-1, 0, 1} {
				t.Run(fmt.Sprintf("%s/%s/%d/missing=%d", arch, row.op, row.width, missing), func(t *testing.T) {
					var source strings.Builder
					fmt.Fprintf(&source, "TEXT ·Value(SB),4,$0-%d\n%s out+0(FP),DI\n", word, move)
					for sourceIndex, register := range []int{0, 1} {
						if sourceIndex == missing {
							continue
						}
						if row.legacy && register == 1 {
							register = 2
						}
						fmt.Fprintf(&source, "VPXOR %s%d,%s%d,%s%d\n", row.bank(), register, row.bank(), register, row.bank(), register)
					}
					fmt.Fprintf(&source, "%s\nVMOVUPS %s2,(DI)\nRET\n", row.instruction("0xa5"), row.bank())
					x86LEAActualTargetGoObject(t, arch, triple, source.String())
					for _, api := range []string{"text", "module", "Go"} {
						ir, err := x86ScalarFPBitViewAPI(t, source.String(), "func Value(out *[32]byte)", arch, triple, api)
						if missing < 0 {
							if err != nil || ir == "" {
								t.Fatal("complete explicit numerical source producers rejected", api, err)
							}
						} else if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("a selected source or legacy old-destination byte became numerical without its producer", api, missing, err)
						}
					}
				})
			}
		}
	}
}
