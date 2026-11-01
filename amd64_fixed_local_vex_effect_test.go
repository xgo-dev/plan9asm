package plan9asm

import (
	"errors"
	"fmt"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

type fixedLocalVEXWitness struct {
	owner, source string
}

// The scope is independent of the translator's registration maps. Keep every
// original VEX row, including overlapping signed/unsigned immediate classes.
// EVEX rows are inventoried separately and do not acquire permission here.
func fixedLocalVEXWitnesses(t *testing.T) []fixedLocalVEXWitness {
	return fixedLocalVEXFamilyWitnesses(t,
		`^(VPADD(B|W|D|Q|SB|SW|USB|USW)|VPALIGNR|V(BLENDP[DS]|PBLEND[WD])|V(ANDN?|OR|XOR)P[DS]|VP(ANDN?|OR|XOR)|VMOV(AP[DS]|UP[DS]|DQ[AU])|VPERM2[FI]128|VPS(LL|RL|RA)(W|D|Q|V[WDQ]|DQ)|VPSHUFB|VZERO(UPPER|ALL))$`,
		146, 354)
}

func fixedLocalVEXBinaryWitnesses(t *testing.T) []fixedLocalVEXWitness {
	return fixedLocalVEXFamilyWitnesses(t,
		`^VP(SUB(B|W|D|Q|SB|SW|USB|USW)|MUL(LD|LQ|LW|HW|HUW|HRSW|DQ|UDQ)|AVG(B|W)|MADD(WD|UBSW)|(MIN|MAX)[SU][BWDQ])$`,
		62, 186)
}

func fixedLocalVEXFamilyWitnesses(t *testing.T, pattern string, wantRows, wantWitnesses int) []fixedLocalVEXWitness {
	t.Helper()
	rules, err := goasmrules.LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	family := regexp.MustCompile(pattern)
	var witnesses []fixedLocalVEXWitness
	rows := 0
	for _, rule := range rules {
		if !family.MatchString(rule.Opcode) || !strings.HasPrefix(rule.ZCase, "Zvex") {
			continue
		}
		rows++
		if rule.Prefix != "Pavx" || rule.EncodingOffset < 0 || rule.EncodingOffset+2 > len(rule.OpBytes) {
			t.Fatalf("unmodeled official VEX attributes: %+v", rule)
		}
		var args []string
		memory := -1
		for index, class := range rule.Classes {
			switch class {
			case "Yxr", "Yxm", "Yyr", "Yym":
				bank := "X"
				if class[1] == 'y' {
					bank = "Y"
				}
				args = append(args, fmt.Sprintf("%s%d", bank, index))
				if class[2] == 'm' {
					if memory >= 0 {
						t.Fatalf("unexpected two-memory VEX row: %+v", rule)
					}
					memory = index
				}
			case "Yi8":
				args = append(args, "$-128")
			case "Yu8":
				args = append(args, "$255")
			default:
				t.Fatalf("unmodeled original VEX operand class: %+v", rule)
			}
		}
		inputs := []string{""}
		if memory >= 0 {
			inputs = []string{args[memory], "64(BP)", "(SI)"}
		}
		for _, input := range inputs {
			if memory >= 0 {
				args[memory] = input
			}
			witnesses = append(witnesses, fixedLocalVEXWitness{
				owner:  fmt.Sprintf("%s/row%d/%s", rule.Opcode, rule.RowIndex, input),
				source: strings.TrimSpace(rule.Opcode + " " + strings.Join(args, ",")),
			})
		}
	}
	if rows != wantRows || len(witnesses) != wantWitnesses {
		t.Fatalf("official non-masked VEX inventory changed: rows=%d witnesses=%d, want %d/%d", rows, len(witnesses), wantRows, wantWitnesses)
	}
	return witnesses
}

func fixedLocalVEXFixture(t *testing.T, operation string) (Func, FuncSig, string) {
	t.Helper()
	source := fixedLocalVEXAssembly(operation)
	_, _, sig, _ := x86ResultInitializationFixture(t, "amd64", "func Value(p *uint64, a uint64) uint64", "RET")
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	return file.Funcs[0], sig, source
}

func fixedLocalVEXAssembly(operation string) string {
	// Reuse the complete aligned scratch fixture. Input pointers are typed,
	// not inferred from numerical register contents or private frame offsets.
	source := fixedLocalPackedAssembly("VMOVDQU 64(BP),Y0\nVMOVDQU 64(BP),Y1\n" +
		"VMOVDQU 64(BP),Y2\nVMOVDQU 64(BP),Y3\n" + operation)
	source = strings.Replace(source, "$256-16", "$256-24", 1)
	source = strings.Replace(source, "MOVQ a+0(FP),AX", "MOVQ p+0(FP),SI\nMOVQ a+8(FP),AX", 1)
	source = strings.Replace(source, "ret+8(FP)", "ret+16(FP)", 1)
	return source
}

func TestGoAMD64FixedLocalVEXOfficialEncodings(t *testing.T) {
	fixedLocalCheckVEXEncodings(t, fixedLocalVEXWitnesses(t))
}

func TestGoAMD64FixedLocalVEXBinaryOfficialEncodings(t *testing.T) {
	fixedLocalCheckVEXEncodings(t, fixedLocalVEXBinaryWitnesses(t))
}

func fixedLocalCheckVEXEncodings(t *testing.T, witnesses []fixedLocalVEXWitness) {
	t.Helper()
	rows := make([]string, len(witnesses))
	for index, row := range witnesses {
		rows[index] = row.source
	}
	code, pcs := x86NumericalBoundaryGoBytes(t, "amd64", strings.Join(rows, "\n")+"\nRET")
	if len(pcs) != len(rows)+1 {
		t.Fatal("Go changed the complete source instruction inventory", len(pcs), len(rows))
	}
	for index, row := range witnesses {
		instruction := code[pcs[index]:pcs[index+1]]
		if len(instruction) < 3 || instruction[0] != 0xc4 && instruction[0] != 0xc5 {
			t.Fatalf("%s selected non-VEX bytes %x", row.owner, instruction)
		}
	}
	t.Logf("%d legal original Go source witnesses; VEX generation check, not exact row-encoding or execution proof", len(witnesses))
}

func TestGoAMD64FixedLocalVEXCompleteFamilies(t *testing.T) {
	fixedLocalCheckVEXFamilies(t, fixedLocalVEXWitnesses(t))
}

func TestGoAMD64FixedLocalVEXBinaryCompleteFamilies(t *testing.T) {
	fixedLocalCheckVEXFamilies(t, fixedLocalVEXBinaryWitnesses(t))
}

func fixedLocalCheckVEXFamilies(t *testing.T, witnesses []fixedLocalVEXWitness) {
	t.Helper()
	for _, row := range witnesses {
		t.Run(row.owner, func(t *testing.T) {
			fn, sig, _ := fixedLocalVEXFixture(t, row.source)
			if _, err := proveX86FixedLocal(fn, sig); err != nil {
				t.Fatal("initialized complete VEX source rejected", err)
			}
		})
	}
}

func TestGoAMD64FixedLocalVEXPhysicalBoundaries(t *testing.T) {
	fixedLocalCheckVEXPhysicalBoundaries(t, fixedLocalVEXWitnesses(t))
}

func TestGoAMD64FixedLocalVEXBinaryPhysicalBoundaries(t *testing.T) {
	fixedLocalCheckVEXPhysicalBoundaries(t, fixedLocalVEXBinaryWitnesses(t))
}

func fixedLocalCheckVEXPhysicalBoundaries(t *testing.T, witnesses []fixedLocalVEXWitness) {
	t.Helper()
	rows := make([]string, len(witnesses))
	for index, row := range witnesses {
		rows[index] = row.source
	}
	code, pcs := x86NumericalBoundaryGoBytes(t, "amd64", strings.Join(rows, "\n")+"\nRET")
	if len(pcs) != len(rows)+1 {
		t.Fatal("Go changed the complete source instruction inventory", len(pcs), len(rows))
	}
	for index, row := range witnesses {
		t.Run(row.owner, func(t *testing.T) {
			instruction := code[pcs[index]:pcs[index+1]]
			boundaries, scalar, err := x86NumericalNativeBoundaries(instruction, 64)
			if err != nil || len(boundaries) != 1 || boundaries[0].Length != len(instruction) || len(scalar) != 0 {
				t.Fatalf("original Go boundary for %s (%x): %v %v %v", row.source, instruction, boundaries, scalar, err)
			}
		})
	}
}

func TestGoAMD64FixedLocalVEXBoundaries(t *testing.T) {
	for _, row := range []struct{ name, operation string }{
		{"unknown source", "VPADDQ Y7,Y1,Y2"},
		{"missing count upper qword", "VPSRLQ 184(BP),Y1,Y2"},
		{"outside private frame", "VPSHUFB 256(BP),Y1,Y2"},
		{"numeric pointer", "VPOR (AX),Y1,Y2"},
		{"unbound FP", "VPAND a+8(FP),Y1,Y2"},
		{"EVEX high register", "VPADDQ X16,X1,X2"},
		{"EVEX width", "VPADDQ Z0,Z1,Z2"},
		{"EVEX mask", "KMOVQ AX,K1\nVPADDQ Y0,Y1,K1,Y2"},
		{"EVEX broadcast", "VPADDQ.BCST (SI),Y1,Y2"},
		{"EVEX-only member", "VPSRAQ $1,Y1,Y2"},
		{"EVEX immediate memory", "VPSRLQ $1,64(BP),Y2"},
		{"MMX", "PADDQ M0,M1"},
	} {
		t.Run(row.name, func(t *testing.T) {
			fn, sig, _ := fixedLocalVEXFixture(t, row.operation)
			if _, err := proveX86FixedLocal(fn, sig); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("unproved form acquired fixed-local permission", err)
			}
		})
	}
}

func TestGoAMD64FixedLocalVEXUpperAliases(t *testing.T) {
	for _, operation := range []string{
		"VPADDQ X0,X1,X2", "VPOR X0,X1,X2", "VPSHUFB X0,X1,X2",
		"VPSRLQ $3,X1,X2", "VPALIGNR $3,X0,X1,X2", "VPBLENDD $3,X0,X1,X2",
		"VPERM2F128 $3,Y0,Y1,Y2", "VPERM2I128 $3,Y0,Y1,Y2",
	} {
		t.Run(operation, func(t *testing.T) {
			ins := x86ScalarLaneInstruction(t, operation)
			state := x86FixedLocalState{vectors: map[Reg]uint64{
				"Z0": 0xffffffff, "Z1": 0xffffffff, "Z2": 0,
			}, flags: x86ByteFlagCF}
			if err := fixedLocalVectorStep(&ins, &state, nil, 0); err != nil {
				t.Fatal(err)
			}
			if state.vectors["Z2"] != ^uint64(0) || state.vectors["Z0"] != 0xffffffff ||
				state.vectors["Z1"] != 0xffffffff || state.flags != x86ByteFlagCF {
				t.Fatal("VEX did not define upper zeros independently of the old destination", state)
			}
		})
	}
	for _, op := range []string{"VZEROALL", "VZEROUPPER"} {
		t.Run(op, func(t *testing.T) {
			ins := x86ScalarLaneInstruction(t, op)
			state := x86FixedLocalState{vectors: map[Reg]uint64{"Z0": 3, "Z16": 5}, flags: x86ByteFlagCF}
			if err := fixedLocalStep(&ins, &state, FuncSig{}, nil, 0); err != nil {
				t.Fatal(err)
			}
			want := ^uint64(0)
			if op == "VZEROUPPER" {
				want = ^uint64(65535) | 3
			}
			if state.vectors["Z0"] != want || state.vectors["Z16"] != 5 || state.flags != x86ByteFlagCF {
				t.Fatal("VZERO changed an unaffected low/high-bank byte or FLAGS", state)
			}
		})
	}
}

func TestGoAMD64FixedLocalVEXBinaryInputAndAliasEffects(t *testing.T) {
	names := make(map[string]bool)
	for _, row := range fixedLocalVEXBinaryWitnesses(t) {
		names[strings.Fields(row.source)[0]] = true
	}
	if len(names) != 31 {
		t.Fatalf("official VEX binary members=%d, want 31", len(names))
	}
	for name := range names {
		for width, bank := range map[int]string{16: "X", 32: "Y"} {
			t.Run(name+"/"+bank, func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, fmt.Sprintf("%s %s0,%s1,%s2", name, bank, bank, bank))
				mask := x86CallerVectorByteMask(int64(width))
				state := x86FixedLocalState{vectors: map[Reg]uint64{"Z0": mask, "Z1": mask}, flags: x86ByteFlagCF}
				if err := fixedLocalVectorStep(&ins, &state, nil, 0); err != nil {
					t.Fatal("complete VEX inputs rejected", err)
				}
				if state.vectors["Z2"] != ^uint64(0) || state.vectors["Z0"] != mask ||
					state.vectors["Z1"] != mask || state.flags != x86ByteFlagCF {
					t.Fatal("VEX did not read inputs before defining result/upper zeros", state)
				}
				state.vectors["Z0"] &^= uint64(1) << (width - 1)
				state.vectors["Z2"] = 0
				if err := fixedLocalVectorStep(&ins, &state, nil, 0); !errors.Is(err, ErrProbeNeedsContext) ||
					state.vectors["Z2"] != 0 {
					t.Fatal("missing input byte published VEX result or upper-zero knowledge", err, state)
				}
			})
		}
	}
	for _, operation := range []string{
		"VPMULLQ X0,X1,X2", "VPMINSQ X0,X1,X2", "VPMINUQ Y0,Y1,Y2",
		"VPMAXSQ X0,X1,X2", "VPMAXUQ Y0,Y1,Y2",
		"VPSUBW Z0,Z1,Z2", "VPMULHW X16,X1,X2", "VPAVGB X0,X1,K1,X2",
		"VPMADDWD.Z X0,X1,K1,X2", "VPMINSD.BCST (SI),X1,X2",
	} {
		t.Run(operation, func(t *testing.T) {
			ins := x86ScalarLaneInstruction(t, operation)
			if _, known, err := fixedLocalVectorByteEffect(ins); known && err == nil {
				t.Fatal("separate EVEX form acquired a VEX effect before input checks")
			}
			fn, sig, _ := fixedLocalVEXFixture(t, operation)
			if _, err := proveX86FixedLocal(fn, sig); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("separate EVEX width/mask/broadcast acquired VEX permission", err)
			}
		})
	}
}

func TestGoAMD64FixedLocalVEXCompleteObjects(t *testing.T) {
	fixedLocalCheckVEXObjects(t, fixedLocalVEXWitnesses(t))
}

func TestGoAMD64FixedLocalVEXBinaryCompleteObjects(t *testing.T) {
	fixedLocalCheckVEXObjects(t, fixedLocalVEXBinaryWitnesses(t))
}

func fixedLocalCheckVEXObjects(t *testing.T, witnesses []fixedLocalVEXWitness) {
	t.Helper()
	goAMD64FramePrepareOwnedToolCache(t)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	passed := 0
	for start := 0; start < len(witnesses); start += 32 {
		end := start + 32
		if end > len(witnesses) {
			end = len(witnesses)
		}
		if t.Run(fmt.Sprintf("batch%d", start/32), func(t *testing.T) {
			var assembly, declarations strings.Builder
			for index := start; index < end; index++ {
				name := fmt.Sprintf("Value%d", index)
				assembly.WriteString(strings.Replace(fixedLocalVEXAssembly(witnesses[index].source), "·Value", "·"+name, 1))
				fmt.Fprintf(&declarations, "func %s(p *uint64, a uint64) uint64\n", name)
			}
			const triple = "x86_64-unknown-linux-gnu"
			pkg, request, _, options := fixedLocalTransportFixture(t, assembly.String(), declarations.String(), "linux/amd64", triple)
			fixedLocalFreshAPIs(t, pkg, request, options, []string{"Translate", "Module", "GoModule"},
				func(t *testing.T, ir string, err error) {
					if err != nil {
						t.Fatal(err)
					}
					compileLLVMToObject(t, llc, triple, "vex.ll", "vex.o", ir)
					compileLLVMToObject(t, llc, triple, "vex-opt.ll", "vex-opt.o", x86MulDivRoundOptimize(t, ir))
				})
		}) {
			passed += end - start
		}
	}
	if passed != len(witnesses) {
		t.Fatalf("three-API LLVM22 object witnesses passed=%d total=%d", passed, len(witnesses))
	}
	t.Logf("all %d non-masked VEX source witnesses passed three APIs and LLVM22 objects; not execution evidence", passed)
}

func BenchmarkGoAMD64FixedLocalVEXCandidate(b *testing.B) {
	// This is the candidate query, not successful source proof, LLVM or
	// native execution. No earlier scalar scratch store may short-circuit
	// the register-only negative filter this benchmark measures.
	source := "TEXT ·Value(SB),4,$256-0\n" + strings.Repeat("VPADDQ Y0,Y0,Y1\n", 32) +
		"VMOVDQU 64(BP),Y0\nRET\n"
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		if !GoAMD64FixedLocalFrameBindingNeeded(file, "amd64") {
			b.Fatal("complete scratch source lost its candidate role")
		}
	}
}

func TestGoAMD64FixedLocalVEXCandidateAllocations(t *testing.T) {
	source := "TEXT ·Value(SB),4,$256-0\n" + strings.Repeat("VPADDQ Y0,Y0,Y1\n", 32) +
		"VMOVDQU 64(BP),Y0\nRET\n"
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	if !GoAMD64FixedLocalFrameBindingNeeded(file, "amd64") {
		t.Fatal("complete scratch source lost its candidate role")
	}
	allocations := testing.AllocsPerRun(100, func() {
		GoAMD64FixedLocalFrameBindingNeeded(file, "amd64")
	})
	if allocations != 0 {
		t.Fatalf("candidate query allocated for register-only noncandidates: %g", allocations)
	}
}
