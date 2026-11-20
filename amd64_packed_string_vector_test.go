package plan9asm

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func TestX86PackedStringCompleteActualGoTableAttributes(t *testing.T) {
	root := filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86")
	read := func(name string) string {
		data, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		return strings.Join(strings.Fields(string(data)), "")
	}
	legacy, vector := read("asm6.go"), read("avx_optabs.go")
	for _, table := range []struct{ source, definition string }{
		{legacy, "var yxshuf = []ytab{ {Zibm_r, 2, argList{Yu8, Yxm, Yxr}}, }"},
		{vector, "var _yvaeskeygenassist = []ytab{ {zcase: Zvex_i_rm_r, zoffset: 0, args: argList{Yu8, Yxm, Yxr}}, {zcase: Zvex_i_rm_r, zoffset: 2, args: argList{Yi8, Yxm, Yxr}}, }"},
	} {
		if !strings.Contains(table.source, strings.Join(strings.Fields(table.definition), "")) {
			t.Fatal("actual selected SDK packed-string complete operand table changed", table.definition)
		}
	}
	for _, row := range []struct {
		op, opcode, width string
	}{
		{"PCMPESTRI", "61", "WIG"}, {"PCMPESTRM", "60", "WIG"},
		{"PCMPISTRI", "63", "WIG"}, {"PCMPISTRM", "62", "W0"},
	} {
		legacyRecord := fmt.Sprintf("{A%s,yxshuf,Pq,opBytes{0x3a,0x%s,0}}", row.op, row.opcode)
		vectorRecord := fmt.Sprintf("{as:AV%s,ytab:_yvaeskeygenassist,prefix:Pavx,op:opBytes{avxEscape|vex128|vex66|vex0F3A|vex%s,0x%s,}},", row.op, row.width, row.opcode)
		if !strings.Contains(legacy, legacyRecord) || !strings.Contains(vector, vectorRecord) {
			t.Fatalf("actual selected SDK opcode/prefix/width attributes changed: %s", row.op)
		}
	}
	// Count actual family registrations as well as checking each expected row.
	// A shared ytab alone is not evidence of equal WIG or prefix attributes.
	pattern := regexp.MustCompile(`\{(?:as:)?A(V?PCMP[EI]STR[[:alnum:]]+),`)
	actual := make(map[string]int)
	for _, source := range []string{legacy, vector} {
		for _, match := range pattern.FindAllStringSubmatch(source, -1) {
			actual[match[1]]++
		}
	}
	if len(actual) != len(amd64PackedStringCompareSpecs) {
		t.Fatal("actual selected SDK packed-string family denominator changed", actual)
	}
	for opcode := range amd64PackedStringCompareSpecs {
		if actual[string(opcode)] != 1 {
			t.Fatalf("actual selected SDK family registration is missing/duplicate: %s", opcode)
		}
	}
}

type x86PackedStringVectorCase struct {
	op          string
	source, dst int
	memory      bool
	imm         int
}

func x86PackedStringVectorCases() []x86PackedStringVectorCase {
	var cases []x86PackedStringVectorCase
	for _, op := range []string{
		"PCMPESTRI", "PCMPESTRM", "PCMPISTRI", "PCMPISTRM",
		"VPCMPESTRI", "VPCMPESTRM", "VPCMPISTRI", "VPCMPISTRM",
	} {
		for _, operands := range []struct {
			source, dst int
			memory      bool
		}{{0, 1, false}, {1, 0, false}, {0, 0, false}, {1, 1, false}, {2, 1, false}, {2, 0, true}, {2, 1, true}} {
			for _, immediate := range []int{0, 8, 64} {
				cases = append(cases, x86PackedStringVectorCase{op, operands.source, operands.dst, operands.memory, immediate})
			}
		}
	}
	return cases
}

func x86PackedStringVectorFixture(cases []x86PackedStringVectorCase, arch string) (string, string) {
	var declarations, source strings.Builder
	move, pointer, args := "MOVQ", 8, 16
	if arch == "386" {
		move, pointer, args = "MOVL", 4, 8
	}
	for index, row := range cases {
		name := fmt.Sprintf("stringvector%d", index)
		fmt.Fprintf(&declarations, "func %s(out *[360]byte, in *[192]byte)\n", name)
		fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n%s out+0(FP),DI\n%s in+%d(FP),SI\n", name, args, move, move, pointer)
		for register := 0; register < 3; register++ {
			fmt.Fprintf(&source, "VMOVUPS %d(SI),Z%d\n", register*64, register)
		}
		source.WriteString("MOVL $5,AX\nMOVL $9,DX\nMOVL $73,CX\n")
		operand := fmt.Sprintf("X%d", row.source)
		if row.memory {
			operand = fmt.Sprintf("%d(SI)", row.source*64)
		}
		fmt.Fprintf(&source, "%s $%d,%s,X%d\n", row.op, row.imm, operand, row.dst)
		for register := 0; register < 3; register++ {
			for _, view := range []struct {
				bank   string
				offset int
			}{{"X", 0}, {"Y", 16}, {"Z", 48}} {
				fmt.Fprintf(&source, "VMOVUPS %s%d,%d(DI)\n", view.bank, register, register*112+view.offset)
			}
		}
		source.WriteString(x86PackedStringStatusObservation(arch, true))
	}
	return declarations.String(), source.String()
}

func x86PackedStringStatusObservation(arch string, refined bool) string {
	suffix := "Q"
	if arch == "386" {
		suffix = "L"
	}
	if !refined {
		return "PUSHF" + suffix + "\nPOP" + suffix + " AX\nMOV" + suffix +
			" AX,336(DI)\nLAHF\nMOVB AH,344(DI)\nMOV" + suffix + " CX,352(DI)\nRET\n"
	}
	// PCMP defines all six arithmetic flags, not incoming DF/ID. Capture LAHF
	// first, then refine the popped FLAGS immediately, before any other effect
	// can invalidate its transient bit knowledge or AND can change FLAGS.
	return "LAHF\nMOVB AH,344(DI)\nPUSHF" + suffix + "\nPOP" + suffix + " BX\nAND" +
		suffix + " $0x8d5,BX\nMOV" + suffix + " BX,336(DI)\nMOV" + suffix + " CX,352(DI)\nRET\n"
}

func x86PackedStringObjectBatches(rows []x86PackedStringVectorCase) [][]x86PackedStringVectorCase {
	const maxFunctions = 64
	var batches [][]x86PackedStringVectorCase
	for len(rows) != 0 {
		count := len(rows)
		if count > maxFunctions {
			count = maxFunctions
		}
		batches = append(batches, rows[:count])
		rows = rows[count:]
	}
	return batches
}

func TestX86PackedStringObjectBatchInventory(t *testing.T) {
	original := x86PackedStringVectorCases()
	var joined []x86PackedStringVectorCase
	seen := make(map[x86PackedStringVectorCase]bool)
	for _, batch := range x86PackedStringObjectBatches(original) {
		if len(batch) == 0 || len(batch) > 64 {
			t.Fatal("empty or oversized packed-string object batch", len(batch))
		}
		for _, row := range batch {
			if seen[row] {
				t.Fatal("duplicate original packed-string form", row)
			}
			seen[row] = true
		}
		joined = append(joined, batch...)
	}
	if len(original) != 8*7*3 || !reflect.DeepEqual(joined, original) {
		t.Fatal("bounded batches changed the complete ordered original form inventory")
	}
	owners := map[string]string{
		"i386-unknown-linux-gnu":   "386",
		"i686-pc-windows-msvc":     "386",
		"x86_64-apple-darwin":      "amd64",
		"x86_64-unknown-linux-gnu": "amd64",
		"x86_64-pc-windows-msvc":   "amd64",
	}
	if len(x86RawReturnTargets) != len(owners) {
		t.Fatal("new object targets need their own complete packed-string owner")
	}
	for _, target := range x86RawReturnTargets {
		if owners[target.triple] != target.arch {
			t.Fatal("missing or duplicate complete target owner", target)
		}
		delete(owners, target.triple)
	}
	if len(owners) != 0 {
		t.Fatal("orphaned packed-string object owner", owners)
	}
}

// Each target is independently schedulable, and each bounded LLVM unit is
// released before the next batch. Partitioning retains all 168 original rows,
// all five targets and the original three-API/two-optimization matrix.
func x86PackedStringTargetObjects(t *testing.T, arch, triple string) {
	t.Helper()
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc is required")
	}
	for index, batch := range x86PackedStringObjectBatches(x86PackedStringVectorCases()) {
		t.Run(fmt.Sprintf("batch-%d", index), func(t *testing.T) {
			declarations, source := x86PackedStringVectorFixture(batch, arch)
			x86LEAActualTargetGoObject(t, arch, triple, source)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir := x86CPUQueryIRFromDeclaration(t, source, declarations, arch, triple, api)
					for _, level := range []string{"-O0", "-O2"} {
						t.Run(level, func(t *testing.T) {
							input := ir
							if level == "-O2" {
								input = x86UndefinedTrapOptimizedIR(t, input)
							}
							x86PackedStringCompileObject(t, llc, triple, input, level)
						})
					}
				})
			}
		})
	}
}

func TestX86PackedStringObjectsLinux386(t *testing.T) {
	x86PackedStringTargetObjects(t, "386", "i386-unknown-linux-gnu")
}

func TestX86PackedStringObjectsWindows386(t *testing.T) {
	x86PackedStringTargetObjects(t, "386", "i686-pc-windows-msvc")
}

func TestX86PackedStringObjectsDarwinAMD64(t *testing.T) {
	x86PackedStringTargetObjects(t, "amd64", "x86_64-apple-darwin")
}

func TestX86PackedStringObjectsLinuxAMD64(t *testing.T) {
	x86PackedStringTargetObjects(t, "amd64", "x86_64-unknown-linux-gnu")
}

func TestX86PackedStringObjectsWindowsAMD64(t *testing.T) {
	x86PackedStringTargetObjects(t, "amd64", "x86_64-pc-windows-msvc")
}

func TestX86PackedStringResultEffectsAndPreEmissionIdentity(t *testing.T) {
	for _, row := range go127PackedStringCompareSpecs() {
		spec := amd64PackedStringCompareSpecs[Op(row.op)]
		reg, width, zeroUpper := spec.resultEffect()
		wantReg, wantWidth := CX, 4
		if row.mask {
			wantReg, wantWidth = "X0", 16
		}
		if reg != wantReg || width != wantWidth || zeroUpper != (row.vector && row.mask) {
			t.Fatalf("%s implicit writer effect = %s/%d/%t", row.op, reg, width, zeroUpper)
		}
		for _, identity := range []Op{"", Op(row.op), Op(strings.ToLower(row.op)), "MOVOU", "UNKNOWN"} {
			for _, arch := range []string{"amd64", "386"} {
				t.Run(row.op+"/"+arch+"/"+string(identity), func(t *testing.T) {
					ctx, output := newAMD64CtxWithFuncForTest(t, Func{}, FuncSig{Ret: Void}, nil)
					ctx.goarch = arch
					instruction := Instr{Op: identity, Args: []Operand{
						{Kind: OpImm, Imm: 8}, {Kind: OpReg, Reg: "X0"}, {Kind: OpReg, Reg: "X1"},
					}}
					before, temporary := output.String(), ctx.tmp
					original := fmt.Sprintf("%#v", instruction)
					known, terminated, err := ctx.lowerPackedStringCompare(Op(row.op), instruction)
					invalid := identity != "" && !strings.EqualFold(string(identity), row.op)
					if !known || terminated || (err != nil) != invalid || invalid && (before != output.String() || temporary != ctx.tmp) ||
						original != fmt.Sprintf("%#v", instruction) {
						t.Fatalf("implicit writer bypassed source identity or emitted before rejection: %v", err)
					}
				})
			}
		}
	}
}

func TestX86PackedStringImmediateCompleteByteDomainOriginalObjects(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		t.Run(arch, func(t *testing.T) {
			var source strings.Builder
			source.WriteString("TEXT ·query(SB),4,$0-0\n")
			for _, row := range go127PackedStringCompareSpecs() {
				first := 0
				if row.vector {
					first = -128
				}
				for immediate := first; immediate <= 255; immediate++ {
					fmt.Fprintf(&source, "%s $%d,X0,X1\n", row.op, immediate)
				}
			}
			source.WriteString("RET\n")
			x86LEAActualTargetGoObject(t, arch, testTargetTriple("linux", arch), source.String())
		})
	}
}

func TestX86PackedStringStrictMalformedOperands(t *testing.T) {
	for _, row := range go127PackedStringCompareSpecs() {
		for _, operands := range []string{
			"$256,X0,X1", "$-129,X0,X1", "$0.0,X0,X1", "$8,Y0,X1",
			"$8,X0,X16", "$8,X0,Y1", "$8,X0,(AX)", "$8,X0,X1,X2",
		} {
			t.Run(row.op+"/"+operands, func(t *testing.T) {
				source := "TEXT ·query(SB),4,$0-0\n" + row.op + " " + operands + "\nRET\n"
				goAssemblerOracleOutput(t, "amd64", source, "", false)
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					return
				}
				ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu", ResolveSym: func(symbol string) string {
					return strings.TrimPrefix(symbol, "·")
				}, Sigs: map[string]FuncSig{"query": {Name: "query", Ret: Void}}})
				if err == nil || ir != "" {
					t.Fatal("malformed implicit vector writer returned IR", err)
				}
			})
		}
	}
}

func TestX86PackedStringMode32HighBankNeedsPhysicalContext(t *testing.T) {
	for _, op := range []string{"VPCMPESTRI", "VPCMPESTRM", "VPCMPISTRI", "VPCMPISTRM"} {
		for _, operands := range []string{"X8,X1", "X1,X8", "X15,X15"} {
			t.Run(op+"/"+operands, func(t *testing.T) {
				source := fmt.Sprintf("TEXT ·query(SB),4,$0-0\n%s $8,%s\nRET\n", op, operands)
				goAssemblerOracleOutput(t, "386", source, "", true)
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				pkg := mustGoPackage(t, "query", "package query\nfunc query()\n")
				resolve := func(symbol string) string { return strings.TrimPrefix(symbol, "·") }
				sigs, err := goSigsForAsmFile(pkg, file, resolve, "386", nil, nil, nil)
				if err != nil {
					t.Fatal(err)
				}
				ir, err := Translate(file, Options{Goarch: "386", TargetTriple: "i386-unknown-linux-gnu", ResolveSym: resolve, Sigs: sigs})
				if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
					t.Fatalf("frontend high spelling acquired a physical mode32 vector binding: %v", err)
				}
			})
		}
	}
}

func TestX86PackedStringDoesNotSupplyCallerDefinedness(t *testing.T) {
	for _, op := range []string{
		"PCMPESTRI", "PCMPESTRM", "PCMPISTRI", "PCMPISTRM",
		"VPCMPESTRI", "VPCMPESTRM", "VPCMPISTRI", "VPCMPISTRM",
	} {
		for _, operand := range []string{"X0", "(DI)", "(DX)"} {
			t.Run(op+"/"+operand, func(t *testing.T) {
				assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", op+" $8,"+operand+",X1\nMOVL AX,(DX)", 1)
				goAssemblerOracleOutput(t, "amd64", assembly, "", true)
				pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
				if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("unregistered implicit vector inputs/writers acquired caller permission: %v", err)
				}
			})
		}
	}
}

func TestX86PackedStringDescriptorDoesNotInventInitializedBytes(t *testing.T) {
	for _, row := range go127PackedStringCompareSpecs() {
		instruction := Instr{Op: Op(row.op), Args: []Operand{
			{Kind: OpImm, Imm: 8}, {Kind: OpReg, Reg: "X0"}, {Kind: OpReg, Reg: "X1"},
		}}
		state := x86SourceStackState{vectors: map[Reg]uint64{"Z0": 0xffff, "Z1": 0xff}, masks: map[Reg]bool{"K1": true}}
		before := state
		before.vectors, before.masks = x86CloneCallerVectorState(state.vectors, state.masks)
		if x86CallerVectorMoveKnown(instruction) || x86CallerVectorMoveStep(&instruction, &state, nil) ||
			x86SourceStackInstructionKnown(instruction, OpMOVQ, "Q", "amd64") {
			t.Fatalf("%s descriptor granted an unregistered caller effect", row.op)
		}
		if !reflect.DeepEqual(state, before) || instruction.x86CallerMemory != nil {
			t.Fatalf("%s failed caller effect mutated byte knowledge or native certificates", row.op)
		}
	}
}

func TestX86PackedStringIndependentFPFieldsRequireEveryByte(t *testing.T) {
	var parameters strings.Builder
	for index := 0; index < 16; index++ {
		if index != 0 {
			parameters.WriteString(",")
		}
		fmt.Fprintf(&parameters, "a%d uint8", index)
	}
	pkg := mustGoPackage(t, "strings", "package strings\nfunc query("+parameters.String()+")\n")
	for _, row := range go127PackedStringCompareSpecs() {
		t.Run(row.op, func(t *testing.T) {
			source := "TEXT ·query(SB),4,$0-16\n" + row.op + " $8,a0+0(FP),X1\nRET\n"
			goAssemblerOracleOutput(t, "amd64", source, "", true)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			resolve := func(symbol string) string { return strings.TrimPrefix(symbol, "·") }
			sigs, err := goSigsForAsmFile(pkg, file, resolve, "amd64", nil, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			options := Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu", ResolveSym: resolve, Sigs: sigs}
			if _, err := Translate(file, options); err != nil {
				t.Fatalf("complete independent logical FP fields: %v", err)
			}
			for missing := 0; missing < 16; missing++ {
				t.Run(fmt.Sprint(missing), func(t *testing.T) {
					// Each mutation starts from the original complete declaration.
					// Logical FP completeness is not native address backing or an
					// initialized caller-region witness.
					signature := sigs["query"]
					signature.Frame.Params = append([]FrameSlot(nil), signature.Frame.Params...)
					signature.Frame.Params = append(signature.Frame.Params[:missing], signature.Frame.Params[missing+1:]...)
					mutated := options
					mutated.Sigs = map[string]FuncSig{"query": signature}
					if ir, err := Translate(file, mutated); err == nil || ir != "" {
						t.Fatalf("missing logical FP byte%d acquired a complete m128 source: %v", missing, err)
					}
				})
			}
		})
	}
}

func x86PackedStringCompileObject(t *testing.T, llc, triple, ir, level string) {
	t.Helper()
	if level != "-O0" && level != "-O2" {
		t.Fatal("unexpected packed-string object level", level)
	}
	dir := t.TempDir()
	input, output := filepath.Join(dir, "strings.ll"), filepath.Join(dir, "strings.o")
	if err := os.WriteFile(input, []byte(ir), 0600); err != nil {
		t.Fatal(err)
	}
	x86FloatCompareCaptureCommand(t, exec.Command(llc, level, "-mtriple="+triple, "-filetype=obj", input, "-o", output))
	info, err := os.Lstat(output)
	if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
		t.Fatalf("packed-string object is missing/nonregular/empty: %v", err)
	}
}
