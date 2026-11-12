package plan9asm

import (
	"errors"
	"fmt"
	"go/types"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

var x86AverageNames = []string{"PAVGB", "PAVGW", "VPAVGB", "VPAVGW"}

// Independent of the production grammar. Named mode32 MMX is excluded by
// Go's Py1 selector, while low X/Y/Z operands have physical mode32 identities.
func x86AveragePhysicalRows(arch string) []string {
	var rows []string
	for _, name := range x86AverageNames[:2] {
		for _, source := range []string{"X0", "X7", "(AX)", "16(AX)(CX*4)", "·data(SB)", "(FS)", "(GS)"} {
			rows = append(rows, name+" "+source+",X1")
		}
		if arch == "amd64" {
			rows = append(rows, name+" X15,X0", name+" M0,M7", name+" (AX),M7")
		}
	}
	for _, name := range x86AverageNames[2:] {
		for _, bank := range []string{"X", "Y", "Z"} {
			for _, source := range []string{bank + "0", bank + "7", "(AX)", "16(AX)(CX*4)", "·data(SB)", "(FS)", "(GS)"} {
				rows = append(rows, fmt.Sprintf("%s %s,%s1,%s2", name, source, bank, bank))
				if arch == "amd64" {
					rows = append(rows, fmt.Sprintf("%s %s,%s31,K1,%s30", name, source, bank, bank),
						fmt.Sprintf("%s.Z %s,%s31,K7,%s30", name, source, bank, bank))
				}
			}
		}
	}
	return rows
}

func TestX86PackedAverageThreeAPIsFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, triple := range []string{"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc", "i386-unknown-linux-gnu", "i686-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			arch := "amd64"
			if strings.HasPrefix(triple, "i") {
				arch = "386"
			}
			var source, declarations strings.Builder
			declarations.WriteString("package oracle\n")
			for index, row := range x86AveragePhysicalRows(arch) {
				fmt.Fprintf(&source, "TEXT ·F%d(SB),4,$0-0\n%s\nRET\n", index, row)
				fmt.Fprintf(&declarations, "func F%d()\n", index)
			}
			goAssemblerOracleOutput(t, arch, source.String(), "", true)
			pkg := mustGoPackage(t, "oracle", declarations.String())
			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			sigs := make(map[string]FuncSig)
			for _, fn := range file.Funcs {
				name := strings.TrimPrefix(fn.Sym, "·")
				sig, err := DeriveGoFuncABI0Signature(name, pkg.Types.Scope().Lookup(name).(*types.Func), arch, types.SizesFor("gc", arch))
				if err != nil {
					t.Fatal(err)
				}
				sigs[name] = sig
			}
			for _, api := range []string{"text", "module", "Go"} {
				if ir, err := x86ScalarFPBitViewPackageAPI(t, source.String(), pkg, arch, triple, api); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("complete original format source invented input or memory state", api, err)
				}
			}
			ir := x86AverageFormatObjectUnit(t, file, sigs, arch, triple)
			x86ResultInitializationObject(t, llc, triple, ir, "average-original-emitter-only")
			x86ResultInitializationObject(t, llc, triple, x86MulDivRoundOptimize(t, ir), "average-O2")
		})
	}
}

func TestX86PackedAverageShapesEffectsDoNotGrantCallerPermissions(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range append(x86AveragePhysicalRows(arch), "VPAVGB.Z value+0(FP),X1,K1,X2", "VPAVGW value+0(FP),Z1,Z2") {
			file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-64\n"+row+"\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			ins := file.Funcs[0].Instrs[1]
			before := fmt.Sprintf("%#v", ins)
			form, known, err := x86PackedAverageProperties(ins.Op, ins, arch)
			if arch == "386" && strings.Contains(row, "K1") {
				if err == nil {
					t.Fatal("named mode32 mask became a physical encoding")
				}
				continue
			}
			if !known || err != nil || before != fmt.Sprintf("%#v", ins) || x86CallerVectorMoveKnown(ins) {
				t.Fatalf("shape changed input or acquired caller permission: %s: %v", row, err)
			}
			for index := range ins.Args {
				width, write, valid := x86InstructionMemoryShape(ins, index, arch)
				if valid != (index == form.memory) || valid && (width != int64(form.memoryBytes) || write) {
					t.Fatal("memory read shape differs from native width", row, width, write, valid)
				}
			}
			effect, observed, err := x86TypedInstructionByteEffect(ins.Op, ins, arch)
			if form.legacy && (!observed || err != nil || len(effect.operands) != 2 ||
				effect.flagsDefined != 0 || effect.flagsKilled != 0 ||
				!effect.operands[0].read || effect.operands[0].write ||
				!effect.operands[1].read || !effect.operands[1].write ||
				effect.operands[0].width != int64(form.byteWidth) || effect.operands[1].width != int64(form.byteWidth)) {
				t.Fatal("legacy full input/output byte effect changed", row, effect, err)
			}
			// All three dispatch identities are equivalent, but a contradictory
			// source never emits IR. Keep the existing empty direct-helper API.
			for _, identity := range []Op{"", ins.Op, Op(strings.ToLower(string(ins.Op))), "PADDW"} {
				local := ins
				local.Op = identity
				copy := local
				_, _, err := x86PackedAverageProperties(ins.Op, local, arch)
				bad := identity == "PADDW"
				if (err != nil) != bad || !reflect.DeepEqual(copy, local) {
					t.Fatal("dispatch identity mismatch", ins.Op, identity, err)
				}
			}
		}
	}
}

func TestX86PackedAverageActualGoCompleteTables(t *testing.T) {
	root := filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86")
	legacy, err := os.ReadFile(filepath.Join(root, "asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	avx, err := os.ReadFile(filepath.Join(root, "avx_optabs.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []string{
		"{APAVGB, ymm, Py1, opBytes{0xe0, Pe, 0xe0}}",
		"{APAVGW, ymm, Py1, opBytes{0xe3, Pe, 0xe3}}",
	} {
		if strings.Count(string(legacy), row) != 1 {
			t.Fatalf("actual Go legacy registration changed: %s", row)
		}
	}
	start := strings.Index(string(legacy), "var ymm =")
	if start < 0 {
		t.Fatal("missing actual ymm table")
	}
	ymm := strings.SplitN(string(legacy)[start:], "\n}", 2)[0]
	for _, row := range []string{"{Zm_r_xm, 1, argList{Ymm, Ymr}}", "{Zm_r_xm, 2, argList{Yxm, Yxr}}"} {
		if strings.Count(ymm, "argList{") != 2 || strings.Count(ymm, row) != 1 {
			t.Fatal("actual ymm class/selector table changed", ymm)
		}
	}
	for index, name := range x86AverageNames[2:] {
		opcode := []string{"E0", "E3"}[index]
		expected := fmt.Sprintf(`{as: A%s, ytab: _yvandnpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F | vexW0, 0x%s,
		avxEscape | vex256 | vex66 | vex0F | vexW0, 0x%s,
		avxEscape | evex128 | evex66 | evex0F | evexW0, evexN16 | evexZeroingEnabled, 0x%s,
		avxEscape | evex256 | evex66 | evex0F | evexW0, evexN32 | evexZeroingEnabled, 0x%s,
		avxEscape | evex512 | evex66 | evex0F | evexW0, evexN64 | evexZeroingEnabled, 0x%s,
	}},`, name, opcode, opcode, opcode, opcode, opcode)
		if err := x86SignedPackedFloatValidateGoOpcodeRows(string(avx), name, expected); err != nil {
			t.Fatal(err)
		}
	}
	start = strings.Index(string(avx), "var _yvandnpd =")
	if start < 0 {
		t.Fatal("missing actual ytab")
	}
	table := strings.SplitN(string(avx)[start:], "\n}", 2)[0] + "\n}"
	if err := x86AverageValidateGoYtab(table); err != nil {
		t.Fatal(err)
	}
}

const x86AverageGoYtab = `var _yvandnpd = []ytab{
 {zcase: Zvex_rm_v_r, zoffset: 2, args: argList{Yxm, Yxr, Yxr}},
 {zcase: Zvex_rm_v_r, zoffset: 2, args: argList{Yym, Yyr, Yyr}},
 {zcase: Zevex_rm_v_r, zoffset: 0, args: argList{YxmEvex, YxrEvex, YxrEvex}},
 {zcase: Zevex_rm_v_k_r, zoffset: 3, args: argList{YxmEvex, YxrEvex, Yknot0, YxrEvex}},
 {zcase: Zevex_rm_v_r, zoffset: 0, args: argList{YymEvex, YyrEvex, YyrEvex}},
 {zcase: Zevex_rm_v_k_r, zoffset: 3, args: argList{YymEvex, YyrEvex, Yknot0, YyrEvex}},
 {zcase: Zevex_rm_v_r, zoffset: 0, args: argList{Yzm, Yzr, Yzr}},
 {zcase: Zevex_rm_v_k_r, zoffset: 3, args: argList{Yzm, Yzr, Yknot0, Yzr}},
}`

func x86AverageValidateGoYtab(table string) error {
	actual, err := x86SignedPackedFloatGoOpcodeTokens(table)
	if err != nil {
		return err
	}
	expected, err := x86SignedPackedFloatGoOpcodeTokens(x86AverageGoYtab)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(actual, expected) {
		return fmt.Errorf("complete actual Go packed-average selector table changed:\n%s", table)
	}
	return nil
}

func TestX86PackedAverageGoSelectorMutationsAreDetected(t *testing.T) {
	if err := x86AverageValidateGoYtab(x86AverageGoYtab); err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []struct{ old, replacement string }{
		{"zoffset: 2", "zoffset: 3"},
		{"Zvex_rm_v_r", "Zevex_rm_v_r"},
		{"Yknot0", "Yk"},
		{"YxmEvex", "YymEvex"},
		{"{zcase: Zvex_rm_v_r, zoffset: 2, args: argList{Yxm, Yxr, Yxr}},", ""},
	} {
		changed := strings.Replace(x86AverageGoYtab, mutation.old, mutation.replacement, 1)
		if err := x86AverageValidateGoYtab(changed); err == nil {
			t.Fatalf("selector mutation retained source authority: %#v", mutation)
		}
	}
}

func TestX86PackedAverageActualGoModeAndPhysicalBoundary(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		var source strings.Builder
		source.WriteString("TEXT f(SB),4,$0-0\n")
		for _, row := range x86AveragePhysicalRows(arch) {
			source.WriteString(row + "\n")
		}
		source.WriteString("RET\n")
		goAssemblerOracleOutput(t, arch, source.String(), "", true)
	}
	for _, name := range x86AverageNames[:2] {
		for _, source := range []string{"M0", "(AX)", "AX"} {
			goAssemblerOracleOutput(t, "386", "TEXT f(SB),4,$0-0\n"+name+" "+source+",M1\nRET\n", "", false)
		}
	}
	for _, name := range x86AverageNames[2:] {
		for _, bank := range []string{"X", "Y"} {
			for position := 0; position < 3; position++ {
				args := []string{bank + "0", bank + "1", bank + "2"}
				args[position] = bank + "20"
				assembly := "TEXT f(SB),4,$0-0\n" + name + " " + strings.Join(args, ",") + "\nRET\n"
				goAssemblerOracleOutput(t, "386", assembly, "", true)
				file, err := Parse(ArchAMD64, assembly)
				if err != nil {
					t.Fatal(err)
				}
				ctx, out := newAMD64CtxWithFuncForTest(t, file.Funcs[0], FuncSig{Ret: Void}, nil)
				ctx.goarch = "386"
				before := out.String()
				known, _, err := ctx.lowerPackedUnsignedAverage(file.Funcs[0].Instrs[1].Op, file.Funcs[0].Instrs[1])
				if !known || !errors.Is(err, ErrProbeNeedsContext) || out.String() != before {
					t.Errorf("unproved physical high bank emitted IR: %s: %v", assembly, err)
				}
			}
		}
	}
}

func TestX86PackedAverageNativeStorageAndIdentityBoundaries(t *testing.T) {
	for _, name := range x86AverageNames[:2] {
		for _, row := range []string{name + " (SP),X0", name + " (BP),X0", name + " (AX)(BP*2),X0", name + " value+0(FP),X0"} {
			file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-64\n"+row+"\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			ctx, out := newAMD64CtxWithFuncForTest(t, file.Funcs[0], x86WordMaddFPType(t), nil)
			before := out.String()
			_, _, err = ctx.lowerPackedUnsignedAverage(file.Funcs[0].Instrs[1].Op, file.Funcs[0].Instrs[1])
			if !errors.Is(err, ErrProbeNeedsContext) || out.String() != before {
				t.Errorf("virtual storage gained native m128 alignment: %s: %v", row, err)
			}
		}
	}
	for _, name := range x86AverageNames {
		row := name + " X0,X1"
		if strings.HasPrefix(name, "V") {
			row += ",X2"
		}
		file, _ := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
		ins := file.Funcs[0].Instrs[1]
		ins.Op = "PADDW"
		ctx, out := newAMD64CtxWithFuncForTest(t, file.Funcs[0], FuncSig{Ret: Void}, nil)
		before := out.String()
		if _, _, err := ctx.lowerPackedUnsignedAverage(Op(name), ins); err == nil || out.String() != before {
			t.Errorf("contradictory opcode emitted PAVG IR: %s: %v", name, err)
		}
	}
}
