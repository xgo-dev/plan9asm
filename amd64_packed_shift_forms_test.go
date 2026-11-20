package plan9asm

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
)

func x86PackedShiftNames() []string {
	var names []string
	for op := range amd64PackedLogicalShiftSpecs {
		names = append(names, string(op))
	}
	for op, spec := range amd64PerLaneVariableShiftSpecs {
		if !spec.arithmetic {
			names = append(names, op)
		}
	}
	names = append(names, "PSLLO", "PSLLDQ", "PSRLO", "PSRLDQ", "VPSLLDQ", "VPSRLDQ")
	sort.Strings(names)
	return names
}

func x86PackedShiftRows(op, arch string) []string {
	legacy := !strings.HasPrefix(op, "V")
	bytes := strings.HasSuffix(op, "DQ") || op == "PSLLO" || op == "PSRLO"
	perLane := strings.Contains(op, "LLV") || strings.Contains(op, "RLV")
	if legacy {
		rows := []string{op + " $-128,X0", op + " $127,X1"}
		if !bytes {
			rows = append(rows, op+" X0,X1", op+" (AX),X1")
			if arch == "amd64" {
				rows = append(rows, op+" $1,M0", op+" M0,M1", op+" (AX),M1")
			}
		}
		return rows
	}
	var rows []string
	for _, bank := range []string{"X", "Y", "Z"} {
		if !perLane {
			rows = append(rows, fmt.Sprintf("%s $0,%s0,%s2", op, bank, bank), fmt.Sprintf("%s $255,(AX),%s2", op, bank))
			if bank != "Z" {
				rows = append(rows, fmt.Sprintf("%s $-128,%s0,%s2", op, bank, bank))
			}
		}
		if bytes {
			continue
		}
		countBank := "X"
		if perLane {
			countBank = bank
		}
		rows = append(rows, fmt.Sprintf("%s %s0,%s1,%s2", op, countBank, bank, bank), fmt.Sprintf("%s (AX),%s1,%s2", op, bank, bank))
		if arch == "amd64" {
			rows = append(rows, fmt.Sprintf("%s %s0,%s1,K1,%s2", op, countBank, bank, bank), fmt.Sprintf("%s.Z (AX),%s1,K7,%s2", op, bank, bank))
			if !perLane {
				rows = append(rows, fmt.Sprintf("%s.Z $3,(AX),K1,%s2", op, bank))
			}
		}
		if !strings.HasSuffix(op, "W") {
			input := "$3,(AX),"
			if perLane {
				input = "(AX)," + bank + "1,"
			}
			rows = append(rows, fmt.Sprintf("%s.BCST %s%s2", op, input, bank))
			if arch == "amd64" {
				rows = append(rows, fmt.Sprintf("%s.BCST.Z %sK1,%s2", op, input, bank))
			}
		}
	}
	return rows
}

func TestX86PackedShiftEveryGoOpcodeAndAttribute(t *testing.T) {
	if len(x86PackedShiftNames()) != 24 {
		t.Fatal("incomplete logical-shift family")
	}
	dir := filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86")
	avx, err := os.ReadFile(filepath.Join(dir, "avx_optabs.go"))
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := os.ReadFile(filepath.Join(dir, "asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`\{as: A(VPS(?:LL|RL)(?:[WDQ]|V[WDQ]|DQ)), ytab: ([^,]+),`)
	rows := re.FindAllStringSubmatch(string(avx), -1)
	if len(rows) != 14 {
		t.Fatalf("Go AVX family inventory changed: %d", len(rows))
	}
	for _, row := range rows {
		op, table := row[1], "_yvpslld"
		if strings.HasSuffix(op, "DQ") {
			table = "_yvpslldq"
		} else if strings.Contains(op, "LLV") || strings.Contains(op, "RLV") {
			table = "_yvandnpd"
			if strings.HasSuffix(op, "W") {
				table = "_yvblendmpd"
			}
		}
		if row[2] != table {
			t.Fatalf("%s Go table %s != %s", op, row[2], table)
		}
		start := strings.Index(string(avx), row[0])
		block := strings.SplitN(string(avx)[start:], "\n\t}},", 2)[0]
		for _, line := range strings.Split(block, "\n") {
			if !strings.Contains(line, "avxEscape | evex") {
				continue
			}
			byteShift := strings.HasSuffix(op, "DQ")
			uniformCount := !strings.Contains(op, "LLV") && !strings.Contains(op, "RLV") && !strings.Contains(line, "0x7")
			broadcast := !byteShift && !strings.HasSuffix(op, "W") && !uniformCount
			if strings.Contains(line, "evexZeroingEnabled") == byteShift || strings.Contains(line, "evexBcstN") != broadcast ||
				strings.Contains(line, "evexRounding") || strings.Contains(line, "evexSae") {
				t.Fatalf("%s attribute disagreement: %s", op, line)
			}
		}
	}
	for _, op := range []string{"PSLLW", "PSLLL", "PSLLQ", "PSRLW", "PSRLL", "PSRLQ"} {
		if !strings.Contains(string(legacy), "{A"+op+", yps,") {
			t.Fatalf("Go yps member changed: %s", op)
		}
	}
	// Bind the complete operand-class inventory, not just the table names.
	// These four AVX tables are shared with unrelated instructions; checking
	// their actual rows detects a changed immediate, mask or memory class.
	tables := map[string][]string{
		"_yvpslld": {
			"Yu8,Yxr,Yxr", "Yi8,Yxr,Yxr", "Yu8,Yyr,Yyr", "Yi8,Yyr,Yyr",
			"Yxm,Yxr,Yxr", "Yxm,Yyr,Yyr",
			"Yu8,YxmEvex,YxrEvex", "Yu8,YxmEvex,Yknot0,YxrEvex",
			"Yu8,YymEvex,YyrEvex", "Yu8,YymEvex,Yknot0,YyrEvex",
			"Yu8,Yzm,Yzr", "Yu8,Yzm,Yknot0,Yzr",
			"YxmEvex,YxrEvex,YxrEvex", "YxmEvex,YxrEvex,Yknot0,YxrEvex",
			"YxmEvex,YyrEvex,YyrEvex", "YxmEvex,YyrEvex,Yknot0,YyrEvex",
			"YxmEvex,Yzr,Yzr", "YxmEvex,Yzr,Yknot0,Yzr",
		},
		"_yvpslldq": {
			"Yu8,Yxr,Yxr", "Yi8,Yxr,Yxr", "Yu8,Yyr,Yyr", "Yi8,Yyr,Yyr",
			"Yu8,YxmEvex,YxrEvex", "Yu8,YymEvex,YyrEvex", "Yu8,Yzm,Yzr",
		},
		"_yvandnpd": {
			"Yxm,Yxr,Yxr", "Yym,Yyr,Yyr",
			"YxmEvex,YxrEvex,YxrEvex", "YxmEvex,YxrEvex,Yknot0,YxrEvex",
			"YymEvex,YyrEvex,YyrEvex", "YymEvex,YyrEvex,Yknot0,YyrEvex",
			"Yzm,Yzr,Yzr", "Yzm,Yzr,Yknot0,Yzr",
		},
		"_yvblendmpd": {
			"YxmEvex,YxrEvex,YxrEvex", "YxmEvex,YxrEvex,Yknot0,YxrEvex",
			"YymEvex,YyrEvex,YyrEvex", "YymEvex,YyrEvex,Yknot0,YyrEvex",
			"Yzm,Yzr,Yzr", "Yzm,Yzr,Yknot0,Yzr",
		},
	}
	assertRows := func(source, name string, want []string) {
		t.Helper()
		block := regexp.MustCompile(`(?s)var ` + regexp.QuoteMeta(name) + ` = \[\]ytab\{(.*?)\n\}`).FindStringSubmatch(source)
		if len(block) != 2 {
			t.Fatalf("missing Go table %s", name)
		}
		var got []string
		for _, row := range regexp.MustCompile(`argList\{([^}]+)\}`).FindAllStringSubmatch(block[1], -1) {
			got = append(got, strings.ReplaceAll(row[1], " ", ""))
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s operand classes changed:\ngot %q\nwant %q", name, got, want)
		}
	}
	for name, want := range tables {
		assertRows(string(avx), name, want)
	}
	assertRows(string(legacy), "yps", []string{"Ymm,Ymr", "Yi8,Ymr", "Yxm,Yxr", "Yi8,Yxr"})
	assertRows(string(legacy), "ypsdq", []string{"Yi8,Yxr"})
	aliases, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/asm/internal/arch/arch.go"))
	if err != nil {
		t.Fatal(err)
	}
	for alias, canonical := range map[string]string{"PSLLDQ": "APSLLO", "PSRLDQ": "APSRLO"} {
		if !regexp.MustCompile(`instructions\["` + alias + `"\]\s*=\s*x86\.` + canonical).Match(aliases) {
			t.Fatalf("Go byte-shift alias changed: %s", alias)
		}
	}
}

func TestX86PackedShiftCompleteGoRowsThreeAPIsFiveObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc missing")
	}
	for _, target := range []struct{ arch, triple string }{
		{"amd64", "x86_64-apple-darwin"}, {"amd64", "x86_64-unknown-linux-gnu"}, {"amd64", "x86_64-pc-windows-msvc"},
		{"386", "i386-unknown-linux-gnu"}, {"386", "i686-pc-windows-msvc"},
	} {
		t.Run(target.triple, func(t *testing.T) {
			var source strings.Builder
			source.WriteString("TEXT shifts(SB),4,$0-0\n")
			for _, op := range x86PackedShiftNames() {
				for _, row := range x86PackedShiftRows(op, target.arch) {
					fmt.Fprintln(&source, row)
				}
			}
			source.WriteString("RET\n")
			goAssemblerOracleOutput(t, target.arch, source.String(), "", true)
			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			pkg := x86PackedShiftGoPackage(t, target.arch)
			for _, api := range []string{"text", "module", "Go"} {
				if ir, err := x86ScalarFPBitViewPackageAPI(t, source.String(), pkg, target.arch, target.triple, api); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("original format source invented numerical/native entry inputs", api, err)
				}
			}
			ir := x86InstructionFormatObjectUnit(t, file, map[string]FuncSig{"shifts": {Name: "shifts", Ret: Void}},
				target.arch, target.triple, 0, func(c *amd64Ctx, ins Instr) (bool, bool, error) {
					return c.lowerX86PackedShift(ins.Op, ins)
				})
			for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
				for _, level := range []string{"-O0", "-O2"} {
					x86PackedStringCompileObject(t, llc, target.triple, text, level)
				}
			}
		})
	}
}

func TestX86PackedShiftImmediateAnd386RejectedGoRows(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range []string{
			"PSLLW $128,X0", "PSRLO $128,X0", "VPSRLW $-1,X20,X21",
			"VPSRLW $-1,(AX),X1", "VPSRLQ.Z $-1,X0,K1,X1", "VPSLLDQ $-1,Z0,Z1",
			"VPSRLD $256,X0,X1", "VPSRLVW $1,X0,X1", "VPSRLW.BCST $1,(AX),X1",
		} {
			goAssemblerOracleOutput(t, arch, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n", "", false)
			assertX86PackedLogicalShiftRejected(t, arch, testTargetTriple("linux", arch), row)
		}
	}
	for _, op := range []string{"PSLLW", "PSLLL", "PSLLQ", "PSRLW", "PSRLL", "PSRLQ"} {
		for _, row := range []string{op + " $1,M0", op + " M0,M1", op + " (AX),M1"} {
			goAssemblerOracleOutput(t, "386", "TEXT f(SB),4,$0-0\n"+row+"\nRET\n", "", false)
			assertX86PackedLogicalShiftRejected(t, "386", "i386-unknown-linux-gnu", row)
		}
	}
}

func TestX86PackedShiftIdentityAndInvalidFormsHaveNoIRSideEffects(t *testing.T) {
	for _, op := range x86PackedShiftNames() {
		row := x86PackedShiftRows(op, "amd64")[0]
		file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		original := file.Funcs[0].Instrs[1]
		for _, identity := range []Op{"", Op(strings.ToLower(op)), original.Op} {
			ins := original
			ins.Op = identity
			ctx, _ := newAMD64CtxWithFuncForTest(t, Func{Instrs: []Instr{ins}}, FuncSig{Ret: Void}, nil)
			if recognized, _, err := ctx.lowerX86PackedShift(Op(strings.ToLower(op)), ins); !recognized || err != nil {
				t.Fatalf("matching identity %s/%s: %v", op, identity, err)
			}
		}
		for _, dispatch := range []Op{"UNKNOWN_SHIFT", "PSRAD", "PSLLL"} {
			if dispatch == original.Op {
				continue
			}
			ins := original
			before := append([]Operand(nil), ins.Args...)
			ctx, output := newAMD64CtxWithFuncForTest(t, Func{Instrs: []Instr{ins}}, FuncSig{Ret: Void}, nil)
			length := output.Len()
			recognized, _, err := ctx.lowerX86PackedShift(dispatch, ins)
			if recognized && err == nil || output.Len() != length || !reflect.DeepEqual(before, ins.Args) || ins.Op != original.Op {
				t.Fatalf("conflicting/unknown %s/%s mutated or emitted IR", op, dispatch)
			}
		}
	}
	for _, row := range []string{
		"VPSRLW $8,X0,Y1", "VPSLLDQ.Z $1,X0,K1,X1", "VPSLLW $1,X0,K0,X1",
		"VPSLLD.BCST X0,X1,X2", "VPSRLD.RN_SAE $1,X0,X1", "VPSRLW $1,8(BAD),X1",
		"VPSRLW $1,8(AX)(SP*2),X1", "VPSRLW $1,2147483648(AX),X1",
	} {
		file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
		if err != nil {
			continue
		}
		ins := file.Funcs[0].Instrs[1]
		ctx, output := newAMD64CtxWithFuncForTest(t, Func{Instrs: []Instr{ins}}, FuncSig{Ret: Void}, nil)
		length := output.Len()
		if _, _, err := ctx.lowerX86PackedShift(ins.Op, ins); err == nil || output.Len() != length {
			t.Fatalf("invalid row %s emitted %d bytes: %v", row, output.Len()-length, err)
		}
	}
}

func TestX86PackedShiftFullNativeMemoryReadAndSuppression(t *testing.T) {
	for _, test := range []struct {
		row        string
		bytes      int
		suppressed bool
	}{
		{"VPSRLW (AX),Y0,K1,Y1", 16, false},
		{"VPSRLD (AX),Z0,K1,Z1", 16, false},
		{"VPSRLQ (AX),Z0,K1,Z1", 16, false},
		{"VPSRLW.Z $1,(AX),K1,Z1", 64, true},
		{"VPSRLD.Z $1,(AX),K1,Z1", 64, true},
		{"VPSRLQ.BCST.Z $1,(AX),K1,Z1", 8, true},
		{"VPSRLVW.Z (AX),Z0,K1,Z1", 64, true},
		{"VPSRLVD.BCST.Z (AX),Z0,K1,Z1", 4, true},
		{"VPSRLDQ $1,(AX),Z1", 64, false},
	} {
		file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+test.row+"\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		ins := file.Funcs[0].Instrs[1]
		form, recognized, err := x86PackedShiftProperties(ins.Op, ins, "amd64")
		if !recognized || err != nil || form.memoryBytes != test.bytes || form.faultSuppressed != test.suppressed {
			t.Fatalf("native operand mismatch %s: %+v/%v", test.row, form, err)
		}
		if !test.suppressed {
			ctx, output := newAMD64CtxWithFuncForTest(t, file.Funcs[0], FuncSig{Ret: Void}, nil)
			if _, _, err := ctx.lowerX86PackedShift(ins.Op, ins); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(output.String(), fmt.Sprintf("load volatile <%d x i8>", test.bytes)) {
				t.Fatalf("lost full native read %s:\n%s", test.row, output.String())
			}
		}
	}
}

func x86PackedShiftGoPackage(t *testing.T, arch string) GoPackage {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "shifts.go", "package shifts\nfunc shifts()\n", 0)
	if err != nil {
		t.Fatal(err)
	}
	typed, err := (&types.Config{Sizes: types.SizesFor("gc", arch)}).Check("shifts", fset, []*ast.File{file}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return GoPackage{Path: "shifts", Types: typed, Syntax: []*ast.File{file}}
}
