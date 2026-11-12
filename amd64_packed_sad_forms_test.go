package plan9asm

import (
	"bytes"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func x86SADRows(arch string) []string {
	rows := []string{"PSADBW X0,X7", "PSADBW (AX),X7", "MPSADBW $0,X0,X7", "MPSADBW $255,16(AX)(BX*2),X7"}
	if arch == "amd64" {
		rows = append(rows, "PSADBW X15,X0", "PSADBW data(SB),X1", "PSADBW (FS),X1", "MPSADBW $128,(GS),X15")
	}
	for _, bank := range []string{"X", "Y", "Z"} {
		for _, source := range []string{bank + "0", "16(AX)(BX*2)"} {
			rows = append(rows, fmt.Sprintf("VPSADBW %s,%s1,%s7", source, bank, bank))
			if arch == "amd64" {
				rows = append(rows, fmt.Sprintf("VPSADBW %s,%s31,%s30", source, bank, bank))
				for _, imm := range []int{0, 1, 7, 8, 37, 228, 255} {
					rows = append(rows,
						fmt.Sprintf("VDBPSADBW $%d,%s,%s31,%s30", imm, source, bank, bank),
						fmt.Sprintf("VDBPSADBW $%d,%s,%s31,K1,%s30", imm, source, bank, bank),
						fmt.Sprintf("VDBPSADBW.Z $%d,%s,%s31,K7,%s30", imm, source, bank, bank))
				}
				if bank != "Z" {
					rows = append(rows, fmt.Sprintf("VMPSADBW $37,%s,%s1,%s15", source, bank, bank))
				}
			}
		}
	}
	return rows
}

func x86SADGoPackage(t *testing.T, arch, declaration string) GoPackage {
	t.Helper()
	fset := token.NewFileSet()
	syntax, err := parser.ParseFile(fset, "sad.go", "package sad\nfunc sad"+declaration+"\n", 0)
	if err != nil {
		t.Fatal(err)
	}
	typed, err := (&types.Config{Sizes: types.SizesFor("gc", arch)}).Check("sad", fset, []*ast.File{syntax}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return GoPackage{Path: "sad", Types: typed, Syntax: []*ast.File{syntax}}
}

func TestX86PackedSADActualGoCompleteOptabs(t *testing.T) {
	root := filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86")
	legacy, err := os.ReadFile(filepath.Join(root, "asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	avx, err := os.ReadFile(filepath.Join(root, "avx_optabs.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []string{"{APSADBW, yxm, Pq, opBytes{0xf6}}", "{AMPSADBW, yxshuf, Pq, opBytes{0x3a, 0x42, 0}}"} {
		if !strings.Contains(string(legacy), row) {
			t.Fatal("actual Go legacy registration changed: " + row)
		}
	}
	for name, expected := range map[string][]string{
		"yxm":        {"Yxm,Yxr"},
		"yxshuf":     {"Yu8,Yxm,Yxr"},
		"_yvaesdec":  {"Yxm,Yxr,Yxr", "Yym,Yyr,Yyr", "YxmEvex,YxrEvex,YxrEvex", "YymEvex,YyrEvex,YyrEvex", "Yzm,Yzr,Yzr"},
		"_yvblendpd": {"Yu8,Yxm,Yxr,Yxr", "Yu8,Yym,Yyr,Yyr"},
		"_yvalignd":  {"Yu8,YxmEvex,YxrEvex,YxrEvex", "Yu8,YxmEvex,YxrEvex,Yknot0,YxrEvex", "Yu8,YymEvex,YyrEvex,YyrEvex", "Yu8,YymEvex,YyrEvex,Yknot0,YyrEvex", "Yu8,Yzm,Yzr,Yzr", "Yu8,Yzm,Yzr,Yknot0,Yzr"},
	} {
		text := string(avx)
		if !strings.HasPrefix(name, "_") {
			text = string(legacy)
		}
		section := regexp.MustCompile(`(?s)var ` + name + ` = \[\]ytab\{(.*?)\n\}`).FindStringSubmatch(text)
		if len(section) != 2 {
			t.Fatal("actual table missing " + name)
		}
		var got []string
		for _, row := range regexp.MustCompile(`argList\{([^}]*)\}`).FindAllStringSubmatch(section[1], -1) {
			got = append(got, strings.ReplaceAll(row[1], " ", ""))
		}
		if !reflect.DeepEqual(got, expected) {
			t.Fatalf("actual %s rows %q != %q", name, got, expected)
		}
	}
	for _, row := range []struct {
		op, table string
		count     int
	}{{"VPSADBW", "_yvaesdec", 5}, {"VMPSADBW", "_yvblendpd", 2}, {"VDBPSADBW", "_yvalignd", 3}} {
		start := strings.Index(string(avx), "{as: A"+row.op+",")
		if start < 0 {
			t.Fatal("missing actual " + row.op)
		}
		entry := strings.SplitN(string(avx)[start:], "\n\t}},", 2)[0]
		if !strings.Contains(entry, "ytab: "+row.table) || strings.Count(entry, "avxEscape") != row.count || strings.Contains(entry, "Bcst") || strings.Contains(entry, "Sae") || strings.Contains(entry, "Rounding") {
			t.Fatalf("actual SAD registration changed: %s", entry)
		}
		if strings.Contains(entry, "ZeroingEnabled") != (row.op == "VDBPSADBW") {
			t.Fatal("actual SAD zeroing attribute changed " + row.op)
		}
	}
}

func TestX86PackedSADCompleteRowsThreeAPIsFiveObjects(t *testing.T) {
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
			source := "TEXT sad(SB),4,$0-0\n" + strings.Join(x86SADRows(arch), "\n") + "\nRET\n"
			// Retain all original operands as actual-Go/public-Context/emitter
			// formats. Separate complete-input programs own public objects.
			ir := x86UnboundVoidScalarFormatObject(t, source, "sad", arch, triple)
			compileLLVMToObject(t, llc, triple, "sad-text.ll", "sad-text.o", ir)
			compileLLVMToObject(t, llc, triple, "sad-O2.ll", "sad-O2.o", x86MulDivRoundOptimize(t, ir))
		})
	}
}

func TestX86PackedSADDispatchMalformedAndPhysicalBounds(t *testing.T) {
	for _, row := range []string{"PSADBW X0,X1", "VPSADBW Z0,Z1,Z2", "MPSADBW $5,X0,X1", "VMPSADBW $37,Y0,Y1,Y2", "VDBPSADBW.Z $228,Z0,Z1,K1,Z2"} {
		file, _ := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
		ins := file.Funcs[0].Instrs[1]
		for _, identity := range []Op{"", ins.Op, Op(strings.ToLower(string(ins.Op))), "UNKNOWN", "PSADBW.Z"} {
			local := ins
			local.Op = identity
			original := local
			ctx, output := newAMD64CtxWithFuncForTest(t, file.Funcs[0], FuncSig{Ret: Void}, nil)
			before := output.String()
			known, term, err := ctx.lowerPackedSumAbsoluteDifferences(ins.Op, local)
			bad := identity != "" && !strings.EqualFold(string(identity), string(ins.Op))
			if !known || term || (err != nil) != bad || bad && output.String() != before || !reflect.DeepEqual(local, original) {
				t.Fatalf("dispatch %s/%s: %v", ins.Op, identity, err)
			}
		}
	}
	for _, row := range []string{"PSADBW M0,M1", "PSADBW Y0,Y1", "PSADBW $1,X0", "VPSADBW X0,Y1,Y2", "VPSADBW X0,X1,K1,X2", "VPSADBW.Z X0,X1,X2", "VPSADBW.BCST (AX),Z0,Z1", "MPSADBW $-1,X0,X1", "MPSADBW $256,X0,X1", "VMPSADBW $1,Z0,Z1,Z2", "VMPSADBW $1,Y16,Y1,Y2", "VDBPSADBW $1,X0,X1,K0,X2", "VDBPSADBW.Z $1,X0,X1,X2", "VDBPSADBW.BCST $1,(AX),X0,X1", "PSADBW (AX)(SP*2),X0", "VPSADBW 2147483648(AX),Z0,Z1", "MPSADBW $1,$data(SB),X0"} {
		source := "TEXT f(SB),4,$0-0\n" + row + "\nRET\n"
		if row == "VDBPSADBW.Z $1,X0,X1,X2" {
			x86SADReservedZeroMaskGoObservation(t, source)
		} else {
			goAssemblerOracleOutput(t, "amd64", source, "", false)
		}
		file, err := Parse(ArchAMD64, source)
		if err != nil {
			continue
		}
		ctx, output := newAMD64CtxWithFuncForTest(t, file.Funcs[0], FuncSig{Ret: Void}, nil)
		before := output.String()
		if known, _, err := ctx.lowerPackedSumAbsoluteDifferences(file.Funcs[0].Instrs[1].Op, file.Funcs[0].Instrs[1]); !known || err == nil || output.String() != before {
			t.Fatalf("malformed SAD emitted IR %s: %v", row, err)
		}
	}
	for _, row := range []string{"PSADBW X8,X0", "MPSADBW $1,X0,X15", "VPSADBW Y0,Y1,Y20", "VPSADBW Z0,Z1,Z31"} {
		source := "TEXT f(SB),4,$0-0\n" + row + "\nRET\n"
		rejected := !strings.HasPrefix(row, "V") || strings.Contains(row, "Z31")
		goAssemblerOracleOutput(t, "386", source, "", !rejected)
		file, _ := Parse(ArchAMD64, source)
		_, _, err := x86PackedSADProperties(file.Funcs[0].Instrs[1], "386")
		if rejected && err == nil || !rejected && !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatalf("386 accepted spelling acquired physical register %s: %v", row, err)
		}
	}
}

func x86SADReservedZeroMaskGoObservation(t *testing.T, source string) {
	t.Helper()
	dir := t.TempDir()
	asm, object := filepath.Join(dir, "reserved.s"), filepath.Join(dir, "reserved.o")
	if err := os.WriteFile(asm, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	command := exec.CommandContext(ctx, "go", "tool", "asm", "-S", "-p", "sad", "-o", object, asm)
	command.Env = append(os.Environ(), "GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local", "GOOS=linux", "GOARCH=amd64")
	output, err := runtimeOracleCombinedOutput(ctx, command)
	if failure := goAssemblerOracleOutcome(asm, object, output, err, ctx.Err(), err == nil, "amd64"); failure != nil {
		t.Fatalf("actual reserved zero-mask observation: %v\n%s", failure, output)
	}
	if err != nil {
		if !bytes.Contains(output, []byte("mask register must be specified for .Z instructions")) {
			t.Fatalf("unexpected original-Go diagnostic: %s", output)
		}
		t.Log("actual Go rejected unchanged source without its nonzero mask")
		return
	}
	// Intel SDM Vol. 2A Table 2-40 defines EVEX.z=1/aaa=0 as #UD.
	// Older Go accepts this source and emits precisely that reserved pattern;
	// acceptance is an observation, not authorization to execute or translate it.
	if !bytes.Contains(output, []byte("62 f3 75 88 42 d0 01 c3")) {
		t.Fatalf("actual Go accepted reserved-body bytes changed: %s", output)
	}
	code := []byte{0x62, 0xf3, 0x75, 0x88, 0x42, 0xd0, 0x01}
	if _, _, known, err := decodedX86RawPackedSADInstruction(code, 64); !known || err == nil {
		t.Fatal("actual reserved bytes acquired valid raw semantics")
	}
	t.Log("actual Go accepted reserved EVEX.z/aaa=0 bytes; named and raw validators still reject them")
}

func TestX86PackedSADFPSpanAndNativeMemoryBoundary(t *testing.T) {
	for _, row := range []string{"VPSADBW source+0(FP),Z0,Z1", "VMPSADBW $37,source+0(FP),Y0,Y1", "VDBPSADBW.Z $228,source+0(FP),Z0,K1,Z1"} {
		source := "TEXT sad(SB),4,$0-64\n" + row + "\nRET\n"
		goAssemblerOracleOutput(t, "amd64", source, "", true)
		file, _ := Parse(ArchAMD64, source)
		ins := file.Funcs[0].Instrs[1]
		form, _, err := x86PackedSADProperties(ins, "amd64")
		if err != nil {
			t.Fatal(err)
		}
		for _, missing := range []int{-1, 0, form.memoryBytes - 1} {
			sig := x86WordMaddFPType(t)
			if missing >= 0 {
				for i, slot := range sig.Frame.Params {
					if slot.Offset == int64(missing) {
						sig.Frame.Params = append(sig.Frame.Params[:i], sig.Frame.Params[i+1:]...)
						break
					}
				}
			}
			ctx, output := newAMD64CtxWithFuncForTest(t, file.Funcs[0], sig, nil)
			before := output.String()
			_, _, err := ctx.lowerPackedSumAbsoluteDifferences(ins.Op, ins)
			if (err != nil) != (missing >= 0) || missing >= 0 && output.String() != before {
				t.Fatalf("FP complete native-width span %s missing%d: %v", row, missing, err)
			}
		}
	}
	for _, row := range []string{"PSADBW source+0(FP),X0", "MPSADBW $1,(SP),X0", "PSADBW 8(BP),X0", "MPSADBW $1,(AX)(BP*2),X0"} {
		source := "TEXT f(SB),4,$0-64\n" + row + "\nRET\n"
		goAssemblerOracleOutput(t, "amd64", source, "", true)
		file, _ := Parse(ArchAMD64, source)
		ctx, output := newAMD64CtxWithFuncForTest(t, file.Funcs[0], x86WordMaddFPType(t), nil)
		before := output.String()
		if _, _, err := ctx.lowerPackedSumAbsoluteDifferences(file.Funcs[0].Instrs[1].Op, file.Funcs[0].Instrs[1]); !errors.Is(err, ErrProbeNeedsContext) || output.String() != before {
			t.Fatalf("virtual slots became native storage %s: %v", row, err)
		}
	}
}

func TestX86PackedSADLowerEffectAndFullReadClassificationAgree(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range x86SADRows(arch) {
			file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			ins := file.Funcs[0].Instrs[1]
			form, known, err := x86PackedSADProperties(ins, arch)
			if !known || err != nil || !x86CallerVectorMoveKnown(ins) {
				t.Fatalf("lowered accepted SAD lacks registered source effect %s: %v", row, err)
			}
			for index := range ins.Args {
				width, write, valid := x86CallerMoveMemoryShape(ins, index)
				if valid != (index == form.memory) || valid && (write || width != int64(form.byteWidth)) {
					t.Fatalf("source/native read classifications disagree %s operand%d: %d/%t/%t", row, index, width, write, valid)
				}
			}
		}
	}
}

func TestX86PackedSADDecoderPhysicalRowsDoNotGrantSourcePermissions(t *testing.T) {
	for _, encoded := range []Op{"VPSADBW", "VPSADBW.EVEX", "VMPSADBW", "VDBPSADBW"} {
		for width := 0; width < 3; width++ {
			if width == 2 && (encoded == "VMPSADBW" || encoded == "VPSADBW") {
				continue
			}
			code := encodeX86RawPackedSAD(encoded, width, 0, 1, 2, 0, false, false)
			for _, mode := range []int{32, 64} {
				ins, length, known, err := decodedX86RawPackedSADInstruction(code, mode)
				if !known || err != nil || length != len(code) {
					t.Fatalf("physical %x mode%d: %v", code, mode, err)
				}
				arch := "amd64"
				if mode == 32 {
					arch = "386"
				}
				if _, known, err := x86PackedSADProperties(ins, arch); !known || err != nil {
					t.Fatalf("actual physical decoder row %x: %v", code, err)
				}
				if mode == 32 && len(ins.Args) > 3 {
					local := ins
					local.x86Encoded = false
					if _, _, err := x86PackedSADProperties(local, arch); err == nil {
						t.Fatal("named/public source borrowed physical frontend permission")
					}
				}
				// Byte identity is not initialized input or pointer permission.
				body := x86SourceStackState{vectors: make(map[Reg]uint64), masks: make(map[Reg]bool)}
				form, _, _ := x86PackedSADProperties(ins, "amd64")
				if !x86CallerSADStep(&ins, form, &body, nil) {
					t.Fatal("pure register effect unexpectedly failed")
				}
				knownBytes := body.vectors[x86CallerVectorRoot(ins.Args[form.destination].Reg)]
				if knownBytes&3 != 0 {
					t.Fatal("raw producer invented initialized SAD input bytes")
				}
			}
		}
	}
}
