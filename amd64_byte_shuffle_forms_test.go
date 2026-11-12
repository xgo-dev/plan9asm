package plan9asm

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestX86ByteShuffleCompleteGoEncoderRows(t *testing.T) {
	root := filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86")
	legacy, err := os.ReadFile(filepath.Join(root, "asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []string{
		"{APSHUFB, ymshufb, Pq, opBytes{0x38, 0x00}}",
		"var ymshufb = []ytab{\n\t{Zm2_r, 2, argList{Yxm, Yxr}},\n}",
	} {
		if !strings.Contains(string(legacy), row) {
			t.Fatal("actual legacy Go row changed", row)
		}
	}
	avx, err := os.ReadFile(filepath.Join(root, "avx_optabs.go"))
	if err != nil {
		t.Fatal(err)
	}
	if len(x86ByteShuffleSpecs) != 2 {
		t.Fatal("byte shuffle family changed")
	}
	for _, row := range []struct{ begin, end, want string }{
		{"{as: AVPSHUFB,", "\n\t}},", `{as: AVPSHUFB, ytab: _yvandnpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0x00,
		avxEscape | vex256 | vex66 | vex0F38 | vexW0, 0x00,
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN16 | evexZeroingEnabled, 0x00,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN32 | evexZeroingEnabled, 0x00,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN64 | evexZeroingEnabled, 0x00,`},
		{"var _yvandnpd =", "\n}", `var _yvandnpd = []ytab{
	{zcase: Zvex_rm_v_r, zoffset: 2, args: argList{Yxm, Yxr, Yxr}},
	{zcase: Zvex_rm_v_r, zoffset: 2, args: argList{Yym, Yyr, Yyr}},
	{zcase: Zevex_rm_v_r, zoffset: 0, args: argList{YxmEvex, YxrEvex, YxrEvex}},
	{zcase: Zevex_rm_v_k_r, zoffset: 3, args: argList{YxmEvex, YxrEvex, Yknot0, YxrEvex}},
	{zcase: Zevex_rm_v_r, zoffset: 0, args: argList{YymEvex, YyrEvex, YyrEvex}},
	{zcase: Zevex_rm_v_k_r, zoffset: 3, args: argList{YymEvex, YyrEvex, Yknot0, YyrEvex}},
	{zcase: Zevex_rm_v_r, zoffset: 0, args: argList{Yzm, Yzr, Yzr}},
	{zcase: Zevex_rm_v_k_r, zoffset: 3, args: argList{Yzm, Yzr, Yknot0, Yzr}},`},
	} {
		start := strings.Index(string(avx), row.begin)
		if start < 0 || strings.SplitN(string(avx)[start:], row.end, 2)[0] != row.want {
			t.Fatal("actual Go encoder classes, offsets or attributes changed", row.begin)
		}
	}
}

func x86ByteShuffleFormatRows(arch string) []string {
	var rows []string
	for _, source := range []string{"X0", "(AX)", "16(AX)(CX*4)", "value+0(FP)", "local-16(SP)", "·data(SB)", "(FS)", "(GS)"} {
		rows = append(rows, "PSHUFB "+source+",X1")
	}
	for _, bank := range []string{"X", "Y", "Z"} {
		for _, source := range []string{bank + "0", "(AX)", "16(AX)(CX*4)", "value+0(FP)", "local-64(SP)", "·data(SB)", "(FS)", "(GS)"} {
			for mode := 0; mode < 3; mode++ {
				if arch == "386" && mode != 0 {
					continue
				}
				name, args := "VPSHUFB", source+","+bank+"1"
				if mode != 0 {
					args += ",K7"
				}
				if mode == 2 {
					name += ".Z"
				}
				rows = append(rows, name+" "+args+","+bank+"2")
			}
		}
	}
	return rows
}

func TestX86ByteShuffleGoFormsAndMemoryShapes(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range x86ByteShuffleFormatRows(arch) {
			t.Run(arch+"/"+row, func(t *testing.T) {
				goAssemblerOracleOutput(t, arch, "TEXT f(SB),4,$64-64\n"+row+"\nRET\n", "", true)
				ins := x86ScalarLaneInstruction(t, row)
				form, known, err := x86ByteShuffleProperties(ins.Op, ins, arch)
				if !known || err != nil || !x86CallerVectorMoveKnown(ins) {
					t.Fatal("Go shape missing in a consumer", known, err)
				}
				if form.memory >= 0 {
					width, write, known := x86InstructionMemoryShape(ins, form.memory, arch)
					if !known || write || width != int64(form.byteWidth) {
						t.Fatal("lost full E4NF control tuple", width, write, known)
					}
				}
			})
		}
	}
}

func TestX86ByteShuffleMode32HighBanksRemainContext(t *testing.T) {
	for _, bank := range []string{"X", "Y"} {
		for _, index := range []int{8, 15, 16, 31} {
			row := fmt.Sprintf("VPSHUFB %s%d,%s1,%s2", bank, index, bank, bank)
			goAssemblerOracleOutput(t, "386", "TEXT f(SB),4,$0-0\n"+row+"\nRET\n", "", true)
			ins := x86ScalarLaneInstruction(t, row)
			if _, known, err := x86ByteShuffleProperties(ins.Op, ins, "386"); !known || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("source acceptance invented physical high-bank identity", row, err)
			}
		}
	}
}

func TestX86ByteShuffleInvalidFormsAndSourceIdentity(t *testing.T) {
	for _, row := range []string{
		"PSHUFB M0,M1", "PSHUFB X16,X1", "PSHUFB.Z X0,X1",
		"VPSHUFB X0,Y1,Y2", "VPSHUFB X0,(AX),X2", "VPSHUFB $1,X1,X2",
		"VPSHUFB X0,X1,K0,X2", "VPSHUFB.BCST (AX),X1,X2",
		"VPSHUFB.SAE X0,X1,X2", "VPSHUFB.RN_SAE X0,X1,X2",
		"VPSHUFB (AX)(CX*3),X1,X2", "VPSHUFB 2147483648(AX),X1,X2",
	} {
		goAssemblerOracleOutput(t, "amd64", "TEXT f(SB),4,$0-0\n"+row+"\nRET\n", "", false)
		file, parseErr := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
		if parseErr != nil {
			// The original Go rejection above still owns this source axis.
			continue
		}
		ins := file.Funcs[0].Instrs[1]
		if _, known, err := x86ByteShuffleProperties(ins.Op, ins, "amd64"); !known || err == nil || x86CallerVectorMoveKnown(ins) {
			t.Fatal("invalid Go form acquired an effect", row, known, err)
		}
	}
	for _, row := range []string{"PSHUFB (AX),X1", "VPSHUFB (AX),X1,X2"} {
		for _, mutation := range []string{"dispatch", "address-size", "unbound-override"} {
			ins := x86ScalarLaneInstruction(t, row)
			op := ins.Op
			switch mutation {
			case "dispatch":
				ins.Op = "MOVOU"
			case "address-size":
				ins.x86AddressBits = 32
			case "unbound-override":
				ins.x86UnboundAddressOverride = true
			}
			var out strings.Builder
			ctx := amd64Ctx{goarch: "amd64", b: &out}
			if known, _, err := ctx.lowerPackedByteShuffle(op, ins); !known || err == nil || out.Len() != 0 {
				t.Fatal("changed source identity emitted IR", row, mutation, err, out.String())
			}
		}
	}
}

func TestX86ByteShuffleVectorDispatcherUsesCompleteGrammar(t *testing.T) {
	for _, row := range []string{
		"PSHUFB Y0,X0", "PSHUFB X0", "PSHUFB.Z X0,X1",
		"VPSHUFB Y0,Y1,AX", "VPSHUFB X0,Y1,Y2",
		"VPSHUFB X0,X1,K0,X2", "VPSHUFB.BCST (AX),X1,X2",
	} {
		goAssemblerOracleOutput(t, "amd64", "TEXT f(SB),4,$0-0\n"+row+"\nRET\n", "", false)
		for _, keepOpcode := range []bool{false, true} {
			ins := x86ScalarLaneInstruction(t, row)
			op := ins.Op
			if !keepOpcode {
				ins.Op = ""
			}
			var output strings.Builder
			ctx := amd64Ctx{goarch: "amd64", b: &output}
			known, terminated, err := ctx.lowerVec(op, ins)
			if !known || terminated || err == nil || output.Len() != 0 {
				t.Fatalf("vector dispatcher bypassed byte-shuffle grammar for %q: (%v, %v, %v), IR %q", row, known, terminated, err, output.String())
			}
		}
	}
	for _, row := range []string{
		"PSHUFB X0,X1", "VPSHUFB X0,X1,X2", "VPSHUFB Y0,Y1,Y2",
		"VPSHUFB Z0,Z1,Z2", "VPSHUFB X0,X1,K7,X2", "VPSHUFB.Z Z0,Z1,K7,Z2",
	} {
		ins := x86ScalarLaneInstruction(t, row)
		function := Func{Instrs: []Instr{ins}}
		family, familyOutput := newAMD64CtxWithFuncForTest(t, function, FuncSig{Name: "shuffle", Ret: Void}, nil)
		dispatch, dispatchOutput := newAMD64CtxWithFuncForTest(t, function, FuncSig{Name: "shuffle", Ret: Void}, nil)
		if known, terminated, err := family.lowerPackedByteShuffle(ins.Op, ins); !known || terminated || err != nil {
			t.Fatal("independent family entry", row, known, terminated, err)
		}
		if known, terminated, err := dispatch.lowerVec(ins.Op, ins); !known || terminated || err != nil {
			t.Fatal("vector family entry", row, known, terminated, err)
		}
		if familyOutput.String() != dispatchOutput.String() {
			t.Fatal("vector dispatcher changed the family's emitted effects", row)
		}
	}
}
