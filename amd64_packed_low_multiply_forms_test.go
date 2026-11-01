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

func TestX86PackedLowMultiplyCompleteGoEncoderRows(t *testing.T) {
	root := filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86")
	legacy, err := os.ReadFile(filepath.Join(root, "asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []string{
		"{APMULLD, yxm_q4, Pq4, opBytes{0x40}}",
		"{Zm_r, 1, argList{Yxm, Yxr}}",
	} {
		if !strings.Contains(string(legacy), row) {
			t.Fatal("actual legacy Go row changed", row)
		}
	}
	avx, err := os.ReadFile(filepath.Join(root, "avx_optabs.go"))
	if err != nil {
		t.Fatal(err)
	}
	if len(x86PackedLowMultiplySpecs) != 3 {
		t.Fatal("incomplete D/Q low-product inventory")
	}
	for _, name := range []string{"VPMULLD", "VPMULLQ"} {
		table, w, broadcast, rows := "_yvandnpd", 0, 4, 5
		if name == "VPMULLQ" {
			table, w, broadcast, rows = "_yvblendmpd", 1, 8, 3
		}
		start := strings.Index(string(avx), "{as: A"+name+",")
		if start < 0 {
			t.Fatal("missing Go opcode", name)
		}
		record := strings.SplitN(string(avx)[start:], "\n\t}},", 2)[0]
		if !strings.Contains(record, "ytab: "+table+", prefix: Pavx") || strings.Count(record, "avxEscape") != rows {
			t.Fatal("Go opcode row inventory changed", record)
		}
		if name == "VPMULLD" {
			for _, width := range []int{128, 256} {
				want := fmt.Sprintf("avxEscape | vex%d | vex66 | vex0F38 | vexW0, 0x40,", width)
				if !strings.Contains(record, want) {
					t.Fatal("Go VEX attributes changed", want)
				}
			}
		}
		for _, width := range []int{128, 256, 512} {
			want := fmt.Sprintf("avxEscape | evex%d | evex66 | evex0F38 | evexW%d, evexN%d | evexBcstN%d | evexZeroingEnabled, 0x40,", width, w, width/8, broadcast)
			if !strings.Contains(record, want) {
				t.Fatal("Go EVEX attributes changed", want)
			}
		}
		start = strings.Index(string(avx), "var "+table+" =")
		if start < 0 {
			t.Fatal("missing Go operand table", table)
		}
		operands := strings.SplitN(string(avx)[start:], "\n}", 2)[0]
		var expected []string
		if name == "VPMULLD" {
			expected = append(expected,
				"{zcase: Zvex_rm_v_r, zoffset: 2, args: argList{Yxm, Yxr, Yxr}}",
				"{zcase: Zvex_rm_v_r, zoffset: 2, args: argList{Yym, Yyr, Yyr}}")
		}
		for _, classes := range [][2]string{{"YxmEvex", "YxrEvex"}, {"YymEvex", "YyrEvex"}, {"Yzm", "Yzr"}} {
			expected = append(expected,
				fmt.Sprintf("{zcase: Zevex_rm_v_r, zoffset: 0, args: argList{%s, %s, %s}}", classes[0], classes[1], classes[1]),
				fmt.Sprintf("{zcase: Zevex_rm_v_k_r, zoffset: 3, args: argList{%s, %s, Yknot0, %s}}", classes[0], classes[1], classes[1]))
		}
		if strings.Count(operands, "argList{") != len(expected) {
			t.Fatal("Go operand row inventory changed", operands)
		}
		for _, row := range expected {
			if !strings.Contains(operands, row) {
				t.Fatal("Go operand classes/encoding changed", row)
			}
		}
	}
}

func x86LowMultiplyFormatRows(arch string) []string {
	var rows []string
	for _, source := range []string{"X0", "(AX)", "16(AX)(CX*4)", "value+0(FP)", "local-16(SP)", "·data(SB)", "(FS)", "(GS)"} {
		rows = append(rows, "PMULLD "+source+",X1")
	}
	for _, op := range []string{"VPMULLD", "VPMULLQ"} {
		for _, bank := range []string{"X", "Y", "Z"} {
			for _, source := range []string{bank + "0", "(AX)", "16(AX)(CX*4)", "value+0(FP)", "local-64(SP)", "·data(SB)", "(FS)", "(GS)"} {
				for _, broadcast := range []bool{false, true} {
					if broadcast && source == bank+"0" {
						continue
					}
					for mode := 0; mode < 3; mode++ {
						if arch == "386" && mode != 0 {
							continue
						}
						name, args := op, source+","+bank+"1"
						if broadcast {
							name += ".BCST"
						}
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
		}
	}
	return rows
}

func TestX86PackedLowMultiplyGoFormatsAndConsumerShapes(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range x86LowMultiplyFormatRows(arch) {
			t.Run(arch+"/"+row, func(t *testing.T) {
				goAssemblerOracleOutput(t, arch, "TEXT f(SB),4,$64-64\n"+row+"\nRET\n", "", true)
				ins := x86ScalarLaneInstruction(t, row)
				form, known, err := x86PackedLowMultiplyProperties(ins.Op, ins, arch)
				if !known || err != nil {
					t.Fatal("valid Go shape lost", known, err)
				}
				if !x86CallerVectorMoveKnown(ins) {
					t.Fatal("caller consumer lost valid family")
				}
				if form.memory >= 0 {
					width, write, known := x86InstructionMemoryShape(ins, form.memory, arch)
					want := form.byteWidth
					if strings.Contains(row, ".BCST") {
						want = 4
						if strings.HasPrefix(row, "VPMULLQ") {
							want = 8
						}
					}
					if !known || write || width != int64(want) {
						t.Fatal("read tuple differs from Go", width, write, known, want)
					}
				}
			})
		}
	}
}

func TestX86PackedLowMultiplyMode32HighBanksRemainContext(t *testing.T) {
	for _, name := range []string{"VPMULLD", "VPMULLQ"} {
		for _, bank := range []string{"X", "Y"} {
			for _, register := range []int{8, 15, 16, 31} {
				row := fmt.Sprintf("%s %s%d,%s1,%s2", name, bank, register, bank, bank)
				goAssemblerOracleOutput(t, "386", "TEXT f(SB),4,$0-0\n"+row+"\nRET\n", "", true)
				for _, target := range []string{"i386-unknown-linux-gnu", "i686-pc-windows-msvc"} {
					file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
					if err != nil {
						t.Fatal(err)
					}
					_, err = Translate(file, Options{Goarch: "386", TargetTriple: target, Sigs: map[string]FuncSig{"f": {Name: "f", Ret: Void}}})
					if !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("Go syntax invented a physical high bank", row, target, err)
					}
				}
			}
		}
	}
}

func TestX86PackedLowMultiplyResultBytes(t *testing.T) {
	for _, row := range []string{"PMULLW X0,X1", "VPMULLW X0,X1,X2", "PMULLD X0,X1", "VPMULLD X0,X1,X2", "VPMULLQ X0,X1,X2"} {
		for _, arch := range []string{"amd64", "386"} {
			for missing := -1; missing < 16; missing++ {
				ins := x86ScalarLaneInstruction(t, row)
				state := x86ResultState{flags: 0x3f}
				state.xmm[0], state.xmm[1] = 0xffff, 0xffff
				state.vectorUpper[1], state.vectorUpper[2] = 0xffff0000, 0xff000000
				if missing >= 0 {
					state.xmm[0] &^= 1 << uint(missing)
				}
				if !x86ResultTransfer(ins, &state, nil, 0, arch) {
					t.Fatalf("registered low multiply result effect missing: %s/%s", arch, row)
				}
				laneBytes := 4
				if strings.Contains(row, "LLW") {
					laneBytes = 2
				} else if strings.Contains(row, "LLQ") {
					laneBytes = 8
				}
				want := uint64(0xffff)
				if missing >= 0 {
					want &^= (uint64(1)<<uint(laneBytes) - 1) << uint(missing/laneBytes*laneBytes)
				}
				dst := 1
				if strings.HasPrefix(row, "V") {
					dst = 2
					want |= ^uint64(0xffff)
				} else {
					want |= 0xffff0000
				}
				if got := state.vectorBytes(dst); got != want || state.flags != 0x3f {
					t.Fatalf("%s missing=%d: got=%x want=%x flags=%x", row, missing, got, want, state.flags)
				}
			}
		}
	}
}

func TestX86PackedLowMultiplyInvalidGoAxesAndSourceIdentity(t *testing.T) {
	for _, row := range []string{
		"PMULLD M0,M1", "PMULLD X16,X1", "PMULLD.BCST (AX),X1",
		"VPMULLD X0,Y1,Y2", "VPMULLD X0,(AX),X2", "VPMULLD $1,X1,X2",
		"VPMULLD X0,X1,K0,X2", "VPMULLD.BCST X0,X1,X2",
		"VPMULLD.Z.BCST (AX),X1,K1,X2", "VPMULLD.SAE X0,X1,X2",
		"VPMULLQ X0,Y1,Y2", "VPMULLQ X0,(AX),X2", "VPMULLQ $1,X1,X2",
		"VPMULLQ X0,X1,K0,X2", "VPMULLQ.BCST X0,X1,X2",
		"VPMULLQ.BCST.BCST (AX),X1,X2", "VPMULLQ.RN_SAE X0,X1,X2",
	} {
		t.Run(row, func(t *testing.T) {
			goAssemblerOracleOutput(t, "amd64", "TEXT f(SB),4,$0-0\n"+row+"\nRET\n", "", false)
			ins := x86ScalarLaneInstruction(t, row)
			if _, known, err := x86PackedLowMultiplyProperties(ins.Op, ins, "amd64"); !known || err == nil {
				t.Fatal("invalid Go form acquired typed effects", row, known, err)
			}
			if x86CallerVectorMoveKnown(ins) {
				t.Fatal("invalid Go form acquired a caller effect", row)
			}
		})
	}
	for _, row := range []string{"PMULLD (AX),X1", "VPMULLD (AX),X1,X2", "VPMULLQ (AX),X1,X2"} {
		ins := x86ScalarLaneInstruction(t, row)
		for _, mutation := range []string{"dispatch", "address-size", "unbound-override"} {
			changed, op := ins, ins.Op
			switch mutation {
			case "dispatch":
				op = "VPMULLD"
				changed.Op = "VPMULLQ"
			case "address-size":
				changed.x86AddressBits = 32
			case "unbound-override":
				changed.x86UnboundAddressOverride = true
			}
			if _, known, err := x86PackedLowMultiplyProperties(op, changed, "amd64"); !known || err == nil {
				t.Fatal("changed source metadata retained a form", row, mutation, err)
			}
		}
	}
}
