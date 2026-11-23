package plan9asm

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestGoAMD64FixedLocalImmediateShuffleObjects(t *testing.T) {
	original := x86OfficialAMD64EncodingRows(t, "avx512enc/avx512f.s", `VPSHUFD \$\d+, 17\(SP\)\(BP\*[12]\), K\d+, [XY]\d+`)
	if len(original) != 2 {
		t.Fatalf("expected both original indexed VPSHUFD occurrences, got %d", len(original))
	}
	var operations []string
	for _, row := range original {
		operations = append(operations, row.instruction)
	}
	code, pcs := x86NumericalBoundaryGoBytes(t, "amd64", strings.Join(operations, "\n")+"\nRET")
	if len(pcs) != len(original)+1 {
		t.Fatal("missing original Go instruction boundaries")
	}
	for index, row := range original {
		if got := code[pcs[index]:pcs[index+1]]; !bytes.Equal(got, row.code) {
			t.Fatalf("%s: original Go emitted %x, corpus records %x", row.location, got, row.code)
		}
	}
	for _, row := range x86OfficialImmediateShuffleRows(t) {
		op, arguments, _ := strings.Cut(row, " ")
		args := strings.Split(arguments, ",")
		operations = append(operations, row)
		if len(args) == 4 {
			operations = append(operations, op+".Z "+arguments)
		}
		args[1] = "17(SP)(BP*2)"
		memory := strings.Join(args, ",")
		operations = append(operations, op+" "+memory)
		if len(args) == 4 {
			operations = append(operations, op+".Z "+memory)
		}
	}
	for _, bank := range []string{"X", "Y", "Z"} {
		operations = append(operations,
			"VPSHUFD.BCST $27,17(SP)(BP*2),"+bank+"17",
			"VPSHUFD.BCST $27,17(SP)(BP*2),K1,"+bank+"17",
			"VPSHUFD.BCST.Z $27,17(SP)(BP*2),K1,"+bank+"17",
		)
	}

	var source, declarations strings.Builder
	for i, operation := range operations {
		name := fmt.Sprintf("Value%d", i)
		source.WriteString(fixedLocalVectorStackAssembly(t, name, operation, "", ""))
		fmt.Fprintf(&declarations, "func %s(a uint64) uint64\n", name)
	}
	fixedLocalCompleteVectorObjects(t, source.String(), declarations.String(), len(operations))
}

func TestGoAMD64FixedLocalImmediateShuffleWritemaskAndExtent(t *testing.T) {
	_, _, sig, _ := x86ResultInitializationFixture(t, "amd64", "func Value(a uint64) uint64", "RET")
	for _, row := range []struct {
		name, operation string
		setup           string
		omit            Reg
		width, offset   int64
	}{
		{"merging reads destination", "VPSHUFHW $27,17(SP)(BP*2),K1,Y3", "", "Z3", 0, 0},
		{"zeroing defines destination", "VPSHUFHW.Z $27,17(SP)(BP*2),K1,Y3", "", "Z3", 32, 19},
		{"zeroing needs mask", "VPSHUFLW.Z $27,17(SP)(BP*2),K1,Y3", "", "K1", 0, 0},
		{"broadcast reads four bytes", "VPSHUFD.BCST.Z $27,123(SP)(BP*1),K1,Z3", "", "Z3", 4, 124},
		{"broadcast needs its final byte", "VPSHUFD.BCST.Z $27,124(SP)(BP*1),K1,Z3", "", "", 0, 0},
		{"full read with zero mask", "VPSHUFD.Z $0,123(SP)(BP*1),K1,Z3", "MOVQ $0,AX\n", "", 0, 0},
	} {
		t.Run(row.name, func(t *testing.T) {
			source := fixedLocalVectorStackAssembly(t, "Value", row.operation, row.setup, row.omit)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			proven, err := proveX86FixedLocal(file.Funcs[0], sig)
			if row.width == 0 {
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("expected unbound input, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			for _, ins := range proven.Instrs {
				if ins.Raw == row.operation {
					access := ins.x86FixedLocalMemory[1]
					if access.width != row.width || access.write || access.nativeInput || access.owner != proven.x86FixedLocal {
						t.Fatalf("wrong private read certificate: %+v", access)
					}
					for _, offset := range access.offset {
						if offset != row.offset {
							t.Fatalf("private read offset %d, want %d", offset, row.offset)
						}
					}
					return
				}
			}
			t.Fatal("missing original shuffle in proved function")
		})
	}
}

func TestX86ImmediateShuffleOfficialRowsThreeAPIsFiveTargets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range []struct{ arch, triple string }{
		{"amd64", "x86_64-apple-darwin"}, {"amd64", "x86_64-unknown-linux-gnu"},
		{"amd64", "x86_64-pc-windows-msvc"}, {"386", "i386-unknown-linux-gnu"},
		{"386", "i686-pc-windows-msvc"},
	} {
		t.Run(target.triple, func(t *testing.T) {
			rows := x86OfficialImmediateShuffleRows(t)
			var selected []string
			for _, row := range rows {
				if target.arch == "386" {
					if strings.Count(row, ",") == 3 {
						// This is an actual frontend refusal, not a skipped test.
						goAssemblerOracleOutput(t, target.arch, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n", "", false)
						continue
					}
					row = strings.NewReplacer("X17", "X1", "Y17", "Y1").Replace(row)
				}
				selected = append(selected, row)
				args := strings.Split(strings.Fields(row)[1], ",")
				args[1] = "8(AX)"
				selected = append(selected, strings.Fields(row)[0]+" "+strings.Join(args, ","))
			}
			for _, op := range []string{"PSHUFL", "PSHUFD", "PSHUFHW", "PSHUFLW"} {
				selected = append(selected, op+" $255,X0,X1", op+" $0,16(AX),X1")
			}
			selected = append(selected, "PSHUFW $-128,M0,M1", "PSHUFW $127,8(AX),M1")
			if target.arch == "386" {
				for _, op := range []string{"PSHUFW", "PSHUFL", "PSHUFD", "PSHUFHW", "PSHUFLW", "VPSHUFD", "VPSHUFHW", "VPSHUFLW"} {
					bank, values := "X", []int{0, 27, 255}
					if op == "PSHUFW" {
						bank, values = "M", []int{0, -1, 127}
					} else if strings.HasPrefix(op, "V") {
						values = []int{0, -1, 255}
					}
					for _, value := range values {
						selected = append(selected, fmt.Sprintf("%s $%d,%s0,%s1", op, int64(4294967296)+int64(value), bank, bank))
					}
				}
			}
			for _, bank := range []string{"X", "Y", "Z"} {
				selected = append(selected, "VPSHUFD.BCST $0,8(AX),"+bank+"1")
				if target.arch == "amd64" {
					selected = append(selected, "VPSHUFD.BCST.Z $255,8(AX),K1,"+bank+"1")
				}
			}
			want := 76
			if target.arch == "386" {
				want = 79
			}
			if len(selected) != want {
				t.Fatal("official row/operand variation denominator changed", len(selected), want)
			}
			var source strings.Builder
			for index, row := range selected {
				name := fmt.Sprintf("F%d", index)
				fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-0\n%s\nRET\n", name, row)
			}
			// Preserve every original uninitialized row, including the unclosed
			// MMX sources. Syntax objects cannot supply numerical or x87 state.
			file, sigs := x86UnboundVoidFormatSources(t, source.String(), target.arch, target.triple)
			before := fmt.Sprintf("%#v %#v", file, sigs)
			ir := x86ScalarFormatObjectUnit(t, file, sigs, target.arch, target.triple, 0)
			for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
				for _, level := range []string{"-O0", "-O2"} {
					x86PackedStringCompileObject(t, llc, target.triple, text, level)
				}
			}
			if before != fmt.Sprintf("%#v %#v", file, sigs) {
				t.Fatal("object verification mutated original input or signatures")
			}
			t.Logf("%d original Go forms, three public Context checks and emitter-only LLVM22 objects; initialized caller/MMX owners are separate", len(selected))
		})
	}
}
