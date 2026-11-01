package plan9asm

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// This directory is independent of both the existing raw decoder and lowerer.
// DDUP selects even qwords; SH/SLDUP select odd/even dwords respectively.
var x86DuplicateMoveOracle = []struct {
	name   string
	bytes  int
	odd    bool
	vector bool
}{
	{"MOVDDUP", 8, false, false}, {"MOVSHDUP", 4, true, false}, {"MOVSLDUP", 4, false, false},
	{"VMOVDDUP", 8, false, true}, {"VMOVSHDUP", 4, true, true}, {"VMOVSLDUP", 4, false, true},
}

func TestX86DuplicateMoveCompleteIndependentGoRows(t *testing.T) {
	read := func(name string) string {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86", name))
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	legacy, vector := read("asm6.go"), read("avx_optabs.go")
	for _, table := range []struct{ source, name, rows string }{
		{legacy, "yxm", `{Zm_r_xm,1,argList{Yxm,Yxr}},`},
		{vector, "_yvmovddup", `{zcase:Zvex_rm_v_r,zoffset:2,args:argList{Yxm,Yxr}},
{zcase:Zvex_rm_v_r,zoffset:2,args:argList{Yym,Yyr}},
{zcase:Zevex_rm_v_r,zoffset:0,args:argList{YxmEvex,YxrEvex}},
{zcase:Zevex_rm_k_r,zoffset:3,args:argList{YxmEvex,Yknot0,YxrEvex}},
{zcase:Zevex_rm_v_r,zoffset:0,args:argList{YymEvex,YyrEvex}},
{zcase:Zevex_rm_k_r,zoffset:3,args:argList{YymEvex,Yknot0,YyrEvex}},
{zcase:Zevex_rm_v_r,zoffset:0,args:argList{Yzm,Yzr}},
{zcase:Zevex_rm_k_r,zoffset:3,args:argList{Yzm,Yknot0,Yzr}},`},
	} {
		match := regexp.MustCompile(`(?s)var ` + table.name + ` = \[\]ytab\{(.*?)\n\}`).FindStringSubmatch(table.source)
		if len(match) != 2 || strings.Join(strings.Fields(match[1]), "") != strings.Join(strings.Fields(table.rows), "") {
			t.Fatal("complete duplicate-move Go operand rows changed", table.name)
		}
	}
	for _, row := range []struct{ name, prefix, opcode, scale string }{
		{"MOVDDUP", "Pf2", "0x12", "evexN8"},
		{"MOVSHDUP", "Pf3", "0x16", "evexN16"},
		{"MOVSLDUP", "Pf3", "0x12", "evexN16"},
	} {
		if !strings.Contains(legacy, "{A"+row.name+", yxm, "+row.prefix+", opBytes{"+row.opcode+"}}") {
			t.Fatal("legacy duplicate-move prefix/operation changed", row.name)
		}
		match := regexp.MustCompile(`(?s)\{as: AV` + row.name + `, ytab: _yvmovddup, prefix: Pavx, op: opBytes\{(.*?)\n\s*\}\}`).FindStringSubmatch(vector)
		if len(match) != 2 || strings.Count(match[1], "avxEscape") != 5 ||
			!strings.Contains(match[1], row.scale+" | evexZeroingEnabled") ||
			!strings.Contains(match[1], "evexN32 | evexZeroingEnabled") ||
			!strings.Contains(match[1], "evexN64 | evexZeroingEnabled") {
			t.Fatal("VEX/EVEX duplicate-move width/mask/memory tuple changed", row.name)
		}
	}
}

func TestX86DuplicateMoveInitializedFamilyFiveTargets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			word, move := goWordSize(target.arch), "MOVQ"
			if target.arch == "386" {
				move = "MOVL"
			}
			var source, declarations strings.Builder
			count := 0
			for _, row := range x86DuplicateMoveOracle {
				for _, bank := range []string{"X", "Y", "Z"} {
					if !row.vector && bank != "X" {
						continue
					}
					for _, masking := range []string{"plain", "merge", "zero"} {
						if !row.vector && masking != "plain" {
							continue
						}
						for _, memory := range []bool{false, true} {
							name, operation, mask := fmt.Sprint("Duplicate", count), row.name, ""
							if masking != "plain" {
								mask = "K1,"
							}
							if masking == "zero" {
								operation += ".Z"
							}
							input := bank + "0"
							if memory {
								input = "(BX)"
							}
							fmt.Fprintf(&declarations, "func %s(out,input,old *[64]byte,mask uint64)\n", name)
							fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n%s out+0(FP),AX\n%s input+%d(FP),BX\n%s old+%d(FP),CX\nKMOVD mask+%d(FP),K1\nVMOVDQU64 (BX),Z0\nVMOVDQU64 (CX),Z2\n%s %s,%s%s2\nVMOVDQU64 Z2,(AX)\nRET\n",
								name, 3*word+8, move, move, word, move, 2*word, 3*word, operation, input, mask, bank)
							count++
						}
					}
				}
			}
			if count != 60 {
				t.Fatal("complete independent duplicate-move width/mask/source matrix changed", count)
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("initialized original duplicate family lost its result or native read", api, err)
					}
					for _, body := range []string{ir, x86DwordProductIROptimize(t, ir)} {
						compileLLVMToObject(t, llc, target.triple, "duplicate-family.ll", "duplicate-family.o", body)
					}
				})
			}
		})
	}
}

func TestX86DuplicateMoveDeadVoidRetainsInputAndMaskObligations(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, row := range x86DuplicateMoveOracle {
			for _, bank := range []string{"X", "Y", "Z"} {
				if !row.vector && bank != "X" {
					continue
				}
				for _, unused := range []bool{false, true} {
					for _, control := range []string{"source", "mask", "merge"} {
						if !row.vector && control != "source" {
							continue
						}
						t.Run(fmt.Sprintf("%s/%s/%s/unused=%t/%s", target.triple, row.name, bank, unused, control), func(t *testing.T) {
							declaration, extent := "func Value()", 0
							if unused {
								declaration, extent = "func Value(unused bool)", 1
							}
							setup, mask := "VPXORQ Z2,Z2,Z2\n", ""
							if control != "source" {
								setup += "VPXORQ Z0,Z0,Z0\n"
								mask = "K1,"
								if control == "merge" {
									setup = "VPXORQ Z0,Z0,Z0\nMOVL $1,AX\nKMOVD AX,K1\n"
								}
							}
							source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s%s %s0,%s%s2\nRET\n", extent, setup, row.name, bank, mask, bank)
							for _, api := range []string{"text", "module", "Go"} {
								if ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, api); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
									t.Fatal("dead duplicate operation borrowed unknown data/mask/merge bytes", api, err)
								}
							}
						})
					}
				}
			}
		}
	}
}

func TestX86DuplicateMoveDeadMemoryKeepsExactAccessAfterO2(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, row := range x86DuplicateMoveOracle {
			for _, bank := range []string{"X", "Y", "Z"} {
				if !row.vector && bank != "X" {
					continue
				}
				t.Run(target.triple+"/"+row.name+"/"+bank, func(t *testing.T) {
					word, move, operation, mask := goWordSize(target.arch), "MOVQ", row.name, ""
					if target.arch == "386" {
						move = "MOVL"
					}
					if row.vector {
						operation, mask = operation+".Z", "K1,"
					}
					source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s p+0(FP),SI\nMOVL $0,AX\nKMOVD AX,K1\n%s (SI),%s%s2\nRET\n", word, move, operation, mask, bank)
					ir, err := x86ScalarFPBitViewAPI(t, source, "func Value(p *byte)", target.arch, target.triple, "Go")
					if err != nil {
						t.Fatal("actual incoming address did not retain a dead native access", err)
					}
					width := map[string]int{"X": 16, "Y": 32, "Z": 64}[bank]
					if row.bytes == 8 && bank == "X" {
						width = 8
					}
					for _, body := range []string{ir, x86DwordProductIROptimize(t, ir)} {
						if !row.vector && row.bytes == 4 {
							if !strings.Contains(body, `asm sideeffect "`+strings.ToLower(row.name)+` `) || !strings.Contains(body, `~{memory}`) {
								t.Fatal("legacy Type4 aligned memory fault was replaced by an ordinary or stronger access")
							}
						} else if !x86DuplicateMoveExactVolatileRead(body, width) &&
							!strings.Contains(body, `asm sideeffect "`+strings.ToLower(row.name)+` `) {
							t.Fatal("E4NF/E5NF dead or zero-mask access vanished or shrank", width, body)
						}
					}
				})
			}
		}
	}
}

func x86DuplicateMoveExactVolatileRead(ir string, width int) bool {
	if strings.Contains(ir, fmt.Sprintf("load volatile i%d", width*8)) ||
		width == 8 && strings.Contains(ir, "load volatile double") {
		return true
	}
	for _, element := range []struct {
		name string
		bits int
	}{{"i8", 8}, {"i16", 16}, {"i32", 32}, {"i64", 64}, {"float", 32}, {"double", 64}} {
		if strings.Contains(ir, fmt.Sprintf("load volatile <%d x %s>", width*8/element.bits, element.name)) {
			return true
		}
	}
	return false
}
