package plan9asm

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
)

func x86ScalarLaneInstruction(t *testing.T, row string) Instr {
	t.Helper()
	file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
	if err != nil {
		t.Fatal(err)
	}
	return file.Funcs[0].Instrs[1]
}

func TestX86ScalarLaneCompleteGoTables(t *testing.T) {
	read := func(name string) string {
		data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86", name))
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	legacy, vector := read("asm6.go"), read("avx_optabs.go")
	compact := func(s string) string { return strings.ToLower(strings.Join(strings.Fields(s), "")) }
	for name, expected := range map[string]string{
		"yinsr":  "{Zibm_r,3,argList{Yu8,Ymm,Yxr}},",
		"yinsrw": "{Zibm_r,2,argList{Yu8,Yml,Yxr}},",
		"yextr":  "{Zibr_m,3,argList{Yu8,Yxr,Ymm}},",
		"yextrw": "{Zibm_r,2,argList{Yu8,Yxr,Yrl}},{Zibr_m,2,argList{Yu8,Yxr,Yml}},",
	} {
		block := regexp.MustCompile(`(?s)var ` + name + ` = \[\]ytab\{(.*?)\n\}`).FindStringSubmatch(legacy)
		if len(block) != 2 || compact(block[1]) != compact(expected) {
			t.Fatalf("actual complete %s table changed: %v", name, block)
		}
	}
	for name, expected := range map[string]string{
		"_yvpinsrb":    "{zcase:Zvex_i_rm_v_r,zoffset:2,args:argList{Yu8,Yml,Yxr,Yxr}},{zcase:Zevex_i_rm_v_r,zoffset:3,args:argList{Yu8,Yml,YxrEvex,YxrEvex}},",
		"_yvextractps": "{zcase:Zvex_i_r_rm,zoffset:0,args:argList{Yu8,Yxr,Yml}},{zcase:Zvex_i_r_rm,zoffset:2,args:argList{Yi8,Yxr,Yml}},{zcase:Zevex_i_r_rm,zoffset:3,args:argList{Yu8,YxrEvex,Yml}},",
		"_yvpextrw":    "{zcase:Zvex_i_r_rm,zoffset:0,args:argList{Yu8,Yxr,Yml}},{zcase:Zvex_i_r_rm,zoffset:2,args:argList{Yi8,Yxr,Yml}},{zcase:Zvex_i_rm_r,zoffset:0,args:argList{Yu8,Yxr,Yrl}},{zcase:Zvex_i_rm_r,zoffset:2,args:argList{Yi8,Yxr,Yrl}},{zcase:Zevex_i_r_rm,zoffset:3,args:argList{Yu8,YxrEvex,Yml}},{zcase:Zevex_i_rm_r,zoffset:3,args:argList{Yu8,YxrEvex,Yrl}},",
	} {
		block := regexp.MustCompile(`(?s)var ` + name + ` = \[\]ytab\{(.*?)\n\}`).FindStringSubmatch(vector)
		if len(block) != 2 || compact(block[1]) != compact(expected) {
			t.Fatalf("actual complete %s table changed: %v", name, block)
		}
	}
	var names []string
	for _, action := range []string{"INSR", "EXTR"} {
		for _, size := range []struct{ suffix, opcode, tuple string }{
			{"B", map[string]string{"INSR": "20", "EXTR": "14"}[action], "1"},
			{"W", map[string]string{"INSR": "c4", "EXTR": "15"}[action], "2"},
			{"D", map[string]string{"INSR": "22", "EXTR": "16"}[action], "4"},
			{"Q", map[string]string{"INSR": "22", "EXTR": "16"}[action], "8"},
		} {
			name := "P" + action + size.suffix
			names = append(names, name, "V"+name)
			table, prefix, opbytes := "yinsr", "Pq", "0x3a,0x"+size.opcode+",00"
			if action == "EXTR" {
				table = "yextr"
			}
			if size.suffix == "Q" {
				prefix = "Pq3"
			}
			if size.suffix == "W" {
				if action == "INSR" {
					table = "yinsrw"
					opbytes = "0xc4,00"
				} else {
					table = "yextrw"
					opbytes = "0xc5,0,0x3a,0x15,0"
				}
			}
			if !strings.Contains(compact(legacy), compact("{A"+name+","+table+","+prefix+",opBytes{"+opbytes+"}},")) {
				t.Fatal("actual legacy opcode changed", name)
			}
			vt := "_yvpinsrb"
			if action == "EXTR" {
				vt = "_yvextractps"
				if size.suffix == "W" {
					vt = "_yvpextrw"
				}
			}
			vmap, vw := "0F3A", "0"
			if size.suffix == "W" && action == "INSR" {
				vmap = "0F"
			}
			if size.suffix == "Q" {
				vw = "1"
			}
			body := "avxEscape|vex128|vex66|vex" + vmap + "|vexW" + vw + ",0x" + size.opcode + ",avxEscape|evex128|evex66|evex" + vmap + "|evexW" + vw + ",evexN" + size.tuple + ",0x" + size.opcode + ","
			if action == "EXTR" && size.suffix == "W" {
				body = "avxEscape|vex128|vex66|vex0F3A|vexW0,0x15,avxEscape|vex128|vex66|vex0F|vexW0,0xc5,avxEscape|evex128|evex66|evex0F3A|evexW0,evexN2,0x15,avxEscape|evex128|evex66|evex0F|evexW0,0,0xc5,"
			}
			entry := "{as:A" + "V" + name + ",ytab:" + vt + ",prefix:Pavx,op:opBytes{" + body + "}},"
			if !strings.Contains(compact(vector), compact(entry)) {
				t.Fatalf("actual complete VEX/EVEX W/pp/opcode/tuple changed: %s", name)
			}
		}
	}
	var actual []string
	for name := range amd64PackedIntegerInsertSpecs {
		actual = append(actual, name)
	}
	for name := range amd64PackedScalarExtractSpecs {
		if !strings.HasSuffix(string(name), "PS") {
			actual = append(actual, string(name))
		}
	}
	sort.Strings(names)
	sort.Strings(actual)
	if !reflect.DeepEqual(names, actual) {
		t.Fatal("incomplete typed family", names, actual)
	}
}

func TestX86ScalarLaneGoBytesAndEncodedGPSpellings(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, action := range []string{"INSR", "EXTR"} {
			for _, suffix := range []string{"B", "W", "D", "Q"} {
				if arch == "386" && suffix == "Q" {
					continue
				}
				op := "P" + action + suffix
				for index, gp := range []string{"AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI"} {
					if suffix == "W" {
						break
					} // yinsrw/yextrw have no Ymm selector.
					t.Run(arch+"/"+op+"/"+gp, func(t *testing.T) {
						row := fmt.Sprintf("%s $255,%s,X1", op, gp)
						alias := fmt.Sprintf("%s $255,M%d,X1", op, index)
						if action == "EXTR" {
							row = fmt.Sprintf("%s $255,X1,%s", op, gp)
							alias = fmt.Sprintf("%s $255,X1,M%d", op, index)
						}
						bytes := func(row string) []byte {
							var result []byte
							for _, line := range strings.Split(string(x86InsertExtractGoListing(t, arch, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")), "\n") {
								result = append(result, x86InsertExtractListedBytes(line)...)
							}
							return result
						}
						if !reflect.DeepEqual(bytes(row), bytes(alias)) {
							t.Fatal("original Go Ymm encoding is not the GP identity", row, alias)
						}
						f, known, err := x86ScalarLaneProperties(x86ScalarLaneInstruction(t, alias), arch)
						if !known || err != nil || f.transferReg != Reg(gp) {
							t.Fatal("typed selected GP identity differs", f, known, err)
						}
					})
				}
			}
		}
	}
}

func TestX86ScalarLaneGrammarRejectsAdjacentClasses(t *testing.T) {
	for _, op := range []string{"PINSRB", "PINSRW", "PINSRD", "PINSRQ", "VPINSRB", "VPINSRW", "VPINSRD", "VPINSRQ", "PEXTRB", "PEXTRW", "PEXTRD", "PEXTRQ", "VPEXTRB", "VPEXTRW", "VPEXTRD", "VPEXTRQ"} {
		row := op + " $1,AX,X1"
		if strings.Contains(op, "EXTR") {
			row = op + " $1,X1,AX"
		} else if op[0] == 'V' {
			row += ",X2"
		}
		for _, mutate := range []string{"float", "unresolved", "suffix", "mask", "vector-kind", "gp-byte"} {
			t.Run(op+"/"+mutate, func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, row)
				switch mutate {
				case "float":
					ins.Args[0].ImmIsFloat = true
				case "unresolved":
					ins.Args[0].ImmRaw = "missing"
				case "suffix":
					ins.Op += ".Z"
				case "mask":
					ins.Args = append(ins.Args, Operand{Kind: OpReg, Reg: "K1"})
				case "vector-kind":
					ins.Args[2].Reg = "Y1"
				case "gp-byte":
					if strings.Contains(op, "EXTR") {
						ins.Args[len(ins.Args)-1].Reg = "AL"
					} else {
						ins.Args[1].Reg = "AL"
					}
				}
				if _, known, err := x86ScalarLaneProperties(ins, "amd64"); !known || err == nil {
					t.Fatal("invalid form acquired typed effect", ins)
				}
			})
		}
	}
}

func TestX86ScalarLaneGoImmediateClassBoundaries(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, op := range []string{"PINSRB", "PINSRW", "PINSRD", "PINSRQ", "VPINSRB", "VPINSRW", "VPINSRD", "VPINSRQ", "PEXTRB", "PEXTRW", "PEXTRD", "PEXTRQ", "VPEXTRB", "VPEXTRW", "VPEXTRD", "VPEXTRQ"} {
			insert, vector := strings.Contains(op, "INSR"), op[0] == 'V'
			for _, value := range []int64{-129, -128, -1, 0, 255, 256, 1 << 32, 1<<32 + 255, -(1 << 32), 1<<32 - 128} {
				t.Run(fmt.Sprintf("%s/%s/%d", arch, op, value), func(t *testing.T) {
					row := fmt.Sprintf("%s $%d,X0,AX", op, value)
					if insert {
						row = fmt.Sprintf("%s $%d,AX,X0", op, value)
						if vector {
							row += ",X1"
						}
					}
					classified := value
					if arch == "386" {
						classified = int64(int32(value))
					}
					minimum := int64(0) // Complete legacy and V-insert Yu8 rows.
					if vector && !insert {
						minimum = -128 // Complete low-X VEX extract Yi8 rows.
					}
					accepted := classified >= minimum && classified <= 255 &&
						!(arch == "386" && (insert && vector || !vector && op[len(op)-1] == 'Q'))
					goAssemblerOracleOutput(t, arch, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n", "", accepted)
					ins := x86ScalarLaneInstruction(t, row)
					form, known, err := x86ScalarLaneProperties(ins, arch)
					if !known || (err == nil) != accepted || accepted && form.offset != int(byte(value))%(128/form.bits)*(form.bits/8) {
						t.Fatalf("actual Go class/typed lane disagreement: %+v known=%t err=%v", form, known, err)
					}
					if ins.Args[0].Imm != value {
						t.Fatal("class observation changed the original source operand")
					}
				})
			}
		}
	}
}
