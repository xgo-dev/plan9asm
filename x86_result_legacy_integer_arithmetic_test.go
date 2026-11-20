package plan9asm

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// This is the complete legacy Go add/subtract surface, not its V-prefixed
// forms. PADDD is the assembler's explicit PADDL alias. PADDQ and every PSUB
// use yxm; only the other PADD rows use ymm and Py1's mode64-only MMX axis.
var x86LegacyIntegerArithmeticTestNames = []string{
	"PADDB", "PADDW", "PADDL", "PADDD", "PADDQ",
	"PADDSB", "PADDSW", "PADDUSB", "PADDUSW",
	"PSUBB", "PSUBW", "PSUBL", "PSUBQ",
	"PSUBSB", "PSUBSW", "PSUBUSB", "PSUBUSW",
}

func TestX86ABI0ResultLegacyIntegerArithmeticCompleteBytes(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, op := range x86LegacyIntegerArithmeticTestNames {
			for _, form := range []string{"register", "alias", "FP", "AUTO"} {
				t.Run(arch+"/"+op+"/"+form, func(t *testing.T) {
					body := "MOVSD a+0(FP),X0\nMOVSD c+16(FP),X1\n"
					for offset := -32; offset < -16; offset += 4 {
						body += fmt.Sprintf("MOVL $%d,value%d(SP)\n", offset*71, offset)
					}
					source := "X1"
					switch form {
					case "alias":
						source = "X0"
					case "FP":
						source = "a+0(FP)"
					case "AUTO":
						source = "value-32(SP)"
					}
					body += op + " " + source + ",X0\nMOVSD X0,ret0+32(FP)\nRET"
					file, sig, assembly := x86ResultAUTOFixture(t, arch, "func Value(a,b,c,d uint64) uint64", 64, body)
					goAssemblerOracleOutput(t, arch, assembly, "", true)
					if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, arch); err != nil {
						t.Fatalf("accepted complete legacy arithmetic lacks byte effects: %v\n%s", err, assembly)
					}
				})
			}
		}
	}
}

func TestX86LegacyIntegerArithmeticCompleteOriginalGoRows(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, op := range x86LegacyIntegerArithmeticTestNames {
			forms := []string{"X0,X7", "X0,X0", "(AX),X1", "8(AX)(CX*4),X1", "a+0(FP),X1", "value-32(SP),X1", "·data(SB),X1", "(FS),X1", "(GS),X1"}
			if arch == "amd64" {
				forms = append(forms, "X15,X0", "X0,X15")
				if strings.HasPrefix(op, "PADD") && op != "PADDQ" {
					forms = append(forms, "M0,M7", "(AX),M7", "a+0(FP),M7", "value-32(SP),M7", "·data(SB),M7")
					for _, reg := range []string{"AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI", "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"} {
						forms = append(forms, reg+",M7")
					}
				}
			}
			for _, operands := range forms {
				t.Run(arch+"/accept/"+op+" "+operands, func(t *testing.T) {
					goAssemblerOracleOutput(t, arch, "TEXT ·Value(SB),4,$64-64\n"+op+" "+operands+"\nRET\n", "", true)
				})
			}
			for _, operands := range []string{"$1,X0", "X0,(AX)", "X0,Y1", "Y0,Y1", "Z0,Z1", "X16,X0", "(AX),(BX)", "X0,K1,X1", "X0,M1", "M0,X1"} {
				t.Run(arch+"/reject/"+op+" "+operands, func(t *testing.T) {
					goAssemblerOracleOutput(t, arch, "TEXT ·Value(SB),4,$0-0\n"+op+" "+operands+"\nRET\n", "", false)
				})
			}
			if arch == "386" || op == "PADDQ" || strings.HasPrefix(op, "PSUB") {
				t.Run(arch+"/reject/"+op+" M0,M1", func(t *testing.T) {
					goAssemblerOracleOutput(t, arch, "TEXT ·Value(SB),4,$0-0\n"+op+" M0,M1\nRET\n", "", false)
				})
			}
		}
	}
	data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src", "cmd", "internal", "obj", "x86", "asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	rows := regexp.MustCompile(`\{(APADD\w+|APSUB\w+), (ymm|yxm),`).FindAllStringSubmatch(string(data), -1)
	var inventory []string
	for _, row := range rows {
		inventory = append(inventory, row[1]+":"+row[2])
	}
	if got := strings.Join(inventory, ","); got != "APADDB:ymm,APADDL:ymm,APADDQ:yxm,APADDSB:ymm,APADDSW:ymm,APADDUSB:ymm,APADDUSW:ymm,APADDW:ymm,APSUBB:yxm,APSUBL:yxm,APSUBQ:yxm,APSUBSB:yxm,APSUBSW:yxm,APSUBUSB:yxm,APSUBUSW:yxm,APSUBW:yxm" {
		t.Fatal("complete SDK legacy add/sub table changed", got)
	}
	for table, expected := range map[string]string{
		"ymm": "Zm_r_xm:1:Ymm, Ymr;Zm_r_xm:2:Yxm, Yxr",
		"yxm": "Zm_r_xm:1:Yxm, Yxr",
	} {
		body := regexp.MustCompile(`(?s)var ` + table + ` = \[\]ytab\{(.*?)\n\}`).FindStringSubmatch(string(data))
		if len(body) != 2 {
			t.Fatal("missing complete SDK operand table", table)
		}
		var actual []string
		for _, row := range regexp.MustCompile(`\{(\w+), (\d+), argList\{([^}]+)\}\}`).FindAllStringSubmatch(body[1], -1) {
			actual = append(actual, row[1]+":"+row[2]+":"+row[3])
		}
		if strings.Join(actual, ";") != expected {
			t.Fatal("complete SDK operand rows changed", table, actual)
		}
	}
	for _, class := range []string{"Yax", "Ycx", "Yrx", "Yrl", "Yrl32", "Ym", "Ymr"} {
		if !strings.Contains(string(data), "ycover["+class+"*Ymax+Ymm] = 1") {
			t.Fatal("Go physical MMX compatibility class changed", class)
		}
	}
	aliases, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src", "cmd", "asm", "internal", "arch", "arch.go"))
	if err != nil || !strings.Contains(string(aliases), `instructions["PADDD"] = x86.APADDL`) {
		t.Fatal("actual Go PADDD alias changed", err)
	}
}
