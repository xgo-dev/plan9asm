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

// This directory is the complete whole-128-bit legacy subset of yxmov,
// including MOVOA. The same ytab also serves distinct scalar/half moves; the
// table inventory below retains those names without borrowing their effects.
var x86LegacyPackedMoveTestNames = []string{"MOVOU", "MOVOA", "MOVO", "MOVUPS", "MOVAPS", "MOVUPD", "MOVAPD"}

func TestX86ABI0ResultLegacyPackedMoveCompleteDeclaredBytes(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, op := range x86LegacyPackedMoveTestNames {
			for _, form := range []string{"register", "alias", "FP", "AUTO load", "AUTO store"} {
				t.Run(arch+"/"+op+"/"+form, func(t *testing.T) {
					body := "MOVSD a+0(FP),X0\nMOVSD c+16(FP),X1\n"
					for offset := -32; offset < -16; offset += 4 {
						body += fmt.Sprintf("MOVL $%d,value%d(SP)\n", offset*71, offset)
					}
					switch form {
					case "register":
						body += op + " X1,X0\n"
					case "alias":
						body += op + " X0,X0\n"
					case "FP":
						body += op + " a+0(FP),X0\n"
					case "AUTO load":
						body += op + " value-32(SP),X0\n"
					case "AUTO store":
						body += op + " X0,value-32(SP)\nMOVSD value-32(SP),X0\n"
					}
					body += "MOVSD X0,ret0+32(FP)\nRET"
					file, sig, source := x86ResultAUTOFixture(t, arch, "func Value(a,b,c,d uint64) uint64", 64, body)
					goAssemblerOracleOutput(t, arch, source, "", true)
					if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, arch); err != nil {
						t.Fatalf("complete Go legacy-move effect is missing: %v\n%s", err, source)
					}
				})
			}
		}
	}
}

func TestX86LegacyPackedMoveCompleteActualGoRows(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, op := range x86LegacyPackedMoveTestNames {
			for _, operands := range []string{
				"X0,X1", "(AX),X1", "8(AX)(CX*4),X1", "a+0(FP),X1", "value-32(SP),X1", "·data(SB),X1",
				"X0,(AX)", "X0,8(AX)(CX*4)", "X0,a+0(FP)", "X0,value-32(SP)", "X0,·data(SB)",
			} {
				instruction := op + " " + operands
				t.Run(arch+"/"+instruction, func(t *testing.T) {
					goAssemblerOracleOutput(t, arch, "TEXT ·Value(SB),4,$64-64\n"+instruction+"\nRET\n", "", true)
				})
			}
		}
	}
	for _, arch := range []string{"amd64", "386"} {
		for _, op := range x86LegacyPackedMoveTestNames {
			for _, operands := range []string{"M0,M1", "AX,X0", "X0,AX", "$1,X0", "Y0,Y1", "Z0,Z1", "X16,X0", "(AX),(BX)", "X0,K1,X1"} {
				t.Run(arch+"/reject/"+op+" "+operands, func(t *testing.T) {
					goAssemblerOracleOutput(t, arch, "TEXT ·Value(SB),4,$0-0\n"+op+" "+operands+"\nRET\n", "", false)
				})
			}
		}
	}
	data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src", "cmd", "internal", "obj", "x86", "asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	rows := regexp.MustCompile(`\{(AMOV\w+), yxmov,`).FindAllStringSubmatch(string(data), -1)
	var names []string
	for _, row := range rows {
		names = append(names, row[1])
	}
	if strings.Join(names, ",") != "AMOVAPD,AMOVAPS,AMOVO,AMOVOU,AMOVHPD,AMOVHPS,AMOVLPD,AMOVLPS,AMOVSD,AMOVSS,AMOVUPD,AMOVUPS" {
		t.Fatalf("complete current SDK yxmov rows changed: %v", names)
	}
	for _, row := range []string{"{Zm_r_xm, 1, argList{Yxm, Yxr}}", "{Zr_m_xm, 1, argList{Yxr, Yxm}}"} {
		if !strings.Contains(string(data), row) {
			t.Fatal("actual Go legacy packed-move operand row disappeared", row)
		}
	}
	aliases, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src", "cmd", "asm", "internal", "arch", "arch.go"))
	if err != nil || !strings.Contains(string(aliases), `instructions["MOVOA"] = x86.AMOVO`) {
		t.Fatalf("actual Go MOVOA alias changed: %v", err)
	}
}

func TestX86ABI0ResultLegacyPackedMoveDoesNotBorrowPermission(t *testing.T) {
	for _, op := range x86LegacyPackedMoveTestNames {
		for name, body := range map[string]string{
			"unknown vector":       op + " X1,X0\nMOVSD X0,ret0+0(FP)\nRET",
			"unknown upper vector": "MOVSS X1,X0\n" + op + " X0,value-32(SP)\nMOVSD value-32(SP),X0\nMOVSD X0,ret0+0(FP)\nRET",
			"unknown AUTO":         "MOVL $1,value-32(SP)\n" + op + " value-32(SP),X0\nMOVSD X0,ret0+0(FP)\nRET",
			"native pointer":       op + " (AX),X0\nMOVSD X0,ret0+0(FP)\nRET",
			"native store":         "MOVSD $1.0,X0\n" + op + " X0,(AX)\nMOVSD X0,ret0+0(FP)\nRET",
			"FP gap":               op + " a+0(FP),X0\nMOVSD X0,ret0+8(FP)\nRET",
			"result overstore":     "MOVSD $1.0,X0\n" + op + " X0,ret0+0(FP)\nRET",
			"AUTO extent":          "MOVSD $1.0,X0\n" + op + " X0,value-8(SP)\nMOVSD X0,ret0+0(FP)\nRET",
		} {
			t.Run(op+"/"+name, func(t *testing.T) {
				decl := "func Value() uint64"
				if name == "FP gap" {
					decl = "func Value(a uint32) uint64"
				}
				file, sig, _ := x86ResultAUTOFixture(t, "amd64", decl, 64, body)
				if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, "amd64"); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("legacy move borrowed unknown bytes/backing: %v", err)
				}
			})
		}
	}
}

func TestX86ABI0ResultLegacyPackedMovePartialBytesAndJoinedPaths(t *testing.T) {
	for _, op := range x86LegacyPackedMoveTestNames {
		ins := Instr{Op: Op(op), Args: []Operand{{Kind: OpReg, Reg: "X1"}, {Kind: OpReg, Reg: "X0"}}}
		for missing := 0; missing < 16; missing++ {
			t.Run(fmt.Sprintf("%s/missing%d", op, missing), func(t *testing.T) {
				state := x86ResultState{flags: x86ByteFlagsAll}
				state.xmm[1] = 0xffff &^ (uint16(1) << uint(missing))
				if x86ResultTransfer(ins, &state, nil, 0, "amd64") {
					t.Fatal("one missing source byte was fabricated by an old destination")
				}
				state.xmm[1] = 0xffff
				if !x86ResultTransfer(ins, &state, nil, 0, "amd64") || state.xmm[0] != 0xffff || state.flags != x86ByteFlagsAll {
					t.Fatal("full overwrite read the old destination or changed flags")
				}
			})
		}
		body := "MOVSS a+0(FP),X1\nMOVL $1,AX\nCMPL AX,$0\nJE partial\n" + op + " X1,X0\nJMP joined\npartial:\nMOVSS X1,X0\njoined:\n" + op + " X0,value-32(SP)\nMOVSD value-32(SP),X0\nMOVSD X0,ret0+8(FP)\nRET"
		file, sig, _ := x86ResultAUTOFixture(t, "amd64", "func Value(a uint32) uint64", 64, body)
		if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, "amd64"); !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("mixed full/partial vector paths became initialized", op, err)
		}
	}
}
