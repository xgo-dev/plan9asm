package plan9asm

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func TestX86ScalarShiftOriginalPhysicalByteWitnesses(t *testing.T) {
	for _, test := range []struct {
		arch, row string
		code      []byte
	}{
		{"amd64", "SHRQ $5,R8", []byte{0x49, 0xc1, 0xe8, 5}},
		{"amd64", "SHLL $0,AX", []byte{0xc1, 0xe0, 0}},
		{"amd64", "RCLL $0,AX", []byte{0xc1, 0xd0, 0}},
		{"amd64", "SHLB $1,AH", []byte{0xd0, 0xe4}},
		{"amd64", "SHLB CX,AH", []byte{0xd2, 0xe4}},
		{"amd64", "SHLW $16,BX,AX", []byte{0x66, 0x0f, 0xa4, 0xd8, 16}},
		{"amd64", "SHRW $16,BX,AX", []byte{0x66, 0x0f, 0xac, 0xd8, 16}},
		{"386", "SHLL $0,AX", []byte{0xc1, 0xe0, 0}},
		{"386", "SHLW CL,BX,AX", []byte{0x66, 0x0f, 0xa5, 0xd8}},
	} {
		t.Run(test.arch+"/"+test.row, func(t *testing.T) {
			code := assembleX87ControlBytes(t, test.arch, "TEXT f(SB),4,$0-0\n"+test.row+"\nRET\n")
			if !bytes.Equal(code, append(append([]byte(nil), test.code...), 0xc3)) {
				t.Fatalf("actual Go bytes%x want%x", code, test.code)
			}
			decoded, err := decodeX86RawDirectives(rawX86Function(test.code), test.arch)
			if err != nil || len(decoded.Instrs) != 1 {
				t.Fatalf("actual source byte decoder %v %+v", err, decoded)
			}
			ins := decoded.Instrs[0]
			// A CL count and a W double-shift variable count still have their
			// numerical obligations; decoding does not grant initialized bytes.
			undefined := test.arch == "386" && test.row == "SHLW CL,BX,AX"
			for _, consumer := range x86ResultGPSIMDConsumers {
				state := x86ResultState{flags: x86ByteFlagsAll}
				for index := range state.gp {
					state.gp[index] = 0xff
				}
				if got := consumer.step(ins, &state, nil, 0, test.arch); got == undefined {
					t.Fatalf("%s physical source accepted%t undefined%t", consumer.name, got, undefined)
				}
			}
		})
	}
}

func TestX86ScalarShiftThreeAPIFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			word, move, typ, widths := 8, "MOVQ", "uint64", []string{"B", "W", "L", "Q"}
			if target.arch == "386" {
				word, move, typ, widths = 4, "MOVL", "uint32", widths[:3]
			}
			for _, raw := range []bool{false, true} {
				t.Run(fmt.Sprintf("raw=%t", raw), func(t *testing.T) {
					var body strings.Builder
					fmt.Fprintf(&body, "%s x+0(FP),AX\n%s y+%d(FP),BX\n%s count+%d(FP),CX\n", move, move, word, move, 2*word)
					emit := func(row string) {
						fmt.Fprintf(&body, "CMP%s AX,BX\n", map[string]string{"amd64": "Q", "386": "L"}[target.arch])
						if !raw {
							body.WriteString(row + "\n")
							return
						}
						code := assembleX87ControlBytes(t, target.arch, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
						if len(code) == 0 || code[len(code)-1] != 0xc3 {
							t.Fatal("original instruction object lacks RET")
						}
						for _, b := range code[:len(code)-1] {
							fmt.Fprintf(&body, "BYTE $%#x\n", b)
						}
					}
					for _, stem := range x86ScalarShiftTestStems {
						for _, width := range widths {
							for _, count := range []string{"$0", "$1", "$255", "CL", "CX"} {
								emit(stem + width + " " + count + ",AX")
							}
							if width == "B" {
								emit(stem + width + " $1,AH")
							}
						}
					}
					for _, stem := range []string{"SHL", "SHR"} {
						for _, width := range widths[1:] {
							counts := []string{"$0", "$1", "$16", "CL", "CX"}
							if width == "W" {
								counts = counts[:3]
							}
							for _, count := range counts {
								emit(stem + width + " " + count + ",BX,AX")
							}
						}
					}
					for _, op := range []string{"SARXL", "SARXQ", "SHLXL", "SHLXQ", "SHRXL", "SHRXQ", "RORXL", "RORXQ"} {
						if strings.HasPrefix(op, "RORX") {
							emit(op + " $-128,BX,AX")
						} else {
							emit(op + " CX,BX,AX")
						}
					}
					fmt.Fprintf(&body, "%s AX,X0\nVPEXTRQ $0,X0,BX\n%s BX,ret0+%d(FP)\nRET", move, move, 3*word)
					pkg, file, sig, source := x86ResultInitializationFixture(t, target.arch, "func Value(x,y,count "+typ+") "+typ, body.String())
					goAssemblerOracleOutput(t, target.arch, source, "", true)
					// Named source is checked directly. Raw APIs independently
					// consume the complete original object bytes before checking.
					if !raw {
						for _, check := range []func(Func, FuncSig, string) error{CheckX86ABI0ResultInitialization, checkX86ScalarFPResultInitialization} {
							if err := check(file.Funcs[0], sig, target.arch); err != nil {
								t.Fatal(err)
							}
						}
					}
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(api, func(t *testing.T) {
							ir, err := x86ResultSwapTranslateAPI(t, api, source, pkg, target.arch, target.triple)
							if err != nil {
								t.Fatal(err)
							}
							x86ResultInitializationObject(t, llc, target.triple, ir, "scalar-shift-"+api)
						})
					}
				})
			}
		})
	}
}
