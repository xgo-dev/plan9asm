package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

var x86ResultGPSIMDConsumers = []struct {
	name string
	step func(Instr, *x86ResultState, []bool, int64, string) bool
}{
	{"public", x86ResultTransfer},
	{"private", x86ScalarFPResultTransfer},
}

// Enumerate independent register axes, not the implementation's spec map.
// SP and AMD64 BP retain their separate frame roles. Mode32 BP is an
// ordinary GP; numerical availability still requires actual defined bytes.
func x86ResultGPSIMDRegisterRows(arch string) []string {
	gps := []string{"AX", "CX", "DX", "BX", "SI", "DI"}
	if arch == "amd64" {
		gps = append(gps, "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15")
	} else {
		gps = append(gps, "BP")
	}
	var rows []string
	seen := make(map[string]bool)
	add := func(op, source, destination string) {
		row := op + " " + source + "," + destination
		if !seen[row] {
			rows = append(rows, row)
			seen[row] = true
		}
	}
	for _, op := range []string{"MOVL", "MOVQ", "MOVD", "VMOVD", "VMOVQ"} {
		legacy := !strings.HasPrefix(op, "V")
		gpLegal := arch != "386" || !legacy || op == "MOVL"
		if gpLegal {
			for _, gp := range gps {
				add(op, gp, "X0")
				add(op, "X0", gp)
			}
		}
		limit := 8
		if arch == "amd64" {
			limit = 16
			if !legacy {
				limit = 32
			}
		}
		for index := 0; index < limit; index++ {
			x := fmt.Sprint("X", index)
			if gpLegal {
				add(op, "AX", x)
				add(op, x, "AX")
			}
			if op == "MOVQ" || op == "MOVD" || op == "VMOVQ" {
				add(op, x, x)
				add(op, x, fmt.Sprint("X", (index+1)%limit))
			}
		}
	}
	return rows
}

func TestX86ResultGPSIMDRegisterCompleteGoAxes(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		rows := x86ResultGPSIMDRegisterRows(arch)
		goAssemblerOracleOutput(t, arch, "TEXT f(SB),4,$0-0\n"+strings.Join(rows, "\n")+"\nRET\n", "", true)
		for _, row := range rows {
			t.Run(arch+"/"+row, func(t *testing.T) {
				ins := x86YMMReadSource(t, row)
				before := fmt.Sprintf("%#v", ins)
				for _, consumer := range x86ResultGPSIMDConsumers {
					state := x86ResultState{flags: x86ByteFlagsAll}
					for index := range state.gp {
						state.gp[index] = 0xff
					}
					for index := range state.xmm {
						state.xmm[index] = 0xffff
					}
					if !consumer.step(ins, &state, nil, 0, arch) {
						t.Errorf("%s omitted a Go-accepted numerical register effect", consumer.name)
					}
				}
				if before != fmt.Sprintf("%#v", ins) {
					t.Fatal("result observer mutated original source metadata")
				}
			})
		}
	}
}

func TestX86ResultGPSIMDRegisterIndependentEncoderRows(t *testing.T) {
	// This existing independent oracle pins all 12 AVX rows: full prefix,
	// zcase, row offset/advance, complete opcode bytes, W and tuple attributes.
	rows := x86OfficialGPSIMDTransferRows(t)
	for _, op := range []string{"MOVL", "MOVQ", "MOVD"} {
		rows = append(rows, op+" AX,X0", op+" X0,AX")
		if op != "MOVL" {
			rows = append(rows, op+" X0,X1")
		}
	}
	if len(rows) != 20 {
		t.Fatalf("independent encoder witness denominator: %d, want 20", len(rows))
	}
	goAssemblerOracleOutput(t, "amd64", "TEXT f(SB),4,$0-0\n"+strings.Join(rows, "\n")+"\nRET\n", "", true)
	for _, row := range rows {
		t.Run(row, func(t *testing.T) {
			ins := x86YMMReadSource(t, row)
			for _, consumer := range x86ResultGPSIMDConsumers {
				state := x86ResultState{}
				state.gp[0], state.xmm[0], state.xmm[17] = 0xff, 0xffff, 0xffff
				if !consumer.step(ins, &state, nil, 0, "amd64") {
					t.Errorf("%s lacks independent original-row effect", consumer.name)
				}
			}
		})
	}
}

func TestX86ResultGPSIMDRegisterEveryInputByteAndOverwrite(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, op := range []string{"MOVL", "MOVQ", "MOVD", "MOVDQ2Q", "VMOVD", "VMOVQ"} {
			qword := op == "MOVQ" || op == "MOVD" || op == "MOVDQ2Q" || op == "VMOVQ"
			for _, direction := range []string{"gp-to-x", "x-to-gp", "x-to-x", "self"} {
				gp := direction == "gp-to-x" || direction == "x-to-gp"
				if !qword && !gp || arch == "386" && gp && qword && !strings.HasPrefix(op, "V") {
					continue
				}
				width, row := 4, op+" AX,X1"
				if qword {
					width = 8
				}
				if arch == "386" && gp {
					width = 4 // VEX.W is ignored for mode32 GP operands only.
				}
				switch direction {
				case "x-to-gp":
					row = op + " X0,BX"
				case "x-to-x":
					row = op + " X0,X1"
				case "self":
					row = op + " X0,X0"
				}
				t.Run(arch+"/"+op+"/"+direction, func(t *testing.T) {
					ins := x86YMMReadSource(t, row)
					for missing := -1; missing < 16; missing++ {
						initial := x86ResultState{flags: x86ByteFlagsAll}
						initial.gp[0], initial.xmm[0], initial.xmm[1] = 0xff, 0xffff, 0x5151
						initial.pointerGP[3], initial.callerAddressGP[3] = true, true
						initial.canonicalGP[3] = 0xff
						if missing >= 0 {
							if direction == "gp-to-x" {
								initial.gp[0] &^= uint8(1) << uint(missing)
							} else {
								initial.xmm[0] &^= uint16(1) << uint(missing)
							}
						}
						want := initial.clone()
						mask := uint16(1)<<uint(width) - 1
						known := initial.xmm[0] & mask
						if direction == "gp-to-x" {
							known = uint16(initial.gp[0]) & mask
						}
						switch direction {
						case "gp-to-x", "x-to-x":
							want.xmm[1] = known | 0xffff&^mask
							if strings.HasPrefix(op, "V") {
								want.vectorUpper[1] = ^uint64(0xffff)
							}
						case "self":
							want.xmm[0] = known | 0xffff&^mask
							if strings.HasPrefix(op, "V") {
								want.vectorUpper[0] = ^uint64(0xffff)
							}
						case "x-to-gp":
							want.gp[3] = uint8(known) | ^uint8(mask)
							want.pointerGP[3], want.callerAddressGP[3], want.canonicalGP[3] = false, false, 0
						}
						for _, consumer := range x86ResultGPSIMDConsumers {
							state := initial.clone()
							if got := consumer.step(ins, &state, nil, 0, arch); !got || !reflect.DeepEqual(state, want) {
								t.Fatalf("%s missing byte %d: accepted=%t, state=%#v want=%#v", consumer.name, missing, got, state, want)
							}
						}
					}
				})
			}
		}
	}
}

func TestX86ResultGPSIMDRegisterAllPathsAndAuthorityBoundaries(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		move, word := "MOVQ", 8
		if arch == "386" {
			move, word = "MOVL", 4
		}
		finish := fmt.Sprintf("PEXTRD $0,X0,BX\nMOVL BX,ret0+%d(FP)\nRET", word)
		for name, test := range map[string]struct {
			body string
			pass bool
		}{
			"defined input":                  {"MOVL n+0(FP),AX\nMOVL AX,X0\n" + finish, true},
			"both branches":                  {"MOVL n+0(FP),AX\nCMPL AX,$0\nJE other\nMOVL AX,X0\nJMP done\nother:\nVMOVD AX,X0\ndone:\n" + finish, true},
			"unknown GP":                     {"MOVL AX,X0\n" + finish, false},
			"partial GP":                     {"MOVW $7,AX\nMOVL AX,X0\n" + finish, false},
			"one branch only":                {"MOVL n+0(FP),AX\nCMPL AX,$0\nJE done\nMOVL AX,X0\ndone:\n" + finish, false},
			"unknown branch overwrite":       {"MOVL n+0(FP),AX\nMOVL AX,X0\nCMPL AX,$0\nJE done\nMOVL CX,X0\ndone:\n" + finish, false},
			"pointee is not numeric":         {move + " p+0(FP),AX\nMOVL (AX),CX\nMOVL CX,X0\n" + finish, false},
			"opaque identity is not numeric": {move + " p+0(FP),AX\nMOVL AX,X0\n" + finish, false},
			"opaque VEX identity":            {move + " p+0(FP),AX\nVMOVQ AX,X0\n" + finish, false},
			"SP role":                        {"MOVL SP,X0\n" + finish, false},
			"BP role":                        {"MOVL BP,X0\n" + finish, false},
		} {
			t.Run(arch+"/"+name, func(t *testing.T) {
				declaration := "func Value(n uint32) uint32"
				if strings.HasPrefix(name, "opaque") || strings.HasPrefix(name, "pointee") {
					declaration = "func Value(p *byte) uint32"
				}
				_, file, sig, source := x86ResultInitializationFixture(t, arch, declaration, test.body)
				goAssemblerOracleOutput(t, arch, source, "", true)
				for _, check := range []func(Func, FuncSig, string) error{CheckX86ABI0ResultInitialization, checkX86ScalarFPResultInitialization} {
					err := check(file.Funcs[0], sig, arch)
					if test.pass && err != nil || !test.pass && !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatalf("all-path numerical proof changed authority: pass=%t error=%v", test.pass, err)
					}
				}
			})
		}
	}
}

// Retain the original failing public-consumer sequence, including the opaque
// MOVD import, rather than substituting PINSRD for its GP-to-X MOVL effect.
func TestX86ResultGPSIMDRegisterOriginalOpaqueAliasWitness(t *testing.T) {
	for _, register := range []string{"AX", "CX", "DX", "BX", "SI", "DI", "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"} {
		t.Run(register, func(t *testing.T) {
			body := fmt.Sprintf("MOVD x+0(FP),%s\nMOVD %s,SI\nMOVL $42,DX\nMOVL DX,X0\nPEXTRD $0,X0,BX\nMOVL BX,ret0+8(FP)\nRET", register, register)
			_, file, sig, source := x86ResultInitializationFixture(t, "amd64", "func Value(x *byte) uint32", body)
			goAssemblerOracleOutput(t, "amd64", source, "", true)
			for _, check := range []func(Func, FuncSig, string) error{CheckX86ABI0ResultInitialization, checkX86ScalarFPResultInitialization} {
				if err := check(file.Funcs[0], sig, "amd64"); err != nil {
					t.Fatal("original GP/X witness still lacks complete numerical result effect", err)
				}
			}
		})
	}
}

func TestX86ResultGPSIMDRegisterDoesNotAdoptPrivateMemoryRoles(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		word := x86ResultPointerWord(arch)
		for name, body := range map[string]string{
			"logical FP load": fmt.Sprintf("MOVL x+0(FP),X0\nPEXTRD $0,X0,AX\nMOVL AX,ret0+%d(FP)\nRET", word),
			"static SB store": fmt.Sprintf("MOVL x+0(FP),AX\nMOVL AX,X0\nMOVL X0,table(SB)\nMOVL AX,ret0+%d(FP)\nRET", word),
		} {
			t.Run(arch+"/"+name, func(t *testing.T) {
				_, file, sig, source := x86ResultInitializationFixture(t, arch, "func Value(x uint32) uint32", body)
				goAssemblerOracleOutput(t, arch, source, "", true)
				if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, arch); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("public register consumer acquired a private memory role", err)
				}
				if err := checkX86ScalarFPResultInitialization(file.Funcs[0], sig, arch); err != nil {
					t.Fatal("existing private memory effect changed", err)
				}
			})
		}
	}
}

func TestX86ResultGPSIMDRegisterThreeAPIFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		for _, op := range []string{"MOVL", "MOVQ", "MOVD", "VMOVD", "VMOVQ"} {
			if target.arch == "386" && (op == "MOVQ" || op == "MOVD") {
				continue // Those GP/X forms are rejected by Go, not a skipped test.
			}
			t.Run(target.triple+"/"+op, func(t *testing.T) {
				word, move, typ := 8, "MOVL", "uint32"
				if target.arch == "386" {
					word = 4
				} else if op == "MOVQ" || op == "MOVD" || op == "VMOVQ" {
					move, typ = "MOVQ", "uint64"
				}
				source := fmt.Sprintf("TEXT ·view(SB),4,$0-%d\n%s x+0(FP),AX\n%s AX,X0\nMOVQ X0,X1\n%s X1,BX\n%s BX,ret+%d(FP)\nRET\n", 2*word, move, op, op, move, word)
				_, file, sig, _ := x86ResultInitializationFixture(t, target.arch, "func Value(x "+typ+") "+typ,
					fmt.Sprintf("%s x+0(FP),AX\n%s AX,X0\nMOVQ X0,X1\n%s X1,BX\n%s BX,ret0+%d(FP)\nRET", move, op, op, move, word))
				x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
				if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, target.arch); err != nil {
					t.Fatal(err)
				}
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(api, func(t *testing.T) {
						ir, err := x86ScalarFPBitViewAPI(t, source, "func view(x "+typ+") "+typ+"\n", target.arch, target.triple, api)
						if err != nil {
							t.Fatal(err)
						}
						compileLLVMToObject(t, llc, target.triple, "result-gp-x.ll", "result-gp-x.o", ir)
					})
				}
			})
		}
	}
}
