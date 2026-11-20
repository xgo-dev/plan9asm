package plan9asm

import (
	"errors"
	"fmt"
	"go/types"
	"reflect"
	"strings"
	"testing"
)

func TestX86ResultGPSIMDSparseByteBroadcastThreeAPIs(t *testing.T) {
	for _, target := range []struct{ arch, triple, move string }{
		{"amd64", "x86_64-unknown-linux-gnu", "MOVD"},
		{"386", "i386-unknown-linux-gnu", "MOVL"},
	} {
		t.Run(target.arch, func(t *testing.T) {
			declaration := "func view(c byte) uint32\n"
			pkg := mustGoPackage(t, "bitview", "package bitview\n"+declaration)
			sig, err := DeriveGoFuncABI0Signature("view", pkg.Types.Scope().Lookup("view").(*types.Func), target.arch, types.SizesFor("gc", target.arch))
			if err != nil {
				t.Fatal(err)
			}
			result := int64(8)
			if target.arch == "386" {
				result = 4
			}
			if len(sig.Frame.Params) != 1 || sig.Frame.Params[0].Offset != 0 || sig.Frame.Params[0].Type != I8 ||
				len(sig.Frame.Results) != 1 || sig.Frame.Results[0].Offset != result || sig.Frame.Results[0].Type != I32 {
				t.Fatalf("fixture disagrees with actual typed ABI0 layout: %#v", sig.Frame)
			}
			source := fmt.Sprintf("TEXT ·view(SB),4,$0-%d\nMOVB c+0(FP),AX\n%s AX,X0\nPUNPCKLBW X0,X0\nPUNPCKLBW X0,X0\nPSHUFL $0,X0,X0\nPEXTRD $0,X0,AX\nMOVL AX,ret+%d(FP)\nRET\n", result+4, target.move, result)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					if ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, api); err != nil || ir == "" {
						t.Fatalf("known byte broadcast requires unused unknown GP bytes: %v", err)
					}
				})
			}
		})
	}
}

func TestX86ResultGPSIMDSparseKnownByteMasksAndAliases(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, op := range []string{"MOVL", "MOVQ", "MOVD", "MOVDQ2Q", "VMOVD", "VMOVQ"} {
			qword := op == "MOVQ" || op == "MOVD" || op == "MOVDQ2Q" || op == "VMOVQ"
			for _, direction := range []string{"gp-to-x", "x-to-gp", "x-to-x", "self"} {
				gp := direction == "gp-to-x" || direction == "x-to-gp"
				if !qword && !gp || arch == "386" && gp && qword && !strings.HasPrefix(op, "V") {
					continue // Not part of the typed Go GP/X register grammar.
				}
				width, row := 4, op+" AX,X1"
				if qword && !(arch == "386" && gp) {
					width = 8
				}
				switch direction {
				case "x-to-gp":
					row = op + " X0,BX"
				case "x-to-x":
					row = op + " X0,X1"
				case "self":
					row = op + " X0,X0"
				}
				t.Run(arch+"/"+row, func(t *testing.T) {
					ins := x86ScalarLaneInstruction(t, row)
					original := fmt.Sprintf("%#v", ins)
					for seed := 0; seed < 256; seed++ {
						initial := x86ResultState{flags: x86ByteFlagsAll}
						initial.gp[0], initial.gp[3] = uint8(seed), 0xff
						initial.pointerGP[3], initial.callerAddressGP[3], initial.canonicalGP[3] = true, true, 0xff
						initial.xmm[0], initial.xmm[1] = 0x9b00|uint16(seed), 0x7531
						initial.vectorUpper[0], initial.vectorUpper[1] = 0x5837bba945de0000, 0x7346edab91250000
						initial.masks[1] = true
						want := initial.clone()
						// Independent per-byte oracle: source bytes below the width
						// retain exactly their original knowledge. Only the bytes
						// outside the transfer width are cleared by the instruction.
						var vector uint16
						var gpBytes uint8
						for index := 0; index < 16; index++ {
							if index >= width || seed&(1<<uint(index)) != 0 {
								vector |= 1 << uint(index)
								if index < 8 {
									gpBytes |= 1 << uint(index)
								}
							}
						}
						if direction == "x-to-gp" {
							want.gp[3] = gpBytes
							want.pointerGP[3], want.callerAddressGP[3], want.canonicalGP[3] = false, false, 0
						} else {
							destination := 1
							if direction == "self" {
								destination = 0
							}
							want.xmm[destination] = vector
							if strings.HasPrefix(op, "V") {
								want.vectorUpper[destination] = ^uint64(0xffff)
							}
						}
						for _, consumer := range x86ResultGPSIMDConsumers {
							state := initial.clone()
							if !consumer.step(ins, &state, nil, 0, arch) || !reflect.DeepEqual(state, want) {
								t.Fatalf("%s seed=%02x: got=%#v want=%#v", consumer.name, seed, state, want)
							}
						}
						if fmt.Sprintf("%#v", ins) != original {
							t.Fatal("numerical propagation changed original source metadata")
						}
					}
				})
			}
		}
	}
}

func TestX86ResultGPSIMDSparseGoAliasesFiveTargets(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, op := range []string{"MOVL", "MOVQ", "MOVD", "MOVDQ2Q", "VMOVD", "VMOVQ"} {
			if target.arch == "386" && (op == "MOVQ" || op == "MOVD" || op == "MOVDQ2Q") {
				continue // Those GP/X qword aliases have no mode32 Go row.
			}
			t.Run(target.triple+"/"+op, func(t *testing.T) {
				result := 8
				if target.arch == "386" {
					result = 4
				}
				source := fmt.Sprintf("TEXT ·view(SB),4,$0-%d\nMOVB c+0(FP),AX\n%s AX,X0\nPUNPCKLBW X0,X0\nPUNPCKLBW X0,X0\nPSHUFL $0,X0,X0\nPEXTRD $0,X0,AX\nMOVL AX,ret+%d(FP)\nRET\n", result+4, op, result)
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(api, func(t *testing.T) {
						if ir, err := x86ScalarFPBitViewAPI(t, source, "func view(c byte) uint32\n", target.arch, target.triple, api); err != nil || ir == "" {
							t.Fatal("typed alias lost sparse numerical dependencies", err)
						}
					})
				}
			})
		}
	}
}

func TestX86ResultGPSIMDSparseUnknownResultBytesThreeAPIs(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		move, pointerMove, word, triple := "MOVD", "MOVQ", 8, "x86_64-unknown-linux-gnu"
		if arch == "386" {
			move, pointerMove, word, triple = "MOVL", "MOVL", 4, "i386-unknown-linux-gnu"
		}
		prefix := "MOVB c+0(FP),AX\n" + move + " AX,X0\n"
		broadcast := "PUNPCKLBW X0,X0\nPUNPCKLBW X0,X0\nPSHUFL $0,X0,X0\n"
		finish := fmt.Sprintf("MOVL BX,ret+%d(FP)\nRET\n", word)
		for _, test := range []struct {
			name, body string
			pass       bool
		}{
			{"whole unknown dword", prefix + "PEXTRD $0,X0,BX\n" + finish, false},
			{"one interleave is insufficient", prefix + "PUNPCKLBW X0,X0\nPEXTRD $0,X0,BX\n" + finish, false},
			{"selector needs next unknown byte", prefix + "PUNPCKLBW X0,X0\nPUNPCKLBW X0,X0\nPSHUFL $0x55,X0,X0\nPEXTRD $0,X0,BX\n" + finish, false},
			{"unknown GP overwrites broadcast", prefix + broadcast + move + " CX,X0\nPEXTRD $0,X0,BX\n" + finish, false},
			// The existing lane probe activates the whole-function result
			// observer. This tests its transfer, not a new admission hook.
			{"unknown X overwrites GP", prefix + "PEXTRD $3,X0,DX\nMOVL $0,BX\nMOVL X0,BX\n" + finish, false},
			{"one path overwrites known input", prefix + "CMPB AX,$0\nJE done\n" + move + " CX,X0\ndone:\n" + broadcast + "PEXTRD $0,X0,BX\n" + finish, false},
			{"known X old value is discarded", "PXOR X0,X0\n" + move + " AX,X0\nPEXTRD $0,X0,BX\n" + finish, false},
			{"guaranteed cleared X bytes", prefix + "PEXTRD $3,X0,BX\n" + finish, true},
			{"unknown numeric GP is discarded", move + " AX,X0\nPEXTRD $3,X0,BX\n" + finish, true},
			{"opaque pointer is not numeric", fmt.Sprintf("%s p+0(FP),AX\n%s AX,X0\nPEXTRD $3,X0,BX\n", pointerMove, move) + finish, false},
		} {
			t.Run(arch+"/"+test.name, func(t *testing.T) {
				declaration := "func view(c byte) uint32\n"
				if test.name == "opaque pointer is not numeric" {
					declaration = "func view(p *byte) uint32\n"
				}
				source := fmt.Sprintf("TEXT ·view(SB),4,$0-%d\n%s", word+4, test.body)
				pkg := mustGoPackage(t, "bitview", "package bitview\n"+declaration)
				sig, err := DeriveGoFuncABI0Signature("view", pkg.Types.Scope().Lookup("view").(*types.Func), arch, types.SizesFor("gc", arch))
				if err != nil {
					t.Fatal(err)
				}
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				for _, check := range []func(Func, FuncSig, string) error{CheckX86ABI0ResultInitialization, checkX86ScalarFPResultInitialization} {
					err := check(file.Funcs[0], sig, arch)
					if test.pass && err != nil || !test.pass && !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatalf("whole-function byte observer disagrees: pass=%t error=%v", test.pass, err)
					}
				}
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(api, func(t *testing.T) {
						ir, err := x86ScalarFPBitViewAPI(t, source, declaration, arch, triple, api)
						if test.pass {
							if err != nil || ir == "" {
								t.Fatal("discarded unknown numerical bytes became dependencies", err)
							}
						} else if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
							t.Fatalf("unknown bytes or opaque identity supplied result authority: ir=%q err=%v", ir, err)
						}
					})
				}
			})
		}
	}
}

func TestX86ResultGPSIMDSparseRejectsUnboundSourceRoles(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, test := range []struct {
			name, row       string
			pointer, caller bool
		}{
			{"opaque pointer", "MOVL AX,X1", true, false},
			{"caller address", "MOVL AX,X1", false, true},
			{"stack pointer", "MOVL SP,X1", false, false},
			{"frame pointer", "MOVL BP,X1", false, false},
			{"physical MMX", "MOVQ X0,M0", false, false},
			{"unknown FP store", "MOVL X0,ret+4(FP)", false, false},
			{"unknown SB store", "MOVL X0,table(SB)", false, false},
		} {
			t.Run(arch+"/"+test.name, func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, test.row)
				initial := x86ResultState{fp: make([]bool, 8), flags: x86ByteFlagsAll}
				initial.gp[0], initial.xmm[1], initial.canonicalGP[0] = 0xff, 0xffff, 0xff
				initial.pointerGP[0], initial.callerAddressGP[0] = test.pointer, test.caller
				owned := make([]bool, 8)
				for index := range owned {
					owned[index] = true
				}
				for _, consumer := range x86ResultGPSIMDConsumers {
					state := initial.clone()
					accepted := consumer.step(ins, &state, owned, 4, arch)
					if arch == "386" && test.row == "MOVL BP,X1" {
						// The ordinary register exists, but its low input bytes
						// are unknown. Only X's architectural high zeros follow.
						want := initial.clone()
						want.xmm[1] = 0xfff0
						if !accepted || !reflect.DeepEqual(state, want) {
							t.Fatal("unknown mode32 BP acquired numerical low bytes", consumer.name, state)
						}
						continue
					}
					if accepted || !reflect.DeepEqual(state, initial) {
						t.Fatalf("%s changed an unbound source role: got=%#v want=%#v", consumer.name, state, initial)
					}
				}
			})
		}
		for missing := 0; missing < 8; missing++ {
			t.Run(fmt.Sprintf("%s/full-memory-byte%d", arch, missing), func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, "MOVQ c+0(FP),X1")
				state := x86ResultState{fp: make([]bool, 8)}
				owned := make([]bool, 8)
				for index := range owned {
					owned[index], state.fp[index] = true, index != missing
				}
				before := state.clone()
				if x86ScalarFPResultTransfer(ins, &state, owned, 8, arch) || !reflect.DeepEqual(state, before) {
					t.Fatal("sparse register rule reduced the complete memory read extent")
				}
			})
		}
	}
}

func TestX86ResultGPSIMDSparseXToGPByteResultThreeAPIs(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		move, word, triple := "MOVD", 8, "x86_64-unknown-linux-gnu"
		if arch == "386" {
			move, word, triple = "MOVL", 4, "i386-unknown-linux-gnu"
		}
		for _, op := range []string{"MOVL", "MOVQ", "MOVD", "MOVDQ2Q", "VMOVD", "VMOVQ"} {
			if arch == "386" && (op == "MOVQ" || op == "MOVD" || op == "MOVDQ2Q") {
				continue
			}
			t.Run(arch+"/"+op, func(t *testing.T) {
				// Unknown X bytes are transported to GP unchanged. Only the
				// known low byte becomes the result. The independent extraction
				// of guaranteed-zero bytes activates the existing lane observer.
				source := fmt.Sprintf("TEXT ·view(SB),4,$0-%d\nMOVB c+0(FP),AX\n%s AX,X0\nPEXTRD $3,X0,DX\n%s X0,BX\nMOVB BX,ret+%d(FP)\nRET\n", word+1, move, op, word)
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(api, func(t *testing.T) {
						if ir, err := x86ScalarFPBitViewAPI(t, source, "func view(c byte) byte\n", arch, triple, api); err != nil || ir == "" {
							t.Fatal("discarded X-to-GP bytes became low-byte dependencies", err)
						}
					})
				}
			})
		}
	}
}

func TestX86ResultGPSIMDSparseOfficialRegisterFormats(t *testing.T) {
	rows := x86OfficialGPSIMDTransferRows(t)
	for _, op := range []string{"MOVL", "MOVQ", "MOVD", "MOVDQ2Q"} {
		rows = append(rows, op+" AX,X0", op+" X0,AX")
		if op != "MOVL" {
			rows = append(rows, op+" X0,X1")
		}
	}
	if len(rows) != 23 {
		t.Fatalf("complete GP/X register projection changed: %d, want 23", len(rows))
	}
	for _, row := range rows {
		t.Run(row, func(t *testing.T) {
			ins := x86ScalarLaneInstruction(t, row)
			form, known, err := x86GPSIMDTransferProperties(ins, "amd64")
			if !known || err != nil || form.memory != -1 || form.mmx {
				t.Fatal("original table's numerical register role lost", known, err)
			}
			width := 8
			if ins.Op == "MOVL" || ins.Op == "VMOVD" {
				width = 4
			}
			if form.bits != 8*width {
				t.Fatal("Go's typed source width changed", form.bits, width)
			}
			initial := x86ResultState{flags: x86ByteFlagsAll}
			for index := range initial.gp {
				initial.gp[index] = 0x05
			}
			for index := range initial.xmm {
				initial.xmm[index], initial.vectorUpper[index] = 0xff05, 0x497eb58a129c0000
			}
			want := initial.clone()
			var byteMask uint16
			for index := 0; index < 16; index++ {
				if index >= width || 0x05&(1<<uint(index)) != 0 {
					byteMask |= 1 << uint(index)
				}
			}
			if form.destinationX {
				index, _ := amd64ParseXReg(ins.Args[1].Reg)
				want.xmm[index] = byteMask
				if strings.HasPrefix(string(ins.Op), "V") {
					want.vectorUpper[index] = ^uint64(0xffff)
				}
			} else {
				index, _, valid := x86ResultGP(ins.Args[1].Reg, int64(width), "amd64")
				if !valid {
					t.Fatal("official GP destination lost")
				}
				want.gp[index] = uint8(byteMask)
			}
			for _, consumer := range x86ResultGPSIMDConsumers {
				state := initial.clone()
				if !consumer.step(ins, &state, nil, 0, "amd64") || !reflect.DeepEqual(state, want) {
					t.Fatalf("%s omitted a complete original register row: got=%#v want=%#v", consumer.name, state, want)
				}
			}
		})
	}
}
