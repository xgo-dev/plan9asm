package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestX86NativeGPStoreCompleteWidthsThreeAPIs(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		word, move := 8, "MOVQ"
		if target.arch == "386" {
			word, move = 4, "MOVL"
		}
		for _, row := range []struct {
			op, register string
			width        int
		}{{"MOVB", "AL", 1}, {"MOVW", "AX", 2}, {"MOVL", "AX", 4}, {"MOVQ", "AX", 8}, {"MOVD", "AX", 8}, {"MOVDQ2Q", "AX", 8}} {
			if row.width > word {
				continue // Go386 has no ordinary qword GP-to-memory row.
			}
			source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s p+0(FP),DI\n%s value+%d(FP),AX\n%s %s,8(DI)\nMOVL $7,AX\nMOVL AX,ret+%d(FP)\nRET\n",
				word*2+4, move, move, word, row.op, row.register, word*2)
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(target.triple+"/"+row.op+"/"+api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, "func Value(p *byte,value uintptr) uint32", target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("complete numerical GP store lost its paired continuation", err)
					}
					if strings.Count(ir, fmt.Sprintf("store volatile i%d ", row.width*8)) != 1 {
						t.Fatal("the paired emitter did not retain exactly one full native store")
					}
					pkg := mustGoPackage(t, "store", "package store\nfunc Value(p *byte,value uintptr) uint32")
					file := mustParseX86RawReturn(t, source)
					sigs, err := goSigsForAsmFile(pkg, file, func(name string) string { return strings.TrimPrefix(name, "·") }, target.arch, nil, nil, nil)
					if err != nil {
						t.Fatal(err)
					}
					if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sigs["Value"], target.arch); !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("a declaration-only query acquired native write authority", err)
					}
					for _, level := range []string{"-O0", "-O2"} {
						x86PackedStringCompileObject(t, llc, target.triple, ir, level)
					}
				})
			}
		}
	}
}

func TestX86NativeGPStoreOriginalByteAliasesAndUnchangedState(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, instruction := range []string{"MOVL AX,(DX)(FS*1)", "MOVL AX,8(GS)", "MOVL AX,table(SB)", "MOVL AX,result+0(FP)", "MOVL AX,local-4(SP)", "MOVL X0,(DX)"} {
			ins := x86ScalarLaneInstruction(t, instruction)
			if _, known, _ := x86ScalarNativeStoreProperties(ins.Op, ins, arch); known {
				t.Fatal("ordinary GP store consumed a separate segment/static/frame/SIMD row", arch, instruction)
			}
		}
	}
	for ordinal, register := range []string{"AH", "CH", "DH", "BH"} {
		for _, address := range []string{"(DX)", "(R8)", "(DX)(R9*2)"} {
			instruction := "MOVB " + register + "," + address
			code := x86OrderingHintGoBytes(t, "amd64", "TEXT native(SB),4,$0-0\n"+instruction+"\nRET\n")
			want := []byte{0x88, byte(0x22 + ordinal*8), 0xc3}
			if address == "(R8)" {
				want = []byte{0x41, 0x88, byte(0x20 + ordinal*8), 0xc3}
			} else if address == "(DX)(R9*2)" {
				want = []byte{0x42, 0x88, byte(0x24 + ordinal*8), 0x4a, 0xc3}
			}
			if !reflect.DeepEqual(code, want) {
				t.Fatalf("original Go store byte role changed: %s = %x, want %x", instruction, code, want)
			}
			ins := x86ScalarLaneInstruction(t, instruction)
			form, known, err := x86ScalarNativeStoreProperties(ins.Op, ins, "amd64")
			effective := Reg(register)
			if address != "(DX)" {
				effective = []Reg{SP, BP, SI, DI}[ordinal]
			}
			if !known || err != nil || form.source.Kind != OpReg || form.source.Reg != effective || form.bytes != 1 {
				t.Fatal("typed store disagrees with actual ModRM/REX", form, err)
			}
			if address != "(DX)" && ordinal < 2 {
				context, output := newAMD64CtxWithFuncForTest(t, Func{}, FuncSig{Name: "store", Ret: Void}, nil)
				before := output.String()
				if err := context.lowerScalarNativeStore(form, ins); !errors.Is(err, ErrProbeNeedsContext) || output.String() != before {
					t.Fatal("unbound physical SP/BP read emitted a store", err)
				}
			}
		}
	}
	for _, arch := range []string{"386", "amd64"} {
		move := "MOVL"
		if arch == "amd64" {
			move = "MOVQ"
		}
		ins := x86ScalarLaneInstruction(t, move+" AX,-1(DX)(BX*2)")
		state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionBackward}
		state.gp[0], state.gp[3], state.pointerGP[2] = 0xff, 0xff, true
		before := state.clone()
		if accepted, known := x86LoweredScalarNativeStore(ins, &state, nil, arch); !accepted || !known || !reflect.DeepEqual(state, before) {
			t.Fatal("native store manufactured or revoked a state fact", arch, state)
		}
		for _, mutation := range []string{"physical", "address", "unknown-index", "commuted-pointer", "pointer-data"} {
			changed, next := ins, before.clone()
			switch mutation {
			case "physical":
				changed.x86Encoded = true
			case "address":
				changed.x86AddressBits = 16
			case "unknown-index":
				next.gp[3] = 0
			case "commuted-pointer":
				next.pointerGP[2], next.gp[2], next.pointerGP[3], next.gp[3] = false, 0xff, true, 0
			case "pointer-data":
				next.gp[0], next.pointerGP[0] = 0, true
			}
			unchanged := next.clone()
			if accepted, _ := x86LoweredScalarNativeStore(changed, &next, nil, arch); accepted || !reflect.DeepEqual(next, unchanged) {
				t.Fatal("native store acquired a foreign permission or changed rejected state", arch, mutation)
			}
		}
	}
}

func TestX86NativeGPStoreCannotBorrowUnknownOrPointerData(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		word, move := 8, "MOVQ"
		if target.arch == "386" {
			word, move = 4, "MOVL"
		}
		body := fmt.Sprintf("%s p+0(FP),DI\n%s value+%d(FP),AX\n%s AX,(DI)\nMOVL $7,ret+%d(FP)\nRET\n", move, move, word, move, word*2)
		for _, mutation := range []struct {
			name, body string
			frame      int
		}{
			{"unknown-address", strings.Replace(body, move+" p+0(FP),DI\n", "", 1), 0},
			{"numerical-address", strings.Replace(body, move+" p+0(FP),DI", fmt.Sprintf("%s value+%d(FP),DI", move, word), 1), 0},
			{"unknown-data", strings.Replace(body, fmt.Sprintf("%s value+%d(FP),AX\n", move, word), "", 1), 0},
			{"pointer-data-foreign-frame", strings.Replace(body, fmt.Sprintf("%s value+%d(FP),AX", move, word), move+" p+0(FP),AX", 1), 16},
			{"partial-data", strings.Replace(body, fmt.Sprintf("%s value+%d(FP),AX", move, word), fmt.Sprintf("MOVB value+%d(FP),AL", word), 1), 0},
			{"raw-return", strings.Replace(body, "RET", "BYTE $0xc3\nRET", 1), 0},
		} {
			source := fmt.Sprintf("TEXT ·Value(SB),4,$%d-%d\n%s", mutation.frame, word*2+4, mutation.body)
			goAssemblerOracleOutput(t, target.arch, source, "", true)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(target.triple+"/"+mutation.name+"/"+api, func(t *testing.T) {
					if ir, err := x86ScalarFPBitViewAPI(t, source, "func Value(p *byte,value uintptr) uint32", target.arch, target.triple, api); !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
						t.Fatal("unproved native write data/address/source was admitted", err)
					}
				})
			}
		}
		// Preserve the former pointer-data fixture verbatim as an explicit
		// positive for the independently proved closed-leaf bit-copy scope.
		pointerBody := strings.Replace(body, fmt.Sprintf("%s value+%d(FP),AX", move, word), move+" p+0(FP),AX", 1)
		source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s", word*2+4, pointerBody)
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(target.triple+"/closed-leaf-pointer-bits/"+api, func(t *testing.T) {
				if ir, err := x86ScalarFPBitViewAPI(t, source, "func Value(p *byte,value uintptr) uint32", target.arch, target.triple, api); err != nil || ir == "" {
					t.Fatal("actual complete entry-address bits need no numerical-byte permission", err)
				}
			})
		}
	}
}
