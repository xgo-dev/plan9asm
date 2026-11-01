package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func x86BlockNativeStoreRows(arch string) []string {
	var rows []string
	for _, row := range x86InsertExtractFormats() {
		if !strings.HasPrefix(row, "VEXTRACT") || strings.HasPrefix(row, "VEXTRACTPS ") ||
			!strings.HasSuffix(row, "(BX)") || arch == "386" && strings.Contains(row, "K1") {
			continue
		}
		rows = append(rows, row)
	}
	return rows
}

func TestX86BlockExtractStoreEmitterKeepsExactAccess(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range x86BlockNativeStoreRows(arch) {
			t.Run(arch+"/"+row, func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, row)
				ctx, output := newAMD64CtxWithFuncForTest(t, Func{Instrs: []Instr{ins}}, FuncSig{Ret: Void}, nil)
				ctx.goarch = arch
				before := output.Len()
				known, _, err := ctx.lowerInsertExtractFamily(ins.Op, ins)
				if !known || err != nil {
					t.Fatal("complete extraction row rejected by its emitter", err)
				}
				text := output.String()[before:]
				if strings.Contains(row, "K1") {
					if !strings.Contains(text, "call void asm sideeffect") || !strings.Contains(text, "; vextract") {
						t.Fatal("masked extraction lost its write-only native opcode")
					}
				} else {
					chunk, _, _ := x86InsertExtractMaskedMemoryShape(row)
					if strings.Count(text, fmt.Sprintf("store volatile <%d x i8>", chunk)) != 1 {
						t.Fatal("unmasked extraction lost its exact observable native store")
					}
				}
			})
		}
	}
}

func TestX86BlockExtractNativeStoreContinuation(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		rows := x86BlockNativeStoreRows(arch)
		if len(rows) != map[string]int{"amd64": 26, "386": 14}[arch] {
			t.Fatal("incomplete independent block-store forms", arch, len(rows))
		}
		for _, row := range rows {
			t.Run(arch+"/"+row, func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, row)
				form, known, err := x86InsertExtractProperties(ins, arch)
				if !known || err != nil || !form.memoryWrite || form.spec.scalar {
					t.Fatal("complete block-store grammar changed", err)
				}
				chunk, width, _ := x86InsertExtractMaskedMemoryShape(row)
				offset := (255 % (width / chunk)) * chunk
				selected := (uint64(1)<<uint(chunk) - 1) << uint(offset)
				state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionBackward}
				state.pointerGP[3], state.masks[1] = true, true
				state.writeVector(1, 64, selected, false)
				before := state.clone()
				if !x86ResultBlockTransferWithNativeMemory(ins, form, &state, nil, 0, arch, true) || !reflect.DeepEqual(state, before) {
					t.Fatal("paired block store rejected exact selected bytes or changed numerical facts")
				}
				if x86ResultBlockTransfer(ins, form, &state, nil, 0, arch) {
					t.Fatal("standalone query acquired native write authority")
				}
				indexed := ins
				indexed.Args = append([]Operand(nil), ins.Args...)
				indexed.Args[form.destination].Mem.Index = CX
				indexed.Args[form.destination].Mem.Scale = 4
				indexed.Args[form.destination].Mem.Off = 3
				state = before.clone()
				wordMask := uint8(1)<<uint(x86ResultPointerWord(arch)) - 1
				state.gp[1] = wordMask
				indexedBefore := state.clone()
				if !x86ResultBlockTransferWithNativeMemory(indexed, form, &state, nil, 0, arch, true) ||
					!reflect.DeepEqual(state, indexedBefore) {
					t.Fatal("complete numerical index lost the exact native store")
				}
				state.gp[1] = wordMask >> 1
				indexedBefore = state.clone()
				if x86ResultBlockTransferWithNativeMemory(indexed, form, &state, nil, 0, arch, true) ||
					!reflect.DeepEqual(state, indexedBefore) {
					t.Fatal("partial index supplied a native write address")
				}
				for _, mutation := range []string{"physical", "address-size", "segment"} {
					changed := ins
					switch mutation {
					case "physical":
						changed.x86Encoded = true
					case "address-size":
						changed.x86AddressBits = 32
					case "segment":
						changed.x86SegmentPrefix = 0x64
					}
					state = before.clone()
					if x86ResultBlockTransferWithNativeMemory(changed, form, &state, nil, 0, arch, true) ||
						!reflect.DeepEqual(state, before) {
						t.Fatal("named block store supplied a physical entry or access", mutation)
					}
				}
				for missing := -2; missing < chunk; missing++ {
					state = before.clone()
					switch missing {
					case -2:
						state.pointerGP[3] = false
					case -1:
						if form.mask < 0 {
							continue
						}
						state.masks[1] = false
					default:
						state.writeVector(1, 64, selected&^(uint64(1)<<uint(offset+missing)), false)
					}
					original := state.clone()
					if x86ResultBlockTransferWithNativeMemory(ins, form, &state, nil, 0, arch, true) || !reflect.DeepEqual(state, original) {
						t.Fatal("missing address, mask or selected byte was fabricated", missing)
					}
				}
			})
		}
	}
}

func TestX86BlockExtractNativeStoreVoidRequiresInputs(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		move, word, triple := "MOVQ", 8, "x86_64-unknown-linux-gnu"
		if arch == "386" {
			move, word, triple = "MOVL", 4, "i386-unknown-linux-gnu"
		}
		for _, row := range x86BlockNativeStoreRows(arch) {
			for _, unused := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/unused-bool=%t", arch, row, unused), func(t *testing.T) {
					declaration, extent := "func Value(p *byte)", word
					if unused {
						declaration, extent = "func Value(p *byte,unused bool)", word+1
					}
					mask := ""
					if strings.Contains(row, "K1") {
						mask = "MOVL $1,AX\nKMOVW AX,K1\n"
					}
					source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s p+0(FP),BX\n%s%s\nRET\n", extent, move, mask, row)
					x86LEAActualTargetGoObject(t, arch, triple, source)
					for _, api := range []string{"text", "module", "Go"} {
						ir, err := x86ScalarFPBitViewAPI(t, source, declaration, arch, triple, api)
						if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("Void or unused bool supplied unknown block bytes", api, err)
						}
					}
				})
			}
		}
	}
}

func TestX86BlockExtractNativeStoresFiveTargets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			move, word := "MOVQ", 8
			if target.arch == "386" {
				move, word = "MOVL", 4
			}
			var source, declarations strings.Builder
			masked, plain := 0, 0
			for index, row := range x86BlockNativeStoreRows(target.arch) {
				name := fmt.Sprint("Copy", index)
				fmt.Fprintf(&declarations, "func %s(out, input *byte, mask uint32)\n", name)
				fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n%s out+0(FP),BX\n%s input+%d(FP),DX\nMOVL mask+%d(FP),AX\nKMOVW AX,K1\nVMOVUPS (DX),Z1\n%s\n%s\nRET\n",
					name, 2*word+4, move, move, word, 2*word, row, row)
				if strings.Contains(row, "K1") {
					masked++
				} else {
					plain++
				}
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("complete original native block stores rejected", err)
					}
					for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
						if strings.Count(text, "store volatile <") != 2*plain ||
							strings.Count(text, "; vextract") != 2*masked {
							t.Fatal("overwritten block stores lost exact native effects", plain, masked)
						}
						for _, level := range []string{"-O0", "-O2"} {
							x86PackedStringCompileObject(t, llc, target.triple, text, level)
						}
					}
				})
			}
		})
	}
}
