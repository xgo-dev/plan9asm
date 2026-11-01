package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func x86MULXTestOps(arch string) []string {
	if arch == "386" {
		return []string{"MULXL"}
	}
	return []string{"MULXL", "MULXQ"}
}

// The official table/physical full-family roots separately retain all 28 GP
// rows. These original Go/LLVM priors bind the exact source/alias forms below
// before a public API sees the full initialized or missing-input program.
func x86MULXTestPhysical(t *testing.T, arch, op string) map[string]string {
	t.Helper()
	rows := []string{
		op + " AX,CX,DX", op + " DX,CX,DX", op + " (BX),CX,DX",
		op + " 1(BX)(SI*2),CX,DX", op + " 1(DX)(SI*2),CX,DX",
		op + " 1(BX)(SI*2),BX,DX",
	}
	code, pcs := x86NumericalBoundaryGoBytes(t, arch, strings.Join(rows, "\n")+"\nRET\n")
	if len(pcs) != len(rows)+1 {
		t.Fatal("actual MULX physical grammar/alias prior omitted a row", pcs)
	}
	mode := 64
	if arch == "386" {
		mode = 32
	}
	x86NumericalVEXGPRequireMC(t, code, mode, len(pcs))
	result := make(map[string]string)
	for index, row := range rows {
		result[row] = x86RawDisplacementDirectives(code[pcs[index]:pcs[index+1]])
	}
	return result
}

func x86MULXTestSource(name, arch, op, instruction string, dead bool) (string, string) {
	word, move, push, pop := goWordSize(arch), "MOVQ", "PUSHFQ", "POPQ"
	if arch == "386" {
		move, push, pop = "MOVL", "PUSHFL", "POPL"
	}
	width, store := 4, "MOVL"
	if op == "MULXQ" {
		width, store = 8, "MOVQ"
	}
	body := fmt.Sprintf("TEXT %s(SB),4,$0-%d\n%s out+0(FP),DI\n%s p+%d(FP),BX\n",
		name, 2*word, move, move, word) + "MOVL $7,AX\nMOVL $3,DX\nMOVL $0,SI\nCMPL AX,$1\nSTD\n" + instruction + "\n"
	if !dead {
		body += fmt.Sprintf("%s CX,0(DI)\n%s DX,%d(DI)\n", store, store, width)
	}
	body += push + "\n" + pop + " SI\nANDL $0xcd5,SI\nMOVL SI,16(DI)\nCLD\nRET\n"
	return body, fmt.Sprintf("func %s(out *[32]byte,p *[64]byte)\n", name)
}

func TestX86MULXNativeMemoryMissingFactsThreeAPIs(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, op := range x86MULXTestOps(arch) {
			physical := x86MULXTestPhysical(t, arch, op)
			for _, raw := range []bool{false, true} {
				var prior strings.Builder
				var programs []string
				const data = "DATA unused+0(SB)/8,$7\nGLOBL unused(SB),8,$8\n"
				for index, missing := range []string{"original-Void", "address", "index", "implicit-DX", "opaque-DX-address"} {
					instruction := op + " 1(BX)(SI*2),CX,DX"
					if missing == "opaque-DX-address" {
						instruction = op + " 1(DX)(SI*2),CX,DX"
					}
					if missing == "original-Void" {
						instruction = op + " (BX),CX,DX"
					}
					if raw {
						instruction = physical[instruction]
					}
					body, _ := x86MULXTestSource("Value", arch, op, instruction, false)
					switch missing {
					case "original-Void":
						body = "TEXT Value(SB),4,$0-0\n" + instruction + "\nRET\n"
					case "address":
						move := "MOVQ"
						if arch == "386" {
							move = "MOVL"
						}
						body = strings.Replace(body, fmt.Sprintf("%s p+%d(FP),BX\n", move, goWordSize(arch)), "", 1)
					case "index":
						body = strings.Replace(body, "MOVL $0,SI\n", "", 1)
					case "implicit-DX":
						body = strings.Replace(body, "MOVL $3,DX\n", "", 1)
					case "opaque-DX-address":
						move := "MOVQ"
						if arch == "386" {
							move = "MOVL"
						}
						body = strings.Replace(body, "MOVL $3,DX\n", fmt.Sprintf("%s p+%d(FP),DX\n", move, goWordSize(arch)), 1)
					}
					// The unused legitimate DATA stays in every public program;
					// its presence cannot initialize the unrelated BX address.
					prior.WriteString(strings.Replace(body, "TEXT Value(SB)", fmt.Sprintf("TEXT Missing%d(SB)", index), 1))
					programs = append(programs, body+data)
				}
				// Establish every original Go body before asking a public API.
				x86LEAActualTargetGoObject(t, arch, x86AddressMemoryTargets(arch)[0], prior.String()+data)
				for index, text := range programs {
					declaration := "func Value(out *[32]byte,p *[64]byte)\n"
					if index == 0 {
						declaration = "func Value()\n"
					}
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(fmt.Sprintf("%s/%s/raw=%t/missing%d/%s", arch, op, raw, index, api), func(t *testing.T) {
							ir, err := x86ScalarFPBitViewAPI(t, text, declaration, arch, x86AddressMemoryTargets(arch)[0], api)
							if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
								t.Fatal("MULX borrowed a missing native address, index or implicit numerical DX", err)
							}
						})
					}
				}
			}
		}
	}
}

func TestX86MULXInitializedNativeReadEffectsFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("complete MULX source/read objects require LLVM22")
	}
	for _, target := range x86RawReturnTargets {
		var source, declarations strings.Builder
		widths := make(map[string]int)
		for _, op := range x86MULXTestOps(target.arch) {
			physical := x86MULXTestPhysical(t, target.arch, op)
			for _, raw := range []bool{false, true} {
				for _, memory := range []bool{false, true} {
					for _, dead := range []bool{false, true} {
						instruction := op + " AX,CX,DX"
						if memory {
							instruction = op + " 1(BX)(SI*2),CX,DX"
							if !dead {
								instruction = op + " 1(BX)(SI*2),BX,DX"
							}
						}
						if raw {
							instruction = physical[instruction]
						}
						name := fmt.Sprint("MULXInput", len(widths))
						body, declaration := x86MULXTestSource(name, target.arch, op, instruction, dead)
						if memory && !dead {
							// The effective address must be consumed before MULX
							// replaces the old pointer with its low product.
							store := "MOVL"
							if op == "MULXQ" {
								store = "MOVQ"
							}
							body = strings.Replace(body, store+" CX,0(DI)", store+" BX,0(DI)", 1)
						}
						widths[name] = 0
						if memory {
							widths[name] = 32
							if op == "MULXQ" {
								widths[name] = 64
							}
						}
						source.WriteString(body)
						declarations.WriteString(declaration)
					}
				}
			}
		}
		x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(target.triple+"/"+api, func(t *testing.T) {
				ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
				if err != nil {
					t.Fatal("fully initialized MULX cannot compose with its actual native inputs", err)
				}
				for _, body := range []string{ir, x86DwordProductIROptimize(t, ir)} {
					for name, bits := range widths {
						function := x86StringMemoryFunction(t, body, name)
						if bits == 0 {
							continue
						}
						load := fmt.Sprintf("load volatile i%d,", bits)
						count := strings.Count(function, load)
						if count != 1 {
							t.Fatal("dead or live MULX lost its sole exact unaligned native read", name, bits, count)
						}
						for _, line := range strings.Split(function, "\n") {
							if strings.Contains(line, load) && !strings.Contains(line, "align 1") {
								t.Fatal("MULX native read invented an alignment contract", name, line)
							}
						}
					}
					compileLLVMToObject(t, llc, target.triple, "mulx-inputs.ll", "mulx-inputs.o", body)
				}
			})
		}
	}
}

func TestX86MULXTypedInputsOutputsAndPreservedFlags(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, op := range x86MULXTestOps(arch) {
			x86MULXTestPhysical(t, arch, op)
			ins := x86YMMReadSource(t, op+" AX,CX,DX")
			effect, known, err := x86TypedInstructionByteEffect(ins.Op, ins, arch)
			if !known || err != nil || effect.flagsRead|effect.flagsDefined|effect.flagsKilled != 0 {
				t.Fatal("MULX lost complete typed operands or incorrectly changed FLAGS", arch, op, effect, known, err)
			}
			reads, writes := make(map[Reg]bool), make(map[Reg]bool)
			for _, operand := range effect.operands {
				width := int64(4)
				if op == "MULXQ" {
					width = 8
				}
				if operand.width != width {
					t.Fatal("MULX source/output width differs from its physical operand", op, operand)
				}
				if operand.read {
					reads[operand.operand.Reg] = true
				}
				if operand.write {
					writes[operand.operand.Reg] = true
				}
			}
			if !reflect.DeepEqual(reads, map[Reg]bool{AX: true, DX: true}) ||
				!reflect.DeepEqual(writes, map[Reg]bool{CX: true, DX: true}) {
				t.Fatal("MULX omitted implicit DX, invented old outputs or lost a product half", reads, writes)
			}
		}
	}
}

func TestX86MULXMode32PhysicalWIGRetainsOrdinarySourceBoundary(t *testing.T) {
	x86MULXTestPhysical(t, "386", "MULXQ")
	for _, row := range []string{"MULXQ AX,CX,DX", "MULXQ (BX),CX,DX"} {
		code, pcs := x86NumericalBoundaryGoBytes(t, "386", row+"\nRET\n")
		x86NumericalVEXGPRequireMC(t, code, 32, len(pcs))
		decoded, size, known, err := decodedX86MULXInstructionWithMemory(code, 32, x86RawMemoryDecoder{physicalPC: true})
		if !known || err != nil || size != int(pcs[1]) || decoded.Op != "MULXL" {
			t.Fatal("physical mode32 WIG prior did not remain a dword boundary", decoded, size, err)
		}
		if _, _, known, err := decodedX86MULXInstruction(code, 32); !known || err == nil {
			t.Fatal("physical WIG observation broadened the default raw source entry", known, err)
		}
		body, declaration := x86MULXTestSource("Value", "386", "MULXQ", row, true)
		x86LEAActualTargetGoObject(t, "386", "i386-unknown-linux-gnu", body)
		for _, api := range []string{"text", "module", "Go"} {
			ir, err := x86ScalarFPBitViewAPI(t, body, declaration, "386", "i386-unknown-linux-gnu", api)
			if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("named mode32 Q acquired an ordinary qword role from physical WIG", api, err)
			}
		}
	}
}
