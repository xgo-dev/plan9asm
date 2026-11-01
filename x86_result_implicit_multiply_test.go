package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

type x86ImplicitMultiplyCase struct {
	x86ScalarFPTupleSpanCase
	op    string
	width int
}

func x86ImplicitMultiplyCases(arch string) []x86ImplicitMultiplyCase {
	var cases []x86ImplicitMultiplyCase
	for _, stem := range []string{"MUL", "IMUL"} {
		for _, width := range []int{1, 2, 4, 8} {
			if arch == "386" && width == 8 {
				continue // No Go mode32 Q encoding, not a skipped target.
			}
			suffix := map[int]string{1: "B", 2: "W", 4: "L", 8: "Q"}[width]
			move, input, result, declaration := "MOV"+suffix, "7", 2*width, fmt.Sprintf("func Value() (uint%d,uint%d)", width*8, width*8)
			want := []uint64{21, 0}
			if stem == "IMUL" {
				input = "-2"
				mask := ^uint64(0)
				if width != 8 {
					mask = (uint64(1) << uint(width*8)) - 1
				}
				want = []uint64{mask - 5, mask}
			}
			stores := fmt.Sprintf("%s AX,ret+0(FP)\n%s DX,ret+%d(FP)\n", move, move, width)
			if width == 1 {
				declaration, result, stores = "func Value() uint16", 2, "MOVW AX,ret+0(FP)\n"
				want = []uint64{21}
				if stem == "IMUL" {
					want = []uint64{0xfffa}
				}
			}
			op := stem + suffix
			body := fmt.Sprintf("%s $%s,AX\n%s $3,BX\n%s BX\n%sRET\n", move, input, move, op, stores)
			cases = append(cases, x86ImplicitMultiplyCase{x86ScalarFPTupleSpanCase{
				name: op, declaration: declaration,
				source: fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s", result, body), want: want,
			}, op, width})
		}
	}
	return cases
}

func TestX86ImplicitMultiplyWholeSourceThreeAPIs(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, row := range x86ImplicitMultiplyCases(target.arch) {
			for _, api := range []string{"text", "module", "Go"} {
				for _, missing := range []string{"", "accumulator", "source"} {
					t.Run(target.triple+"/"+row.op+"/"+api+"/missing="+missing, func(t *testing.T) {
						source := row.source
						if missing != "" {
							lines := strings.Split(source, "\n")
							index := 1
							if missing == "source" {
								index = 2
							}
							lines[index] = "NOP"
							source = strings.Join(lines, "\n")
						}
						ir, err := x86ScalarFPBitViewAPI(t, source, row.declaration, target.arch, target.triple, api)
						if missing != "" {
							if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
								t.Fatalf("implicit operand was invented: output=%t error=%v", ir != "", err)
							}
							return
						}
						if err != nil || ir == "" {
							t.Fatal("complete implicit product rejected", err)
						}
						x86ScalarFPTupleSpanConstantResult(t, ir, row.want)
					})
				}
			}
		}
	}
}

func TestX86ImplicitMultiplyMissingFPResultsThreeAPIs(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, stem := range []string{"MUL", "IMUL"} {
			for _, tuple := range []bool{false, true} {
				declaration, bytes := "func Value() uint32", 4
				if tuple {
					declaration, bytes = "func Value() (uint32,uint32)", 8
				}
				for _, initialized := range []bool{false, true} {
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(fmt.Sprintf("%s/%s/tuple=%t/initialized=%t/%s", target.triple, stem, tuple, initialized, api), func(t *testing.T) {
							body := stem + "L BX\nRET\n"
							if initialized {
								body = "MOVL $2,AX\nMOVL $3,BX\n" + body
							}
							source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s", bytes, body)
							ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, api)
							if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
								t.Fatalf("unwritten declared result escaped whole-source proof: output=%t error=%v", ir != "", err)
							}
						})
					}
				}
			}
		}
	}
}

func TestX86ImplicitMultiplyNUMBytesAndStatus(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range x86ImplicitMultiplyCases(arch) {
			t.Run(arch+"/"+row.op, func(t *testing.T) {
				ins := x86YMMReadSource(t, row.op+" BX")
				width := int64(row.width)
				input := uint8((uint16(1) << uint(width)) - 1)
				state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionBackward}
				ax, _, _ := x86ResultGP(AX, width, arch)
				bx, _, _ := x86ResultGP(BX, width, arch)
				dx, _, _ := x86ResultGP(DX, width, arch)
				state.gp[ax], state.gp[bx], state.gp[dx] = input, input, 0x80
				before := state.clone()
				if !x86ScalarFPResultTransfer(ins, &state, nil, 0, arch) {
					t.Fatal("missing implicit numerical effect")
				}
				wantAX, wantDX := input, input|0x80
				if width == 1 {
					wantAX, wantDX = 3, before.gp[dx] // B writes AX16, never DX.
				} else if width == 4 {
					wantAX, wantDX = 0xff, 0xff // Dword writes clear both upper32 halves.
				}
				if state.gp[ax] != wantAX || state.gp[dx] != wantDX || state.flags != x86ByteFlagCF|x86ByteFlagOF || state.direction != before.direction {
					t.Fatal("incorrect implicit widths or undefined status retained", state.gp, state.flags)
				}
				var addresses [16]bool
				var canonical [16]uint8
				for index := range addresses {
					addresses[index], canonical[index] = true, 255
				}
				after := x86ResultCallerAddressesAfter(ins, addresses, nil, arch)
				addresses[ax] = false
				if width != 1 {
					addresses[dx] = false
				}
				if after != addresses {
					t.Fatal("implicit output retained/revoked wrong opaque address", after)
				}
				boolean := x86RegisterCanonicalBytesAfter(ins, canonical, arch)
				mask := input
				if width == 1 {
					mask = 3
				}
				canonical[ax] &^= mask
				if width != 1 {
					canonical[dx] &^= mask
				}
				if width == 4 && arch == "amd64" {
					canonical[ax] |= 240
					canonical[dx] |= 240
				}
				if boolean != canonical {
					t.Fatal("product bytes borrowed canonical inputs", boolean)
				}
				unknown := before.clone()
				unknown.gp[ax] = 0
				original := unknown.clone()
				if x86ScalarFPResultTransfer(ins, &unknown, nil, 0, arch) || !reflect.DeepEqual(unknown, original) {
					t.Fatal("unknown accumulator acquired initialized bytes")
				}
			})
		}
	}
}

func TestX86ImplicitMultiplyDoesNotRegisterRawEntryOrDivide(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range x86ImplicitMultiplyCases(arch) {
			ins := x86YMMReadSource(t, row.op+" BX")
			if _, known, _ := x86TypedGPByteEffect(ins.Op, ins, arch); known || x86SourceStackInstructionKnown(ins, "MOVQ", "Q", arch) {
				t.Fatal("NUM-only effect widened an independent raw/source-stack registry", arch, row.op)
			}
			ins.x86Encoded = true
			if _, known, _ := x86TypedInstructionByteEffect(ins.Op, ins, arch); known {
				t.Fatal("named implicit product supplied a physical instruction effect")
			}
		}
		for _, row := range []string{"DIVB BX", "DIVW BX", "DIVL BX", "DIVQ BX", "IDIVB BX", "IDIVW BX", "IDIVL BX", "IDIVQ BX"} {
			ins := x86YMMReadSource(t, row)
			if _, known, _ := x86TypedInstructionByteEffect(ins.Op, ins, arch); known {
				t.Fatal("implicit multiply granted division/poison authority", arch, row)
			}
		}
	}
}

type x86ImplicitMultiplyFPCase struct {
	name, params, arguments, source string
	paramBytes, width               int
	want                            uint64
}

func x86ImplicitMultiplyFPCases(arch string) []x86ImplicitMultiplyFPCase {
	rows := []x86ImplicitMultiplyFPCase{
		{"natural-byte", "a uint8", "i8 3", "a+0(FP)", 1, 1, 6},
		{"natural-word", "a uint16", "i16 3", "a+0(FP)", 2, 2, 6},
		{"natural-long", "a uint32", "i32 3", "a+0(FP)", 4, 4, 6},
		{"partial-byte", "a uint64", "i64 134678021", "a+0(FP)", 8, 1, 10},
		{"partial-word", "a uint64", "i64 134678021", "a+0(FP)", 8, 2, 0x0c0a},
		{"partial-long", "a uint64", "i64 134678021", "a+0(FP)", 8, 4, 0x100e0c0a},
		{"interior-byte", "a uint64", "i64 134678021", "a+1(FP)", 8, 1, 12},
		{"interior-word", "a uint64", "i64 134678021", "a+1(FP)", 8, 2, 0x0e0c},
		{"interior-long", "a uint64", "i64 578437695752307201", "a+1(FP)", 8, 4, 0x0a080604},
		{"cross-word", "a,b uint8", "i8 3,i8 4", "a+0(FP)", 2, 2, 0x0806},
		{"cross-long", "a,b uint16", "i16 513,i16 1027", "a+0(FP)", 4, 4, 0x08060402},
		{"natural-float-bits", "a float32", "float 1.000000e+00", "a+0(FP)", 4, 4, 0x7f000000},
	}
	if arch == "amd64" {
		rows = append(rows,
			x86ImplicitMultiplyFPCase{"natural-quad", "a uint64", "i64 3", "a+0(FP)", 8, 8, 6},
			x86ImplicitMultiplyFPCase{"interior-quad", "a,b uint64", "i64 578437695752307201,i64 16", "a+1(FP)", 16, 8, 0x20100e0c0a080604},
			x86ImplicitMultiplyFPCase{"cross-quad", "a,b uint32", "i32 67305985,i32 134678021", "a+0(FP)", 8, 8, 0x100e0c0a08060402},
			x86ImplicitMultiplyFPCase{"natural-double-bits", "a float64", "double 1.000000e+00", "a+0(FP)", 8, 8, 0x7fe0000000000000},
		)
	}
	return rows
}

func x86ImplicitMultiplyFPFixture(row x86ImplicitMultiplyFPCase, stem, arch string) (string, string) {
	word, move, resultType := 8, "MOVQ", "uint64"
	if arch == "386" {
		word, move, resultType = 4, "MOVL", "uint32"
	}
	result := (row.paramBytes + word - 1) & -word
	suffix := map[int]string{1: "B", 2: "W", 4: "L", 8: "Q"}[row.width]
	source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\nMOVL $2,AX\n%s%s %s\n", result+word, stem, suffix, row.source)
	if row.width <= 2 {
		source += "MOVWLZX AX,AX\n" // B observes AX16; W also clears the old upper bytes.
	}
	source += fmt.Sprintf("%s AX,ret+%d(FP)\nRET\n", move, result)
	return source, "func Value(" + row.params + ") " + resultType
}

func TestX86ImplicitMultiplyFPSourceBytesThreeAPIs(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, row := range x86ImplicitMultiplyFPCases(target.arch) {
			for _, stem := range []string{"MUL", "IMUL"} {
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(target.triple+"/"+stem+"/"+row.name+"/"+api, func(t *testing.T) {
						source, declaration := x86ImplicitMultiplyFPFixture(row, stem, target.arch)
						ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, api)
						if err != nil || ir == "" {
							t.Fatal("complete typed FP source rejected", err)
						}
						typ := fmt.Sprintf("i%d", goWordSize(target.arch)*8)
						probe := fmt.Sprintf("define %s @Probe() {\n %%r = call %s @Value(%s)\n ret %s %%r\n}\n", typ, typ, row.arguments, typ)
						x86ScalarFPNamedConstantResult(t, ir+probe, "Probe", []uint64{row.want})
					})
				}
			}
		}
	}
}
