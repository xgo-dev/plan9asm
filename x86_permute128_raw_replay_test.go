package plan9asm

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestX86Permute128PhysicalModeAndWholeProducerReplay(t *testing.T) {
	mc := findLLVM22Tool("llvm-mc")
	if mc == "" {
		t.Fatal("LLVM22 llvm-mc required for independent physical VEX prior")
	}
	for _, arch := range []string{"386", "amd64"} {
		triple := testTargetTriple("linux", arch)
		for member := range x86Permute128Members {
			for _, memory := range []bool{false, true} {
				row := x86Permute128OracleRow{member: member, immediate: 0x21, second: 1, destination: 2, memory: memory, raw: true}
				t.Run(arch+"/"+row.instruction(), func(t *testing.T) {
					code := row.code()
					observed := x86PackedShiftRawSingleMC(t, mc, triple, code)
					if strings.Contains(observed, "warning") || strings.Contains(observed, "invalid") ||
						strings.Count(observed, strings.ToLower(x86Permute128Members[member].op)) != 1 {
						t.Fatal("independent LLVM22 rejected this complete VEX instruction", observed)
					}
					actual, _ := x86NumericalBoundaryGoBytes(t, arch, x86RawDisplacementDirectives(code)+"RET")
					if !bytes.Equal(actual, append(append([]byte(nil), code...), 0xc3)) {
						t.Fatal("actual Go BYTE object changed the independently decoded VEX bytes", actual, code)
					}
					source, declaration := row.program(arch, "Value")
					x86LEAActualTargetGoObject(t, arch, triple, source)
					decoded, length, known, err := decodedX86Permute128Instruction(code, map[string]int{"386": 32, "amd64": 64}[arch])
					if !known || err != nil || length != len(code) || decoded.Op != Op(x86Permute128Members[member].op) {
						t.Fatal("physically valid low-bank VEX form inherited the named frontend cap", known, length, err)
					}
					file, err := normalizeX86RawFile(mustParseX86RawReturn(t, source), arch)
					if err != nil {
						t.Fatal("complete original physically valid source could not normalize", err)
					}
					original, ordinal := file.Funcs[0], -1
					for i, ins := range original.Instrs {
						if ins.Op == decoded.Op && ins.x86SourceRaw != nil {
							ordinal = i
						}
					}
					if ordinal < 0 || original.x86RawReplay == nil || original.x86RawReplay.validate(original, arch) != nil {
						t.Fatal("complete immutable raw producer replay disappeared")
					}
					state := x86FMA3ResultInputState()
					state.pointerGP[0] = true
					state.valueStack = &x86ResultValueStack{bytes: []uint8{0xa5, 0x37}, id: true}
					before := state.clone()
					if x86ScalarFPResultTransfer(original.Instrs[ordinal], &state, nil, 0, arch) || !reflect.DeepEqual(state, before) {
						t.Fatal("standalone raw query borrowed a named/native source role")
					}
					// This private paired step consumes the exact original above;
					// it does not stand in for the complete public replay check.
					ins := original.Instrs[ordinal]
					expected := before.clone()
					expected.writeVector(2, 32, 0xffffffff, false)
					accepted, owned := x86ResultPermute128Step(ins, &state, nil, arch, true)
					if !accepted || !owned || !reflect.DeepEqual(state, expected) ||
						x86ResultDirectionAfterSource(ins, before.direction, arch) != before.direction ||
						!x86ResultPreservesPrivateStorage(ins, arch) ||
						x86ResultCallerAddressesAfter(ins, before.callerAddressGP, nil, arch) != before.callerAddressGP {
						t.Fatal("paired VEX selection changed FLAGS/DF/ID/private cells or existing GP identities", accepted, owned)
					}
					check := x86LegacyFloatReplayCheck(t, arch, source, declaration)
					for _, mutation := range []string{"original", "origin-only", "missing-replay", "producer", "operand", "encoded", "vector-width", "original-bytes", "generation", "snapshot", "named-forgery"} {
						t.Run(mutation, func(t *testing.T) {
							candidate := original
							candidate.Instrs = cloneX86ReplayInstrs(original.Instrs)
							ins := &candidate.Instrs[ordinal]
							switch mutation {
							case "origin-only":
								ins.x86SourceRaw = nil
							case "missing-replay":
								candidate.x86RawReplay = nil
							case "producer":
								candidate.Instrs[1].Raw += " changed"
							case "operand":
								ins.Args[2].Reg = "Y7"
							case "encoded":
								ins.x86Encoded = !ins.x86Encoded
							case "vector-width":
								ins.x86VectorBytes = 7
							case "generation":
								ins.x86Permute128VEX = false
							case "snapshot":
								origin := *ins.x86SourceRaw
								origin.permute128.vex = false
								ins.x86SourceRaw = &origin
							case "named-forgery":
								ins.x86Encoded, ins.x86Permute128VEX, ins.x86SourceRaw, ins.x86VectorBytes = false, false, nil, 0
							case "original-bytes":
								replay := *original.x86RawReplay
								replay.source = strings.Replace(replay.source, "BYTE $", "BYTE $1+", 1)
								candidate.x86RawReplay = &replay
							}
							failure := check(candidate)
							if mutation == "original" {
								if failure != nil {
									t.Fatal("complete initialized original VEX source lost its paired owner", failure)
								}
							} else if !errors.Is(failure, ErrProbeNeedsContext) {
								t.Fatal("edited physical generation or producer borrowed named source authority", failure)
							}
							if original.x86RawReplay.validate(original, arch) != nil {
								t.Fatal("cloned mutation damaged the sealed original")
							}
						})
					}
				})
			}
		}
	}
}

// This is the exact low-bank encoding formerly rejected by a named Go
// arity check. Keep it as a physical positive, not a deleted old fixture.
func TestDecodedX86RawVPERM2X128OriginalMode32LowBank(t *testing.T) {
	for _, member := range x86Permute128Members {
		code := encodeX86RawVPERM2X128(member.opcode, 1, 0, 1, 2)
		actual, _ := x86NumericalBoundaryGoBytes(t, "386", x86RawDisplacementDirectives(code)+"RET")
		if !bytes.Equal(actual, append(append([]byte(nil), code...), 0xc3)) {
			t.Fatal("original mode32 BYTE encoding changed", actual, code)
		}
		got, length, known, err := decodedX86Permute128Instruction(code, 32)
		if !known || err != nil || length != len(code) || got.Raw != member.op+" $1, Y0, Y1, Y2" ||
			!got.x86Encoded || !got.x86Permute128VEX || got.x86VectorBytes != 32 {
			t.Fatal("original complete physical mode32 form inherited a named Go cap", got, length, known, err)
		}
	}
}

func TestX86Permute128FixedWAndNamedModeBoundaries(t *testing.T) {
	for _, member := range x86Permute128Members {
		for _, control := range []string{"W1", "L0", "pp", "truncated-imm", "address-override", "legacy-prefix", "RIP"} {
			t.Run(fmt.Sprint(member.op, "/", control), func(t *testing.T) {
				code := encodeX86RawVPERM2X128(member.opcode, 0x21, 0, 1, 2)
				switch control {
				case "W1":
					code[2] |= 0x80
				case "L0":
					code[2] &^= 4
				case "pp":
					code[2] &^= 3
				case "truncated-imm":
					code = code[:len(code)-1]
				case "address-override":
					code = append([]byte{0x67}, code...)
				case "legacy-prefix":
					code = append([]byte{0x66}, code...)
				case "RIP":
					code = []byte{0xc4, 0xe3, 0x75, member.opcode, 0x15, 0, 0, 0, 0, 0x21}
				}
				if ins, length, known, err := decodedX86Permute128Instruction(code, 64); known && err == nil {
					t.Fatal("invalid W/L/prefix or unbound RIP acquired a native instruction", ins, length)
				}
			})
		}
		for _, row := range []string{
			member.op + " $0,Y0,Y1,Y2", member.op + " $255,(AX),Y1,Y2",
		} {
			requireX86GoAssemblerResult(t, "386", "TEXT InvalidNamed(SB),4,$0-0\n"+row+"\nRET\n", false)
			assertX86Permute128Rejected(t, "386", "i386-unknown-linux-gnu", row)
		}
		// P0's high bits still identify a real VEX prefix in mode32. Do
		// not confuse unavailable vvvv=8 with a legacy LDS prefix alias.
		code := encodeX86RawVPERM2X128(member.opcode, 0x21, 0, 8, 2)
		if ins, length, known, err := decodedX86Permute128Instruction(code, 32); known && err == nil {
			t.Fatal("mode32 inherited an unavailable high vector input", ins, length)
		}
	}
}
