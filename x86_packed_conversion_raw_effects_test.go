package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

type x86PackedConversionContinuationOracle struct {
	input, active, destination int
	legacy, merge              bool
}

// Expected byte widths come from the independent Go/Intel test inventories,
// never the production typed forms or the raw adapter under test.
func x86PackedConversionContinuationEffect(t *testing.T, ins Instr) x86PackedConversionContinuationOracle {
	t.Helper()
	base, _, _ := strings.Cut(string(ins.Op), ".")
	destination := amd64VectorByteWidth(ins.Args[len(ins.Args)-1].Reg)
	merge := len(ins.Args) == 3 && !strings.HasSuffix(string(ins.Op), ".Z")
	for _, spec := range x86PackedConversionOracleSpecs() {
		if spec.name != base {
			continue
		}
		for _, shape := range spec.shapes() {
			if shape.destination == destination {
				return x86PackedConversionContinuationOracle{
					input: shape.lanes * spec.input / 8, active: shape.lanes * spec.output / 8,
					destination: destination, legacy: spec.legacy, merge: merge,
				}
			}
		}
		t.Fatal("independent conversion shape missing", ins.Raw)
	}
	switch base {
	case "CVTPL2PS", "VCVTDQ2PS":
		return x86PackedConversionContinuationOracle{destination, destination, destination, base == "CVTPL2PS", merge}
	case "CVTPL2PD", "VCVTDQ2PD":
		return x86PackedConversionContinuationOracle{destination / 2, destination, destination, base == "CVTPL2PD", merge}
	}
	t.Fatal("independent 42-member inventory missing", ins.Raw)
	return x86PackedConversionContinuationOracle{}
}

func x86PackedConversionContinuationInstructions(t *testing.T, arch string, rows []string) []Instr {
	t.Helper()
	raw := x86PackedConversionContinuationRawRows(t, arch, rows)
	file := mustParseX86RawReturn(t, "TEXT f(SB),4,$0-0\n"+strings.Join(raw, "\n")+"\nRET\n")
	normalized, err := normalizeX86RawFile(file, arch)
	if err != nil || len(normalized.Funcs[0].Instrs) != len(rows)+2 {
		t.Fatal("whole original conversion stream lost its exact row boundaries", arch, err)
	}
	return normalized.Funcs[0].Instrs[1 : len(rows)+1]
}

func x86PackedConversionContinuationState() x86ResultState {
	state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionBackward}
	state.pointerGP[0], state.pointerGP[3] = true, true
	state.callerAddressGP[0], state.callerAddressGP[3] = true, true
	state.gp[1], state.gp[2], state.gp[6] = 0xff, 0xff, 0x5a
	state.masks[1], state.masks[7] = true, true
	state.valueStack = &x86ResultValueStack{bytes: []uint8{0xa5, 0x5a, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, id: true}
	for index := 0; index < 32; index++ {
		state.writeVector(index, 64, ^uint64(0), true)
	}
	return state
}

func TestX86PackedConversionRawEveryInputMaskAndMergeByte(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			rows := x86PackedConversionContinuationRows(arch)
			for ordinal, ins := range x86PackedConversionContinuationInstructions(t, arch, rows) {
				oracle := x86PackedConversionContinuationEffect(t, ins)
				destination, valid := amd64VectorRegisterIndex(ins.Args[len(ins.Args)-1].Reg, oracle.destination)
				if !valid || !x86RawPackedConversionSource(ins, arch) {
					t.Fatal("fresh actual-Go conversion has no exact source identity", rows[ordinal])
				}
				state := x86PackedConversionContinuationState()
				want := state.clone()
				want.writeVector(destination, oracle.destination, x86CallerVectorByteMask(int64(oracle.destination)), oracle.legacy)
				accepted, known := x86LoweredPackedConversionResultStep(ins, &state, nil, arch)
				if !accepted || !known || !reflect.DeepEqual(state, want) {
					t.Fatal("conversion changed independent state or lost architectural zero padding/aliases", rows[ordinal], accepted, known)
				}
				for _, register := range []int{0, 1, 7, 31} {
					required := uint64(0)
					if source := ins.Args[0]; source.Kind == OpReg {
						index, _ := amd64VectorRegisterIndex(source.Reg, amd64VectorByteWidth(source.Reg))
						if index == register {
							required |= x86CallerVectorByteMask(int64(oracle.input))
						}
					}
					if oracle.merge && destination == register {
						required |= x86CallerVectorByteMask(int64(oracle.active))
					}
					for missing := 0; missing < 64; missing++ {
						rejected := x86PackedConversionContinuationState()
						rejected.writeVector(register, 64, ^(uint64(1) << uint(missing)), true)
						before := rejected.clone()
						accepted, known := x86LoweredPackedConversionResultStep(ins, &rejected, nil, arch)
						if !known || accepted != (required&(uint64(1)<<uint(missing)) == 0) ||
							!accepted && !reflect.DeepEqual(rejected, before) {
							t.Fatal("raw conversion borrowed a missing source/merge byte or changed rejected state", rows[ordinal], register, missing)
						}
					}
				}
				if len(ins.Args) == 3 {
					mask, _ := amd64ParseKReg(ins.Args[1].Reg)
					state := x86PackedConversionContinuationState()
					state.masks[mask] = false
					before := state.clone()
					if accepted, known := x86LoweredPackedConversionResultStep(ins, &state, nil, arch); accepted || !known || !reflect.DeepEqual(state, before) {
						t.Fatal("raw conversion invented an actual writemask", rows[ordinal])
					}
				}
			}
		})
	}
}

func TestX86PackedConversionRawIdentityAndNativeBoundaries(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			rows := x86PackedConversionContinuationRows(arch)
			for ordinal, original := range x86PackedConversionContinuationInstructions(t, arch, rows) {
				for _, mutation := range []string{
					"origin", "absent-physical-identity", "foreign-mode", "opcode", "source", "destination", "mask",
					"vector-width", "address-size", "unbound-address", "segment", "literal", "native-return", "numerical-read",
					"EVEX-generation", "MMX-state", "encoded-bit", "standalone", "native-pointer", "numeric-address", "index",
				} {
					ins := cloneX86ReplayInstrs([]Instr{original})[0]
					state := x86PackedConversionContinuationState()
					switch mutation {
					case "origin":
						ins.x86SourceRaw = nil
					case "absent-physical-identity":
						ins.x86SourceRaw.packedConversion = x86RawPackedConversionIdentity{}
					case "foreign-mode":
						ins.x86SourceRaw.packedConversion.arch = map[string]string{"386": "amd64", "amd64": "386"}[arch]
					case "opcode":
						ins.Op = "CVTPL2PS"
						if original.Op == ins.Op {
							ins.Op = "CVTPL2PD"
						}
					case "source":
						if ins.Args[0].Kind == OpMem {
							ins.Args[0].Mem.Off++
						} else {
							ins.Args[0].Reg = Reg(string(ins.Args[0].Reg)[:1] + "6")
						}
					case "destination":
						last := len(ins.Args) - 1
						ins.Args[last].Reg = Reg(string(ins.Args[last].Reg)[:1] + "6")
					case "mask":
						if len(ins.Args) != 3 {
							continue
						}
						ins.Args[1].Reg = "K2"
					case "vector-width":
						ins.x86VectorBytes ^= 16
					case "address-size":
						ins.x86AddressBits = 16
					case "unbound-address":
						ins.x86UnboundAddressOverride = true
					case "segment":
						ins.x86SegmentPrefix = 0x64
					case "literal":
						ins.x86RIPLiteral = true
					case "native-return":
						ins.x86RawNearReturn = new(x86RawNearReturnForm)
					case "numerical-read":
						ins.x86NumericalRead = new(x86NumericalReadCertificate)
					case "EVEX-generation":
						ins.x86PackedNumericEVEX = !ins.x86PackedNumericEVEX
					case "MMX-state":
						ins.x86MMXSourceConversion = !ins.x86MMXSourceConversion
					case "encoded-bit":
						ins.x86Encoded = !ins.x86Encoded
					case "native-pointer", "numeric-address", "index":
						if ins.Args[0].Kind != OpMem {
							continue
						}
						base, _, valid := x86ResultGP(ins.Args[0].Mem.Base, x86ResultPointerWord(arch), arch)
						if !valid {
							t.Fatal("independent native source lost its GP base", rows[ordinal])
						}
						if mutation == "index" {
							if ins.Args[0].Mem.Index == "" {
								continue
							}
							index, _, valid := x86ResultGP(ins.Args[0].Mem.Index, x86ResultPointerWord(arch), arch)
							if !valid {
								t.Fatal("independent native source lost its numerical index", rows[ordinal])
							}
							state.gp[index] = 0
						} else {
							state.pointerGP[base] = false
							if mutation == "numeric-address" {
								state.gp[base] = 0xff
							}
						}
					}
					before := state.clone()
					var accepted, known bool
					if mutation == "standalone" {
						accepted, known = x86ResultSignedPackedFloatStep(ins, &state, nil, arch, false)
						if !known {
							accepted, known = x86ResultPackedConversionStep(ins, &state, nil, arch)
						}
					} else {
						accepted, known = x86LoweredPackedConversionResultStep(ins, &state, nil, arch)
					}
					// Some original legacy/VEX decoder forms have no encoded
					// grammar relaxation. Removing their sole raw-origin marker
					// makes a real named instruction, which this raw-only adapter
					// must leave to the independent strict named effect.
					becameNamed := mutation == "origin" && x86ResultNamedPredicateInstruction(ins)
					if accepted || known == becameNamed || !reflect.DeepEqual(before, state) {
						t.Fatal("conversion borrowed physical identity, native backing or standalone authority", rows[ordinal], mutation, accepted, known)
					}
					if becameNamed {
						accepted, known = x86ResultSignedPackedFloatStep(ins, &state, nil, arch, false)
						if !known {
							accepted, known = x86ResultPackedConversionStep(ins, &state, nil, arch)
						}
						// Only an initialized register input is a standalone
						// positive; native memory still has no paired reader.
						if !known || accepted != (ins.Args[0].Kind == OpReg) || x86RawPackedConversionSource(ins, arch) {
							t.Fatal("removed origin confused the raw-only and strict named effects", rows[ordinal], accepted, known)
						}
					}
				}
				copy := cloneX86ReplayInstrs([]Instr{original})[0]
				copy.x86SourceRaw.packedConversion.evex = !copy.x86SourceRaw.packedConversion.evex
				copy.x86SourceRaw.args[0] = Operand{}
				if !x86RawPackedConversionSource(original, arch) {
					t.Fatal("mutable replay clone changed original physical identity", rows[ordinal])
				}
				if !x86ResultPreservesPrivateStorage(original, arch) || x86PreservesNumericalSourceState(original) ||
					x86ResultDirectionAfterSource(original, x86ResultDirectionEither, arch) != x86ResultDirectionEither ||
					x86ResultDirectionAfter(original, x86ResultDirectionEither) != x86ResultDirectionUnknown {
					t.Fatal("conversion confused source-state preservation with inert numerical or standalone authority", rows[ordinal])
				}
				state := x86PackedConversionContinuationState()
				if x86ResultCallerAddressesAfter(original, state.callerAddressGP, nil, arch) != state.callerAddressGP ||
					!x86ResultValueStackContinuation(original, &state, arch) {
					t.Fatal("exact conversion revoked independent address or private-storage facts", rows[ordinal])
				}
			}
		})
	}
}

func TestX86PackedConversionRawVoidAndUnusedBoolNeedInputs(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		var rows []string
		// Use each independent source shape, rather than guessing X for
		// narrowing members whose source is Y/Z.
		bank := map[int]string{16: "X", 32: "Y", 64: "Z"}
		for _, spec := range x86PackedConversionOracleSpecs() {
			shape := spec.shapes()[0]
			rows = append(rows, spec.name+" "+bank[shape.source]+"0,"+bank[shape.destination]+"1")
		}
		for _, op := range []string{"CVTPL2PS", "CVTPL2PD", "VCVTDQ2PS", "VCVTDQ2PD"} {
			rows = append(rows, op+" X0,X1")
		}
		if len(rows) != 42 {
			t.Fatal("missing independent dead conversion member", len(rows))
		}
		rawRows := x86PackedConversionContinuationRawRows(t, arch, rows)
		for index, raw := range rawRows {
			for _, signature := range []struct{ name, extent, declaration string }{
				{"Void", "0", "func Value()"},
				{"unusedBool", "1", "func Value(unused bool)"},
			} {
				source := "TEXT ·Value(SB),4,$0-" + signature.extent + "\n" + raw + "\nRET\n"
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, source, signature.declaration, arch, x86AddressMemoryTargets(arch)[0], api)
					if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("raw dead conversion acquired missing input bytes", arch, rows[index], signature.name, api, err)
					}
				}
			}
		}
	}
}

func TestX86PackedConversionOriginalRawPhysicalMetadata(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, code := range [][]byte{
			{0x62, 0xf1, 0x7c, 0x08, 0x5b, 0xc8},
			{0x62, 0xf1, 0x7e, 0x08, 0xe6, 0xc8},
			{0x0f, 0x2a, 0x00}, {0x66, 0x0f, 0x2a, 0x00},
		} {
			file := mustParseX86RawReturn(t, "TEXT Value(SB),4,$0-0\n"+x86RawDisplacementDirectives(code)+"RET\n")
			normalized, err := normalizeX86RawFile(file, arch)
			if err != nil {
				t.Fatal("original physical conversion identity", arch, fmt.Sprintf("%x", code), err)
			}
			ins := normalized.Funcs[0].Instrs[1]
			wantMMX := code[0] != 0x62
			origin := ins.x86SourceRaw
			if origin == nil || origin.packedConversion.arch != arch || origin.packedConversion.evex == wantMMX ||
				origin.packedConversion.mmx != wantMMX || ins.x86PackedNumericEVEX == wantMMX || ins.x86MMXSourceConversion != wantMMX {
				t.Fatal("physical EVEX/MMX generation was inferred from a false default or lost", arch, ins)
			}
			if x86RawPackedConversionSource(ins, arch) == wantMMX {
				t.Fatal("physical MMX source gained an SSE/native numerical continuation", arch, ins)
			}
			if err := normalized.Funcs[0].x86RawReplay.validate(normalized.Funcs[0], arch); err != nil {
				t.Fatal("fresh complete raw replay missing", err)
			}
			changed := normalized.Funcs[0]
			changed.Instrs = cloneX86ReplayInstrs(changed.Instrs)
			changed.Instrs[1].x86SourceRaw.packedConversion.evex = !origin.packedConversion.evex
			if changed.x86RawReplay.validate(changed, arch) == nil ||
				normalized.Funcs[0].x86RawReplay.validate(normalized.Funcs[0], arch) != nil {
				t.Fatal("changed physical metadata borrowed or mutated immutable whole-source replay")
			}
		}
	}
}
