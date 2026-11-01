package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestX86UnsignedScalarIntegerFloatPublicInputAndAuthorityBoundaries(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		move, triple, word := "MOVQ", "x86_64-unknown-linux-gnu", 8
		if arch == "386" {
			move, triple, word = "MOVL", "i386-unknown-linux-gnu", 4
		}
		for _, member := range x86UnsignedScalarIntegerFloatOracle {
			input := member.input
			if arch == "386" {
				input = 4
			}
			for _, sourceKind := range []string{"GP", "FP", "native"} {
				row := x86UnsignedScalarIntegerFloatRow{op: member.op, source: sourceKind, input: input, output: member.output, destination: 1}
				source, declaration, _ := x86UnsignedScalarIntegerFloatProgram(0, row, arch)
				goAssemblerOracleOutput(t, arch, source, "", true)
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(arch+"/"+member.op+"/"+sourceKind+"/"+api, func(t *testing.T) {
						if ir, err := x86ScalarFPBitViewAPI(t, source, declaration, arch, triple, api); err != nil || ir == "" {
							t.Fatal("legitimate initialized unsigned baseline failed before any negative", err)
						}
						mutations := map[string]string{
							"unknown-upper":          strings.Replace(source, "VMOVDQU64 (SI),Z0\n", "", 1),
							"missing-output-pointer": strings.Replace(source, move+" out+8(FP),DI\n", "", 1),
						}
						if sourceKind == "GP" {
							load := fmt.Sprintf("MOV%s value+0(FP),CX\n", map[int]string{4: "L", 8: "Q"}[input])
							mutations["missing-integer"] = strings.Replace(source, load, "", 1)
							mutations["partial-integer"] = strings.Replace(source, load, "MOVB value+0(FP),CX\n", 1)
							mutations["opaque-pointer-as-integer"] = strings.Replace(source, load, fmt.Sprintf("%s p+%d(FP),CX\n", move, 8+word), 1)
						} else if sourceKind == "native" {
							mutations["missing-native-address"] = strings.Replace(source, fmt.Sprintf("%s p+%d(FP),BX\n", move, 8+word), "", 1)
						}
						for name, changed := range mutations {
							if changed == source {
								t.Fatal("unsigned input mutation did not apply", name)
							}
							if ir, err := x86ScalarFPBitViewAPI(t, changed, declaration, arch, triple, api); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
								t.Fatal("unknown data, upper bytes or opaque/native address gained authority", name, err)
							}
						}
					})
				}
			}
		}
	}
}

func TestX86UnsignedScalarIntegerFloatDeadInputsAndNativeEffects(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		move, word := "MOVQ", goWordSize(target.arch)
		if target.arch == "386" {
			move = "MOVL"
		}
		for _, member := range x86UnsignedScalarIntegerFloatOracle {
			t.Run(target.triple+"/"+member.op, func(t *testing.T) {
				declaration := "func view(p *byte)\n"
				source := fmt.Sprintf("TEXT ·view(SB),4,$0-%d\n%s p+0(FP),BX\n%s (BX),X0,X1\nRET\n", word, move, member.op)
				goAssemblerOracleOutput(t, target.arch, source, "", true)
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(api, func(t *testing.T) {
						ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, api)
						if err != nil || ir == "" {
							t.Fatal("dead native unsigned read lost its complete incoming pointer", err)
						}
						op := member.op
						if target.arch == "386" && strings.HasSuffix(op, "Q") {
							op = strings.TrimSuffix(op, "Q") + "L"
						}
						for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
							x86ScalarPrecisionRequireNativeEffects(t, text, map[string][]string{"view": {op}})
						}
						missing := strings.Replace(source, move+" p+0(FP),BX\n", "", 1)
						if ir, err := x86ScalarFPBitViewAPI(t, missing, declaration, target.arch, target.triple, api); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("Void waived an actual native source address", err)
						}
					})
				}
			})
		}
	}
}

func TestX86UnsignedScalarIntegerFloatSourceIdentityAndPhysicalBankBoundaries(t *testing.T) {
	for _, member := range x86UnsignedScalarIntegerFloatOracle {
		for _, change := range []string{"encoded", "origin", "address-size", "address-override", "segment", "pointer-GP", "caller-address-GP", "standalone-native-read", "high-bank-mode32"} {
			t.Run(member.op+"/"+change, func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, member.op+" CX,X0,X1")
				state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionBackward}
				state.gp[1], state.xmm[0], state.xmm[16] = 0xff, 0xffff, 0xffff
				arch := "amd64"
				switch change {
				case "encoded":
					ins.x86Encoded = true
				case "origin":
					ins.x86SourceRaw = &x86SourceRawInstruction{op: ins.Op, args: ins.Args}
				case "address-size":
					ins.x86AddressBits = 16
				case "address-override":
					ins.x86UnboundAddressOverride = true
				case "segment":
					ins.x86SegmentPrefix = 0x64
				case "pointer-GP":
					state.pointerGP[1] = true
				case "caller-address-GP":
					state.callerAddressGP[1] = true
				case "standalone-native-read":
					ins.Args[0] = x86ScalarLaneInstruction(t, member.op+" (BX),X0,X1").Args[0]
					state.pointerGP[3] = true
				case "high-bank-mode32":
					arch, ins.Args[1].Reg = "386", "X16"
				}
				before := state.clone()
				if x86ResultTransfer(ins, &state, nil, 0, arch) || !reflect.DeepEqual(state, before) {
					t.Fatal("unsigned numerical transfer borrowed raw/physical or pointer authority", change)
				}
			})
		}
	}
}

func TestX86UnsignedScalarIntegerFloatTargetCannotBorrowPortableArithmetic(t *testing.T) {
	for _, member := range x86UnsignedScalarIntegerFloatOracle {
		body := "MOVL value+0(FP),CX\n"
		if member.input == 8 {
			body = "MOVQ value+0(FP),CX\n"
		}
		declaration := "func view(value uint64) uint64\n"
		source := x86ResultGPSIMDAdmissionSource(t, "amd64", declaration,
			body+"PXOR X0,X0\n"+member.op+" CX,X0,X1\nMOVQ X1,ret+RESULT(FP)")
		goAssemblerOracleOutput(t, "amd64", source, "", true)
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(member.op+"/"+api, func(t *testing.T) {
				if ir, err := x86ScalarFPBitViewAPI(t, source, declaration, "amd64", "x86_64-unknown-linux-gnu", api); err != nil || ir == "" {
					t.Fatal("initialized native-target control failed before cross-target negatives", err)
				}
				for _, triple := range []string{"aarch64-unknown-linux-gnu", "wasm32-unknown-unknown"} {
					if ir, err := x86ScalarFPBitViewAPI(t, source, declaration, "amd64", triple, api); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("pure arithmetic falsely certified original native MXCSR effects on a foreign target", triple, err)
					}
				}
			})
		}
	}
}
