package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func x86StaticRMWTestContext(t *testing.T, arch string) *amd64Ctx {
	t.Helper()
	source, _ := x86StaticRelocationRMWFixture(true)
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	resolve := func(symbol string) string { return strings.TrimPrefix(symbol, "·") }
	return &amd64Ctx{resolve: resolve,
		fpStaticAddressValues: x86LoweredStaticAddressValues(file, resolve, nil, arch),
		fpScalarData:          x86LoweredScalarDataReads(file, resolve, nil, arch),
	}
}

func TestX86StaticRMWExactStatusAndNoEscapingFacts(t *testing.T) {
	for _, stem := range []string{"ADD", "SUB", "ADC", "SBB", "AND", "OR", "XOR"} {
		for _, memory := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/memory=%t", stem, memory), func(t *testing.T) {
				context := x86StaticRMWTestContext(t, "386")
				destination := "AX"
				if memory {
					destination = "·sink(SB)"
				}
				ins := x86ScalarLaneInstruction(t, stem+"L $·cell+8(SB),"+destination)
				state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionBackward}
				state.gp[0], state.gp[2], state.canonicalGP[0] = 0xff, 0x55, 0xff
				state.callerAddressGP[0], state.callerAddressGP[2] = true, true
				state.callerAddressOrigin[0], state.callerAddressOrigin[2] = 8, 9
				state.resultAddressGP[0] = x86ResultSlotAddress{start: 0, end: 4, valid: true}
				state.pointerGP[2] = true
				want := state.clone()
				if stem == "AND" || stem == "OR" || stem == "XOR" {
					want.flags &^= x86ByteFlagAF
				}
				if !memory {
					want.canonicalGP[0], want.callerAddressGP[0], want.callerAddressOrigin[0] = 0xf0, false, 0
					want.resultAddressGP[0] = x86ResultSlotAddress{}
				}
				query := state.clone()
				if x86ResultTransfer(ins, &query, nil, 0, "386") {
					t.Fatal("standalone transfer borrowed an actual module's storage")
				}
				accepted, known := context.scalarStaticRMWTransfer(ins, &state, nil, "386")
				if !accepted || !known || !reflect.DeepEqual(state, want) {
					t.Fatal("static operation changed unrelated numerical/address/storage state", accepted, known)
				}
			})
		}
	}
}

func TestX86StaticRMWRejectsUnboundInputsWithoutPartialState(t *testing.T) {
	for _, mutation := range []string{"no-directory", "unknown-address", "readonly", "short",
		"uninitialized-source", "uninitialized-carry", "raw", "address-override", "segment", "unbound-destination"} {
		t.Run(mutation, func(t *testing.T) {
			context := x86StaticRMWTestContext(t, "386")
			ins := x86ScalarLaneInstruction(t, "ADCL $·cell+8(SB),·sink(SB)")
			state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionForward}
			state.gp[2], state.pointerGP[2], state.callerAddressGP[2] = 0x55, true, true
			switch mutation {
			case "no-directory":
				context.fpStaticAddressValues = nil
			case "unknown-address":
				delete(context.fpStaticAddressValues.objects, "cell")
			case "readonly":
				context.fpStaticAddressValues.writable["sink"] = false
			case "short":
				context.fpScalarData[x86StaticSBAddress{"·sink", 0}] = 3
			case "uninitialized-source":
				ins.Args[0] = Operand{Kind: OpReg, Reg: AX}
			case "uninitialized-carry":
				state.flags &^= x86ByteFlagCF
			case "raw":
				ins.x86Encoded = true
			case "address-override":
				ins.x86AddressBits = 16
			case "segment":
				ins.x86SegmentPrefix = 0x64
			case "unbound-destination":
				ins.Args[1] = Operand{Kind: OpSym, Sym: "external(SB)"}
			}
			before := state.clone()
			if accepted, _ := context.scalarStaticRMWTransfer(ins, &state, nil, "386"); accepted || !reflect.DeepEqual(state, before) {
				t.Fatal("failed static input proof partially changed state")
			}
		})
	}
}

func TestX86StaticRMWActualMutabilityDirectory(t *testing.T) {
	for _, flags := range []string{"", "0", "16", "NOPTR", "8", "RODATA|NOPTR", "missing"} {
		t.Run(flags, func(t *testing.T) {
			source, _ := x86StaticRelocationRMWFixture(true)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			file.Globl[1].Flags = flags
			resolve := func(symbol string) string { return strings.TrimPrefix(symbol, "·") }
			values := x86LoweredStaticAddressValues(file, resolve, nil, "386")
			want := flags == "" || flags == "0" || flags == "16" || flags == "NOPTR"
			if values == nil || values.writable["sink"] != want || values.writable["cell"] {
				t.Fatal("numeric object existence changed actual GLOBL mutability", flags)
			}
		})
	}
}

func TestX86StaticBitStringNativeContinuationDoesNotExportFacts(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range x86LockScalarOracleForms(arch) {
			if !strings.HasPrefix(row.op, "BT") {
				continue
			}
			t.Run(arch+"/"+row.text, func(t *testing.T) {
				context := x86StaticBitStringTestContext(t, arch)
				ins := x86ScalarLaneInstruction(t, strings.Replace(row.text, "1(SI)", "·sink(SB)", 1))
				state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionBackward}
				index, _, _ := x86ResultGP(CX, x86ResultPointerWord(arch), arch)
				state.gp[index], state.canonicalGP[index] = 0xff, 0x55
				state.callerAddressGP[index], state.callerAddressOrigin[index] = true, 9
				state.gp[0], state.pointerGP[0] = 0, true
				want := state.clone()
				want.flags &^= x86ByteFlagOF | x86ByteFlagSF | x86ByteFlagAF | x86ByteFlagPF
				query := state.clone()
				if x86ResultTransfer(ins, &query, nil, 0, arch) {
					t.Fatal("standalone transfer borrowed an actual module's native storage")
				}
				accepted, known := context.scalarStaticRMWTransfer(ins, &state, nil, arch)
				if !accepted || !known || !reflect.DeepEqual(state, want) {
					t.Fatal("paired native bit string changed unrelated state or lost CF", accepted, known)
				}
			})
		}
	}
}

func TestX86StaticBitStringRejectsUnownedOrUndefinedInputs(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range x86LockScalarOracleForms(arch) {
			if !strings.HasPrefix(row.op, "BT") || !strings.Contains(row.text, "CX,") {
				continue
			}
			for _, mutation := range []string{"no-directory", "no-object", "readonly", "short-base", "external",
				"missing-index", "partial-index", "pointer-index", "raw", "address-override", "segment"} {
				t.Run(arch+"/"+row.text+"/"+mutation, func(t *testing.T) {
					context := x86StaticBitStringTestContext(t, arch)
					ins := x86ScalarLaneInstruction(t, strings.Replace(row.text, "1(SI)", "·sink(SB)", 1))
					form, _, _ := x86LockScalarRMWProperties(ins.Op, ins, arch)
					state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionForward}
					index, _, _ := x86ResultGP(CX, x86ResultPointerWord(arch), arch)
					state.gp[index] = 0xff
					switch mutation {
					case "no-directory":
						context.fpStaticAddressValues = nil
					case "no-object":
						delete(context.fpStaticAddressValues.objects, "sink")
					case "readonly":
						context.fpStaticAddressValues.writable["sink"] = false
					case "short-base":
						context.fpScalarData[x86StaticSBAddress{"·sink", 0}] = int64(form.spec.bits/8 - 1)
					case "external":
						ins.Args[1] = Operand{Kind: OpSym, Sym: "external(SB)"}
					case "missing-index":
						state.gp[index] = 0
					case "partial-index":
						state.gp[index] = 1
					case "pointer-index":
						state.gp[index], state.pointerGP[index] = 0, true
					case "raw":
						ins.x86Encoded = true
					case "address-override":
						ins.x86AddressBits = 16
					case "segment":
						ins.x86SegmentPrefix = 0x64
					}
					before := state.clone()
					if accepted, _ := context.scalarStaticRMWTransfer(ins, &state, nil, arch); accepted || !reflect.DeepEqual(state, before) {
						t.Fatal("unowned native bit string acquired facts or partially changed state")
					}
				})
			}
		}
	}
}

func x86StaticBitStringTestContext(t *testing.T, arch string) *amd64Ctx {
	t.Helper()
	file, err := Parse(ArchAMD64, "DATA ·sink+0(SB)/8,$0x1234\n"+
		"DATA ·sink+8(SB)/8,$0x5678\nGLOBL ·sink(SB),16,$16\n"+
		"TEXT ·base(SB),4,$0-0\nBTSL $1,·sink(SB)\nRET\n")
	if err != nil {
		t.Fatal(err)
	}
	resolve := func(symbol string) string { return strings.TrimPrefix(symbol, "·") }
	context := &amd64Ctx{resolve: resolve,
		fpStaticAddressValues: x86LoweredStaticAddressValues(file, resolve, nil, arch),
		fpScalarData:          x86LoweredScalarDataReads(file, resolve, nil, arch),
	}
	if context.fpScalarData[x86StaticSBAddress{"·sink", 0}] != 16 {
		t.Fatal("actual complete source did not expose its initialized base word")
	}
	return context
}
