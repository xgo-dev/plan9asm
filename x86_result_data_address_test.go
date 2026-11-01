package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestX86StaticAddressValueDirectoryRejectsAliasesAndCode(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, mutation := range []string{
			"external target", "code target", "signature target", "signature alias",
			"coalesced holder", "coalesced target", "unresolved extent", "oversize target",
			"overlap holder", "code carrier", "block address", "prepared code address",
			"wrong relocation width", "mixed relocation", "missing target",
		} {
			t.Run(arch+"/"+mutation, func(t *testing.T) {
				file, err := Parse(ArchAMD64, x86RelocationResultSource(arch, "load"))
				if err != nil {
					t.Fatal(err)
				}
				resolve := func(symbol string) string {
					return strings.TrimPrefix(strings.TrimPrefix(symbol, "·"), "alias-")
				}
				key := x86StaticSBAddress{"box<>", 8}
				if values := x86LoweredStaticAddressValues(file, resolve, nil, arch); values == nil || !values.cells[key] {
					t.Fatal("complete original relocation is missing")
				}
				var sigs map[string]FuncSig
				switch mutation {
				case "external target":
					file.Data[1].Addr = "external(SB)"
				case "code target":
					file.Funcs = append(file.Funcs, Func{Sym: "bytes<>"})
				case "signature target":
					sigs = map[string]FuncSig{"bytes<>": {Ret: Void}}
				case "signature alias":
					sigs = map[string]FuncSig{"other": {Ret: Void, Name: "bytes<>"}}
				case "coalesced holder":
					file.Globl = append(file.Globl, GloblStmt{Sym: "alias-box<>", Size: 24})
				case "coalesced target":
					file.Globl = append(file.Globl, GloblStmt{Sym: "alias-bytes<>", Size: 16})
				case "unresolved extent":
					file.Globl[0].SizeRaw = "missing"
				case "oversize target":
					file.Globl[0].Size = maxDataGlobalSize + 1
				case "overlap holder":
					file.Data = append(file.Data, DataStmt{Sym: "box<>", Off: 8, Width: 1, Value: 1})
				case "code carrier":
					file.x86ContinuationGraph = &x86ContinuationGraph{tables: map[string]x86ContinuationTable{"box<>": {}}}
				case "block address":
					file.x86ContinuationGraph = &x86ContinuationGraph{addresses: map[string]x86Continuation{"bytes<>": {root: "Value", label: "inner"}}}
				case "prepared code address":
					file.Funcs[0].x86ContinuationAddresses = map[string]x86Continuation{"bytes<>": {root: "Value", label: "inner"}}
				case "wrong relocation width":
					file.Data[1].Width /= 2
				case "mixed relocation":
					file.Data[1].Value = 1
				case "missing target":
					file.Data, file.Globl = file.Data[1:], file.Globl[1:]
				}
				if values := x86LoweredStaticAddressValues(file, resolve, sigs, arch); values != nil && values.cells[key] {
					t.Fatal("unclosed object or code identity supplied a numerical DATA address", mutation)
				}
			})
		}
	}
}

func TestX86StaticAddressValueWritesOnlyNumericalDestination(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, form := range []string{"load", "address"} {
			for _, prior := range []uint8{0, 0x55, 0xff} {
				t.Run(fmt.Sprintf("%s/%s/%x", arch, form, prior), func(t *testing.T) {
					file, err := Parse(ArchAMD64, x86RelocationResultSource(arch, form))
					if err != nil {
						t.Fatal(err)
					}
					resolve := func(symbol string) string { return strings.TrimPrefix(symbol, "·") }
					context := &amd64Ctx{resolve: resolve, fpStaticAddressValues: x86LoweredStaticAddressValues(file, resolve, nil, arch)}
					state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionBackward}
					state.gp[0], state.gp[2], state.canonicalGP[0] = prior, 0x55, 0xff
					state.pointerGP[0], state.pointerGP[2] = true, true
					state.callerAddressGP[0], state.callerAddressGP[2] = true, true
					state.callerAddressOrigin[0], state.callerAddressOrigin[2] = 8, 9
					state.resultAddressGP[0] = x86ResultSlotAddress{start: 0, end: 8, valid: true}
					expected := state.clone()
					expected.gp[0], expected.canonicalGP[0] = 0xff, 0
					if arch == "386" {
						expected.canonicalGP[0] = 0xf0
					}
					expected.pointerGP[0], expected.callerAddressGP[0], expected.callerAddressOrigin[0] = false, false, 0
					expected.resultAddressGP[0] = x86ResultSlotAddress{}
					var move Instr
					for _, ins := range file.Funcs[0].Instrs {
						if len(ins.Args) == 2 && ins.Args[1].Kind == OpReg {
							move = ins
							break
						}
					}
					accepted, known := context.scalarStaticAddressValueTransfer(move, &state, nil, arch)
					if !accepted || !known || !reflect.DeepEqual(state, expected) {
						t.Fatalf("address value changed another state domain: accepted=%t known=%t", accepted, known)
					}
				})
			}
		}
	}
}

func TestX86StaticAddressValuesCannotSupplyDeclarationOnlyProof(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, form := range []string{"load", "address"} {
			t.Run(arch+"/"+form, func(t *testing.T) {
				_, _, signature, _ := x86ResultInitializationFixture(t, arch, "func Value() uintptr", "RET")
				file, err := Parse(ArchAMD64, x86RelocationResultSource(arch, form))
				if err != nil {
					t.Fatal(err)
				}
				for _, check := range []func(Func, FuncSig, string) error{CheckX86ABI0ResultInitialization, checkX86ScalarFPResultInitialization} {
					if err := check(file.Funcs[0], signature, arch); !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("standalone declaration query acquired an emitted module", err)
					}
				}
			})
		}
	}
}
