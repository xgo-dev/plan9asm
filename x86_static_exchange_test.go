package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

type x86StaticExchangeFixture struct {
	name, source, declaration string
}

func x86StaticExchangeFixtures(arch string) []x86StaticExchangeFixture {
	word, move, typ, widths := 8, "MOVQ", "uint64", "BWLQ"
	if arch == "386" {
		word, move, typ, widths = 4, "MOVL", "uint32", "BWL"
	}
	var fixtures []x86StaticExchangeFixture
	for _, initialized := range []bool{false, true} {
		for _, stem := range []string{"XADD", "XCHG"} {
			for _, width := range widths {
				registers := []string{"CX"}
				if arch == "amd64" {
					registers[0] = "R11"
				}
				if width == 'B' {
					registers = append(registers, "AH")
				}
				for _, register := range registers {
					orders := 1
					if stem == "XCHG" {
						orders = 2
					}
					for order := 0; order < orders; order++ {
						name := fmt.Sprintf("Exchange%d", len(fixtures))
						cell := "·Cell" + name
						var source strings.Builder
						if initialized {
							fmt.Fprintf(&source, "DATA %s+0(SB)/8,$0x12345678\nDATA %s+8(SB)/8,$0x10203040\n", cell, cell)
						}
						flags, root := 16, register
						if initialized {
							flags = 0
						}
						if register == "AH" {
							root = "AX"
						}
						fmt.Fprintf(&source, "GLOBL %s(SB),%d,$16\nTEXT ·%s(SB),4,$0-%d\n%s seed+0(FP),%s\nCLC\n", cell, flags, name, 2*word, move, root)
						operands := register + "," + cell + "+3(SB)"
						if order == 1 {
							operands = cell + "+3(SB)," + register
						}
						fmt.Fprintf(&source, "%s%c %s\nSETCS DL\nMOVBLZX DL,DX\n%s %s+3(SB),BX\nXOR%s %s,BX\nXOR%s DX,BX\n%s BX,ret+%d(FP)\nRET\n",
							stem, width, operands, move, cell, move[3:], root, move[3:], move, word)
						fixtures = append(fixtures, x86StaticExchangeFixture{name, source.String(), fmt.Sprintf("func %s(seed %s) %s\n", name, typ, typ)})
					}
				}
			}
		}
	}
	return fixtures
}

func TestX86StaticExchangeCompleteFamilyInitializedObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			fixtures := x86StaticExchangeFixtures(target.arch)
			want := 30
			if target.arch == "386" {
				want = 24
			}
			if len(fixtures) != want || want > 32 {
				t.Fatal("complete DATA/BSS, width and operand-order inventory changed", len(fixtures), want)
			}
			var source, declarations strings.Builder
			for _, fixture := range fixtures {
				source.WriteString(fixture.source)
				declarations.WriteString(fixture.declaration)
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, fixture := range fixtures {
				t.Run(fixture.name, func(t *testing.T) {
					for _, api := range []string{"text", "module", "Go"} {
						ir, err := x86ScalarFPBitViewAPI(t, fixture.source, fixture.declaration, target.arch, target.triple, api)
						if err != nil || ir == "" {
							t.Error("actual mutable numerical storage lost its exchange continuation", api, err)
						}
					}
				})
			}
			if t.Failed() {
				return // Every independent source/API ran; failed IR is not object evidence.
			}
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
				if err != nil {
					t.Fatal("complete initialized exchange source", api, err)
				}
				for _, output := range []string{ir, x86DwordProductIROptimize(t, ir)} {
					// Every retained source here is bare. Adjacent LOCK sources and
					// their per-function target bytes have an independent owner.
					if strings.Count(output, "asm sideeffect") != want || strings.Count(output, "xadd") != want/3 ||
						strings.Count(output, "xchg") != 2*want/3 || strings.Count(output, "lock; ") != strings.Count(source.String(), "\nLOCK\n") {
						t.Fatal("original native exchange, locking or memory effect was lost", api, output)
					}
					for _, level := range []string{"-O0", "-O2"} {
						x86PackedStringCompileObject(t, llc, target.triple, output, level)
					}
				}
			}
		})
	}
}

func TestX86StaticExchangeRejectsMissingSourceRoles(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, fixture := range x86StaticExchangeFixtures(arch) {
			for _, mutation := range []string{"external", "readonly", "short", "relocated", "missing-register", "pointer-register"} {
				t.Run(arch+"/"+fixture.name+"/"+mutation, func(t *testing.T) {
					source := fixture.source
					cell := "·Cell" + fixture.name
					declaration := fixture.declaration
					switch mutation {
					case "external", "short", "relocated":
						start := strings.Index(source, "TEXT ")
						if start < 0 {
							t.Fatal("fixture lost complete TEXT")
						}
						source = source[start:]
						if mutation == "short" {
							source = "GLOBL " + cell + "(SB),16,$3\n" + source
						} else if mutation == "relocated" {
							word := 4
							if arch == "amd64" {
								word = 8
							}
							source = fmt.Sprintf("DATA %s+0(SB)/%d,$%s(SB)\nGLOBL %s(SB),16,$16\n", cell, word, cell, cell) + source
						}
					case "readonly":
						source = strings.ReplaceAll(source, "(SB),16,$16", "(SB),8,$16")
						source = strings.ReplaceAll(source, "(SB),0,$16", "(SB),8,$16")
					case "missing-register":
						start := strings.Index(source, " seed+0(FP),")
						end := strings.Index(source[start:], "\n") + start
						source = source[:start] + " $0,DX" + source[end:]
					case "pointer-register":
						declaration = strings.Replace(declaration, "seed uint", "seed *uint", 1)
					}
					if source == fixture.source && declaration == fixture.declaration {
						t.Fatal("source-role mutation changed nothing", mutation)
					}
					for _, api := range []string{"text", "module", "Go"} {
						ir, err := x86ScalarFPBitViewAPI(t, source, declaration, arch, x86AddressMemoryTargets(arch)[0], api)
						if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("exchange acquired undefined or unowned numerical storage/input", mutation, api, err)
						}
					}
				})
			}
		}
	}
}

func TestX86StaticExchangeExactEffectsAndInputBoundaries(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, fixture := range x86StaticExchangeFixtures(arch) {
			t.Run(arch+"/"+fixture.name, func(t *testing.T) {
				file, err := Parse(ArchAMD64, fixture.source)
				if err != nil {
					t.Fatal(err)
				}
				var instruction Instr
				for _, ins := range file.Funcs[0].Instrs {
					if strings.HasPrefix(string(ins.Op), "XADD") || strings.HasPrefix(string(ins.Op), "XCHG") {
						instruction = ins
						break
					}
				}
				spec, found := amd64ExchangeSpecs[instruction.Op]
				if !found {
					t.Fatal("fixture lost the original exchange")
				}
				form, err := parseAMD64ExchangeForm(arch, instruction.Op, spec, instruction)
				if err != nil {
					t.Fatal(err)
				}
				width := int64(spec.bits / 8)
				index, mask, valid := x86ResultGP(form.register.Reg, width, arch)
				address, static := x86StaticSBReadAddress(form.other, arch)
				if !valid || !static {
					t.Fatal("fixture lost exact typed operands")
				}
				resolve := func(symbol string) string { return strings.TrimPrefix(symbol, "·") }
				newContext := func() *amd64Ctx {
					return &amd64Ctx{resolve: resolve,
						fpStaticAddressValues: x86LoweredStaticAddressValues(file, resolve, nil, arch),
						fpScalarData:          x86LoweredScalarDataReads(file, resolve, nil, arch)}
				}
				for _, flags := range []uint8{0, x86ByteFlagCF, x86ByteFlagsAll} {
					state := x86ResultState{flags: flags, direction: x86ResultDirectionBackward, boolFrameGP: new([16]x86ResultSlotAddress)}
					state.gp[index], state.canonicalGP[index] = 0xaa|mask, 0xff
					state.callerAddressGP[index], state.callerAddressOrigin[index] = true, 9
					state.resultAddressGP[index] = x86ResultSlotAddress{start: 2, end: 5, valid: true}
					state.boolFrameGP[index] = x86ResultSlotAddress{start: 3, end: 7, valid: true}
					state.gp[15], state.pointerGP[15] = 0x55, true
					want := state.clone()
					want.gp[index] |= mask
					if width >= 4 {
						want.gp[index] = 0xff
					}
					want.canonicalGP[index] &^= mask
					want.callerAddressGP[index], want.callerAddressOrigin[index] = false, 0
					want.resultAddressGP[index], want.boolFrameGP[index] = x86ResultSlotAddress{}, x86ResultSlotAddress{}
					if spec.kind == amd64ExchangeAdd {
						want.flags = x86ByteFlagsAll
					}
					query := state.clone()
					if x86ResultTransfer(instruction, &query, nil, 0, arch) {
						t.Fatal("standalone query borrowed actual-module storage")
					}
					if accepted, known := newContext().scalarStaticExchangeTransfer(instruction, &state, nil, arch); !known || !accepted || !reflect.DeepEqual(state, want) {
						t.Fatal("exchange changed width, alias, FLAGS, DF or unrelated facts", flags, state, want)
					}
				}
				for _, mutation := range []string{"directory", "object", "readonly", "extent", "pointer", "raw", "address", "segment", "numerical"} {
					c := newContext()
					changed := instruction
					state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionForward}
					state.gp[index] = 0xff
					name := resolveAssemblyDataSymbol(address.symbol, resolve)
					switch mutation {
					case "directory":
						c.fpStaticAddressValues = nil
					case "object":
						delete(c.fpStaticAddressValues.objects, name)
					case "readonly":
						c.fpStaticAddressValues.writable[name] = false
					case "extent":
						c.fpScalarData[address] = width - 1
					case "pointer":
						state.pointerGP[index] = true
					case "raw":
						changed.x86Encoded = true
					case "address":
						changed.x86AddressBits = 16
					case "segment":
						changed.x86SegmentPrefix = 0x64
					case "numerical":
						state.gp[index] &^= mask
					}
					before := state.clone()
					if accepted, _ := c.scalarStaticExchangeTransfer(changed, &state, nil, arch); accepted || !reflect.DeepEqual(state, before) {
						t.Fatal("failed static exchange inputs changed state", mutation)
					}
				}
				for bit := uint(0); bit < 8; bit++ {
					if mask&(1<<bit) == 0 {
						continue
					}
					state := x86ResultState{flags: x86ByteFlagsAll}
					state.gp[index] = 0xff &^ (1 << bit)
					before := state.clone()
					if accepted, _ := newContext().scalarStaticExchangeTransfer(instruction, &state, nil, arch); accepted || !reflect.DeepEqual(state, before) {
						t.Fatal("exchange invented an input byte", bit)
					}
				}
			})
		}
	}
}
