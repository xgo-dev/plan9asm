package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

func x86VSIBModeRoleInstruction(t *testing.T, original Instr, data, mask int) Instr {
	t.Helper()
	form, known, err := x86VSIBProperties(original, "amd64")
	if !known || err != nil || form.prefetch {
		t.Fatal("expected an existing complete data VSIB form", err)
	}
	destination := fmt.Sprintf("%s%d", string(form.data.Reg)[:1], data)
	index := string(form.memory.Mem.Index)[:1] + "0"
	memory := fmt.Sprintf("(AX)(%s*1)", index)
	operands := memory + ",K1," + destination
	if form.scatter {
		operands = destination + ",K1," + memory
	} else if !form.evex {
		operands = fmt.Sprintf("%s%d,%s,%s", string(form.mask.Reg)[:1], mask, memory, destination)
	}
	return x86ScalarLaneInstruction(t, string(form.opcode)+" "+operands)
}

// These are explicit controlled model facts, not a Go source/entry certificate.
// The complete input state isolates the VSIB NUM transition from earlier loads.
func TestX86VSIBMode32NumericalRegisterRoles(t *testing.T) {
	avx, err := goasmrules.LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	rows, err := goasmrules.X86IndexedMemoryRows(goasmrules.X86LegacyCatalog{}, avx)
	if err != nil {
		t.Fatal(err)
	}
	dataRows := 0
	for _, row := range rows {
		original := x86ScalarLaneInstruction(t, row.Witnesses[0].Instruction)
		form, known, err := x86VSIBProperties(original, "amd64")
		if !known || err != nil {
			t.Fatal("original official form", row.ID, err)
		}
		if form.prefetch {
			continue
		}
		dataRows++
		roles := []string{"data"}
		if !form.evex {
			roles = append(roles, "vector-mask")
		}
		for _, role := range roles {
			for _, bank := range []int{7, 8, 15, 16, 31} {
				data, mask := 2, 1
				if role == "data" {
					data = bank
				} else {
					mask = bank
				}
				ins := x86VSIBModeRoleInstruction(t, original, data, mask)
				for _, arch := range []string{"386", "amd64"} {
					t.Run(fmt.Sprintf("%s/%s/%s/%d", row.ID, arch, role, bank), func(t *testing.T) {
						// Retain the old physical Go-format class. In particular,
						// 386 X/Y data and VEX-mask high aliases are not deleted.
						_, matched, parseError := x86VSIBProperties(ins, arch)
						formatAllowed := bank < 16 || form.evex && role == "data"
						if arch == "386" && role == "data" && form.dataBytes == 64 && bank >= 8 {
							formatAllowed = false
						}
						if !matched || formatAllowed != (parseError == nil) {
							t.Fatal("physical format boundary changed", parseError, formatAllowed)
						}
						if !formatAllowed {
							return // A physical rejection is distinct from the NUM guard.
						}
						state := x86ResultState{flags: x86ByteFlagsAll, masks: [8]bool{1: true}}
						state.pointerGP[0] = true
						for number := 0; number < 32; number++ {
							state.writeVector(number, 64, ^uint64(0), false)
						}
						baseline := state.clone()
						low := x86VSIBModeRoleInstruction(t, original, 2, 1)
						if accepted, recognized := x86ResultVSIBStep(low, &baseline, arch, true); !accepted || !recognized {
							t.Fatal("complete low-bank numerical input must precede the guard")
						}
						before := state.clone()
						accepted, recognized := x86ResultVSIBStep(ins, &state, arch, true)
						want := arch == "amd64" || bank < 8
						if !recognized || accepted != want {
							t.Fatal("numerical bank availability differs from source format", accepted, want)
						}
						if !want && !reflect.DeepEqual(state, before) {
							t.Fatal("rejected numerical bank changed source facts")
						}
					})
				}
			}
		}
	}
	if dataRows != 64 {
		t.Fatal("complete gather/scatter source-row closure", dataRows)
	}
}

// Actual public sources are independent of the controlled state above. High
// source rejection can occur at an earlier initializer; it is not attributed
// to the VSIB guard without the controlled-transition evidence.
func TestX86VSIBMode32InitializedPublicSourceRoles(t *testing.T) {
	avx, err := goasmrules.LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	rows, err := goasmrules.X86IndexedMemoryRows(goasmrules.X86LegacyCatalog{}, avx)
	if err != nil {
		t.Fatal(err)
	}
	selected := 0
	for _, row := range rows {
		if row.Opcode != "VGATHERDPS" && row.Opcode != "VPSCATTERDD" {
			continue
		}
		if !strings.HasSuffix(row.ID, "/0") && !(row.Opcode == "VGATHERDPS" && strings.HasSuffix(row.ID, "/2")) {
			continue
		}
		selected++
		w := row.Witnesses[0]
		original := x86ScalarLaneInstruction(t, w.Instruction)
		low := x86VSIBModeRoleInstruction(t, original, 2, 1)
		form, _, _ := x86VSIBProperties(low, "amd64")
		oldIndex, oldData := w.Second, w.Destination
		w.Second, w.Destination = string(form.memory.Mem.Index), string(form.data.Reg)
		w.Instruction = strings.ReplaceAll(w.Instruction, oldIndex, w.Second)
		w.Instruction = strings.ReplaceAll(w.Instruction, oldData, w.Destination)
		for _, arch := range []string{"amd64", "386"} {
			t.Run(row.ID+"/"+arch, func(t *testing.T) {
				cases := []x86OfficialPackedCase{{row: row.ID, witness: w}}
				source, declarations := x86OfficialVSIBAssembly(cases)
				triple := "x86_64-unknown-linux-gnu"
				if arch == "386" {
					triple = "i386-unknown-linux-gnu"
					source = strings.NewReplacer(
						"$0-24", "$0-12", "MOVQ out+0(FP),DX", "MOVL out+0(FP),DX",
						"MOVQ data+8(FP),AX", "MOVL data+4(FP),AX",
						"MOVQ seed+16(FP),BX", "MOVL seed+8(FP),BX",
						"MOVQ $1,R9\nKMOVQ R9,K1", "MOVL $1,CX\nKMOVW CX,K1",
						"MOVQ DX,AX", "MOVL DX,AX",
					).Replace(source)
				}
				requireX86GoAssemblerResult(t, arch, source, true)
				for _, api := range []string{"text", "module", "Go"} {
					if _, err := x86ScalarFPBitViewAPI(t, source, declarations, arch, triple, api); err != nil {
						t.Fatal("complete low-bank public source", api, err)
					}
					if arch != "386" {
						continue
					}
					// Preserve the result carrier width rather than introducing Z8
					// into a mode32 X/Y data observation through the initializer.
					high := strings.NewReplacer("X2", "X8", "Y2", "Y8", "Z2", string(form.data.Reg)[:1]+"8").Replace(source)
					if ir, err := x86ScalarFPBitViewAPI(t, high, declarations, arch, triple, api); !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
						t.Fatal("mode32 high data acquired public NUM", api, err)
					}
					if !form.evex {
						high = strings.NewReplacer("X1", "X8", "Y1", "Y8").Replace(source)
						if ir, err := x86ScalarFPBitViewAPI(t, high, declarations, arch, triple, api); !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
							t.Fatal("mode32 high VEX mask acquired public NUM", api, err)
						}
					}
				}
			})
		}
	}
	if selected != 3 {
		t.Fatal("expected one VEX gather, EVEX gather and scatter source", selected)
	}
}
