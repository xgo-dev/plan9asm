package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func TestX86GoCallerPackedShiftWeaviateOriginalBytes(t *testing.T) {
	// Original dot_byte_avx256.s uses c5 ed 71 d1 08 at its first
	// VPSRLW. Keep the complete encoded instruction, not a named surrogate.
	body := "VMOVDQU (DI),Y1\nLONG $0xd171edc5\nBYTE $0x08\nVMOVSS X2,(DX)"
	assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
	requireX86GoAssemblerResult(t, "amd64", assembly, true)
	for _, triple := range []string{"x86_64-unknown-linux-gnu", "x86_64-apple-darwin", "x86_64-pc-windows-msvc"} {
		for _, bound := range []bool{true, false} {
			pkg, file := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
			if !bound {
				pkg.SourceSelection = nil
			}
			resolve := func(symbol string) string { return strings.Replace(symbol, "·", "caller.", 1) }
			sigs, err := goSigsForAsmFile(pkg, file, resolve, "amd64", nil, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			options := Options{Goarch: "amd64", TargetTriple: triple, ResolveSym: resolve, Sigs: sigs}
			ir, err := Translate(file, options)
			if bound {
				if err != nil {
					t.Fatal(err)
				}
				compileLLVMToObject(t, findLLVM22Tool("llc"), triple, "original.ll", "original.o", ir)
			} else if !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("uncontracted Translate: %v", err)
			}
			ctx := llvm.NewContext()
			module, err := TranslateModuleInContext(ctx, file, options)
			if !module.IsNil() {
				module.Dispose()
			}
			ctx.Dispose()
			if bound && err != nil || !bound && !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("bound=%t module: %v", bound, err)
			}
			if err := x86CallerCoreTranslate(t, pkg, assembly, triple); bound && err != nil || !bound && !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("bound=%t GoModule: %v", bound, err)
			}
		}
	}
}

func TestX86GoCallerPackedShiftWholeFamilyEffects(t *testing.T) {
	for _, op := range x86PackedShiftNames() {
		for _, row := range x86PackedShiftRows(op, "amd64") {
			if strings.Contains(row, "(AX)") || strings.Contains(row, "M0") || strings.Contains(row, "M1") {
				continue
			}
			file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			ins := file.Funcs[0].Instrs[1]
			form, recognized, err := x86PackedShiftProperties(ins.Op, ins, "amd64")
			if !recognized || err != nil || !x86CallerVectorMoveKnown(ins) {
				t.Fatalf("missing effect %s: %v", row, err)
			}
			width := x86CallerVectorByteMask(int64(form.byteWidth))
			for _, missing := range []string{"none", "data", "count", "mask"} {
				state := x86SourceStackState{
					vectors: map[Reg]uint64{"Z0": ^uint64(0), "Z1": ^uint64(0), "Z2": 0},
					masks:   map[Reg]bool{"K1": true, "K7": true},
				}
				applicable := true
				switch missing {
				case "data":
					state.vectors[x86CallerVectorRoot(ins.Args[form.data].Reg)] &^= uint64(1) << uint(form.byteWidth-1)
				case "count":
					applicable = ins.Args[form.count].Kind != OpImm
					if applicable {
						state.vectors[x86CallerVectorRoot(ins.Args[form.count].Reg)] &^= 1
					}
				case "mask":
					applicable = form.mask >= 0
					if applicable {
						delete(state.masks, ins.Args[form.mask].Reg)
					}
				}
				if !applicable {
					continue
				}
				before, _ := x86CloneCallerVectorState(state.vectors, state.masks)
				accepted := x86CallerPackedShiftStep(&ins, form, &state, nil)
				if accepted != (missing == "none") || !accepted && !reflect.DeepEqual(before, state.vectors) {
					t.Fatalf("%s missing %s accepted=%t", row, missing, accepted)
				}
				if accepted {
					want := ^uint64(0)
					if form.mask >= 0 && !form.zeroing {
						want = ^width
					}
					if got := state.vectors[x86CallerVectorRoot(ins.Args[form.destination].Reg)]; got != want {
						t.Fatalf("%s known=%x want %x", row, got, want)
					}
				}
			}
		}
	}
}

func TestX86GoCallerPackedShiftMemoryShapesAndTargets(t *testing.T) {
	for _, op := range x86PackedShiftNames() {
		for _, row := range x86PackedShiftRows(op, "amd64") {
			if strings.Contains(row, "M0") || strings.Contains(row, "M1") {
				continue
			}
			row = strings.ReplaceAll(row, "(AX)", "(DI)")
			file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			ins := file.Funcs[0].Instrs[1]
			form, _, err := x86PackedShiftProperties(ins.Op, ins, "amd64")
			if err != nil {
				t.Fatal(err)
			}
			if form.memory >= 0 {
				width, write, valid := x86CallerMoveMemoryShape(ins, form.memory)
				if !valid || write || int(width) != form.memoryBytes {
					t.Fatalf("incorrect read envelope %s: %d/%t/%t", row, width, write, valid)
				}
			}
			body := fmt.Sprintf("VMOVUPS (DI),Z0\nVMOVUPS (SI),Z1\nVMOVUPS (DI),Z2\nMOVQ $-1,AX\nKMOVQ AX,K1\nKMOVQ AX,K7\n%s\nVMOVSS X2,(DX)", row)
			if form.legacy {
				body = strings.Replace(body, "VMOVSS X2,(DX)", "VMOVSS X1,(DX)", 1)
			}
			assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
			requireX86GoAssemblerResult(t, "amd64", assembly, true)
			pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
			// Compile one bounded corpus per target below; individual forms here
			// also exercise the actual caller transport, not a public Ptr noalias.
			err = x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu")
			if form.legacy && form.memory >= 0 {
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("unproved legacy native-memory contract passed %s: %v", row, err)
				}
			} else if err != nil {
				t.Fatalf("%s: %v", row, err)
			}
		}
	}
}

func TestX86GoCallerPackedShiftUnprovedInputsRemainContext(t *testing.T) {
	for name, body := range map[string]string{
		"unknown data":              "VPSRLW $8,Y1,Y2\nVMOVSS X2,(DX)",
		"zero count unknown data":   "VPSRLW $0,Y1,Y2\nVMOVSS X2,(DX)",
		"saturated unknown data":    "VPSRLW $255,Y1,Y2\nVMOVSS X2,(DX)",
		"unknown count":             "VMOVUPS (DI),Y1\nVPSRLW X0,Y1,Y2\nVMOVSS X2,(DX)",
		"partial count":             "MOVL $1,AX\nMOVD AX,X0\nVMOVUPS (DI),Y1\nVPSRLVW Y0,Y1,Y2\nVMOVSS X2,(DX)",
		"unknown mask":              "VMOVUPS (DI),Y1\nVPSRLW.Z $8,Y1,K1,Y2\nVMOVSS X2,(DX)",
		"merge unknown destination": "VMOVUPS (DI),Y1\nMOVL $1,AX\nKMOVW AX,K1\nVPSRLW $8,Y1,K1,Y2\nVMOVSS X2,(DX)",
		"physical SP":               "VMOVUPS (DI),Y1\nVPSRLW 0(SP),Y1,Y2\nVMOVSS X2,(DX)",
		"FP pointer bytes":          "VMOVUPS (DI),Y1\nVPSRLW a+0(FP),Y1,Y2\nVMOVSS X2,(DX)",
		"g":                         "VMOVUPS (DI),Y1\nVPSRLW (R14),Y1,Y2\nVMOVSS X2,(DX)",
		"unknown base":              "VMOVUPS (DI),Y1\nVPSRLW (BX),Y1,Y2\nVMOVSS X2,(DX)",
		"length m128":               "VMOVUPS (DI),Y1\nVPSRLW (CX),Y1,Y2\nVMOVSS X2,(DX)",
		"partial output":            "VMOVUPS (DI),Y1\nVPSRLW $8,Y1,Y2\nVMOVUPS Y2,(DX)",
		"input write":               "VMOVUPS (DI),Y1\nVPSRLW $8,Y1,Y2\nVMOVSS X2,(DI)",
		"branch join":               "CMPQ AX,$0\nJE joined\nVMOVUPS (DI),Y1\njoined:\nVPSRLW $8,Y1,Y2\nVMOVSS X2,(DX)",
	} {
		t.Run(name, func(t *testing.T) {
			assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
			requireX86GoAssemblerResult(t, "amd64", assembly, true)
			pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
			if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("unproved source accepted: %v", err)
			}
		})
	}
}
