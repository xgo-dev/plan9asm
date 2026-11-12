package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestX86GoCallerPackedAddOriginalConsecutiveRawEffects(t *testing.T) {
	// The exact consecutive words in Weaviate dot_byte_avx256.s. Complete
	// selected typed callers are independent of its still-unclosed pointer loop.
	body := "VMOVDQU (DI),Y2\nVMOVDQU (SI),Y4\nVPXOR Y0,Y0,Y0\nLONG $0xd4f5edc5\nLONG $0xc0feedc5\nVMOVSS X0,(DX)"
	assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
	requireX86GoAssemblerResult(t, "amd64", assembly, true)
	pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
	if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); err != nil {
		t.Fatal(err)
	}
}

func TestX86GoCallerPackedAddCompleteOriginalTypedConsumers(t *testing.T) {
	for _, opcode := range append(append([]string(nil), x86WrappingAddOpcodes...), "PADDD") {
		banks := []string{"X"}
		if strings.HasPrefix(opcode, "V") {
			banks = []string{"X", "Y", "Z"}
		}
		for _, bank := range banks {
			for _, first := range []string{bank + "0", "(DI)"} {
				for mode := 0; mode < 3; mode++ {
					if !strings.HasPrefix(opcode, "V") && mode != 0 {
						continue
					}
					row, result := opcode+" "+first+",X1", "X1"
					if strings.HasPrefix(opcode, "V") {
						row, result = opcode+" "+first+","+bank+"1", "X2"
						if mode == 2 {
							row = opcode + ".Z " + first + "," + bank + "1"
						}
						if mode != 0 {
							row += ",K1"
						}
						row += "," + bank + "2"
					}
					t.Run(row, func(t *testing.T) {
						body := "VMOVUPS (DI),Z0\nVMOVUPS (SI),Z1\nVMOVUPS (DI),Z2\nMOVL $1,AX\nKMOVQ AX,K1\n" + row + "\nVMOVSS " + result + ",(DX)"
						assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
						requireX86GoAssemblerResult(t, "amd64", assembly, true)
						pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
						for _, triple := range []string{"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc"} {
							if err := x86CallerCoreTranslate(t, pkg, assembly, triple); err != nil {
								t.Fatal(err)
							}
						}
					})
				}
			}
		}
	}
}

func TestX86GoCallerPackedAddEveryLaneByteKnowledge(t *testing.T) {
	for _, opcode := range x86WrappingAddOpcodes {
		for _, mode := range []string{"", "merge", "zero"} {
			if !strings.HasPrefix(opcode, "V") && mode != "" {
				continue
			}
			row := opcode + " X0,X1"
			if strings.HasPrefix(opcode, "V") {
				row = opcode + " Z0,Z1,Z2"
				if mode != "" {
					row = opcode + " Z0,Z1,K1,Z2"
				}
				if mode == "zero" {
					row = strings.Replace(row, " ", ".Z ", 1)
				}
			}
			file, _ := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
			instruction := file.Funcs[0].Instrs[1]
			form, _, err := x86PackedWrappingAddProperties(instruction, "amd64")
			if err != nil {
				t.Fatal(err)
			}
			width := x86CallerVectorByteMask(int64(form.byteWidth))
			step := form.spec.laneBits / 8
			for operand := 0; operand < 2; operand++ {
				for missing := -1; missing < form.byteWidth; missing++ {
					vectors := map[Reg]uint64{"Z0": ^uint64(0), "Z1": ^uint64(0), "Z2": ^uint64(0)}
					if missing >= 0 {
						root := x86CallerVectorRoot(instruction.Args[operand].Reg)
						vectors[root] &^= uint64(1) << uint(missing)
					}
					state := &x86SourceStackState{vectors: vectors, masks: map[Reg]bool{"K1": true}}
					if !x86CallerPackedWrappingAddStep(&instruction, form, state, nil) {
						t.Fatal("register grammar rejected")
					}
					want := ^uint64(0)
					if missing >= 0 {
						want &^= x86CallerVectorByteMask(int64(step)) << uint(missing/step*step)
					}
					got := state.vectors[x86CallerVectorRoot(instruction.Args[form.destination].Reg)]
					// Legacy preserves its old upper view, while each vector form
					// defines it to zero. Both start fully known in this axis.
					if got != want || got&^width != want&^width {
						t.Fatalf("%s/%s missing%d input%d known=%x want=%x", opcode, mode, missing, operand, got, want)
					}
				}
			}
		}
	}
}

func TestX86GoCallerPackedAddUnknownBoundariesRemainContext(t *testing.T) {
	for name, body := range map[string]string{
		"unknown first":            "VMOVUPS (DI),Y1\nVPADDD Y0,Y1,Y2\nVMOVSS X2,(DX)",
		"unknown second":           "VMOVUPS (DI),Y0\nVPADDQ Y0,Y1,Y2\nVMOVSS X2,(DX)",
		"unknown high byte":        "MOVSS (DI),X0\nMOVSS (SI),X1\nVPADDQ Y0,Y1,Y2\nVEXTRACTF128 $1,Y2,X3\nVMOVSS X3,(DX)",
		"unknown mask":             "VMOVUPS (DI),Z0\nVMOVUPS (SI),Z1\nVPADDB.Z Z0,Z1,K1,Z2\nVMOVSS X2,(DX)",
		"unknown merge":            "VMOVUPS (DI),Z0\nVMOVUPS (SI),Z1\nKMOVQ AX,K1\nVPADDW Z0,Z1,K1,Z2\nVMOVSS X2,(DX)",
		"pointer mask":             "VMOVUPS (DI),Z0\nKMOVQ DI,K1\nVPADDQ.Z Z0,Z0,K1,Z2\nVMOVSS X2,(DX)",
		"zero mask no permission":  "VMOVUPS (DI),Z0\nMOVL $0,AX\nKMOVQ AX,K1\nVPADDD.Z (DX),Z0,K1,Z2\nVMOVSS X2,(DX)",
		"unknown address":          "VMOVUPS (DI),Z0\nVPADDB (BX),Z0,Z2\nVMOVSS X2,(DX)",
		"private stack":            "VMOVUPS (DI),Z0\nVPADDW (SP),Z0,Z2\nVMOVSS X2,(DX)",
		"legacy SP alias":          "VMOVUPS (DI),Z0\nMOVQ SP,BX\nPADDL (BX),X0\nVMOVSS X0,(DX)",
		"input store":              "VMOVUPS (DI),Z0\nVPADDQ Z0,Z0,Z2\nVMOVSS X2,(DI)",
		"MMX":                      "PADDB M0,M1\nVMOVSS X1,(DX)",
		"saturating separate":      "VMOVUPS (DI),Z0\nVPADDSW Z0,Z0,Z2\nVMOVSS X2,(DX)",
		"unknown joined bank":      "VMOVUPS (DI),Z0\nCMPQ AX,$0\nJE joined\nVMOVUPS (SI),Z1\njoined:\nVPADDW Z0,Z1,Z2\nVMOVSS X2,(DX)",
		"different pointer offset": "VMOVUPS (DI),Z0\nCMPQ AX,$0\nJE joined\nADDQ $4,DI\njoined:\nVPADDD (DI),Z0,Z2\nVMOVSS X2,(DX)",
	} {
		t.Run(name, func(t *testing.T) {
			assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
			requireX86GoAssemblerResult(t, "amd64", assembly, true)
			pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
			if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("%s escaped actual source boundary: %v", name, err)
			}
		})
	}
	// Independent caller effect shape does not allow another opcode or a
	// narrowed masked source to reuse a private instruction certificate.
	for _, row := range []string{"PADDL (DI),X0", "VPADDQ.BCST.Z (DI),Z0,K1,Z2"} {
		body := "VMOVUPS (SI),Z0\nMOVL $0,AX\nKMOVQ AX,K1\n" + row + "\nVMOVSS X0,(DX)"
		assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
		pkg, file := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
		resolve := func(symbol string) string { return strings.Replace(symbol, "·", "caller.", 1) }
		sigs, err := goSigsForAsmFile(pkg, file, resolve, "amd64", nil, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		normalized, err := normalizeX86RawFile(file, "amd64", Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu", ResolveSym: resolve, Sigs: sigs})
		if err != nil {
			t.Fatal(err)
		}
		for _, ins := range normalized.Funcs[0].Instrs {
			form, known, err := x86PackedWrappingAddProperties(ins, "amd64")
			if !known || err != nil {
				continue
			}
			access := ins.x86CallerMemory[form.memory]
			if access.width != int64(form.memoryBytes) || access.write || !x86CallerMemoryCertified(ins, form.memory) {
				t.Fatalf("missing full possible source extent for %s", row)
			}
			for _, mutation := range []string{"opcode", "width", "direction", "address"} {
				changedAccess := access
				changed := ins
				changed.Args = append([]Operand(nil), ins.Args...)
				changed.x86CallerMemory = map[int]x86CallerMemoryAccess{form.memory: access}
				switch mutation {
				case "opcode":
					changed.Op = "VPSUBQ"
				case "width":
					changedAccess.width--
					changed.x86CallerMemory[form.memory] = changedAccess
				case "direction":
					changedAccess.write = true
					changed.x86CallerMemory[form.memory] = changedAccess
				case "address":
					changed.Args[form.memory].Mem.Off++
				}
				if x86CallerMemoryCertified(changed, form.memory) {
					t.Fatal(fmt.Sprintf("%s stale %s witness", row, mutation))
				}
			}
		}
	}
}

func TestX86PackedAddLegacyVirtualMemoryCannotForgeNativeAlignment(t *testing.T) {
	for _, row := range []string{"PADDB source+0(FP),X0", "PADDW (SP),X0", "PADDL (BP),X0", "PADDQ source+0(FP),X0"} {
		t.Run(row, func(t *testing.T) {
			source := "TEXT f(SB),4,$0-64\n" + row + "\nRET\n"
			requireX86GoAssemblerResult(t, "amd64", source, true)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			sig := x86WordMaddFPType(t)
			_, err = Translate(file, Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu", Sigs: map[string]FuncSig{"f": sig}})
			if !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("virtual storage acquired physical aligned m128 permission: %v", err)
			}
		})
	}
}
