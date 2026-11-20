package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// These rows come from cmd/internal/obj/x86's yxm and _yvandnpd tables.
// Saturation changes arithmetic, not the operand availability obligation.
func x86PackedSubtractCallerRows() []string {
	var rows []string
	for _, opcode := range []string{
		"PSUBB", "PSUBW", "PSUBL", "PSUBQ",
		"PSUBSB", "PSUBSW", "PSUBUSB", "PSUBUSW",
	} {
		rows = append(rows, opcode+" X0,X15", opcode+" (DI),X15")
	}
	for _, opcode := range []string{
		"VPSUBB", "VPSUBW", "VPSUBD", "VPSUBQ",
		"VPSUBSB", "VPSUBSW", "VPSUBUSB", "VPSUBUSW",
	} {
		for _, bank := range []string{"X", "Y", "Z"} {
			rows = append(rows,
				fmt.Sprintf("%s %s0,%s1,%s2", opcode, bank, bank, bank),
				fmt.Sprintf("%s (DI),%s1,%s2", opcode, bank, bank),
				fmt.Sprintf("%s %s20,%s21,%s22", opcode, bank, bank, bank),
			)
			for _, suffix := range []string{"", ".Z"} {
				rows = append(rows,
					fmt.Sprintf("%s%s %s20,%s21,K1,%s22", opcode, suffix, bank, bank, bank),
					fmt.Sprintf("%s%s (DI),%s21,K1,%s22", opcode, suffix, bank, bank),
				)
			}
			if opcode == "VPSUBD" || opcode == "VPSUBQ" {
				rows = append(rows,
					fmt.Sprintf("%s.BCST (DI),%s21,%s22", opcode, bank, bank),
					fmt.Sprintf("%s.BCST (DI),%s21,K1,%s22", opcode, bank, bank),
					fmt.Sprintf("%s.BCST.Z (DI),%s21,K1,%s22", opcode, bank, bank),
				)
			}
		}
	}
	return rows
}

func TestX86GoCallerPackedSubtractCompleteOriginalTypedConsumers(t *testing.T) {
	rows := x86PackedSubtractCallerRows()
	if len(rows) != 202 {
		t.Fatalf("complete Go subtract surface changed: %d rows", len(rows))
	}
	for _, row := range rows {
		t.Run(row, func(t *testing.T) {
			operands := strings.Split(strings.Fields(row)[1], ",")
			destination := operands[len(operands)-1]
			result := "X" + destination[1:]
			body := "VMOVUPS (DI),Z0\nVMOVUPS (SI),Z1\nVMOVUPS (DI),Z2\n" +
				"VMOVUPS (SI),Z15\nVMOVUPS (DI),Z20\nVMOVUPS (SI),Z21\n" +
				"VMOVUPS (DI),Z22\nMOVL $1,AX\nKMOVQ AX,K1\n" +
				row + "\nVMOVSS " + result + ",(DX)"
			assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
			requireX86GoAssemblerResult(t, "amd64", assembly, true)
			pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
			for _, triple := range []string{
				"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc",
			} {
				if err := x86CallerCoreTranslate(t, pkg, assembly, triple); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestX86PackedSubtractMaskedLoadsRetainActiveLaneEffects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	for _, opcode := range []string{
		"VPSUBB", "VPSUBW", "VPSUBD", "VPSUBQ",
		"VPSUBSB", "VPSUBSW", "VPSUBUSB", "VPSUBUSW",
	} {
		for _, bank := range []string{"X", "Y", "Z"} {
			for _, suffix := range []string{".Z", ".BCST.Z"} {
				if suffix == ".BCST.Z" && opcode != "VPSUBD" && opcode != "VPSUBQ" {
					continue
				}
				row := fmt.Sprintf("%s%s (AX),%s1,K1,%s2", opcode, suffix, bank, bank)
				t.Run(row, func(t *testing.T) {
					assembly := "TEXT maskedsubtract(SB),4,$0-0\n" + row + "\nRET\n"
					ir := x86UnboundVoidScalarFormatObject(t, assembly, "maskedsubtract", "amd64", "x86_64-unknown-linux-gnu")
					if !strings.Contains(ir, "load volatile") || !strings.Contains(ir, "br i1") {
						t.Fatal("masked source needs conditional volatile active-lane reads, not an unconditional vector load")
					}
					compileLLVMToObject(t, llc, "x86_64-unknown-linux-gnu", "masked-subtract.ll", "masked-subtract.o", ir)
				})
			}
		}
	}
}

func TestX86GoCallerPackedSubtractEveryLaneByteKnowledge(t *testing.T) {
	for _, row := range x86PackedSubtractCallerRows() {
		file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		instruction := file.Funcs[0].Instrs[1]
		form, _, err := x86PackedSubtractProperties(instruction, "amd64")
		if err != nil {
			t.Fatal(err)
		}
		if form.memory >= 0 {
			continue // Actual source extents are covered by the typed consumers.
		}
		for operand := 0; operand < 2; operand++ {
			for missing := -1; missing < form.byteWidth; missing++ {
				vectors := make(map[Reg]uint64)
				for _, arg := range instruction.Args {
					if amd64VectorByteWidth(arg.Reg) != 0 {
						vectors[x86CallerVectorRoot(arg.Reg)] = ^uint64(0)
					}
				}
				if missing >= 0 {
					vectors[x86CallerVectorRoot(instruction.Args[operand].Reg)] &^= uint64(1) << uint(missing)
				}
				state := &x86SourceStackState{vectors: vectors, masks: map[Reg]bool{"K1": true}}
				if !x86CallerVectorMoveStep(&instruction, state, nil) {
					t.Fatalf("registered subtract shape rejected: %s", row)
				}
				want := ^uint64(0)
				if missing >= 0 {
					bytes := form.laneBits / 8
					want &^= x86CallerVectorByteMask(int64(bytes)) << uint(missing/bytes*bytes)
				}
				got := state.vectors[x86CallerVectorRoot(instruction.Args[form.destination].Reg)]
				if got != want {
					t.Fatalf("%s missing byte%d input%d: known=%x want=%x", row, missing, operand, got, want)
				}
			}
		}
	}
}

func TestX86GoCallerPackedSubtractUnknownBoundariesRemainContext(t *testing.T) {
	for name, body := range map[string]string{
		"unknown first":            "VMOVUPS (DI),Y1\nVPSUBD Y0,Y1,Y2\nVMOVSS X2,(DX)",
		"unknown second":           "VMOVUPS (DI),Y0\nVPSUBQ Y0,Y1,Y2\nVMOVSS X2,(DX)",
		"unknown high byte":        "MOVSS (DI),X0\nMOVSS (SI),X1\nVPSUBQ Y0,Y1,Y2\nVEXTRACTF128 $1,Y2,X3\nVMOVSS X3,(DX)",
		"unknown mask":             "VMOVUPS (DI),Z0\nVPSUBSB.Z Z0,Z0,K1,Z2\nVMOVSS X2,(DX)",
		"unknown merge":            "VMOVUPS (DI),Z0\nMOVL $1,AX\nKMOVQ AX,K1\nVPSUBSW Z0,Z0,K1,Z2\nVMOVSS X2,(DX)",
		"pointer mask":             "VMOVUPS (DI),Z0\nKMOVQ DI,K1\nVPSUBUSB.Z Z0,Z0,K1,Z2\nVMOVSS X2,(DX)",
		"zero mask no permission":  "VMOVUPS (DI),Z0\nMOVL $0,AX\nKMOVQ AX,K1\nVPSUBUSW.Z (DX),Z0,K1,Z2\nVMOVSS X2,(DX)",
		"unknown address":          "VMOVUPS (DI),Z0\nVPSUBB (BX),Z0,Z2\nVMOVSS X2,(DX)",
		"private stack":            "VMOVUPS (DI),Z0\nVPSUBW (SP),Z0,Z2\nVMOVSS X2,(DX)",
		"legacy SP alias":          "VMOVUPS (DI),Z0\nMOVQ SP,BX\nPSUBL (BX),X0\nVMOVSS X0,(DX)",
		"input store":              "VMOVUPS (DI),Z0\nVPSUBQ Z0,Z0,Z2\nVMOVSS X2,(DI)",
		"unknown joined bank":      "VMOVUPS (DI),Z0\nCMPQ AX,$0\nJE joined\nVMOVUPS (SI),Z1\njoined:\nVPSUBW Z0,Z1,Z2\nVMOVSS X2,(DX)",
		"different pointer offset": "VMOVUPS (DI),Z0\nCMPQ AX,$0\nJE joined\nADDQ $4,DI\njoined:\nVPSUBD (DI),Z0,Z2\nVMOVSS X2,(DX)",
	} {
		t.Run(name, func(t *testing.T) {
			assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
			requireX86GoAssemblerResult(t, "amd64", assembly, true)
			pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
			if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("unproved source boundary accepted: %v", err)
			}
		})
	}
}

func TestX86PackedSubtractLegacyVirtualMemoryCannotForgeNativeAlignment(t *testing.T) {
	for _, opcode := range []string{
		"PSUBB", "PSUBW", "PSUBL", "PSUBQ", "PSUBSB", "PSUBSW", "PSUBUSB", "PSUBUSW",
	} {
		for _, source := range []string{"source+0(FP)", "(SP)", "(BP)"} {
			row := opcode + " " + source + ",X0"
			t.Run(row, func(t *testing.T) {
				assembly := "TEXT f(SB),4,$0-64\n" + row + "\nRET\n"
				requireX86GoAssemblerResult(t, "amd64", assembly, true)
				file, err := Parse(ArchAMD64, assembly)
				if err != nil {
					t.Fatal(err)
				}
				_, err = Translate(file, Options{
					Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu",
					Sigs: map[string]FuncSig{"f": x86WordMaddFPType(t)},
				})
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("virtual storage acquired native alignment permission: %v", err)
				}
			})
		}
	}
}

func TestX86GoCallerPackedSubtractMemoryWitnessBindsExactInstruction(t *testing.T) {
	for _, row := range []string{"PSUBL (DI),X0", "VPSUBQ.BCST.Z (DI),Z0,K1,Z2"} {
		body := "VMOVUPS (SI),Z0\nMOVL $0,AX\nKMOVQ AX,K1\n" + row + "\nVMOVSS X0,(DX)"
		assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
		pkg, file := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
		resolve := func(symbol string) string { return strings.Replace(symbol, "·", "caller.", 1) }
		sigs, err := goSigsForAsmFile(pkg, file, resolve, "amd64", nil, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		normalized, err := normalizeX86RawFile(file, "amd64", Options{
			Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu", ResolveSym: resolve, Sigs: sigs,
		})
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, ins := range normalized.Funcs[0].Instrs {
			form, known, err := x86PackedSubtractProperties(ins, "amd64")
			if !known || err != nil {
				continue
			}
			found = true
			access := ins.x86CallerMemory[form.memory]
			if access.width != int64(form.memoryBytes) || access.write || !x86CallerMemoryCertified(ins, form.memory) {
				t.Fatalf("missing complete possible source extent for %s", row)
			}
			for _, mutation := range []string{"opcode", "width", "direction", "address"} {
				changedAccess := access
				changed := ins
				changed.Args = append([]Operand(nil), ins.Args...)
				changed.x86CallerMemory = map[int]x86CallerMemoryAccess{form.memory: access}
				switch mutation {
				case "opcode":
					changed.Op = "PSUBQ"
					if form.broadcast {
						changed.Op = "VPSUBQ.BCST"
					}
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
					t.Fatalf("%s reused a stale %s witness", row, mutation)
				}
			}
		}
		if !found {
			t.Fatalf("source subtract disappeared from normalization: %s", row)
		}
	}
}
