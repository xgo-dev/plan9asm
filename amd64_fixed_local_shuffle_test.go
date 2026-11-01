package plan9asm

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

// Independent source names, including Go's separate PSHUFL spelling.
// The physical MMX-only PSHUFW row is inventoried below, not authorized.
func fixedLocalShuffleNames() []string {
	return []string{"PSHUFB", "PSHUFD", "PSHUFL", "PSHUFHW", "PSHUFLW"}
}

func TestGoAMD64FixedLocalShuffleOfficialRows(t *testing.T) {
	catalog, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	wanted := map[string]string{"PSHUFB": "Zm2_r:Yxm,Yxr", "PSHUFW": "Zibm_r:Yi8,Ymm,Ymr"}
	for _, name := range fixedLocalShuffleNames()[1:] {
		wanted[name] = "Zibm_r:Yu8,Yxm,Yxr"
	}
	seen := make(map[string]bool)
	for _, opcode := range catalog.Optab {
		if !strings.HasPrefix(opcode.Opcode, "PSHUF") {
			continue
		}
		shape, found := wanted[opcode.Opcode]
		if !found {
			t.Fatalf("new original legacy shuffle opcode requires an explicit row audit: %+v", opcode)
		}
		if seen[opcode.Opcode] || len(opcode.Rows) != 1 ||
			opcode.Rows[0].ZCase+":"+strings.Join(opcode.Rows[0].Classes, ",") != shape {
			t.Fatalf("unmodeled original shuffle row: %+v", opcode)
		}
		seen[opcode.Opcode] = true
	}
	if len(seen) != 6 {
		t.Fatalf("official shuffle denominator changed: %d, want 5 XMM + 1 MMX", len(seen))
	}
}

func fixedLocalShuffleOperation(name, input, immediate string) string {
	if name == "PSHUFB" {
		return name + " " + input + ",X0"
	}
	return name + " $" + immediate + "," + input + ",X0"
}

func fixedLocalShuffleFixture(t *testing.T, operation string, oldDestination bool) (string, FuncSig) {
	t.Helper()
	source, sig, _ := x86PrivateAlignedFrameAuditFixture(t, "MOVOU 16(SP),X1\n"+operation)
	if !oldDestination {
		changed := strings.Replace(source, "MOVOU 48(SP),X0\n", "", 1)
		if changed == source {
			t.Fatal("old-destination fixture did not change the source")
		}
		source = changed
	}
	return source, sig
}

type fixedLocalShuffleCase struct {
	operation      string
	oldDestination bool
}

func fixedLocalShuffleCases() []fixedLocalShuffleCase {
	var cases []fixedLocalShuffleCase
	for _, name := range fixedLocalShuffleNames() {
		immediates := []string{"0", "1", "27", "228", "255"}
		if name == "PSHUFB" {
			immediates = []string{""}
		}
		for _, immediate := range immediates {
			for _, input := range []string{"16(SP)", "X1", "X0"} {
				operation := fixedLocalShuffleOperation(name, input, immediate)
				cases = append(cases, fixedLocalShuffleCase{operation, true})
				if name != "PSHUFB" && input != "X0" {
					cases = append(cases, fixedLocalShuffleCase{operation, false})
				}
			}
		}
	}
	return cases
}

func fixedLocalShuffleProgram(t *testing.T) (string, string, int) {
	t.Helper()
	var assembly, declarations strings.Builder
	cases := fixedLocalShuffleCases()
	for index, row := range cases {
		source, _ := fixedLocalShuffleFixture(t, row.operation, row.oldDestination)
		function := fmt.Sprintf("Value%d", index)
		assembly.WriteString(strings.Replace(source, "·Value", "·"+function, 1))
		fmt.Fprintf(&declarations, "func %s(a,b,c,d uint64) uint64\n", function)
	}
	return assembly.String(), declarations.String(), len(cases)
}

func TestGoAMD64FixedLocalShuffleCompleteFamilies(t *testing.T) {
	assembly, _, count := fixedLocalShuffleProgram(t)
	if count != 103 {
		t.Fatal("complete shuffle register/memory/immediate/old-destination denominator changed", count)
	}
	requireX86GoAssemblerResult(t, "amd64", assembly, true)
	for _, row := range fixedLocalShuffleCases() {
		t.Run(fmt.Sprintf("%s/old=%t", row.operation, row.oldDestination), func(t *testing.T) {
			source, sig := fixedLocalShuffleFixture(t, row.operation, row.oldDestination)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			proved, err := proveX86FixedLocal(file.Funcs[0], sig)
			if err != nil {
				t.Fatal("original Go accepted complete shuffle source but fixed-frame effect is missing", err)
			}
			observed := 0
			for _, ins := range proved.Instrs {
				if !strings.HasPrefix(row.operation, string(ins.Op)+" ") {
					continue
				}
				observed++
				index := 1
				if ins.Op == "PSHUFB" {
					index = 0
				}
				access, found := ins.x86FixedLocalMemory[index]
				if found != strings.Contains(row.operation, "16(SP)") || found &&
					(access.width != 16 || access.write || access.nativeInput || access.owner != proved.x86FixedLocal) {
					t.Fatalf("shuffle changed the exact private source extent or owner: %+v", access)
				}
			}
			if observed != 1 {
				t.Fatal("complete proof did not retain exactly one original shuffle", observed)
			}
		})
	}
}

func TestGoAMD64FixedLocalShuffleImmediateDomainAndAliases(t *testing.T) {
	for _, name := range fixedLocalShuffleNames() {
		t.Run(name, func(t *testing.T) {
			limit := 256
			if name == "PSHUFB" {
				limit = 1
			}
			for immediate := 0; immediate < limit; immediate++ {
				operation := fixedLocalShuffleOperation(name, "X1", fmt.Sprint(immediate))
				ins := x86YMMReadSource(t, operation)
				for _, upper := range []uint64{0, 0x8040201000000000, ^uint64(0xffff)} {
					old := upper
					if name == "PSHUFB" {
						old |= 0xffff // Byte shuffle reads its old data destination.
					}
					state := x86FixedLocalState{vectors: map[Reg]uint64{"Z0": old, "Z1": 0xffff}, flags: x86ByteFlagsAll}
					if err := fixedLocalVectorStep(&ins, &state, nil, 0); err != nil {
						t.Fatalf("%s immediate=%d: %v", name, immediate, err)
					}
					if state.vectors["Z0"] != upper|0xffff || state.vectors["Z1"] != 0xffff || state.flags != x86ByteFlagsAll {
						t.Fatalf("%s changed upper aliases, source or FLAGS: %+v", operation, state)
					}
				}
			}
		})
	}
}

func TestGoAMD64FixedLocalShuffleSharedMetadata(t *testing.T) {
	for _, name := range fixedLocalShuffleNames() {
		ins := x86YMMReadSource(t, fixedLocalShuffleOperation(name, "X1", "0"))
		effect, known, err := x86TypedInstructionByteEffect(ins.Op, ins, "amd64")
		if !known || err != nil || effect.vector.upperWrite != x86TypedVectorUpperPreserve ||
			effect.vector.memoryAlignment != 16 {
			t.Fatalf("%s is not described by the common typed family: %+v %v", name, effect, err)
		}
		readSource, readDestination, writeDestination := false, false, false
		for _, operand := range effect.operands {
			if operand.operand.Kind != OpReg {
				continue
			}
			if operand.width != 16 {
				t.Fatal("shuffle lost the complete XMM input/output width", name, operand)
			}
			switch operand.operand.Reg {
			case "X1":
				readSource = readSource || operand.read
			case "X0":
				readDestination = readDestination || operand.read
				writeDestination = writeDestination || operand.write
			}
		}
		if !readSource || !writeDestination || readDestination != (name == "PSHUFB") {
			t.Fatal("shuffle confused old destination with its sole immediate source", name, effect)
		}
	}
}

func TestGoAMD64FixedLocalShuffleBoundaries(t *testing.T) {
	for _, name := range fixedLocalShuffleNames() {
		for _, row := range []struct{ name, input, from, to string }{
			{"unknown source", "X2", "", ""},
			{"unknown aliased source", "X0", "MOVOU 48(SP),X0", "MOVOU 48(SP),X2"},
			{"missing memory byte", "16(SP)", "MOVQ CX,24(SP)", "MOVB CX,24(SP)"},
			{"unaligned memory", "17(SP)", "", ""},
			{"outside frame", "160(SP)", "", ""},
			{"MMX source", "M0", "", ""},
			{"high bank", "X16", "", ""},
			{"unknown dynamic control", "X1", "MOVOU 16(SP),X1", "MOVOU 16(SP),X2"},
		} {
			t.Run(name+"/"+row.name, func(t *testing.T) {
				operation := fixedLocalShuffleOperation(name, row.input, "0")
				source, sig := fixedLocalShuffleFixture(t, operation, true)
				if row.from != "" {
					changed := strings.Replace(source, row.from, row.to, 1)
					if changed == source {
						t.Fatal("negative fixture did not change the complete source")
					}
					source = changed
				}
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := proveX86FixedLocal(file.Funcs[0], sig); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("unproved shuffle input acquired private frame authority", err)
				}
			})
		}
	}
	invalid := []string{"PSHUFW $0,M0,M1", "PSHUFB.Z X1,X0", "PSHUFB $0,X1,X0"}
	for _, name := range fixedLocalShuffleNames()[1:] {
		for _, immediate := range []string{"-129", "-128", "-1", "256", "257", "1.0", "missing"} {
			invalid = append(invalid, fixedLocalShuffleOperation(name, "X1", immediate))
		}
	}
	for _, operation := range invalid {
		t.Run(operation, func(t *testing.T) {
			ins := x86YMMReadSource(t, operation)
			effect, known, err := fixedLocalVectorByteEffect(ins)
			if known && err == nil {
				t.Fatalf("non-XMM or invalid immediate/format gained effect: %+v", effect)
			}
		})
	}
	t.Run("byte shuffle still reads old data", func(t *testing.T) {
		source, sig := fixedLocalShuffleFixture(t, "PSHUFB X1,X0", false)
		file, err := Parse(ArchAMD64, source)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := proveX86FixedLocal(file.Funcs[0], sig); !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("PSHUFB acquired numerical data from its initialized control alone", err)
		}
	})
}

func TestGoAMD64FixedLocalShuffleObjects(t *testing.T) {
	assembly, declarations, count := fixedLocalShuffleProgram(t)
	if count != 103 {
		t.Fatal("complete-source shuffle denominator changed", count)
	}
	fixedLocalCompleteVectorObjects(t, assembly, declarations, count)
}
