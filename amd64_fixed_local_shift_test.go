package plan9asm

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

func fixedLocalLegacyShiftNames() []string {
	return strings.Fields("PSLLW PSLLL PSLLQ PSRLW PSRLL PSRLQ PSRAW PSRAL PSLLO PSLLDQ PSRLO PSRLDQ")
}

func TestGoAMD64FixedLocalShiftOfficialRows(t *testing.T) {
	catalog, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	uniform := []goasmrules.X86LegacyOperand{
		{RowIndex: 0, Classes: []string{"Ymm", "Ymr"}, ZCase: "Zm_r_xm", ZOffset: 1, UnmatchedOffset: 0},
		{RowIndex: 1, Classes: []string{"Yi8", "Ymr"}, ZCase: "Zibo_m_xm", ZOffset: 2, UnmatchedOffset: 1},
		{RowIndex: 2, Classes: []string{"Yxm", "Yxr"}, ZCase: "Zm_r_xm", ZOffset: 2, UnmatchedOffset: 3},
		{RowIndex: 3, Classes: []string{"Yi8", "Yxr"}, ZCase: "Zibo_m_xm", ZOffset: 3, UnmatchedOffset: 5},
	}
	byteRows := []goasmrules.X86LegacyOperand{
		{RowIndex: 0, Classes: []string{"Yi8", "Yxr"}, ZCase: "Zibo_m", ZOffset: 2, UnmatchedOffset: 0},
	}
	seen := make(map[string]bool)
	for _, opcode := range catalog.Optab {
		if !strings.HasPrefix(opcode.Opcode, "PSLL") && !strings.HasPrefix(opcode.Opcode, "PSRL") && !strings.HasPrefix(opcode.Opcode, "PSRA") {
			continue
		}
		want, table, prefix := uniform, "yps", "Py3"
		if opcode.Opcode == "PSLLO" || opcode.Opcode == "PSRLO" {
			want, table, prefix = byteRows, "ypsdq", "Pq"
		}
		if seen[opcode.Opcode] || opcode.Ytab != table || opcode.Prefix != prefix || !reflect.DeepEqual(opcode.Rows, want) {
			t.Fatalf("unmodeled original packed-shift rows: %+v", opcode)
		}
		seen[opcode.Opcode] = true
	}
	if len(seen) != 10 {
		t.Fatal("original packed-shift denominator changed", len(seen))
	}
	for _, pair := range [][2]string{{"PSLLO", "PSLLDQ"}, {"PSRLO", "PSRLDQ"}} {
		code, pcs := x86NumericalBoundaryGoBytes(t, "amd64", pair[0]+" $7,X1\n"+pair[1]+" $7,X1\nRET")
		if len(pcs) != 3 || !bytes.Equal(code[pcs[0]:pcs[1]], code[pcs[1]:pcs[2]]) {
			t.Fatal("Go byte-shift alias no longer selects identical original bytes", pair)
		}
	}
}

func fixedLocalLegacyShiftCases() []string {
	var operations []string
	for index, name := range fixedLocalLegacyShiftNames() {
		for _, count := range []int{-128, 0, 1, 15, 31, 63, 127} {
			operations = append(operations, fmt.Sprintf("%s $%d,X2", name, count))
		}
		if index < 8 {
			for _, count := range []string{"X1", "X2", "64(BP)", "(SI)"} {
				operations = append(operations, name+" "+count+",X2")
			}
		}
	}
	return operations
}

func TestGoAMD64FixedLocalShiftCompleteFamilies(t *testing.T) {
	operations := fixedLocalLegacyShiftCases()
	if len(operations) != 116 {
		t.Fatal("complete legacy packed-shift inventory changed", len(operations))
	}
	var assembly strings.Builder
	for index, operation := range operations {
		assembly.WriteString(strings.Replace(fixedLocalVEXAssembly(operation), "·Value", fmt.Sprintf("·Value%d", index), 1))
	}
	requireX86GoAssemblerResult(t, "amd64", assembly.String(), true)
	for _, operation := range operations {
		t.Run(operation, func(t *testing.T) {
			fn, sig, _ := fixedLocalVEXFixture(t, operation)
			if _, err := proveX86FixedLocal(fn, sig); err != nil {
				t.Fatal("original Go accepted packed-shift source but its frame effect is missing", err)
			}
		})
	}
}

func TestGoAMD64FixedLocalShiftImmediateDomainAndAliases(t *testing.T) {
	for index, name := range fixedLocalLegacyShiftNames() {
		t.Run(name, func(t *testing.T) {
			for count := -128; count <= 127; count++ {
				ins := x86YMMReadSource(t, fmt.Sprintf("%s $%d,X2", name, count))
				state := x86FixedLocalState{vectors: map[Reg]uint64{"Z2": 0xffff | uint64(1)<<60, "Z7": 123}, flags: x86ByteFlagsAll}
				// Oversized logical/byte shifts do not consume data bits.
				if index != 6 && index != 7 && uint8(count) >= 128 {
					state.vectors["Z2"] = uint64(1) << 60
				}
				if err := fixedLocalVectorStep(&ins, &state, nil, 0); err != nil {
					t.Fatal("valid immediate domain or constant-zero result rejected", count, err)
				}
				if state.vectors["Z2"] != 0xffff|uint64(1)<<60 || state.vectors["Z7"] != 123 || state.flags != x86ByteFlagsAll {
					t.Fatal("legacy shift changed upper aliases, unrelated storage or FLAGS", count, state)
				}
			}
			if index >= 8 {
				return
			}
			ins := x86YMMReadSource(t, name+" X1,X2")
			for _, known := range []uint64{255, 127} {
				state := x86FixedLocalState{vectors: map[Reg]uint64{"Z1": known, "Z2": 0xffff}}
				err := fixedLocalVectorStep(&ins, &state, nil, 0)
				if (err == nil) != (known == 255) {
					t.Fatal("uniform register count must consume exactly its low qword", known, err)
				}
			}
		})
	}
}

func TestGoAMD64FixedLocalShiftGuards(t *testing.T) {
	for index, name := range fixedLocalLegacyShiftNames() {
		forms := []string{"$128,X2", "$-129,X2", "$1,Y2", "$1,X16", "$1,M2", "$1,X7"}
		if index < 8 {
			forms = append(forms, "X7,X2", "65(BP),X2", "256(BP),X2", "(AX),X2")
		} else {
			forms = append(forms, "X1,X2", "64(BP),X2")
		}
		for _, args := range forms {
			t.Run(name+" "+args, func(t *testing.T) {
				fn, sig, _ := fixedLocalVEXFixture(t, name+" "+args)
				if _, err := proveX86FixedLocal(fn, sig); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("unbound form, memory or register acquired a frame effect", err)
				}
			})
		}
		if index < 8 {
			t.Run(name+"/whole-count-memory", func(t *testing.T) {
				_, sig, source := fixedLocalVEXFixture(t, name+" 64(BP),X2")
				changed := strings.ReplaceAll(source, "VMOVDQU 64(BP)", "VMOVDQU 128(BP)")
				if changed == source {
					t.Fatal("register initialization was not moved away from count memory")
				}
				source = strings.Replace(changed, "MOVQ AX,72(BP)\n", "", 1)
				if source == changed {
					t.Fatal("upper count qword initialization was not removed")
				}
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := proveX86FixedLocal(file.Funcs[0], sig); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("low-qword count replaced the full m128 read", err)
				}
			})
		}
	}
}

func TestGoAMD64FixedLocalShiftVEXSharedDependencies(t *testing.T) {
	for _, name := range strings.Fields("VPSLLW VPSLLD VPSLLQ VPSRLW VPSRLD VPSRLQ VPSRAW VPSRAD") {
		for _, bank := range []string{"X", "Y"} {
			t.Run(name+"/"+bank, func(t *testing.T) {
				ins := x86YMMReadSource(t, name+" X1,"+bank+"2,"+bank+"3")
				for _, known := range []uint64{255, 127} {
					state := x86FixedLocalState{vectors: map[Reg]uint64{"Z1": known, "Z2": ^uint64(0), "Z3": 0}, flags: x86ByteFlagsAll}
					err := fixedLocalVectorStep(&ins, &state, nil, 0)
					if (err == nil) != (known == 255) {
						t.Fatal("VEX count must share the complete low-qword dependency", known, err)
					}
					if err == nil && (state.vectors["Z3"] != ^uint64(0) || state.flags != x86ByteFlagsAll) {
						t.Fatal("VEX shared shift lost upper zeros or FLAGS", state)
					}
				}
			})
		}
	}
}

func TestGoAMD64FixedLocalShiftObjects(t *testing.T) {
	operations := fixedLocalLegacyShiftCases()
	var assembly, declarations strings.Builder
	for index, operation := range operations {
		name := fmt.Sprintf("Value%d", index)
		assembly.WriteString(strings.Replace(fixedLocalVEXAssembly(operation), "·Value", "·"+name, 1))
		fmt.Fprintf(&declarations, "func %s(p *uint64,a uint64) uint64\n", name)
	}
	fixedLocalCompleteVectorObjects(t, assembly.String(), declarations.String(), len(operations))
}
