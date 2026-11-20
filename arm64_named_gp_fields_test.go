package plan9asm

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Go 1.20/1.21 Optab has four operand classes; Go 1.22 added a5
// (the second destination). These two families have no second destination.
// Normalize only that known, explicitly empty column, never arbitrary fields.
func arm64NamedNormalizeGoRow(row string) (string, error) {
	fields := strings.Split(strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(row), "{"), "}"), ",")
	for index := range fields {
		fields[index] = strings.TrimSpace(fields[index])
	}
	switch len(fields) {
	case 10:
	case 11:
		if fields[5] != "C_NONE" {
			return "", errors.New("unexpected ARM64 second-destination class")
		}
		fields = append(fields[:5], fields[6:]...)
	default:
		return "", errors.New("unknown ARM64 Optab layout")
	}
	return "{" + strings.Join(fields, ", ") + "}", nil
}

func TestARM64NamedMoveWideAndBitfieldCompleteGoRows(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(testGOROOT(t), "src/cmd/internal/obj/arm64/asm7.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range []struct{ root, row string }{
		{"AMOVK", `{AMOVK, C_VCON, C_NONE, C_NONE, C_ZREG, 33, 4, 0, 0, 0}`},
		{"ABFM", `{ABFM, C_VCON, C_ZREG, C_VCON, C_ZREG, 42, 4, 0, 0, 0}`},
	} {
		source := string(data)
		rows := regexp.MustCompile(`(?m)^\s*(\{`+family.root+`,[^{}]*\})\s*,`).FindAllStringSubmatch(source, -1)
		if len(rows) != 1 ||
			len(regexp.MustCompile(`(?m)^\s*\{`+family.root+`,`).FindAllString(source, -1)) != 1 {
			t.Fatal("complete Go operand row changed", family.root)
		}
		normalized, err := arm64NamedNormalizeGoRow(rows[0][1])
		if err != nil || normalized != family.row {
			t.Fatal("complete Go operand fields changed", family.root, normalized, err)
		}
		start := strings.Index(source, "case "+family.root+":")
		if start < 0 {
			t.Fatal("Go opcode-family registration absent", family.root)
		}
		block := source[start+len("case "+family.root+":"):]
		if end := strings.Index(block, "\n\t\tcase "); end >= 0 {
			block = block[:end]
		}
		want := map[string]bool{}
		if family.root == "AMOVK" {
			for _, name := range []string{"MOVKW", "MOVN", "MOVNW", "MOVZ", "MOVZW"} {
				want[name] = true
			}
		} else {
			for _, name := range []string{"BFMW", "SBFM", "SBFMW", "UBFM", "UBFMW"} {
				want[name] = true
			}
		}
		for _, match := range regexp.MustCompile(`oprangeset\(A([A-Z0-9]+), t\)`).FindAllStringSubmatch(block, -1) {
			if !want[match[1]] {
				t.Fatal("new/unexpected Go family member needs a complete form", match[1])
			}
			delete(want, match[1])
		}
		if len(want) != 0 {
			t.Fatal("Go family member disappeared", want)
		}
	}
	for _, row := range []struct {
		name, source string
		valid        bool
	}{
		{"four-classes", `{AMOVK, C_VCON, C_NONE, C_NONE, C_ZREG, 33, 4, 0, 0, 0}`, true},
		{"five-classes", "{ AMOVK,\tC_VCON, C_NONE, C_NONE, C_ZREG, C_NONE,\n33,4,0,0,0 }", true},
		{"new-destination", `{AMOVK, C_VCON, C_NONE, C_NONE, C_ZREG, C_ZREG, 33, 4, 0, 0, 0}`, false},
		{"unknown-layout", `{AMOVK, C_VCON, C_NONE, C_NONE, C_ZREG, C_NONE, C_NONE, 33, 4, 0, 0, 0}`, false},
		{"missing-column", `{AMOVK, C_VCON, C_NONE, C_NONE, C_ZREG, 33, 4, 0, 0}`, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			normalized, err := arm64NamedNormalizeGoRow(row.source)
			if row.valid {
				if err != nil || normalized != "{AMOVK, C_VCON, C_NONE, C_NONE, C_ZREG, 33, 4, 0, 0, 0}" {
					t.Fatal("known Go layout did not retain every field", normalized, err)
				}
			} else if err == nil {
				t.Fatal("unknown Go operand-table layout accepted", normalized)
			}
		})
	}
}

func TestARM64NamedMoveWideAndBitfieldMalformedForms(t *testing.T) {
	var invalid []string
	for _, op := range []string{"MOVZ", "MOVZW", "MOVN", "MOVNW"} {
		invalid = append(invalid, op+" $0,R2", op+" $0x10001,R2", op+" $1,RSP",
			op+" $1,(R2)", op+" $1.5,R2", op+".P $1,R2", op+" $1,$16,R2")
		if strings.HasSuffix(op, "W") {
			invalid = append(invalid, op+" $(1<<32),R2", op+" $-1,R2")
		}
	}
	for _, op := range []string{"BFM", "BFMW", "SBFM", "SBFMW", "UBFM", "UBFMW"} {
		bits := 64
		if strings.HasSuffix(op, "W") {
			bits = 32
		}
		invalid = append(invalid, fmt.Sprintf("%s $%d,R1,$0,R2", op, bits),
			fmt.Sprintf("%s $0,R1,$%d,R2", op, bits), op+" $-1,R1,$0,R2",
			op+" $0,RSP,$1,R2", op+" $0,R1,$1,RSP", op+" $0,F1,$1,R2",
			op+" $0,R1,$1", op+" $1.5,R1,$1,R2", op+".P $0,R1,$1,R2")
	}
	for _, instruction := range invalid {
		t.Run(instruction, func(t *testing.T) {
			source := "TEXT invalid(SB),4,$0-0\n" + instruction + "\nRET\n"
			requireARM64GoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{Goarch: "arm64", TargetTriple: arm64LinuxGNUTriple,
				Sigs: map[string]FuncSig{"invalid": {Name: "invalid", Ret: Void}},
			}); err == nil {
				t.Fatal("invalid named form acquired lowering", instruction)
			}
		})
	}
}

func TestARM64NamedMoveWideAndBitfieldGPInputRoles(t *testing.T) {
	for _, op := range []Op{"MOVZ", "MOVZW", "MOVN", "MOVNW", "BFM", "BFMW", "SBFM", "SBFMW", "UBFM", "UBFMW"} {
		t.Run(string(op), func(t *testing.T) {
			instruction := fmt.Sprintf("%s $1,R9", op)
			move := strings.HasPrefix(string(op), "MOV")
			if !move {
				instruction = fmt.Sprintf("%s $3,R4,$17,R9", op)
			}
			file, err := Parse(ArchARM64, "TEXT roles(SB),4,$0-0\n"+instruction+"\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			ins := file.Funcs[0].Instrs[1]
			form, handled, err := parseARM64GPDataForm(op, ins)
			if !handled || err != nil || form.destination.Reg != "R9" {
				t.Fatal("named form is absent from shared GP effects", handled, err)
			}
			readsOld := op == "BFM" || op == "BFMW"
			wantInputs := 0
			if !move {
				wantInputs = 1
				if readsOld {
					wantInputs++
				}
			}
			if len(form.inputs) != wantInputs || len(form.implicit) != 0 || form.scratch != nil {
				t.Fatalf("wrong original operand dependencies: %+v", form)
			}
			for _, tainted := range []Reg{"R9", "R4"} {
				state := &arm64RawPrivateFrameState{regs: arm64PrivateFrameAddresses{tainted: {}},
					spills: make(map[int64]arm64PrivateFrameAddress)}
				want := !(tainted == "R9" && readsOld || tainted == "R4" && !move)
				if accepted := state.transfer(ins, ins, 64); accepted != want {
					t.Fatalf("tainted %s: transfer=%t, want %t", tainted, accepted, want)
				}
				if want && tainted == "R9" {
					if _, retained := state.regs["R9"]; retained {
						t.Fatal("full overwrite retained a previous frame identity")
					}
				}
			}
		})
	}
}
