package plan9asm

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestX86ScalarBitScanCompleteOfficialRowsAndOperandGrammar(t *testing.T) {
	table, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	rows := []string{
		"{ABSFL, yml_rl, Pm, opBytes{0xbc}}", "{ABSFQ, yml_rl, Pw, opBytes{0x0f, 0xbc}}",
		"{ABSFW, yml_rl, Pq, opBytes{0xbc}}", "{ABSRL, yml_rl, Pm, opBytes{0xbd}}",
		"{ABSRQ, yml_rl, Pw, opBytes{0x0f, 0xbd}}", "{ABSRW, yml_rl, Pq, opBytes{0xbd}}",
		"var yml_rl = []ytab{\n\t{Zm_r, 1, argList{Yml, Yrl}},\n}",
	}
	if len(x86ScalarBitScanSpecs) != len(rows)-1 {
		t.Fatal("incomplete scalar scan family")
	}
	for _, row := range rows {
		if !strings.Contains(string(table), row) {
			t.Fatal("complete original Go bit-scan encoding row changed", row)
		}
	}
	for _, arch := range []string{"amd64", "386"} {
		for _, op := range []string{"BSFW", "BSFL", "BSFQ", "BSRW", "BSRL", "BSRQ"} {
			for _, operands := range []struct {
				text  string
				valid bool
			}{
				{"AX,BX", true}, {"x+0(FP),BX", true}, {"4(AX)(CX*2),BX", true}, {"table(SB),BX", true},
				{"AL,BX", false}, {"X0,BX", false}, {"$3,BX", false}, {"$table(SB),BX", false},
				{"AX,AH", false}, {"AX,X0", false}, {"AX,4(BX)", false}, {"AX", false}, {"AX,BX,CX", false},
			} {
				t.Run(arch+"/"+op+"/"+operands.text, func(t *testing.T) {
					ins := x86ScalarLaneInstruction(t, op+" "+operands.text)
					_, known, err := x86ScalarBitScanProperties(ins.Op, ins, arch)
					want := operands.valid && !(arch == "386" && strings.HasSuffix(op, "Q"))
					if !known || (err == nil) != want {
						t.Fatal("scan grammar disagrees with complete Yml/Yrl rows", known, err, want)
					}
				})
			}
		}
	}
}

func TestX86ABI0ResultBitScanZeroBranchDefinesOnlyNonzeroEdge(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, family := range []string{"BSF", "BSR"} {
			for _, width := range []struct{ suffix, typ, move string }{
				{"W", "uint16", "MOVW"}, {"L", "uint32", "MOVL"}, {"Q", "uint64", "MOVQ"},
			} {
				if arch == "386" && width.suffix == "Q" {
					continue // The official mode32 Q row is independently rejected.
				}
				for _, branch := range []string{"JE", "JEQ", "JZ", "JNE", "JNZ"} {
					t.Run(arch+"/"+family+width.suffix+"/"+branch, func(t *testing.T) {
						word := 8
						if arch == "386" {
							word = 4
						}
						prefix := fmt.Sprintf("%s x+0(FP),AX\n%s AX,BX\n", width.move, family+width.suffix)
						good := fmt.Sprintf("%s BX,ret+%d(FP)\nRET\n", width.move, word)
						zero := fmt.Sprintf("%s $0,ret+%d(FP)\nRET\n", width.move, word)
						body := prefix + branch + " zero\n" + good + "zero:\n" + zero
						if branch == "JNE" || branch == "JNZ" {
							body = prefix + branch + " nonzero\n" + zero + "nonzero:\n" + good
						}
						_, file, sig, _ := x86ResultInitializationFixture(t, arch, "func Value(x "+width.typ+") "+width.typ, body)
						if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, arch); err != nil {
							t.Fatal("complete zero-guarded scan rejected", err)
						}
					})
				}
			}
		}
	}
}

func TestX86ABI0ResultBitScanUndefinedValuesAndFlagsRemainContext(t *testing.T) {
	for _, family := range []string{"BSF", "BSR"} {
		for name, body := range map[string]string{
			"unguarded":                    "MOVL x+0(FP),AX\nSCAN AX,BX\nMOVL BX,ret+8(FP)\nRET",
			"zero edge observed":           "MOVL x+0(FP),AX\nSCAN AX,BX\nJNZ nonzero\nMOVL BX,ret+8(FP)\nRET\nnonzero:\nMOVL $0,ret+8(FP)\nRET",
			"defined flags are not values": "MOVL x+0(FP),AX\nSCAN AX,BX\nSETEQ CL\nMOVL BX,ret+8(FP)\nRET",
			"flags replaced":               "MOVL x+0(FP),AX\nSCAN AX,BX\nCMPL AX,$0\nJZ zero\nMOVL BX,ret+8(FP)\nRET\nzero:\nMOVL $0,ret+8(FP)\nRET",
			"undefined carry":              "MOVL x+0(FP),AX\nSCAN AX,BX\nJCS zero\nMOVL $0,ret+8(FP)\nRET\nzero:\nMOVL $0,ret+8(FP)\nRET",
			"unknown source":               "SCAN AX,BX\nJZ zero\nMOVL BX,ret+8(FP)\nRET\nzero:\nMOVL $0,ret+8(FP)\nRET",
		} {
			t.Run(family+"/"+name, func(t *testing.T) {
				body = strings.ReplaceAll(body, "SCAN", family+"L")
				_, file, sig, _ := x86ResultInitializationFixture(t, "amd64", "func Value(x uint32) uint32", body)
				if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, "amd64"); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("undefined scan acquired a result/FLAGS proof", err)
				}
			})
		}
	}
}

func TestX86ABI0ResultBitScanGuardedByteAliasesAndCFGJoins(t *testing.T) {
	for _, family := range []string{"BSF", "BSR"} {
		for name, fixture := range map[string]struct {
			body string
			pass bool
		}{
			"word preserves defined upper bytes":        {"MOVQ $0,BX\nSCANW AX,BX\nJZ zero\nMOVQ BX,ret+8(FP)\nRET\nzero:\nMOVQ $0,ret+8(FP)\nRET", true},
			"word cannot define unknown upper bytes":    {"SCANW AX,BX\nJZ zero\nMOVQ BX,ret+8(FP)\nRET\nzero:\nMOVQ $0,ret+8(FP)\nRET", false},
			"dword clears upper on nonzero edge":        {"SCANL AX,BX\nJZ zero\nMOVQ BX,ret+8(FP)\nRET\nzero:\nMOVQ $0,ret+8(FP)\nRET", true},
			"source destination alias":                  {"SCANQ AX,AX\nJZ zero\nMOVQ AX,ret+8(FP)\nRET\nzero:\nMOVQ $0,ret+8(FP)\nRET", true},
			"both edges cannot merge scan result":       {"SCANQ AX,BX\nJZ joined\njoined:\nMOVQ BX,ret+8(FP)\nRET", false},
			"zero result replaced before joining":       {"SCANQ AX,BX\nJNZ joined\nMOVQ $0,BX\njoined:\nMOVQ BX,ret+8(FP)\nRET", true},
			"guard does not initialize other registers": {"SCANQ AX,BX\nJZ zero\nMOVQ CX,ret+8(FP)\nRET\nzero:\nMOVQ $0,ret+8(FP)\nRET", false},
		} {
			t.Run(family+"/"+name, func(t *testing.T) {
				body := "MOVQ x+0(FP),AX\n" + strings.ReplaceAll(fixture.body, "SCAN", family)
				_, file, sig, _ := x86ResultInitializationFixture(t, "amd64", "func Value(x uint64) uint64", body)
				err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, "amd64")
				if fixture.pass && err != nil || !fixture.pass && !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("scan acquired wrong byte/CFG definition", fixture.pass, err)
				}
			})
		}
	}
}

func TestX86ScalarBitScanWholeSourceThreeAPIAdmission(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, op := range []string{"BSFW", "BSFL", "BSFQ", "BSRW", "BSRL", "BSRQ"} {
			if arch == "386" && strings.HasSuffix(op, "Q") {
				continue
			}
			for _, guarded := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/guarded%t", arch, op, guarded), func(t *testing.T) {
					move, typ := "MOVQ", "uint64"
					if arch == "386" {
						move, typ = "MOVL", "uint32"
					}
					declaration := "func view(x " + typ + ") " + typ + "\n"
					body := move + " x+0(FP),AX\n" + move + " $0,BX\n" + op + " AX,BX\n"
					if guarded {
						body += "JZ zero\n" + move + " BX,ret+RESULT(FP)\nRET\nzero:\n" + move + " $0,ret+RESULT(FP)"
					} else {
						body += move + " BX,ret+RESULT(FP)"
					}
					source := x86ResultGPSIMDAdmissionSource(t, arch, declaration, body)
					// This original source initializes the prior destination.
					// Zero input therefore retains numerical bytes, even without
					// the guard. Keep the source unchanged as a positive control.
					x86ResultGPSIMDAdmissionAPIs(t, arch, source, declaration, true)
					unknown := strings.Replace(source, move+" $0,BX\n", "", 1)
					t.Run("unknown-prior", func(t *testing.T) {
						// Even the nonzero W edge cannot initialize a full
						// word result's previously unknown upper bytes.
						x86ResultGPSIMDAdmissionAPIs(t, arch, unknown, declaration, guarded && !strings.HasSuffix(op, "W"))
					})
				})
			}
		}
	}
}

func TestX86ABI0ResultBitScanPendingStateCannotLeakAuthority(t *testing.T) {
	base := x86ScalarLaneInstruction(t, "BSFL AX,BX")
	for name, mutate := range map[string]func(*Instr){
		"encoded":          func(ins *Instr) { ins.x86Encoded = true },
		"address width":    func(ins *Instr) { ins.x86AddressBits = 32 },
		"unbound override": func(ins *Instr) { ins.x86UnboundAddressOverride = true },
		"segment":          func(ins *Instr) { ins.x86SegmentPrefix = 0x64 },
	} {
		t.Run(name, func(t *testing.T) {
			ins := base
			mutate(&ins)
			state := x86ResultState{}
			state.gp[0] = 0xff
			if accepted, known := x86ResultBitScanStep(ins, &state, nil, "amd64"); accepted || !known || state.bitScanPending.mask != 0 {
				t.Fatal("named scan borrowed a native/raw role", accepted, known, state)
			}
		})
	}
	initial := x86ResultState{bitScanPending: x86ResultBitScanPending{register: 3, mask: 0xff}}
	for _, change := range []x86ResultBitScanPending{{}, {register: 1, mask: 0xff}, {register: 3, mask: 3}} {
		other := initial.clone()
		other.bitScanPending = change
		if initial.intersect(other).bitScanPending.mask != 0 {
			t.Fatal("different pending scan facts survived CFG intersection")
		}
	}
	branch := x86ScalarLaneInstruction(t, "JNZ good")
	nonzero := x86ResultBitScanEdge(initial, branch, 1)
	zero := x86ResultBitScanEdge(initial, branch, 0)
	if nonzero.gp[3] != 0xff || zero.gp[3] != 0 || nonzero.bitScanPending.mask != 0 || zero.bitScanPending.mask != 0 || initial.gp[3] != 0 {
		t.Fatal("edge refinement contaminated sibling or predecessor state")
	}
}

func TestX86ABI0ResultBitScanPortableStatusFlagConsumers(t *testing.T) {
	for _, op := range []string{"BSFW", "BSFL", "BSFQ", "BSRW", "BSRL", "BSRQ"} {
		for _, condition := range []string{"CC", "CS", "EQ", "NE", "HI", "LS", "GE", "LT", "GT", "LE", "MI", "PL", "OC", "OS", "PC", "PS"} {
			t.Run(op+"/"+condition, func(t *testing.T) {
				body := "MOVQ x+0(FP),AX\n" + op + " AX,BX\nSET" + condition + " ret+8(FP)\nRET"
				_, file, sig, _ := x86ResultInitializationFixture(t, "amd64", "func Value(x uint64) uint8", body)
				err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, "amd64")
				pass := condition == "EQ" || condition == "NE"
				if pass && err != nil || !pass && !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("scan borrowed nonportable status flags", pass, err)
				}
			})
		}
	}
}
