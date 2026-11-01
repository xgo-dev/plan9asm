package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// Independent complete Go ymm/Py1 and _yvandnpd inventory, not spec-map keys.
func x86AverageValueRows(arch string) []struct{ op, bank, mode string } {
	return x86FixedBinaryValueRows(arch, []string{"PAVGB", "PAVGW", "VPAVGB", "VPAVGW"})
}

func x86FixedBinaryValueRows(arch string, names []string) []struct{ op, bank, mode string } {
	var rows []struct{ op, bank, mode string }
	for _, op := range names {
		banks := []string{"X", "Y", "Z"}
		if !strings.HasPrefix(op, "V") {
			banks = banks[:1]
		}
		for _, bank := range banks {
			for _, mode := range []string{"plain", "merge", "zero"} {
				if mode != "plain" && (arch == "386" || !strings.HasPrefix(op, "V")) {
					continue // Actual named arity/legacy boundary, not a target skip.
				}
				rows = append(rows, struct{ op, bank, mode string }{op, bank, mode})
			}
		}
	}
	return rows
}

func x86AverageValueFixture(arch, op, bank, mode string, result bool) (string, string) {
	return x86FixedBinaryValueFixture(arch, op, bank, mode, result)
}

func x86FixedBinaryValueFixture(arch, op, bank, mode string, result bool) (string, string) {
	word, move, maskMove := 8, "MOVQ", "KMOVQ"
	if arch == "386" {
		word, move, maskMove = 4, "MOVL", "KMOVD"
	}
	instruction := op + " 3(AX)(DX*2)," + bank + "2"
	if strings.HasPrefix(op, "V") {
		mask := ""
		if mode != "plain" {
			mask = "K1,"
		}
		if mode == "zero" {
			op += ".Z"
		}
		instruction = op + " 3(AX)(DX*2)," + bank + "1," + mask + bank + "2"
	}
	declaration, finish, extent := "func Value(p *[128]byte,mask uintptr)", "", 2*word
	if result {
		declaration += " uint32"
		extent += 4
		finish = fmt.Sprintf("PEXTRD $0,X2,AX\nMOVL AX,ret+%d(FP)\n", 2*word)
	}
	return fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s p+0(FP),AX\n%s mask+%d(FP),CX\n%s CX,K1\n"+
		"MOVL $1,DX\nVPXORD Z1,Z1,Z1\nVPXORD Z2,Z2,Z2\n%s\n%sRET\n",
		extent, move, move, word, maskMove, instruction, finish), declaration
}

func TestX86PackedAverageValueCompleteFamilyFiveTargetsThreeAPIs(t *testing.T) {
	x86FixedBinaryCompleteFamilyObjects(t, x86AverageValueRows, 20, 8)
}

func x86FixedBinaryCompleteFamilyObjects(t *testing.T, inventory func(string) []struct{ op, bank, mode string }, amd64Count, mode32Count int) {
	t.Helper()
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			rows := inventory(target.arch)
			want := amd64Count
			if target.arch == "386" {
				want = mode32Count
			}
			if len(rows) != want {
				t.Fatal("complete original average family denominator changed", len(rows), want)
			}
			var source, declarations strings.Builder
			var names []string
			for _, row := range rows {
				for _, result := range []bool{false, true} {
					body, declaration := x86FixedBinaryValueFixture(target.arch, row.op, row.bank, row.mode, result)
					name := fmt.Sprintf("AverageValue%d", len(names))
					names = append(names, name)
					source.WriteString(strings.ReplaceAll(body, "Value", name))
					declarations.WriteString(strings.ReplaceAll(declaration, "Value", name) + "\n")
				}
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("complete average value source lost its native continuation", err)
					}
					x86CompactExpandRequireAllDefinitions(t, ir, names)
					for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
						for _, level := range []string{"-O0", "-O2"} {
							x86PackedStringCompileObject(t, llc, target.triple, text, level)
						}
					}
				})
			}
		})
	}
}

func TestX86PackedAverageVoidCannotInventRegisterInputs(t *testing.T) {
	x86FixedBinaryVoidInputBoundaries(t, x86AverageValueRows)
}

func x86FixedBinaryVoidInputBoundaries(t *testing.T, inventory func(string) []struct{ op, bank, mode string }) {
	t.Helper()
	for _, arch := range []string{"386", "amd64"} {
		triple := "x86_64-unknown-linux-gnu"
		if arch == "386" {
			triple = "i386-unknown-linux-gnu"
		}
		for _, row := range inventory(arch) {
			if row.mode != "plain" {
				continue // Separate native/mask roots retain the complete masked rows.
			}
			instruction := row.op + " " + row.bank + "1," + row.bank + "2"
			if strings.HasPrefix(row.op, "V") {
				instruction = row.op + " " + row.bank + "0," + row.bank + "1," + row.bank + "2"
			}
			for _, missing := range []string{"Z1", "Z2"} {
				if strings.HasPrefix(row.op, "V") && missing == "Z2" {
					missing = "Z0" // VEX destination is not an unmasked data input.
				}
				t.Run(arch+"/"+instruction+"/"+missing, func(t *testing.T) {
					prefix := "TEXT ·Value(SB),4,$0-0\nVPXORD Z0,Z0,Z0\nVPXORD Z1,Z1,Z1\nVPXORD Z2,Z2,Z2\n"
					valid := prefix + instruction + "\nRET\n"
					unknown := strings.Replace(valid, fmt.Sprintf("VPXORD %s,%s,%s\n", missing, missing, missing), "", 1)
					for _, api := range []string{"text", "module", "Go"} {
						if ir, err := x86ScalarFPBitViewAPI(t, valid, "func Value()", arch, triple, api); err != nil || ir == "" {
							t.Fatal("fully initialized independent Void control rejected", api, err)
						}
						if ir, err := x86ScalarFPBitViewAPI(t, unknown, "func Value()", arch, triple, api); !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
							t.Error("Void average borrowed zeroed implementation inputs", api, err)
						}
					}
				})
			}
		}
	}
}

func TestX86PackedAverageNativeInputsStayIndependent(t *testing.T) {
	x86FixedBinaryNativeInputBoundaries(t, x86AverageValueRows)
}

func x86FixedBinaryNativeInputBoundaries(t *testing.T, inventory func(string) []struct{ op, bank, mode string }) {
	t.Helper()
	for _, row := range inventory("amd64") {
		source, declaration := x86FixedBinaryValueFixture("amd64", row.op, row.bank, row.mode, true)
		pkg := mustGoPackage(t, "value", "package value\n"+declaration)
		file := mustParseX86RawReturn(t, source)
		signatures, err := goSigsForAsmFile(pkg, file, func(name string) string {
			return strings.TrimPrefix(name, "·")
		}, "amd64", nil, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := CheckX86ABI0ResultInitialization(file.Funcs[0], signatures["Value"], "amd64"); !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("declaration-only query borrowed paired native memory authority", row, err)
		}
		variants := map[string]string{
			"unknown-pointer": strings.Replace(source, "p+0(FP),AX", "p+0(FP),DI", 1),
			"unknown-index":   strings.Replace(source, "MOVL $1,DX\n", "", 1),
			"numeric-pointer": strings.Replace(source, "MOVL $1,DX", "MOVL $42,AX\nMOVL $1,DX", 1),
		}
		if row.mode != "plain" {
			variants["unknown-mask"] = strings.Replace(source, "KMOVQ CX,K1\n", "", 1)
		}
		if row.mode == "merge" || !strings.HasPrefix(row.op, "V") {
			variants["unknown-destination"] = strings.Replace(source, "VPXORD Z2,Z2,Z2\n", "", 1)
		}
		if strings.HasPrefix(row.op, "V") {
			variants["unknown-vector"] = strings.Replace(source, "VPXORD Z1,Z1,Z1\n", "", 1)
		}
		for name, changed := range variants {
			t.Run(row.op+"/"+row.bank+"/"+row.mode+"/"+name, func(t *testing.T) {
				for _, api := range []string{"text", "module", "Go"} {
					if ir, err := x86ScalarFPBitViewAPI(t, changed, declaration, "amd64", "x86_64-unknown-linux-gnu", api); !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
						t.Fatal("average acquired unknown memory/vector/mask inputs", api, err)
					}
				}
			})
		}
	}
}
