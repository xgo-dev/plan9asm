package plan9asm

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

func TestX86PackedFloatShuffleCompleteOfficialRows(t *testing.T) {
	legacy, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	pattern := regexp.MustCompile(`\{A(SHUFPS|SHUFPD), (\w+), (\w+), opBytes\{([^}]+)\}\}`)
	rows := pattern.FindAllStringSubmatch(string(legacy), -1)
	definition := regexp.MustCompile(`(?s)var yxshuf = \[\]ytab\{(.*?)\n\}`).FindStringSubmatch(string(legacy))
	if len(rows) != 2 || len(definition) != 2 || strings.Join(strings.Fields(definition[1]), "") != "{Zibm_r,2,argList{Yu8,Yxm,Yxr}}," {
		t.Fatal("complete legacy unsigned-immediate two-source grammar changed", rows)
	}
	for _, row := range rows {
		prefix := "Pm"
		if row[1] == "SHUFPD" {
			prefix = "Pq"
		}
		if row[2] != "yxshuf" || row[3] != prefix || strings.Join(strings.Fields(row[4]), "") != "0xc6,00" {
			t.Fatal("unmodeled original legacy opcode/prefix", row)
		}
		for _, arch := range []string{"386", "amd64"} {
			goAssemblerOracleOutput(t, arch, "TEXT Prior(SB),4,$0-0\n"+row[1]+" $255,(AX),X1\nRET\n", "", true)
		}
	}

	rules, err := goasmrules.LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	classes := [][]string{
		{"Yu8", "Yxm", "Yxr", "Yxr"}, {"Yu8", "Yym", "Yyr", "Yyr"},
		{"Yu8", "YxmEvex", "YxrEvex", "YxrEvex"}, {"Yu8", "YxmEvex", "YxrEvex", "Yknot0", "YxrEvex"},
		{"Yu8", "YymEvex", "YyrEvex", "YyrEvex"}, {"Yu8", "YymEvex", "YyrEvex", "Yknot0", "YyrEvex"},
		{"Yu8", "Yzm", "Yzr", "Yzr"}, {"Yu8", "Yzm", "Yzr", "Yknot0", "Yzr"},
	}
	counts := map[string]int{}
	var source strings.Builder
	for _, rule := range rules {
		if rule.Opcode != "VSHUFPS" && rule.Opcode != "VSHUFPD" {
			continue
		}
		index := rule.RowIndex
		offsets, advances := []int{0, 2, 4, 4, 7, 7, 10, 10}, []int{2, 2, 0, 3, 0, 3, 0, 3}
		if index < 0 || index >= 8 || rule.Ytab != "_yvgf2p8affineinvqb" || rule.Prefix != "Pavx" ||
			!reflect.DeepEqual(rule.Classes, classes[index]) || rule.EncodingOffset != offsets[index] || rule.ZOffset != advances[index] || len(rule.OpBytes) != 13 {
			t.Fatal("unmodeled complete official vector-shuffle row", rule)
		}
		generation, bits, zcase := "vex", "128", "Zvex_i_rm_v_r"
		if index == 1 || index == 4 || index == 5 {
			bits = "256"
		} else if index >= 6 {
			bits = "512"
		}
		if index >= 2 {
			generation, zcase = "evex", "Zevex_i_rm_v_r"
			if index%2 == 1 {
				zcase = "Zevex_i_rm_v_k_r"
			}
		}
		terms := []string{"avxEscape", generation + bits}
		if rule.Opcode == "VSHUFPD" {
			terms = append(terms, generation+"66")
		}
		w := "0"
		if generation == "evex" && rule.Opcode == "VSHUFPD" {
			w = "1"
		}
		terms = append(terms, generation+"0F", generation+"W"+w)
		opcode := offsets[index] + 1
		if rule.ZCase != zcase || !reflect.DeepEqual(strings.Split(rule.OpBytes[offsets[index]], " | "), terms) {
			t.Fatal("complete generation/W/prefix opcode identity changed", rule)
		}
		if generation == "evex" {
			broadcast := "4"
			if rule.Opcode == "VSHUFPD" {
				broadcast = "8"
			}
			attributes := "evexN" + map[string]string{"128": "16", "256": "32", "512": "64"}[bits] +
				" | evexBcstN" + broadcast + " | evexZeroingEnabled"
			if rule.OpBytes[opcode] != attributes {
				t.Fatal("complete source/broadcast/masking tuple changed", rule)
			}
			opcode++
		}
		if strings.ToLower(rule.OpBytes[opcode]) != "0xc6" {
			t.Fatal("original full shuffle opcode changed", rule)
		}
		bank, destination, mask := map[string]string{"128": "X", "256": "Y", "512": "Z"}[bits], 2, ""
		if generation == "evex" && bits != "512" {
			destination = 18 // Independently force the unmasked EVEX row.
		}
		if len(rule.Classes) == 5 {
			mask = "K1,"
		}
		fmt.Fprintf(&source, "TEXT Prior%s%d(SB),4,$0-0\n%s $255,%s0,%s1,%s%s%d\nRET\n",
			rule.Opcode, index, rule.Opcode, bank, bank, mask, bank, destination)
		counts[rule.Opcode]++
	}
	if counts["VSHUFPS"] != 8 || counts["VSHUFPD"] != 8 {
		t.Fatal("complete official 2+16-row denominator changed", counts)
	}
	goAssemblerOracleOutput(t, "amd64", source.String(), "", true)
}

// Intel SDM Vol.2B SHUFPS/SHUFPD specifies VEX.WIG. Go emits W0;
// independently decode each W0/W1 physical instruction before asking our
// decoder. This grants neither named mode32 arity nor a numerical raw role.
func TestX86PackedFloatShuffleVEXWIGIndependentPhysicalPrior(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		mode := 64
		if arch == "386" {
			mode = 32
		}
		for pp, op := range []string{"VSHUFPS", "VSHUFPD"} {
			for _, bank := range []string{"X", "Y"} {
				for _, memory := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/%s/%s/memory=%t", arch, op, bank, memory), func(t *testing.T) {
						first := bank + "0"
						if memory {
							first = "(AX)"
						}
						operation := fmt.Sprintf("%s $27,%s,%s1,%s2", op, first, bank, bank)
						// Named four-operand Go priors belong to AMD64; the same
						// low-bank machine encoding independently exists in mode32.
						original, pcs := x86NumericalBoundaryGoBytes(t, "amd64", operation+"\nRET")
						if len(pcs) != 2 || pcs[1] != int64(len(original)-1) {
							t.Fatal("original complete Go VEX instruction prior missing", pcs)
						}
						p1, modrm := byte(0x70|pp), byte(0xd0)
						if bank == "Y" {
							p1 |= 4
						}
						if memory {
							modrm = 0x10
						}
						wantGo := []byte{0xc5, 0x80 | p1, 0xc6, modrm, 27, 0xc3}
						if !reflect.DeepEqual(original, wantGo) {
							t.Fatal("independent original Go source/operand/imm bytes changed", original, wantGo)
						}
						var control Instr
						for _, w := range []byte{0, 0x80} {
							code := []byte{0xc4, 0xe1, p1 | w, 0xc6, modrm, 27}
							x86NumericalNativeRequireMC(t, code, mode, 1, "+avx")
							ins, consumed, known, err := decodedX86VSHUFPSInstruction(code, mode)
							if !known || err != nil || consumed != len(code) || ins.Op != Op(op) {
								t.Fatal("ISA WIG lost a complete physically validated shuffle", w, consumed, known, err)
							}
							if w == 0 {
								control = ins
							} else if !reflect.DeepEqual(ins.Args, control.Args) {
								t.Fatal("WIG changed source/destination/immediate identities", control.Args, ins.Args)
							}
						}
					})
				}
			}
		}
	}
}
