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

func TestX86PackedMoveCompleteIndependentEncoderRows(t *testing.T) {
	rules, err := goasmrules.LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []struct {
		name, table, pp, evexW, store, load string
		vex, evex                           bool
	}{
		{"VMOVDQA", "_yvmovdqa", "66", "", "0x7F", "0x6F", true, false},
		{"VMOVDQU", "_yvmovdqa", "F3", "", "0x7F", "0x6F", true, false},
		{"VMOVAPD", "_yvmovapd", "66", "1", "0x29", "0x28", true, true},
		{"VMOVAPS", "_yvmovapd", "", "0", "0x29", "0x28", true, true},
		{"VMOVUPD", "_yvmovapd", "66", "1", "0x11", "0x10", true, true},
		{"VMOVUPS", "_yvmovapd", "", "0", "0x11", "0x10", true, true},
		{"VMOVDQA32", "_yvmovdqa32", "66", "0", "0x7F", "0x6F", false, true},
		{"VMOVDQA64", "_yvmovdqa32", "66", "1", "0x7F", "0x6F", false, true},
		{"VMOVDQU8", "_yvmovdqa32", "F2", "0", "0x7F", "0x6F", false, true},
		{"VMOVDQU16", "_yvmovdqa32", "F2", "1", "0x7F", "0x6F", false, true},
		{"VMOVDQU32", "_yvmovdqa32", "F3", "0", "0x7F", "0x6F", false, true},
		{"VMOVDQU64", "_yvmovdqa32", "F3", "1", "0x7F", "0x6F", false, true},
	} {
		var classes, zcases, opbytes []string
		var offsets []int
		for _, encoding := range []string{"vex", "evex"} {
			if encoding == "vex" && !expected.vex || encoding == "evex" && !expected.evex {
				continue
			}
			for direction, opcode := range []string{expected.store, expected.load} {
				widths := []int{128, 256}
				if encoding == "evex" {
					widths = append(widths, 512)
				}
				for _, width := range widths {
					bank := map[int]string{128: "x", 256: "y", 512: "z"}[width]
					register, memory := "Y"+bank+"r", "Y"+bank+"m"
					word := "0"
					if encoding == "evex" {
						word = expected.evexW
						if width != 512 {
							register, memory = register+"Evex", memory+"Evex"
						}
					}
					prefix := fmt.Sprintf("avxEscape | %s%d", encoding, width)
					if expected.pp != "" {
						prefix += " | " + encoding + expected.pp
					}
					prefix += " | " + encoding + "0F | " + encoding + "W" + word
					opbytes = append(opbytes, prefix)
					if encoding == "evex" {
						opbytes = append(opbytes, fmt.Sprintf("evexN%d | evexZeroingEnabled", width/8))
					}
					opbytes = append(opbytes, opcode)
					for _, masked := range []bool{false, true} {
						if masked && encoding == "vex" {
							continue
						}
						first, last, zcase := register, memory, "r_v_rm"
						if direction == 1 {
							first, last, zcase = memory, register, "rm_v_r"
						}
						args, offset := first+","+last, 2
						if encoding == "evex" {
							offset = 0
							if masked {
								args, offset = first+",Yknot0,"+last, 3
								zcase = strings.Replace(zcase, "_v_", "_k_", 1)
							}
						}
						classes, zcases, offsets = append(classes, args), append(zcases, "Z"+encoding+"_"+zcase), append(offsets, offset)
					}
				}
			}
		}
		count, encodingOffset := 0, 0
		for _, rule := range rules {
			if rule.Opcode != expected.name {
				continue
			}
			if count >= len(classes) || rule.RowIndex != count || rule.Ytab != expected.table || rule.Prefix != "Pavx" ||
				strings.Join(rule.Classes, ",") != classes[count] || rule.ZCase != zcases[count] || rule.ZOffset != offsets[count] ||
				rule.EncodingOffset != encodingOffset || !reflect.DeepEqual(rule.OpBytes, opbytes) {
				t.Fatalf("%s complete Go row/attributes changed: %+v", expected.name, rule)
			}
			encodingOffset += offsets[count]
			count++
		}
		if count != len(classes) {
			t.Fatal("missing independent encoder rows", expected.name, count, len(classes))
		}
	}
}

func TestX86PackedMoveCompleteRegisterMaskAndAddressAxes(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		var rows []string
		for _, row := range x86PackedMoveResultOracle {
			for _, bank := range []string{"X", "Y", "Z"} {
				if row.vexOnly && bank == "Z" {
					continue
				}
				limit := 32
				if row.vexOnly {
					limit = 16
				}
				if arch == "386" && bank == "Z" {
					limit = 8
				}
				for index := 0; index < limit; index++ {
					rows = append(rows, fmt.Sprintf("%s %s%d,%s1", row.name, bank, index, bank), fmt.Sprintf("%s %s0,%s%d", row.name, bank, bank, index))
				}
				if !row.vexOnly {
					for mask := 1; mask <= 7; mask++ {
						for _, suffix := range []string{"", ".Z"} {
							rows = append(rows, fmt.Sprintf("%s%s %s0,K%d,%s1", row.name, suffix, bank, mask, bank),
								fmt.Sprintf("%s%s (AX),K%d,%s1", row.name, suffix, mask, bank),
								fmt.Sprintf("%s%s %s0,K%d,(AX)", row.name, suffix, bank, mask))
						}
					}
				}
				for _, address := range []string{"(AX)", "-16(BX)(CX*2)", "value+0(FP)", "local-64(SP)", "·data(SB)", "(FS)", "(GS)"} {
					rows = append(rows, fmt.Sprintf("%s %s,%s1", row.name, address, bank), fmt.Sprintf("%s %s1,%s", row.name, bank, address))
				}
			}
		}
		var source strings.Builder
		for index, row := range rows {
			fmt.Fprintf(&source, "TEXT f%d(SB),4,$64-64\n%s\nRET\n", index, row)
		}
		goAssemblerOracleOutput(t, arch, source.String(), "", true)
		file, err := Parse(ArchAMD64, source.String())
		if err != nil {
			t.Fatal(err)
		}
		for index, fn := range file.Funcs {
			ins := fn.Instrs[1]
			_, known, err := amd64PackedVectorMoveProperties(ins, arch)
			physicalContext := false
			for _, arg := range ins.Args {
				register, vector := amd64VectorRegisterIndex(arg.Reg, amd64VectorByteWidth(arg.Reg))
				physicalContext = physicalContext || arch == "386" && vector && register >= 8
			}
			if !known || physicalContext && !errors.Is(err, ErrProbeNeedsContext) || !physicalContext && err != nil {
				t.Fatal("independent Go family grammar mismatch", arch, rows[index], err)
			}
		}
		t.Logf("%s: %d independent actual-Go accepted form axes", arch, len(rows))
	}
}

func TestX86PackedMoveConstructedMemoryCannotBypassGrammar(t *testing.T) {
	for _, row := range x86PackedMoveResultOracle {
		for _, arch := range []string{"amd64", "386"} {
			for _, change := range []string{"unknown offset", "unknown index", "bad scale", "stack index", "vector base", "vector index", "unknown register", "address literal"} {
				ins := x86ScalarLaneInstruction(t, row.name+" (AX),X1")
				switch change {
				case "unknown offset":
					ins.Args[0].Mem.OffRaw = "missing"
				case "unknown index":
					ins.Args[0].Mem.IndexExt = "missing"
				case "bad scale":
					ins.Args[0].Mem.Index, ins.Args[0].Mem.Scale = CX, 3
				case "stack index":
					ins.Args[0].Mem.Index, ins.Args[0].Mem.Scale = SP, 1
				case "vector base":
					ins.Args[0].Mem.Base = "X0"
				case "vector index":
					ins.Args[0].Mem.Index, ins.Args[0].Mem.Scale = "X0", 1
				case "unknown register":
					ins.Args[0].Mem.Base = "UNKNOWN"
				case "address literal":
					ins.Args[0] = Operand{Kind: OpSym, Sym: "$table<>(SB)"}
				}
				if _, known, err := amd64PackedVectorMoveProperties(ins, arch); !known || err == nil {
					t.Fatal("constructed memory bypassed grammar", row.name, arch, change, err)
				}
				if x86ScalarFPResultTransfer(ins, &x86ResultState{}, nil, 0, arch) {
					t.Fatal("invalid memory acquired a result effect", row.name, arch, change)
				}
			}
		}
	}
}
