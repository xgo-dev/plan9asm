package plan9asm

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func TestX86GPSIMDTransferCompleteLegacyOriginalTables(t *testing.T) {
	source, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range []struct{ op, name, prefix, bytes, rows string }{
		{"MOVB", "ymovb", "Pb", "0x88,0x8a,0xb0,0xc6,00", `
		{Zr_m,1,argList{Yrb,Ymb}},{Zm_r,1,argList{Ymb,Yrb}},
		{Zib_rp,1,argList{Yi32,Yrb}},{Zibo_m,2,argList{Yi32,Ymb}},`},
		{"MOVW", "ymovw", "Pe", "0x89,0x8b,0xb8,0xc7,00,0", `
		{Zr_m,1,argList{Yrl,Yml}},{Zm_r,1,argList{Yml,Yrl}},
		{Zil_rp,1,argList{Yi32,Yrl}},{Zilo_m,2,argList{Yi32,Yml}},
		{Zaut_r,2,argList{Yiauto,Yrl}},`},
		{"MOVL", "ymovl", "Px", "0x89,0x8b,0xb8,0xc7,00,0x6e,0x7e,Pe,0x6e,Pe,0x7e,0", `
		{Zr_m,1,argList{Yrl,Yml}},{Zm_r,1,argList{Yml,Yrl}},
		{Zil_rp,1,argList{Yi32,Yrl}},{Zilo_m,2,argList{Yi32,Yml}},
		{Zm_r_xm,1,argList{Yml,Ymr}},{Zr_m_xm,1,argList{Ymr,Yml}},
		{Zm_r_xm,2,argList{Yml,Yxr}},{Zr_m_xm,2,argList{Yxr,Yml}},
		{Zaut_r,2,argList{Yiauto,Yrl}},`},
		{"MOVQ", "ymovq", "Pw8", "0x6f,0x7f,Pf2,0xd6,Pf3,0x7e,Pe,0xd6,0x89,0x8b,0xb8,0xc7,00,0x6e,0x7e,Pe,0x6e,Pe,0x7e,0", `
		{Zm_r_xm_nr,1,argList{Ym,Ymr}},{Zr_m_xm_nr,1,argList{Ymr,Ym}},
		{Zm_r_xm_nr,2,argList{Yxr,Ymr}},{Zm_r_xm_nr,2,argList{Yxm,Yxr}},
		{Zr_m_xm_nr,2,argList{Yxr,Yxm}},{Zr_m,1,argList{Yrl,Yml}},
		{Zm_r,1,argList{Yml,Yrl}},{Ziq_rp,1,argList{Yi64,Yrl}},
		{Zilo_m,2,argList{Yi32,Yml}},{Zm_r_xm,1,argList{Ymm,Ymr}},
		{Zr_m_xm,1,argList{Ymr,Ymm}},{Zm_r_xm,2,argList{Yml,Yxr}},
		{Zr_m_xm,2,argList{Yxr,Yml}},{Zaut_r,1,argList{Yiauto,Yrl}},`},
	} {
		t.Run(table.op, func(t *testing.T) {
			definition := regexp.MustCompile(`(?s)var ` + table.name + ` = \[\]ytab\{(.*?)\n\}`).FindStringSubmatch(string(source))
			entry := regexp.MustCompile(`\{A` + table.op + `, (\w+), (\w+), opBytes\{([^}]+)\}\}`).FindStringSubmatch(string(source))
			strip := func(text string) string {
				text = regexp.MustCompile(`//[^\n]*`).ReplaceAllString(text, "")
				return strings.Join(strings.Fields(text), "")
			}
			if len(definition) != 2 || len(entry) != 4 || entry[1] != table.name || entry[2] != table.prefix {
				t.Fatal("complete legacy row/prefix/opcode inventory changed", entry, definition)
			}
			inventories := []struct{ name, rows, bytes string }{{"current", table.rows, table.bytes}}
			if table.op == "MOVQ" {
				// Go 1.20 has a separate signed-imm32 row before its imm64
				// row. Pin that complete historical inventory, rather than
				// discarding scalar rows to make the GP/X subset look equal.
				inventories = append(inventories, struct{ name, rows, bytes string }{
					"signed-imm32",
					strings.Replace(table.rows, "{Ziq_rp,1,argList{Yi64,Yrl}}",
						"{Zilo_m,2,argList{Ys32,Yrl}},{Ziq_rp,1,argList{Yi64,Yrl}}", 1),
					"0x6f,0x7f,Pf2,0xd6,Pf3,0x7e,Pe,0xd6,0x89,0x8b,0xc7,00,0xb8,0xc7,00,0x6e,0x7e,Pe,0x6e,Pe,0x7e,0",
				})
			}
			for _, inventory := range inventories {
				if strip(definition[1]) == strip(inventory.rows) && strip(entry[3]) == inventory.bytes {
					t.Logf("%s complete %s inventory: %s", runtime.Version(), table.op, inventory.name)
					return
				}
			}
			t.Fatal("complete legacy row/prefix/opcode inventory changed", entry, definition)
		})
	}
}

func TestX86GPSIMDTransferAllRegisterAndAddressAxes(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, arch := range []string{"amd64", "386"} {
		t.Run(arch, func(t *testing.T) {
			var assembly strings.Builder
			assembly.WriteString("TEXT f(SB),4,$0-0\n")
			count := 0
			appendRow := func(op, src, dst string) {
				row := op + " " + src + "," + dst
				ins := x86YMMReadSource(t, row)
				before := fmt.Sprintf("%#v", ins)
				if _, known, err := x86GPSIMDTransferProperties(ins, arch); !known || err != nil {
					t.Fatal("independent valid axis not consumed", row, err)
				}
				if before != fmt.Sprintf("%#v", ins) {
					t.Fatal("grammar mutated original source")
				}
				fmt.Fprintln(&assembly, row)
				count++
			}
			for _, op := range []string{"MOVL", "MOVQ", "MOVD", "VMOVD", "VMOVQ"} {
				legacy := !strings.HasPrefix(op, "V")
				gps := []string{"AX", "BX", "CX", "DX", "DI", "SI", "BP", "SP"}
				if arch == "amd64" {
					gps = append(gps, "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15")
				}
				if arch == "amd64" || !legacy || op == "MOVL" {
					for _, gp := range gps {
						appendRow(op, gp, "X0")
						appendRow(op, "X0", gp)
					}
				}
				limit := 8
				if arch == "amd64" {
					limit = 16
					if !legacy {
						limit = 32
					}
				}
				for index := 0; index < limit; index++ {
					x := fmt.Sprint("X", index)
					appendRow(op, "3(AX)", x)
					appendRow(op, x, "5(BX)")
					if op == "MOVQ" || op == "MOVD" || op == "VMOVQ" {
						appendRow(op, x, "X0")
						appendRow(op, x, x)
					}
				}
				for _, memory := range []string{"(AX)(CX*1)", "7(AX)(CX*2)", "-9(AX)(CX*4)", "11(AX)(CX*8)"} {
					appendRow(op, memory, "X1")
					appendRow(op, "X1", memory)
				}
			}
			assembly.WriteString("RET\n")
			goAssemblerOracleOutput(t, arch, assembly.String(), "", true)
			want := 552
			triples := []string{"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc"}
			if arch == "386" {
				want, triples = 216, []string{"i386-unknown-linux-gnu", "i686-pc-windows-msvc"}
			}
			if count != want {
				t.Fatalf("independent register/address denominator changed: %d, want %d", count, want)
			}
			for _, triple := range triples {
				t.Run(triple, func(t *testing.T) {
					// Keep every original uninitialized axis as a Go/public-Context
					// control, separate from initialized public object owners.
					ir := x86UnboundVoidScalarFormatObject(t, assembly.String(), "f", arch, triple)
					for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
						for _, level := range []string{"-O0", "-O2"} {
							x86PackedStringCompileObject(t, llc, triple, text, level)
						}
					}
				})
			}
		})
	}
}

func TestX86GPSIMDTransferPartialByteKnowledgeAndUnaffectedState(t *testing.T) {
	for _, op := range []string{"MOVL", "MOVQ", "MOVD", "VMOVD", "VMOVQ"} {
		width := 4
		if op == "MOVQ" || op == "MOVD" || op == "VMOVQ" {
			width = 8
		}
		for _, direction := range []string{"gp-to-x", "x-to-gp", "x-to-x"} {
			if direction == "x-to-x" && width == 4 {
				continue
			}
			t.Run(op+"/"+direction, func(t *testing.T) {
				for seed := 0; seed < 256; seed++ {
					initial := x86SourceStackState{
						bp: x86SourceStackAddress{original: true}, gOriginal: true, numericFlags: true,
						callers: map[Reg]x86CallerPointerValue{DI: {argument: 0}}, known: map[Reg]uint8{AX: uint8(seed), BX: 0x53},
						vectors: map[Reg]uint64{"Z0": uint64(seed), "Z1": 0xa735de42c9156ef0, "Z31": 0x1927},
						masks:   map[Reg]bool{"K1": true},
					}
					args := "AX,X1"
					if direction == "x-to-gp" {
						args = "X0,AX"
					} else if direction == "x-to-x" {
						args = "X0,X1"
					}
					ins := x86YMMReadSource(t, op+" "+args)
					state, want := x86CloneCallerState(initial), x86CloneCallerState(initial)
					low := uint64(seed) & (uint64(1)<<uint(width) - 1)
					accepted := direction != "x-to-gp" || low == uint64(1)<<uint(width)-1
					if accepted && direction == "x-to-gp" {
						want.known[AX] = 0xff
					} else if direction != "x-to-gp" {
						known := low | 0xffff&^(uint64(1)<<uint(width)-1)
						if strings.HasPrefix(op, "V") {
							known |= ^uint64(0xffff)
						} else {
							known |= initial.vectors["Z1"] &^ 0xffff
						}
						want.vectors["Z1"] = known
					}
					if got := x86CallerVectorMoveStep(&ins, &state, nil); got != accepted || !reflect.DeepEqual(state, want) {
						t.Fatalf("%s %s seed=%d admitted=%v/%v got=%+v want=%+v", op, args, seed, got, accepted, state, want)
					}
				}
			})
		}
	}
}

func TestX86GPSIMDTransferRejectsUnboundPhysical386Banks(t *testing.T) {
	for _, op := range []string{"VMOVD", "VMOVQ"} {
		for _, row := range []string{op + " AX,X8", op + " X31,AX", op + " (AX),X17", op + " X17,(AX)"} {
			t.Run(row, func(t *testing.T) {
				goAssemblerOracleOutput(t, "386", "TEXT f(SB),4,$0-0\n"+row+"\nRET\n", "", true)
				if _, known, err := x86GPSIMDTransferProperties(x86YMMReadSource(t, row), "386"); !known || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("unbound Go-accepted mode32 bank acquired virtual semantics", err)
				}
				x86RequireZeroMaskAPIOutcome(t, "386", "TEXT f(SB),4,$0-0\n"+row+"\nRET\n", false)
			})
		}
	}
}
