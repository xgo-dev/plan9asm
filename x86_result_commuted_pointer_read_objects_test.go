package plan9asm

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

// These literal ModRM/SIB observations are independent of the address-role
// parser. They establish original Go encodings, not pointer bounds or execution.
func TestX86IncomingPointerCommutedReadOriginalGoBytes(t *testing.T) {
	for _, row := range []struct {
		arch, instruction string
		want              []byte
	}{
		{"amd64", "MOVB -8(BX)(AX*1),CX", []byte{0x8a, 0x4c, 0x03, 0xf8, 0xc3}},
		{"amd64", "MOVB -8(AX)(BX*1),CX", []byte{0x8a, 0x4c, 0x18, 0xf8, 0xc3}},
		{"amd64", "MOVW -8(BX)(AX*1),CX", []byte{0x66, 0x8b, 0x4c, 0x03, 0xf8, 0xc3}},
		{"amd64", "MOVW -8(AX)(BX*1),CX", []byte{0x66, 0x8b, 0x4c, 0x18, 0xf8, 0xc3}},
		{"amd64", "MOVL -8(BX)(AX*1),CX", []byte{0x8b, 0x4c, 0x03, 0xf8, 0xc3}},
		{"amd64", "MOVL -8(AX)(BX*1),CX", []byte{0x8b, 0x4c, 0x18, 0xf8, 0xc3}},
		{"amd64", "MOVQ -8(BX)(AX*1),CX", []byte{0x48, 0x8b, 0x4c, 0x03, 0xf8, 0xc3}},
		{"amd64", "MOVQ -8(AX)(BX*1),CX", []byte{0x48, 0x8b, 0x4c, 0x18, 0xf8, 0xc3}},
		{"amd64", "MOVL -8(AX)(BX*1),AX", []byte{0x8b, 0x44, 0x18, 0xf8, 0xc3}},
		{"amd64", "MOVL -8(AX)(BX*1),BX", []byte{0x8b, 0x5c, 0x18, 0xf8, 0xc3}},
		{"amd64", "MOVD -8(AX)(BX*1),BX", []byte{0x48, 0x8b, 0x5c, 0x18, 0xf8, 0xc3}},
		{"386", "MOVB -8(AX)(BX*1),CX", []byte{0x8a, 0x4c, 0x18, 0xf8, 0xc3}},
		{"386", "MOVW -8(AX)(BX*1),CX", []byte{0x66, 0x8b, 0x4c, 0x18, 0xf8, 0xc3}},
		{"386", "MOVL -8(AX)(BX*1),CX", []byte{0x8b, 0x4c, 0x18, 0xf8, 0xc3}},
		{"386", "MOVL -8(BX)(AX*1),CX", []byte{0x8b, 0x4c, 0x03, 0xf8, 0xc3}},
		{"386", "MOVL -8(AX)(BX*1),AX", []byte{0x8b, 0x44, 0x18, 0xf8, 0xc3}},
		{"386", "MOVL -8(AX)(BX*1),BX", []byte{0x8b, 0x5c, 0x18, 0xf8, 0xc3}},
		{"386", "MOVL -8(AX)(BP*1),CX", []byte{0x8b, 0x4c, 0x28, 0xf8, 0xc3}},
	} {
		t.Run(row.arch+"/"+row.instruction, func(t *testing.T) {
			source := "TEXT original(SB),4,$0-0\n" + row.instruction + "\nRET\n"
			if actual := x86OrderingHintGoBytes(t, row.arch, source); !bytes.Equal(actual, row.want) {
				t.Fatalf("original Go bytes = %x, independent SIB/alias bytes = %x", actual, row.want)
			}
		})
	}
	t.Run("386/Go-invalid-GP-qword", func(t *testing.T) {
		// The memory-to-X m64 row is independent; this is the GP-only row
		// that Go restricts to mode64, not another admitted mode32 format.
		requireLEANativeGoObject(t, "386", "TEXT invalid(SB),4,$0-0\nMOVQ -8(AX)(BX*1),CX\nRET\n", false)
	})
}

func TestX86IncomingPointerCommutedReadFiveTargetOriginalGoAndLLVMObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc is required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			word, nativeMove := goWordSize(target.arch), "MOVQ"
			if target.arch == "386" {
				nativeMove = "MOVL"
			}
			// Complete this bounded read/alias matrix once per target. The
			// independent byte oracle above does not derive its expected bytes
			// from these rows, nor from the production address parser.
			type moveRow struct {
				op, store, result string
				width             int
			}
			rows := []moveRow{
				{"MOVB", "MOVB", "uint8", 1},
				{"MOVW", "MOVW", "uint16", 2},
				{"MOVL", "MOVL", "uint32", 4},
			}
			if target.arch == "amd64" {
				rows = append(rows,
					moveRow{"MOVQ", "MOVQ", "uint64", 8},
					moveRow{"MOVD", "MOVQ", "uint64", 8},
				)
			}
			var source, declarations strings.Builder
			count := 0
			for _, row := range rows {
				for order, address := range []string{"-8(BX)(AX*1)", "-8(AX)(BX*1)"} {
					for _, destination := range []string{"AX", "BX", "CX"} {
						name := fmt.Sprintf("Read%sOrder%dTo%s", row.op, order, destination)
						fmt.Fprintf(&declarations, "func %s(p *byte,n uintptr) %s\n", name, row.result)
						fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n%s p+0(FP),BX\n%s n+%d(FP),AX\n%s %s,%s\n%s %s,ret+%d(FP)\nRET\n",
							name, 2*word+row.width, nativeMove, nativeMove, word,
							row.op, address, destination, row.store, destination, 2*word)
						count++
					}
				}
			}
			want := 30
			if target.arch == "386" {
				want = 18
			}
			if count != want || strings.Count(source.String(), "TEXT ") != want {
				t.Fatal("complete original source/alias denominator changed", count, want)
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
					if err != nil || strings.Count(ir, "define ") != want {
						t.Fatal("complete declared read/alias source failed", err)
					}
					for _, row := range rows {
						reads := 6
						if row.width == 8 {
							reads = 12 // MOVQ and its complete original MOVD alias.
						}
						if strings.Count(ir, fmt.Sprintf("load volatile i%d,", 8*row.width)) != reads {
							t.Fatal("native read lost exact width/volatile semantics", row.op)
						}
					}
					for _, optimizeIR := range []bool{false, true} {
						input, label := ir, "IR-original"
						if optimizeIR {
							input, label = x86MulDivRoundOptimize(t, ir), "IR-O2"
						}
						for _, backend := range []string{"-O0", "-O2"} {
							t.Run(label+"/backend"+backend, func(t *testing.T) {
								x86PackedStringCompileObject(t, llc, target.triple, input, backend)
							})
						}
					}
				})
			}
		})
	}
}
