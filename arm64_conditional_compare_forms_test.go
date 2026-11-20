package plan9asm

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

var arm64ConditionalTestConditions = []string{"EQ", "NE", "CS", "CC", "MI", "PL", "VS", "VC", "HI", "LS", "GE", "LT", "GT", "LE", "AL", "NV"}

// Independent DDI0602 bit layout, not the production decoder or named table.
func arm64ConditionalTestWord(bits, condition, nzcv, left, right int, signaling bool) uint32 {
	word := uint32(0x1e200400) | uint32(left)<<5 | uint32(right)<<16 | uint32(condition)<<12 | uint32(nzcv)
	if bits == 64 {
		word |= 1 << 22
	} else if bits == 16 {
		word |= 3 << 22
	}
	if signaling {
		word |= 1 << 4
	}
	return word
}

func TestARM64ConditionalCompareCompleteGoTableAndBytes(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(testGOROOT(t), "src/cmd/internal/obj/arm64/asm7.go"))
	if err != nil {
		t.Fatal(err)
	}
	sdk := string(data)
	rows := regexp.MustCompile(`(?m)^\s*\{AFCCMP[^\n]+`).FindAllString(sdk, -1)
	if len(rows) != 1 {
		t.Fatalf("Go FCCMP family acquired an unreviewed row: %v", rows)
	}
	fields := strings.Split(strings.Trim(strings.TrimSpace(rows[0]), "{},"), ",")
	for i := range fields {
		fields[i] = strings.TrimSpace(fields[i])
	}
	want := []string{"AFCCMPS", "C_COND", "C_FREG", "C_FREG", "C_VCON", "57", "4", "0", "0", "0"}
	if len(fields) == 11 {
		want = append(append([]string{}, want[:5]...), append([]string{"C_NONE"}, want[5:]...)...)
	}
	if !reflect.DeepEqual(fields, want) {
		t.Fatalf("complete Go FCCMP row changed: %v", fields)
	}
	alias := regexp.MustCompile(`case AFCCMPS:\s*((?:oprangeset\([^\n]+\)\s*)+)`).FindStringSubmatch(sdk)
	if len(alias) != 2 || strings.Join(strings.Fields(alias[1]), " ") != "oprangeset(AFCCMPD, t) oprangeset(AFCCMPES, t) oprangeset(AFCCMPED, t)" {
		t.Fatalf("complete Go FCCMP inheritance changed: %v", alias)
	}
	var source strings.Builder
	source.WriteString("TEXT original(SB),516,$0-0\n")
	var expected []uint32
	appendRow := func(operation, condition string, code, flags, left, right, bits int, signaling bool) {
		line := fmt.Sprintf("%s %s,F%d,F%d,$%d", operation, condition, right, left, flags)
		source.WriteString(line + "\n")
		expected = append(expected, arm64ConditionalTestWord(bits, code, flags, left, right, signaling))
		instruction := arm64ImmediateTestInstruction(t, line)
		form, known, err := parseARM64ConditionalCompare(instruction.Op, instruction)
		if !known || err != nil || form.bits != bits || form.signaling != signaling ||
			form.left != Reg(fmt.Sprintf("F%d", left)) || form.right != Reg(fmt.Sprintf("F%d", right)) || form.nzcv != uint8(flags) {
			t.Fatalf("typed Go row differs: %s %+v %v", line, form, err)
		}
	}
	for _, operation := range arm64ConditionalCompareNames {
		bits, signaling := 32, strings.Contains(operation, "E")
		if strings.HasSuffix(operation, "D") {
			bits = 64
		}
		for condition, spelling := range arm64ConditionalTestConditions {
			for flags := 0; flags < 16; flags++ {
				appendRow(operation, spelling, condition, flags, 0, 31, bits, signaling)
			}
		}
		for left := 0; left < 32; left++ {
			for right := 0; right < 32; right++ {
				appendRow(operation, "AL", 14, 15, left, right, bits, signaling)
			}
		}
		appendRow(operation, "HS", 2, 0, 31, 0, bits, signaling)
		appendRow(operation, "LO", 3, 15, 31, 0, bits, signaling)
	}
	source.WriteString("RET\n")
	actual := arm64ImmediateOriginalGoBytes(t, source.String(), "linux")
	if len(actual) < 4*(len(expected)+1) {
		t.Fatalf("short actual Go object: %d bytes", len(actual))
	}
	for index, word := range expected {
		if got := binary.LittleEndian.Uint32(actual[index*4:]); got != word {
			t.Fatalf("original Go case %d got %#08x want %#08x", index, got, word)
		}
	}
	t.Logf("%d actual Go words: complete inherited row, conditions/flags and both register banks", len(expected))
}

func TestARM64ConditionalCompareRawCompleteFields(t *testing.T) {
	count := 0
	for _, bits := range []int{16, 32, 64} {
		for _, signaling := range []bool{false, true} {
			check := func(condition, flags, left, right int) {
				word := arm64ConditionalTestWord(bits, condition, flags, left, right, signaling)
				form, known := decodeARM64RawConditionalCompare(word)
				if !known || form.bits != bits || form.signaling != signaling || form.nzcv != uint8(flags) ||
					form.condition != arm64ConditionalTestConditions[condition] || form.left != Reg(fmt.Sprintf("F%d", left)) || form.right != Reg(fmt.Sprintf("F%d", right)) {
					t.Fatalf("raw family %#08x: %+v known=%t", word, form, known)
				}
				count++
			}
			for condition := 0; condition < 16; condition++ {
				for flags := 0; flags < 16; flags++ {
					check(condition, flags, 0, 31)
				}
			}
			for left := 0; left < 32; left++ {
				for right := 0; right < 32; right++ {
					check(14, 15, left, right)
				}
			}
		}
	}
	const fixed = uint32(0xff200c00)
	for bit := uint(0); bit < 32; bit++ {
		if fixed&(1<<bit) == 0 {
			continue
		}
		if _, known := decodeARM64RawConditionalCompare(0x1e200400 ^ (1 << bit)); known {
			t.Fatalf("reserved fixed bit %d admitted", bit)
		}
	}
	if _, known := decodeARM64RawConditionalCompare(0x1ea00400); known {
		t.Fatal("reserved ftype=2 admitted")
	}
	t.Logf("%d independent raw operand/condition/NZCV field observations; not runtime credit", count)
}

func TestARM64ConditionalCompareNativeIndependentAxisObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	var source strings.Builder
	source.WriteString("TEXT compareMatrix0(SB),4,$0-16\nMOVD in+0(FP),R0\nMOVD out+8(FP),R1\n")
	for bank := 0; bank < 32; bank++ {
		fmt.Fprintf(&source, "VLD1.P 16(R0),[V%d.B16]\n", bank)
	}
	source.WriteString("CMP R0,R0\n")
	count := 0
	for _, operation := range arm64ConditionalCompareNames {
		for _, condition := range append(append([]string{}, arm64ConditionalTestConditions...), "HS", "LO") {
			fmt.Fprintf(&source, "%s %s,F31,F0,$15\n", operation, condition)
			count++
		}
		for flags := 0; flags < 16; flags++ {
			fmt.Fprintf(&source, "%s EQ,F0,F31,$%d\n", operation, flags)
			count++
		}
		for bank := 0; bank < 32; bank++ {
			fmt.Fprintf(&source, "%s AL,F%d,F%d,$0\n", operation, bank, bank)
			count++
		}
	}
	for _, bits := range []int{16, 32, 64} {
		for _, signaling := range []bool{false, true} {
			for condition := 0; condition < 16; condition++ {
				fmt.Fprintf(&source, "WORD $%#08x\n", arm64ConditionalTestWord(bits, condition, condition, 31, 0, signaling))
				count++
			}
		}
	}
	source.WriteString("CMP R0,R0\nCSET EQ,R2\nMOVD R2,(R1)\nRET\n")
	for _, target := range []struct{ os, triple string }{{"linux", "aarch64-unknown-linux-gnu"}, {"darwin", "aarch64-apple-darwin"}, {"windows", "aarch64-pc-windows-msvc"}} {
		t.Run(target.os, func(t *testing.T) {
			arm64CompareGoObject(t, source.String(), target.os)
			for api, ir := range arm64CompareMatrixIRs(t, source.String(), "package compare\nfunc compareMatrix0(*[66]uint64,*[69]uint64)\n", target.triple) {
				optimized := armFloatEffectOptimizedIR(t, ir)
				if strings.Count(optimized, `asm sideeffect "cmp `) != count {
					t.Fatalf("API%d lost a native conditional effect", api)
				}
				compileLLVMToObject(t, llc, target.triple, "conditional.ll", "conditional.o", optimized)
			}
		})
	}
	t.Logf("%d initialized independent-axis forms x three APIs x three target objects", count)
}

func TestARM64ConditionalCompareNativeBoundaryErrors(t *testing.T) {
	for _, api := range []string{"text", "module", "Go"} {
		for _, triple := range []string{"", "x86_64-unknown-linux-gnu", "aarch64_be-unknown-linux-gnu", "aarch64-unknown-linux-gnu"} {
			for _, invalid := range []string{"FCCMPD EQ,F0,F1,$(0.0)", "FCCMPD EQ,F0,F1,$16", "FCCMPD EQ,R0,F1,$0", "FCCMPD.P EQ,F0,F1,$0", "FCCMPD BAD,F0,F1,$0", "WORD $0x1ea00400"} {
				for _, prefix := range []string{"", "FCCMPS AL,F0,F1,$0\nRET\n"} {
					source := "TEXT comparison(SB),4,$0-0\n" + prefix + invalid + "\nRET\n"
					present, err := arm64CompareTargetAPI(t, api, source, triple)
					if present || err == nil || errors.Is(err, ErrProbeNeedsContext) {
						t.Fatalf("%s malformed/dead form became Context/output: %t %v\n%s", api, present, err, source)
					}
				}
			}
			if triple == "aarch64-unknown-linux-gnu" {
				continue
			}
			for _, instruction := range []string{"FCCMPS AL,F0,F1,$0", "FCCMPED NV,F31,F0,$15", "WORD $0x1ee0e400"} {
				present, err := arm64CompareTargetAPI(t, api, "TEXT comparison(SB),4,$0-0\nRET\n"+instruction+"\n", triple)
				if present || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("%s unbound native target acquired output: %t %v", api, present, err)
				}
			}
		}
	}
	for _, operation := range arm64ConditionalCompareNames {
		for _, arguments := range []string{"EQ,F0,F1,$(0.0)", "EQ,F0,F1,$-1", "EQ,F0,F1,$16", "BAD,F0,F1,$0", "EQ,R0,F1,$0", "EQ,F0,(R1),$0", "EQ,F0,F1"} {
			requireARM64GoAssemblerResult(t, "TEXT original(SB),4,$0-0\n"+operation+" "+arguments+"\nRET\n", false)
		}
	}
}
