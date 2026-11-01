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

// DDI0602 scalar two-source opcode field, independent of production decoding.
var arm64BinaryTestKinds = []struct {
	name   string
	opcode uint32
}{
	{"FADD", 0x2800}, {"FSUB", 0x3800}, {"FMUL", 0x0800},
	{"FNMUL", 0x8800}, {"FDIV", 0x1800},
}

func arm64BinaryTestWord(kind, bits, first, second, destination int) uint32 {
	word := uint32(0x1e200000) | arm64BinaryTestKinds[kind].opcode
	if bits == 64 {
		word |= 1 << 22
	} else if bits == 16 {
		word |= 3 << 22
	}
	return word | uint32(first)<<5 | uint32(second)<<16 | uint32(destination)
}

func TestARM64ScalarBinaryCompleteGoTableAndBytes(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(testGOROOT(t), "src/cmd/internal/obj/arm64/asm7.go"))
	if err != nil {
		t.Fatal(err)
	}
	sdk := string(data)
	rows := regexp.MustCompile(`(?m)^\s*\{AFADDS,[^\n]+`).FindAllString(sdk, -1)
	if len(rows) != 2 {
		t.Fatalf("Go binary family acquired unreviewed rows: %v", rows)
	}
	for index, row := range rows {
		fields := strings.Split(strings.Trim(strings.TrimSpace(row), "{},"), ",")
		for i := range fields {
			fields[i] = strings.TrimSpace(fields[i])
		}
		second := []string{"C_NONE", "C_FREG"}[index]
		want := []string{"AFADDS", "C_FREG", second, "C_NONE", "C_FREG", "54", "4", "0", "0", "0"}
		if len(fields) == 11 {
			want = append(append([]string{}, want[:5]...), append([]string{"C_NONE"}, want[5:]...)...)
		}
		if !reflect.DeepEqual(fields, want) {
			t.Fatalf("complete Go binary row changed: %v", fields)
		}
	}
	alias := regexp.MustCompile(`case AFADDS:\s*((?:oprangeset\([^\n]+\)\s*)+)`).FindStringSubmatch(sdk)
	if len(alias) != 2 {
		t.Fatal("Go case54 inheritance missing")
	}
	for _, name := range arm64ScalarBinaryNames[1:] {
		if strings.Count(alias[1], "oprangeset(A"+name+", t)") != 1 {
			t.Fatalf("complete Go inheritance lacks %s", name)
		}
	}
	for kind, operation := range arm64BinaryTestKinds {
		for width, suffix := range []string{"S", "D"} {
			// Older Go returns the encoding directly; current Go assigns it
			// before the shared epilogue. The complete attributes stay exact.
			encoding := fmt.Sprintf(`case A%s%s:\s*(?:op =|return) FPOP2S\(0, 0, %d, %d\)`, operation.name, suffix, width, []int{2, 3, 0, 8, 1}[kind])
			if !regexp.MustCompile(encoding).MatchString(sdk) {
				t.Fatalf("Go changed %s%s opcode attributes", operation.name, suffix)
			}
		}
	}
	var source strings.Builder
	source.WriteString("TEXT original(SB),516,$0-0\n")
	var expected []uint32
	add := func(kind, bits, first, second, destination, operands int) {
		op := arm64BinaryTestKinds[kind].name + map[int]string{32: "S", 64: "D"}[bits]
		line := fmt.Sprintf("%s F%d,F%d,F%d", op, second, first, destination)
		if operands == 2 {
			first = destination
			line = fmt.Sprintf("%s F%d,F%d", op, second, destination)
		}
		form, known, err := parseARM64ScalarBinary(Op(op), arm64ImmediateTestInstruction(t, line))
		if !known || err != nil || form.bits != bits || form.opcode != strings.ToLower(arm64BinaryTestKinds[kind].name) ||
			form.first != Reg(fmt.Sprintf("F%d", first)) || form.second != Reg(fmt.Sprintf("F%d", second)) || form.destination != Reg(fmt.Sprintf("F%d", destination)) {
			t.Fatalf("typed original Go row %s: %+v %v", line, form, err)
		}
		source.WriteString(line + "\n")
		expected = append(expected, arm64BinaryTestWord(kind, bits, first, second, destination))
	}
	for kind := range arm64BinaryTestKinds {
		for _, bits := range []int{32, 64} {
			for bank := 0; bank < 32; bank++ {
				add(kind, bits, bank, 31, 15, 3)
				add(kind, bits, 0, bank, 15, 3)
				add(kind, bits, 0, 31, bank, 3)
				add(kind, bits, bank, bank, bank, 3)
				add(kind, bits, bank, (bank+1)%32, bank, 2)
			}
		}
	}
	source.WriteString("RET\n")
	actual := arm64ImmediateOriginalGoBytes(t, source.String(), "linux")
	if len(actual) < 4*(len(expected)+1) {
		t.Fatalf("short actual Go object: %d", len(actual))
	}
	for index, word := range expected {
		if got := binary.LittleEndian.Uint32(actual[index*4:]); got != word {
			t.Fatalf("Go word %d got %#08x want %#08x", index, got, word)
		}
	}
	t.Logf("%d actual Go words; two complete table rows, ten names, independent banks/aliases", len(expected))
}

func TestARM64ScalarBinaryActualGoRejectsInvalidFormats(t *testing.T) {
	for _, operation := range arm64ScalarBinaryNames {
		for _, suffix := range []string{" F0", " F0,F1,F2,F3", " R0,F1", " F0,R1", " V0.S4,F1", " (R0),F1", " F0,0(FP)", " $1.0,F1", " F0,F32", ".P F0,F1"} {
			requireARM64GoAssemblerResult(t, "TEXT invalid(SB),4,$0-0\n"+operation+suffix+"\nRET\n", false)
		}
	}
}

func TestARM64ScalarBinaryRawCompleteFields(t *testing.T) {
	count := 0
	for kind, operation := range arm64BinaryTestKinds {
		for _, bits := range []int{16, 32, 64} {
			for first := 0; first < 32; first++ {
				for second := 0; second < 32; second++ {
					for destination := 0; destination < 32; destination++ {
						word := arm64BinaryTestWord(kind, bits, first, second, destination)
						form, known := decodeARM64RawScalarFloatBinary(word)
						if !known || form.kind != strings.ToLower(operation.name[1:]) || form.bits != bits ||
							form.first != first || form.second != second || form.destination != destination {
							t.Fatalf("raw word %#08x: %+v %t", word, form, known)
						}
						count++
					}
				}
			}
			for _, bit := range []uint{10, 21, 24, 25, 26, 27, 28, 29, 30, 31} {
				word := arm64BinaryTestWord(kind, bits, 0, 31, 15) ^ (1 << bit)
				if _, known := decodeARM64RawScalarFloatBinary(word); known {
					t.Fatalf("fixed bit %d changed to known scalar family: %#08x", bit, word)
				}
			}
		}
		word := arm64BinaryTestWord(kind, 32, 0, 31, 15) | 2<<22
		if _, known := decodeARM64RawScalarFloatBinary(word); known {
			t.Fatalf("reserved type accepted: %#08x", word)
		}
	}
	t.Logf("%d exact H/S/D field/alias decode observations; not runtime credit", count)
}

func TestARM64ScalarBinaryNativeIndependentAxisObjects(t *testing.T) {
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
	for _, operation := range arm64ScalarBinaryNames {
		for bank := 0; bank < 32; bank++ {
			fmt.Fprintf(&source, "%s F%d,F%d\n%s F%d,F%d,F%d\n", operation, bank, bank, operation, bank, (bank+1)%32, (bank+2)%32)
			count += 2
		}
	}
	for kind := range arm64BinaryTestKinds {
		for _, bits := range []int{16, 32, 64} {
			fmt.Fprintf(&source, "WORD $%#08x\n", arm64BinaryTestWord(kind, bits, 31, 0, 15))
			count++
		}
	}
	source.WriteString("CSET EQ,R2\nMOVD R2,(R1)\nRET\n")
	for _, target := range []struct{ os, triple string }{{"linux", "aarch64-unknown-linux-gnu"}, {"darwin", "aarch64-apple-darwin"}, {"windows", "aarch64-pc-windows-msvc"}} {
		t.Run(target.os, func(t *testing.T) {
			arm64CompareGoObject(t, source.String(), target.os)
			for api, ir := range arm64BinaryMatrixIRs(t, source.String(), "package compare\nfunc compareMatrix0(*[66]uint64,*[69]uint64)\n", target.triple) {
				optimized := armFloatEffectOptimizedIR(t, ir)
				if strings.Count(optimized, "call <16 x i8> asm sideeffect") != count {
					t.Fatalf("API%d lost a dead native operation", api)
				}
				compileLLVMToObject(t, llc, target.triple, "binary.ll", "binary.o", optimized)
			}
		})
	}
	t.Logf("%d initialized independent-axis forms × three APIs plus typed-Go × three target objects", count)
}

func TestARM64ScalarBinaryTargetAndCompleteSourceBoundaries(t *testing.T) {
	for _, api := range []string{"text", "module", "owned-module", "Go"} {
		for _, operation := range arm64ScalarBinaryNames {
			for _, triple := range []string{"", "x86_64-unknown-linux-gnu", "aarch64_be-unknown-linux-gnu", "aarch64bad-unknown-linux-gnu", "aarch64-unknown-linux-gnu"} {
				for _, body := range []string{operation + " F0,F31", "RET\n" + operation + " F0,F31,F15"} {
					present, err := arm64BinaryTargetAPI(t, api, "TEXT comparison(SB),4,$0-0\n"+body+"\nRET\n", triple)
					if triple == "aarch64-unknown-linux-gnu" {
						if !present || err != nil {
							t.Fatalf("%s native target rejected: %v", api, err)
						}
					} else if present || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatalf("%s unbound native role produced output=%t error=%v", api, present, err)
					}
				}
				for _, suffix := range []string{"", " F0", " F0,F1,F2,F3", " R0,F1", " F0,R1", " V0.S4,F1", " (R0),F1", " F0,0(FP)", " $1.0,F1", " F0,F32", ".P F0,F1"} {
					source := "TEXT comparison(SB),4,$0-0\nFADDS F0,F1\nRET\n" + operation + suffix + "\n"
					present, err := arm64BinaryTargetAPI(t, api, source, triple)
					if present || err == nil || errors.Is(err, ErrProbeNeedsContext) {
						t.Fatalf("%s dead malformed source masked by target: %t %v\n%s", api, present, err, source)
					}
				}
			}
		}
		for kind := range arm64BinaryTestKinds {
			for _, bits := range []int{16, 32, 64} {
				word := arm64BinaryTestWord(kind, bits, 0, 31, 15)
				present, err := arm64BinaryTargetAPI(t, api, fmt.Sprintf("TEXT comparison(SB),4,$0-0\nRET\nWORD $%#08x\n", word), "")
				if present || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("raw native role escaped target: %t %v", present, err)
				}
			}
			word := arm64BinaryTestWord(kind, 32, 0, 31, 15) | 2<<22
			present, err := arm64BinaryTargetAPI(t, api, fmt.Sprintf("TEXT comparison(SB),4,$0-0\nFADDS F0,F1\nRET\nWORD $%#08x\n", word), "")
			if present || err == nil || errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("reserved raw type masked by native Context: %t %v", present, err)
			}
		}
	}
}
