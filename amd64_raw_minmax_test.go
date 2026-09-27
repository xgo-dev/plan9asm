package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

var x86MinMaxTestOps = []string{
	"VPMINSB", "VPMINUB", "VPMAXSB", "VPMAXUB",
	"VPMINSW", "VPMINUW", "VPMAXSW", "VPMAXUW",
	"VPMINSD", "VPMINUD", "VPMAXSD", "VPMAXUD",
	"VPMINSQ", "VPMINUQ", "VPMAXSQ", "VPMAXUQ",
}

func TestX86MinMaxGrammarMatchesGoEncoder(t *testing.T) {
	path := filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/avx_optabs.go")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	pattern := `(?s)\{as: A(VPM(?:IN|AX)[SU][BWDQ]), ytab: (\w+), prefix: Pavx, op: opBytes\{(.*?)\}\}`
	rows := regexp.MustCompile(pattern).FindAllStringSubmatch(string(data), -1)
	if len(rows) != 16 || len(amd64PackedIntegerMinMaxSpecs) != len(rows) {
		t.Fatalf("Go family=%d, typed family=%d", len(rows), len(amd64PackedIntegerMinMaxSpecs))
	}

	for _, row := range rows {
		spec, ok := amd64PackedIntegerMinMaxSpecs[row[1]]
		if !ok {
			t.Fatalf("missing %s", row[1])
		}
		bits := map[byte]int{'B': 8, 'W': 16, 'D': 32, 'Q': 64}[row[1][len(row[1])-1]]
		if spec.laneBits != bits || spec.signed != (row[1][5] == 'S') || spec.minimum != strings.HasPrefix(row[1], "VPMIN") {
			t.Fatalf("incorrect typed semantics for %s: %+v", row[1], spec)
		}
		if (row[2] == "_yvandnpd") != (bits != 64) || strings.Contains(row[3], "| vex128") != (bits != 64) {
			t.Fatalf("incorrect encoding generation for %s", row[1])
		}
		if strings.Contains(row[3], "0F38") != (spec.mapNumber == 2) || strings.Contains(row[3], "evexBcst") != spec.broadcast {
			t.Fatalf("incorrect map/broadcast for %s", row[1])
		}
		opcodes := regexp.MustCompile(`0x[0-9A-F]+`).FindAllString(row[3], -1)
		wantRows := 5
		if bits == 64 {
			wantRows = 3
		}
		if len(opcodes) != wantRows {
			t.Fatalf("%s has %d encodings, want %d", row[1], len(opcodes), wantRows)
		}
		for _, opcode := range opcodes {
			if opcode != fmt.Sprintf("0x%X", spec.opcode) {
				t.Fatalf("%s opcode=%s, typed=%x", row[1], opcode, spec.opcode)
			}
		}
	}

	operandTables := map[string][]string{
		"_yvandnpd": {
			"Yxm, Yxr, Yxr", "Yym, Yyr, Yyr",
			"YxmEvex, YxrEvex, YxrEvex", "YxmEvex, YxrEvex, Yknot0, YxrEvex",
			"YymEvex, YyrEvex, YyrEvex", "YymEvex, YyrEvex, Yknot0, YyrEvex",
			"Yzm, Yzr, Yzr", "Yzm, Yzr, Yknot0, Yzr",
		},
		"_yvblendmpd": {
			"YxmEvex, YxrEvex, YxrEvex", "YxmEvex, YxrEvex, Yknot0, YxrEvex",
			"YymEvex, YyrEvex, YyrEvex", "YymEvex, YyrEvex, Yknot0, YyrEvex",
			"Yzm, Yzr, Yzr", "Yzm, Yzr, Yknot0, Yzr",
		},
	}
	for name, want := range operandTables {
		pattern := `(?s)var ` + name + ` = \[\]ytab\{(.*?)\n\}`
		table := regexp.MustCompile(pattern).FindStringSubmatch(string(data))
		if len(table) != 2 {
			t.Fatal("missing Go operand table", name)
		}
		args := regexp.MustCompile(`argList\{([^}]+)\}`).FindAllStringSubmatch(table[1], -1)
		var got []string
		for _, arg := range args {
			got = append(got, arg[1])
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("Go %s rows=%v, want %v", name, got, want)
		}
	}
}

func TestX86MinMaxGoRejectedForms(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range x86MinMaxTestOps {
			lines := []string{
				op + " X0,Y1,Y2",
				op + " X0,X1,(AX)",
				op + ".Z X0,X1,X2",
				op + ".SAE X0,X1,X2",
				op + " X0,X1,K0,X2",
				op + ".BCST X0,X1,X2",
				op + ".Z.BCST (AX),X1,K1,X2",
				op + " $1,X1,X2",
			}
			if strings.HasSuffix(op, "B") || strings.HasSuffix(op, "W") {
				lines = append(lines, op+".BCST (AX),X1,X2")
			}
			if arch == "386" {
				lines = append(lines, op+" Z8,Z0,Z1", op+" X0,X1,K1,X2")
			}

			for _, line := range lines {
				dir := t.TempDir()
				path := filepath.Join(dir, "invalid.s")
				source := "TEXT bad(SB),4,$0-0\n" + line + "\nRET\n"
				if err := os.WriteFile(path, []byte(source), 0600); err != nil {
					t.Fatal(err)
				}
				cmd := exec.Command("go", "tool", "asm", "-o", filepath.Join(dir, "invalid.o"), path)
				cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+arch)
				out, err := cmd.CombinedOutput()
				historicalZero := strings.HasPrefix(runtime.Version(), "go1.20") && strings.Contains(line, ".Z X0")
				if historicalZero && err != nil || !historicalZero && err == nil {
					t.Fatalf("Go %s unexpected result for %s: %v %s", arch, line, err, out)
				}

				triple := "x86_64-unknown-linux-gnu"
				if arch == "386" {
					triple = "i386-unknown-linux-gnu"
				}
				assertX86PackedIntegerMinMaxRejected(t, arch, triple, line)
			}
		}
	}
}

func TestX86MinMaxZeroMaskDoesNotAccessMemory(t *testing.T) {
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	var prefix []string
	if runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable() {
		triple = "x86_64-apple-macosx"
		prefix = []string{"/usr/bin/arch", "-x86_64"}
	} else if runtime.GOARCH != "amd64" {
		t.Skip("execution requires amd64 or Rosetta; five-target objects remain required")
	}

	file, err := Parse(ArchAMD64, `TEXT zero_mask(SB),4,$0-24
MOVQ source+0(FP), AX
MOVQ out+8(FP), DI
KMOVQ mask+16(FP), K1
VPMINUD (AX), Y0, K1, Y1
VMOVUPS Y1, (DI)
RET
`)
	if err != nil {
		t.Fatal(err)
	}
	sig := FuncSig{
		Name: "zero_mask",
		Args: []LLVMType{Ptr, Ptr, I64},
		Ret:  Void,
		Frame: FrameLayout{Params: []FrameSlot{
			{Offset: 0, Type: Ptr, Index: 0, Field: -1},
			{Offset: 8, Type: Ptr, Index: 1, Field: -1},
			{Offset: 16, Type: I64, Index: 2, Field: -1},
		}},
	}
	ir, err := Translate(file, Options{
		Goarch:       "amd64",
		TargetTriple: triple,
		Sigs:         map[string]FuncSig{"zero_mask": sig},
	})
	if err != nil {
		t.Fatal(err)
	}

	mainC := `
#include <stddef.h>
#include <stdint.h>

extern void zero_mask(const void *source, void *out, uint64_t mask);

int main(void) {
    uint8_t out[32];
    zero_mask(NULL, out, 0);
    return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "minmax_zero_mask", triple, ir, mainC, prefix)
}

func TestX86RawMinMaxEncodingFields(t *testing.T) {
	// The shared operand decoder already has the exhaustive shift-register
	// product test. Here each min/max member checks every register field and
	// W interpretation independently, without repeating that product 16 times.
	opcodes := map[string]byte{
		"VPMINSB": 0x38, "VPMINUB": 0xda, "VPMAXSB": 0x3c, "VPMAXUB": 0xde,
		"VPMINSW": 0xea, "VPMINUW": 0x3a, "VPMAXSW": 0xee, "VPMAXUW": 0x3e,
		"VPMINSD": 0x39, "VPMINUD": 0x3b, "VPMAXSD": 0x3d, "VPMAXUD": 0x3f,
		"VPMINSQ": 0x39, "VPMINUQ": 0x3b, "VPMAXSQ": 0x3d, "VPMAXUQ": 0x3f,
	}
	count := 0
	for _, op := range x86MinMaxTestOps {
		bits := map[byte]int{'B': 8, 'W': 16, 'D': 32, 'Q': 64}[op[len(op)-1]]
		mapNumber := byte(2)
		if op == "VPMINUB" || op == "VPMAXUB" || op == "VPMINSW" || op == "VPMAXSW" {
			mapNumber = 1
		}
		for _, evex := range []bool{false, true} {
			if !evex && bits == 64 {
				continue
			}
			limit, widths := 16, 2
			if evex {
				limit, widths = 32, 3
			}
			for width := 0; width < widths; width++ {
				for axis := 0; axis < 3; axis++ {
					for register := 0; register < limit; register++ {
						regs := [3]int{0, 1, 2} // source2, source1, destination.
						regs[axis] = register
						variants := 1
						if !evex || bits < 32 {
							variants = 2
						}
						for variant := 0; variant < variants; variant++ {
							mask, zero := 0, false
							if evex {
								mask = register % 8
								zero = mask != 0 && register&1 != 0
							}
							code := encodeRawScalarMove(evex, 1, 0, regs[0], regs[1], regs[2], mask, zero)
							code[len(code)-2] = opcodes[op]
							code[1] = code[1]&0xf0 | mapNumber
							code[2] &^= 0x80
							if variant != 0 || bits == 64 {
								code[2] |= 0x80
							}
							if evex {
								code[3] |= byte(width) << 5
							} else {
								code[2] |= byte(width) << 2
							}

							prefix := []string{"X", "Y", "Z"}[width]
							args := []Operand{
								{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", prefix, regs[0]))},
								{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", prefix, regs[1]))},
							}
							if mask != 0 {
								args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("K%d", mask))})
							}
							args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", prefix, regs[2]))})
							wantOp := Op(op)
							if zero {
								wantOp += ".Z"
							}

							got, size, matched, err := decodedX86PackedIntegerMinMaxInstruction(code, 64)
							if err != nil || !matched || size != len(code) || got.Op != wantOp || !reflect.DeepEqual(got.Args, args) {
								t.Fatalf("decode %x: %+v %d %v %v; want %s %+v", code, got, size, matched, err, wantOp, args)
							}
							_, _, matched, err = decodedX86PackedIntegerMinMaxInstruction(code, 32)
							if !matched || (err != nil) != (register >= 8) {
								t.Fatalf("386 decode %x: matched=%v err=%v", code, matched, err)
							}
							count++
						}
					}
				}
			}
		}
	}
	if count != 9216 {
		t.Fatalf("covered %d field cases, want 9216", count)
	}
}

func TestX86RawMinMax386MaskedObjects(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT masked_minmax(SB),4,$0-0\n")
	for _, op := range x86MinMaxTestOps {
		for _, width := range []string{"X", "Y", "Z"} {
			for _, input := range []string{width + "0", "(AX)"} {
				for _, suffix := range []string{"", ".Z"} {
					line := fmt.Sprintf("%s%s %s,%s1,K7,%s2", op, suffix, input, width, width)
					emitX86GoEncodedTestInstruction(t, &source, line, true)
				}
			}
			if strings.HasSuffix(op, "D") || strings.HasSuffix(op, "Q") {
				line := fmt.Sprintf("%s.BCST.Z (AX),%s1,K7,%s2", op, width, width)
				emitX86GoEncodedTestInstruction(t, &source, line, true)
			}
		}
	}
	source.WriteString("RET\n")
	file, err := Parse(ArchAMD64, source.String())
	if err != nil {
		t.Fatal(err)
	}

	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{"i386-unknown-linux-gnu", "i686-pc-windows-msvc"} {
		ir, err := Translate(file, Options{
			Goarch:       "386",
			TargetTriple: triple,
			Sigs:         map[string]FuncSig{"masked_minmax": {Name: "masked_minmax", Ret: Void}},
		})
		if err != nil {
			t.Fatal(err)
		}
		compileLLVMToObject(t, llc, triple, "masked-minmax-386.ll", "masked-minmax-386.o", ir)
	}
}

func TestX86RawMinMaxGoEncoderForms(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}

	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			last := 7
			if arch == "amd64" {
				last = 31
			}

			var source strings.Builder
			source.WriteString("TEXT minmax(SB),4,$0-0\n")
			for _, op := range x86MinMaxTestOps {
				broadcast := strings.HasSuffix(op, "D") || strings.HasSuffix(op, "Q")
				for _, width := range []string{"X", "Y", "Z"} {
					for _, reg := range []int{0, last} {
						inputs := []string{
							fmt.Sprintf("%s%d", width, last-reg),
							"(AX)", "-7(BX)(CX*4)", "64(SI)", "8192(DI)",
						}
						for _, input := range inputs {
							fmt.Fprintf(&source, "%s %s,%s%d,%s%d\n", op, input, width, reg, width, last-reg)
							if arch == "amd64" {
								fmt.Fprintf(&source, "%s %s,%s%d,K1,%s%d\n", op, input, width, reg, width, last-reg)
								fmt.Fprintf(&source, "%s.Z %s,%s%d,K7,%s%d\n", op, input, width, reg, width, last-reg)
							}
						}
						if broadcast {
							fmt.Fprintf(&source, "%s.BCST -8(BX)(CX*4),%s%d,%s%d\n", op, width, reg, width, last-reg)
							if arch == "amd64" {
								fmt.Fprintf(&source, "%s.BCST.Z 64(SI),%s%d,K7,%s%d\n", op, width, reg, width, last-reg)
							}
						}
					}
					if width != "Z" {
						fmt.Fprintf(&source, "%s %s0,%s1,%s2\n", op, width, width, width)
						fmt.Fprintf(&source, "%s (AX),%s1,%s2\n", op, width, width)
					}
				}
			}
			source.WriteString("RET\n")

			code := assembleX87ControlBytes(t, arch, source.String())
			got, err := decodeX86RawDirectives(rawX86Function(code), arch)
			if err != nil {
				t.Fatal(err)
			}
			named, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			want := named.Funcs[0].Instrs[1:]
			if len(got.Instrs) != len(want) {
				t.Fatalf("got %d instructions, want %d", len(got.Instrs), len(want))
			}
			for i, instruction := range got.Instrs {
				if instruction.Op != want[i].Op || !reflect.DeepEqual(instruction.Args, want[i].Args) {
					t.Fatalf("instruction %d: %+v, want %+v", i, instruction, want[i])
				}
			}

			var raw strings.Builder
			raw.WriteString("TEXT minmax(SB),4,$0-0\n")
			for _, b := range code {
				fmt.Fprintf(&raw, "BYTE $%#x\n", b)
			}
			file, err := Parse(ArchAMD64, raw.String())
			if err != nil {
				t.Fatal(err)
			}
			targets := []string{
				"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc",
				"i386-unknown-linux-gnu", "i686-pc-windows-msvc",
			}
			for _, triple := range targets {
				if (arch == "386") != strings.HasPrefix(triple, "i") {
					continue
				}
				ir, err := Translate(file, Options{
					Goarch:       arch,
					TargetTriple: triple,
					Sigs:         map[string]FuncSig{"minmax": {Name: "minmax", Ret: Void}},
				})
				if err != nil {
					t.Fatal(err)
				}
				compileLLVMToObject(t, llc, triple, "minmax.ll", "minmax.o", ir)
			}
			t.Logf("%s: %d actual Go encodings", arch, len(want)-1)
		})
	}
}

func TestX86RawMinMaxInvalidAndMemoryForms(t *testing.T) {
	invalid := [][]byte{
		{0x62, 0xf2, 0x71, 0x0b, 0x39, 0xe0}, // EVEX fixed bit clear.
		{0x62, 0xf2, 0x75, 0x6b, 0x39, 0xe0}, // Reserved vector length.
		{0x62, 0xf2, 0x75, 0x88, 0x39, 0xe0}, // Zeroing without mask.
		{0x62, 0xf2, 0x75, 0x1b, 0x39, 0xe0}, // Register broadcast.
		{0x62, 0xf2, 0x75, 0x1b, 0x38, 0x00}, // Byte broadcast.
		{0x62, 0xf2, 0x74, 0x0b, 0x39, 0xe0}, // Wrong mandatory prefix.
		{0x62, 0xf2, 0x75, 0x0b, 0x39},       // Missing ModRM.
		{0x62, 0xf2, 0x75, 0x0b, 0x39, 0x04}, // Missing SIB.
		{0x62, 0xf2, 0x75, 0x0b, 0x39, 0x40}, // Missing disp8.
		{0x67, 0xc5, 0xf1, 0xda, 0xc0},       // Address-size override.
		{0xc5, 0xf1, 0xda, 0x05, 0, 0, 0, 0}, // Unrelocated RIP source.
	}
	for _, code := range invalid {
		_, _, matched, err := decodedX86PackedIntegerMinMaxInstruction(code, 64)
		if !matched || err == nil {
			t.Fatalf("accepted invalid %x", code)
		}
	}
	if _, _, matched, err := decodedX86PackedIntegerMinMaxInstruction([]byte{0xc5, 0xf1, 0xda, 0xc0}, 16); !matched || err == nil {
		t.Fatal("accepted 16-bit mode")
	}
	for _, code := range [][]byte{nil, {0x62}, {0x90}, {0xc4, 0xe3, 0x79, 0x39, 0xc0}, {0xc4, 0xe2, 0x79, 0x40, 0xc0}} {
		if _, _, matched, err := decodedX86PackedIntegerMinMaxInstruction(code, 64); matched || err != nil {
			t.Fatalf("claimed unrelated %x", code)
		}
	}

	for _, segment := range []struct {
		prefix byte
		reg    Reg
	}{{0x64, FS}, {0x65, GS}} {
		for _, broadcast := range []bool{false, true} {
			code := []byte{segment.prefix, 0x62, 0x92, 0xf5, 0xcb, 0x39, 0x64, 0x88, 0xfe}
			offset, op := int64(-128), Op("VPMINSQ.Z")
			if broadcast {
				code[4] |= 0x10
				offset, op = -16, "VPMINSQ.BCST.Z"
			}
			got, size, matched, err := decodedX86PackedIntegerMinMaxInstruction(code, 64)
			want := MemRef{Segment: segment.reg, Base: "R8", Index: "R9", Scale: 4, Off: offset}
			if err != nil || !matched || size != len(code) || got.Op != op || !reflect.DeepEqual(got.Args[0].Mem, want) {
				t.Fatalf("decode %x: %+v, err=%v", code, got, err)
			}
		}
	}
}
