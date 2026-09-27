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
)

var x86BMI2ShiftTestOps = []string{
	"SARXL", "SARXQ", "SHLXL", "SHLXQ", "SHRXL", "SHRXQ",
}

func TestX86BMI2ShiftGrammarMatchesGoEncoder(t *testing.T) {
	path := filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/avx_optabs.go")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	pattern := `(?s)\{as: A((?:SARX|SHLX|SHRX)[LQ]), ytab: (\w+), prefix: Pavx, op: opBytes\{(.*?)\}\}`
	rows := regexp.MustCompile(pattern).FindAllStringSubmatch(string(data), -1)
	if len(rows) != 6 || len(amd64BMI2ShiftSpecs) != len(rows) {
		t.Fatalf("Go family=%d, typed family=%d", len(rows), len(amd64BMI2ShiftSpecs))
	}
	for _, row := range rows {
		spec, ok := amd64BMI2ShiftSpecs[row[1]]
		prefix := map[int]string{1: "vex66", 2: "vexF3", 3: "vexF2"}[spec.prefix]
		wide := strings.HasSuffix(row[1], "Q")
		if !ok || row[2] != "_ybextrl" || (spec.bits == 64) != wide {
			t.Fatalf("incorrect grammar for %s: %+v", row[1], spec)
		}
		for _, token := range []string{"vex128", "vex0F38", "0xF7", prefix} {
			if !strings.Contains(row[3], token) {
				t.Fatalf("Go %s missing %s", row[1], token)
			}
		}
		if strings.Contains(row[3], "vexW1") != wide {
			t.Fatalf("incorrect W for %s", row[1])
		}
	}
	pattern = `(?s)var _ybextrl = \[\]ytab\{(.*?)\n\}`
	table := regexp.MustCompile(pattern).FindStringSubmatch(string(data))
	if len(table) != 2 || strings.Count(table[1], "argList{") != 1 || !strings.Contains(table[1], "argList{Yrl, Yml, Yrl}") {
		t.Fatal("Go BMI2 shift operand grammar changed")
	}
}

func TestX86RawBMI2ShiftEncodingFields(t *testing.T) {
	cases := 0
	for pp, stem := range map[int]string{1: "SHLX", 2: "SARX", 3: "SHRX"} {
		for _, wide := range []bool{false, true} {
			for source := 0; source < 16; source++ {
				for count := 0; count < 16; count++ {
					for dst := 0; dst < 16; dst++ {
						code := encodeRawScalarMove(false, pp, 0xf7, source, count, dst, 0, false)
						code[1] = code[1]&0xe0 | 2
						if wide {
							code[2] |= 0x80
						}
						for _, mode := range []int{32, 64} {
							got, n, matched, err := decodedX86BMI2ShiftInstruction(code, mode)
							if mode == 32 && (source >= 8 || count >= 8 || dst >= 8) {
								if !matched || err == nil {
									t.Fatalf("386 accepted %x", code)
								}
								continue
							}
							width := "L"
							if wide && mode == 64 {
								width = "Q"
							}
							sr, _ := decodedX86GeneralRegister(source)
							cr, _ := decodedX86GeneralRegister(count)
							dr, _ := decodedX86GeneralRegister(dst)
							want := []Operand{
								{Kind: OpReg, Reg: cr},
								{Kind: OpReg, Reg: sr},
								{Kind: OpReg, Reg: dr},
							}
							if err != nil || !matched || n != len(code) || got.Op != Op(stem+width) || !reflect.DeepEqual(got.Args, want) {
								t.Fatalf("decode %x mode=%d: %+v %v, want %s %+v", code, mode, got, err, stem+width, want)
							}
						}
						cases++
					}
				}
			}
		}
	}
	if cases != 24576 {
		t.Fatalf("checked %d encodings, want 24576", cases)
	}
}

func TestX86RawBMI2ShiftInvalidAndSegmentForms(t *testing.T) {
	invalid := [][]byte{
		{0xc4, 0xe2, 0x7d, 0xf7, 0xc0},             // VEX.L1.
		{0x62, 0xf2, 0x7d, 0x08, 0xf7, 0xc0},       // EVEX.
		{0xc4, 0xe2, 0x79, 0xf7},                   // Missing ModRM.
		{0xc4, 0xe2, 0x79, 0xf7, 0x04},             // Missing SIB.
		{0xc4, 0xe2, 0x79, 0xf7, 0x80},             // Missing displacement.
		{0xc4, 0xe2, 0x79, 0xf7, 0x05, 0, 0, 0, 0}, // RIP-relative.
		{0x67, 0xc4, 0xe2, 0x79, 0xf7, 0x00},       // Address override.
	}
	for _, code := range invalid {
		if _, _, matched, err := decodedX86BMI2ShiftInstruction(code, 64); !matched || err == nil {
			t.Fatalf("accepted %x", code)
		}
	}
	if _, _, matched, err := decodedX86BMI2ShiftInstruction([]byte{0xc4, 0xe2, 0x79, 0xf7, 0xc0}, 16); !matched || err == nil {
		t.Fatal("accepted invalid mode")
	}
	for _, code := range [][]byte{nil, {0xc4}, {0xc4, 0xe2, 0x78, 0xf7, 0xc0}, {0xc4, 0xe1, 0x79, 0xf7, 0xc0}} {
		if _, _, matched, _ := decodedX86BMI2ShiftInstruction(code, 64); matched {
			t.Fatalf("matched unrelated encoding %x", code)
		}
	}

	for _, segment := range []struct {
		prefix byte
		reg    Reg
	}{{0x64, FS}, {0x65, GS}} {
		code := []byte{segment.prefix, 0xc4, 0x02, 0xb1, 0xf7, 0x64, 0x88, 0xf9}
		got, n, matched, err := decodedX86BMI2ShiftInstruction(code, 64)
		want := []Operand{
			{Kind: OpReg, Reg: "R9"},
			{Kind: OpMem, Mem: MemRef{Segment: segment.reg, Base: "R8", Index: "R9", Scale: 4, Off: -7}},
			{Kind: OpReg, Reg: "R12"},
		}
		if err != nil || !matched || n != len(code) || got.Op != "SHLXQ" || !reflect.DeepEqual(got.Args, want) {
			t.Fatalf("decode %x=%+v %v, want %+v", code, got, err, want)
		}
	}
}

func TestX86BMI2ShiftGoRejectedForms(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range x86BMI2ShiftTestOps {
			args := []string{
				" AX,BX", " X0,AX,BX", " AX,X0,BX", " AX,BX,X0",
				" (AX),BX,CX", " AX,BX,(CX)", " $1,BX,CX",
				".Z AX,BX,CX", ".BCST AX,(BX),CX",
			}
			if arch == "386" {
				args = append(args, " R8,BX,CX", " AX,R8,CX", " AX,BX,R8")
			}
			for _, operands := range args {
				source := "TEXT bad(SB),4,$0-0\n" + op + operands + "\nRET\n"
				requireX86GoAssemblerResult(t, arch, source, false)
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				triple := "x86_64-unknown-linux-gnu"
				if arch == "386" {
					triple = "i386-unknown-linux-gnu"
				}
				if _, err := Translate(file, Options{
					Goarch:       arch,
					TargetTriple: triple,
					Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
				}); err == nil {
					t.Fatalf("translator accepted %s%s on %s", op, operands, arch)
				}
			}
		}
	}
}

func TestX86RawBMI2ShiftGoEncoderForms(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}

	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			regs := []string{"AX", "SP", "DI"}
			if arch == "amd64" {
				regs = append(regs, "R8", "R15")
			}

			var source strings.Builder
			source.WriteString("TEXT bmi2shift(SB),4,$0-0\n")
			for _, op := range x86BMI2ShiftTestOps {
				for _, reg := range regs {
					for _, input := range []string{reg, "(BX)", "-7(BP)(CX*4)", "8192(SI)"} {
						fmt.Fprintf(&source, "%s %s,%s,%s\n", op, reg, input, reg)
					}
				}
			}
			source.WriteString("RET\n")

			code := assembleX87ControlBytes(t, arch, source.String())
			decoded, err := decodeX86RawDirectives(rawX86Function(code), arch)
			if err != nil {
				t.Fatal(err)
			}
			named, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			want := named.Funcs[0].Instrs[1:]
			if len(decoded.Instrs) != len(want) {
				t.Fatalf("got %d instructions, want %d", len(decoded.Instrs), len(want))
			}
			for i, got := range decoded.Instrs {
				if arch == "386" && strings.HasSuffix(string(want[i].Op), "Q") {
					want[i].Op = Op(strings.TrimSuffix(string(want[i].Op), "Q") + "L")
				}
				if got.Op != want[i].Op || !reflect.DeepEqual(got.Args, want[i].Args) {
					t.Fatalf("instruction %d=%+v, want %+v", i, got, want[i])
				}
			}

			var raw strings.Builder
			raw.WriteString("TEXT bmi2shift(SB),4,$0-0\n")
			for _, b := range code {
				fmt.Fprintf(&raw, "BYTE $%#02x\n", b)
			}
			file, err := Parse(ArchAMD64, raw.String())
			if err != nil {
				t.Fatal(err)
			}
			triples := []string{
				"x86_64-apple-darwin",
				"x86_64-unknown-linux-gnu",
				"x86_64-pc-windows-msvc",
			}
			if arch == "386" {
				triples = []string{"i386-unknown-linux-gnu", "i686-pc-windows-msvc"}
			}
			for _, triple := range triples {
				ir, err := Translate(file, Options{
					Goarch:       arch,
					TargetTriple: triple,
					Sigs: map[string]FuncSig{
						"bmi2shift": {Name: "bmi2shift", Ret: Void},
					},
				})
				if err != nil {
					t.Fatal(err)
				}
				compileLLVMToObject(t, llc, triple, "raw-bmi2-shift.ll", "raw-bmi2-shift.o", ir)
			}
			t.Logf("checked %d Go encodings", len(want)-1)
		})
	}
}

func TestX86BMI2Shift386IgnoresW(t *testing.T) {
	for _, op := range []string{"SARXQ", "SHLXQ", "SHRXQ"} {
		t.Run(op, func(t *testing.T) {
			file, err := Parse(ArchAMD64, "TEXT shift(SB),4,$0-0\n"+op+" AX,(BX),CX\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				Goarch:       "386",
				TargetTriple: "i386-unknown-linux-gnu",
				Sigs:         map[string]FuncSig{"shift": {Name: "shift", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(ir, "load i32, ptr") || !strings.Contains(ir, ", 31\n") ||
				strings.Contains(ir, "ashr i64") || strings.Contains(ir, "shl i64") || strings.Contains(ir, "lshr i64") {
				t.Fatalf("386 %s must read exactly four bytes:\n%s", op, ir)
			}
		})
	}
}
