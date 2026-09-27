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

func TestX86MinimumPositionGrammarMatchesGoEncoder(t *testing.T) {
	root := filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86")
	for _, form := range []struct {
		file, op, table, operands string
		vector                    bool
	}{
		{"asm6.go", "PHMINPOSUW", "yxm_q4", "Yxm, Yxr", false},
		{"avx_optabs.go", "VPHMINPOSUW", "_yvaesimc", "Yxm, Yxr", true},
	} {
		data, err := os.ReadFile(filepath.Join(root, form.file))
		if err != nil {
			t.Fatal(err)
		}
		text := string(data)
		spec, ok := amd64MinimumPositionSpecs[Op(form.op)]
		if !ok || spec.vector != form.vector || spec.mapNumber != 2 || spec.opcode != 0x41 {
			t.Fatalf("incorrect typed spec for %s: %+v", form.op, spec)
		}
		pattern := `(?s)var ` + form.table + ` = \[\]ytab\{(.*?)\n\}`
		table := regexp.MustCompile(pattern).FindStringSubmatch(text)
		if len(table) != 2 || strings.Count(table[1], "argList{") != 1 ||
			!strings.Contains(table[1], "argList{"+form.operands+"}") {
			t.Fatalf("Go %s operand grammar changed", form.op)
		}
		if form.vector {
			pattern = `(?s)\{as: AVPHMINPOSUW, ytab: (\w+), prefix: Pavx, op: opBytes\{(.*?)\}\}`
			rows := regexp.MustCompile(pattern).FindAllStringSubmatch(text, -1)
			if len(rows) != 1 || rows[0][1] != form.table || strings.Count(rows[0][2], "0x41") != 1 {
				t.Fatal("Go VPHMINPOSUW opcode forms changed")
			}
			for _, token := range []string{"vex128", "vex66", "vex0F38", "vexW0"} {
				if !strings.Contains(rows[0][2], token) {
					t.Fatalf("Go VPHMINPOSUW missing %s", token)
				}
			}
		} else if !strings.Contains(text, "{APHMINPOSUW, yxm_q4, Pq4, opBytes{0x41}}") {
			t.Fatal("Go PHMINPOSUW encoding changed")
		}
	}
	if len(amd64MinimumPositionSpecs) != 2 {
		t.Fatal("minimum-position family must match both Go opcodes")
	}
}

func TestX86RawMinimumPositionEncodingFields(t *testing.T) {
	for _, wide := range []bool{false, true} {
		for src := 0; src < 16; src++ {
			for dst := 0; dst < 16; dst++ {
				code := encodeRawScalarMove(false, 1, 0x41, src, 0, dst, 0, false)
				code[1] = code[1]&0xe0 | 2
				if wide {
					code[2] |= 0x80
				}
				for _, mode := range []int{32, 64} {
					got, size, matched, err := decodedX86MinimumPositionInstruction(code, mode)
					if mode == 32 && (src >= 8 || dst >= 8) {
						if !matched || err == nil {
							t.Fatalf("386 accepted %x", code)
						}
						continue
					}
					want := []Operand{
						{Kind: OpReg, Reg: Reg(fmt.Sprintf("X%d", src))},
						{Kind: OpReg, Reg: Reg(fmt.Sprintf("X%d", dst))},
					}
					if err != nil || !matched || size != len(code) || got.Op != "VPHMINPOSUW" || !reflect.DeepEqual(got.Args, want) {
						t.Fatalf("decode %x mode=%d: %+v %v, want %+v", code, mode, got, err, want)
					}
				}
			}
		}
	}
}

func TestX86RawMinimumPositionInvalidAndSegmentForms(t *testing.T) {
	invalid := [][]byte{
		{0xc4, 0xe2, 0x7d, 0x41, 0xc0},             // VEX.L1.
		{0xc4, 0xe2, 0x71, 0x41, 0xc0},             // vvvv is not reserved.
		{0xc4, 0xe2, 0x78, 0x41, 0xc0},             // No 66 prefix.
		{0x62, 0xf2, 0x7d, 0x08, 0x41, 0xc0},       // No EVEX form.
		{0xc4, 0xe2, 0x79, 0x41},                   // Missing ModRM.
		{0xc4, 0xe2, 0x79, 0x41, 0x04},             // Missing SIB.
		{0xc4, 0xe2, 0x79, 0x41, 0x80},             // Missing displacement.
		{0xc4, 0xe2, 0x79, 0x41, 0x05, 0, 0, 0, 0}, // RIP relative.
		{0x67, 0xc4, 0xe2, 0x79, 0x41, 0x00},       // Address override.
	}
	for _, code := range invalid {
		if _, _, matched, err := decodedX86MinimumPositionInstruction(code, 64); !matched || err == nil {
			t.Fatalf("accepted %x", code)
		}
	}
	if _, _, matched, err := decodedX86MinimumPositionInstruction([]byte{0xc4, 0xe2, 0x79, 0x41, 0xc0}, 16); !matched || err == nil {
		t.Fatal("accepted invalid x86 mode")
	}
	for _, code := range [][]byte{nil, {0xc4}, {0xc4, 0xe1, 0x79, 0x41, 0xc0}, {0xc4, 0xe2, 0x79, 0x40, 0xc0}} {
		if _, _, matched, _ := decodedX86MinimumPositionInstruction(code, 64); matched {
			t.Fatalf("matched unrelated encoding %x", code)
		}
	}
	for _, segment := range []struct {
		prefix byte
		reg    Reg
	}{{0x64, FS}, {0x65, GS}} {
		code := []byte{segment.prefix, 0xc4, 0x02, 0x79, 0x41, 0x64, 0x88, 0xf9}
		got, size, matched, err := decodedX86MinimumPositionInstruction(code, 64)
		want := []Operand{
			{Kind: OpMem, Mem: MemRef{Segment: segment.reg, Base: "R8", Index: "R9", Scale: 4, Off: -7}},
			{Kind: OpReg, Reg: "X12"},
		}
		if err != nil || !matched || size != len(code) || !reflect.DeepEqual(got.Args, want) {
			t.Fatalf("decode %x: %+v %v, want %+v", code, got, err, want)
		}
	}
}

func TestX86MinimumPositionGoRejectedForms(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		triple := "x86_64-unknown-linux-gnu"
		if arch == "386" {
			triple = "i386-unknown-linux-gnu"
		}
		for _, op := range []string{"PHMINPOSUW", "VPHMINPOSUW"} {
			forms := []string{
				" X0", " X0,X1,X2", " X0,K1,X1", " X0,(AX)",
				" M0,M1", " Y0,Y1", " Z0,Z1", " X16,X0", " X0,X16",
				".Z X0,X1", ".BCST (AX),X1", ".SAE X0,X1",
			}
			if arch == "386" && op == "PHMINPOSUW" {
				forms = append(forms, " X8,X0", " X0,X8")
			}
			for _, operands := range forms {
				line := op + operands
				requireX86GoAssemblerResult(t, arch, "TEXT bad(SB),4,$0-0\n"+line+"\nRET\n", false)
				assertX86PackedUnsignedWordMinimumPositionRejected(t, arch, triple, line)
			}
		}
	}
}

func TestX86RawMinimumPositionGoEncoderForms(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			limit := 16
			if arch == "386" {
				limit = 8
			}
			memories := []string{"(AX)", "-7(BP)(CX*4)", "8192(SP)"}
			if arch == "amd64" {
				memories = append(memories, "(R8)", "-7(R13)(R15*8)")
			}
			var source strings.Builder
			source.WriteString("TEXT minpos(SB),4,$0-0\n")
			for _, op := range []string{"PHMINPOSUW", "VPHMINPOSUW"} {
				for dst := 0; dst < limit; dst++ {
					for src := 0; src < limit; src++ {
						fmt.Fprintf(&source, "%s X%d,X%d\n", op, src, dst)
					}
					for _, memory := range memories {
						fmt.Fprintf(&source, "%s %s,X%d\n", op, memory, dst)
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
				t.Fatalf("decoded %d instructions, want %d", len(decoded.Instrs), len(want))
			}
			for i, got := range decoded.Instrs {
				if got.Op != want[i].Op || !reflect.DeepEqual(got.Args, want[i].Args) {
					t.Fatalf("instruction %d=%+v, want %+v", i, got, want[i])
				}
			}
			var raw strings.Builder
			raw.WriteString("TEXT minpos(SB),4,$0-0\n")
			for _, b := range code {
				fmt.Fprintf(&raw, "BYTE $%#02x\n", b)
			}
			file, err := Parse(ArchAMD64, raw.String())
			if err != nil {
				t.Fatal(err)
			}
			triples := []string{"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc"}
			if arch == "386" {
				triples = []string{"i386-unknown-linux-gnu", "i686-pc-windows-msvc"}
			}
			for _, triple := range triples {
				ir, err := Translate(file, Options{
					Goarch: arch, TargetTriple: triple,
					Sigs: map[string]FuncSig{"minpos": {Name: "minpos", Ret: Void}},
				})
				if err != nil {
					t.Fatal(err)
				}
				compileLLVMToObject(t, llc, triple, "raw-minpos.ll", "raw-minpos.o", ir)
			}
			t.Logf("checked %d actual Go encodings", len(want)-1)
		})
	}
}

func TestX86MinimumPositionGoAccepted386HighNamedRegisters(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	var source strings.Builder
	source.WriteString("TEXT minpos(SB),4,$0-0\n")
	for reg := 8; reg < 16; reg++ {
		fmt.Fprintf(&source, "VPHMINPOSUW X%d,X0\nVPHMINPOSUW X0,X%d\nVPHMINPOSUW (AX),X%d\n", reg, reg, reg)
	}
	source.WriteString("RET\n")
	requireX86GoAssemblerResult(t, "386", source.String(), true)
	file, err := Parse(ArchAMD64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"i386-unknown-linux-gnu", "i686-pc-windows-msvc"} {
		ir, err := Translate(file, Options{
			Goarch: "386", TargetTriple: triple,
			Sigs: map[string]FuncSig{"minpos": {Name: "minpos", Ret: Void}},
		})
		if err != nil {
			t.Fatal(err)
		}
		compileLLVMToObject(t, llc, triple, "named-minpos.ll", "named-minpos.o", ir)
	}
}
