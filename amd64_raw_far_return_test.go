package plan9asm

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/arch/x86/x86asm"
)

func TestX86FarReturnGrammarMatchesActualGoRows(t *testing.T) {
	path := filepath.Join(runtime.GOROOT(), "src", "cmd", "internal", "obj", "x86", "asm6.go")
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	want := make(map[Op]amd64FarReturnSpec)
	ast.Inspect(file, func(node ast.Node) bool {
		row, ok := node.(*ast.CompositeLit)
		if !ok || len(row.Elts) == 0 {
			return true
		}
		name, ok := row.Elts[0].(*ast.Ident)
		if !ok || (!strings.HasPrefix(name.Name, "AIRET") && !strings.HasPrefix(name.Name, "ARETF")) {
			return true
		}
		if len(row.Elts) != 4 {
			t.Fatalf("unrecognized actual Go far-return opcode row %s", name.Name)
		}
		operands, ok := row.Elts[1].(*ast.Ident)
		if !ok || (operands.Name != "ynone" && operands.Name != "yret") {
			t.Fatalf("unrecognized actual Go far-return operand row: %#v", row.Elts[1])
		}
		prefix, ok := row.Elts[2].(*ast.Ident)
		if !ok {
			t.Fatalf("unrecognized actual Go far-return prefix: %#v", row.Elts[2])
		}
		bits := map[string]int{"Pe": 16, "Px": 32, "Pw": 64}[prefix.Name]
		if bits == 0 {
			t.Fatalf("unrecognized actual Go far-return width prefix %s", prefix.Name)
		}
		kind := amd64InterruptReturn
		if operands.Name == "yret" {
			kind = amd64FarReturn
		}
		want[Op(strings.TrimPrefix(name.Name, "A"))] = amd64FarReturnSpec{
			kind: kind, bits: bits, allowImmediate: operands.Name == "yret",
		}
		return false
	})
	if len(want) != len(amd64FarReturnSpecs) {
		t.Fatalf("actual Go rows %v do not match typed inventory %v", want, amd64FarReturnSpecs)
	}
	for op, expected := range want {
		spec, ok := amd64FarReturnSpecs[op]
		if !ok || spec != expected {
			t.Fatalf("actual Go %s spec=%+v is missing or differs", op, expected)
		}
	}
	// The row names alone are not operand completeness: audit both entire
	// referenced ytabs, including the operand-free RETF and imm16 truncation.
	seen := make(map[string]bool)
	ast.Inspect(file, func(node ast.Node) bool {
		value, ok := node.(*ast.ValueSpec)
		if !ok || len(value.Names) != 1 || (value.Names[0].Name != "ynone" && value.Names[0].Name != "yret") {
			return true
		}
		name := value.Names[0].Name
		if len(value.Values) != 1 {
			t.Fatalf("unrecognized %s initializer", name)
		}
		table, ok := value.Values[0].(*ast.CompositeLit)
		if !ok {
			t.Fatalf("unrecognized %s table", name)
		}
		classes := make(map[string]bool)
		for _, element := range table.Elts {
			row, ok := element.(*ast.CompositeLit)
			if !ok || len(row.Elts) != 3 {
				t.Fatalf("unrecognized %s operand row", name)
			}
			operands, ok := row.Elts[2].(*ast.CompositeLit)
			if !ok || len(operands.Elts) > 1 {
				t.Fatalf("unrecognized %s argument list", name)
			}
			class := "none"
			if len(operands.Elts) == 1 {
				identifier, ok := operands.Elts[0].(*ast.Ident)
				if !ok {
					t.Fatalf("unrecognized %s argument class", name)
				}
				class = identifier.Name
			}
			if classes[class] {
				t.Fatalf("duplicate %s argument class %s", name, class)
			}
			classes[class] = true
		}
		wantCount := 1
		if name == "yret" {
			wantCount = 2
		}
		if len(classes) != wantCount || !classes["none"] || (name == "yret" && !classes["Yi32"]) {
			t.Fatalf("actual Go %s forms changed: %v", name, classes)
		}
		seen[name] = true
		return false
	})
	if len(seen) != 2 {
		t.Fatal("actual Go far-return operand tables were not both observed")
	}
}

func TestX86RawFarReturnPrefixAndModeAxes(t *testing.T) {
	for _, test := range []struct {
		name string
		mode int
		code []byte
		want string
	}{
		{name: "bare-386", mode: 32, code: []byte{0xcb}, want: "RETFL"},
		{name: "bare-amd64", mode: 64, code: []byte{0xcb}, want: "RETFL"},
		{name: "operand-386", mode: 32, code: []byte{0x66, 0xcb}, want: "RETFW"},
		{name: "operand-amd64", mode: 64, code: []byte{0x66, 0xcb}, want: "RETFW"},
		{name: "rex-without-w", mode: 64, code: []byte{0x47, 0xcb}, want: "RETFL"},
		{name: "rex-w", mode: 64, code: []byte{0x4f, 0xcb}, want: "RETFQ"},
		{name: "rex-w-overrides-66", mode: 64, code: []byte{0x66, 0x48, 0xcb}, want: "RETFQ"},
		{name: "repeated-operand", mode: 64, code: []byte{0x66, 0x66, 0xcf}, want: "IRETW"},
	} {
		t.Run(test.name, func(t *testing.T) {
			inst, err := x86asm.Decode(test.code, test.mode)
			if err != nil || inst.Len != len(test.code) {
				t.Fatalf("actual decoder: %+v %v", inst, err)
			}
			got, err := decodedX86GoSyntax(inst, test.code)
			if err != nil || got != test.want {
				t.Fatalf("actual prefixes %+v DataSize%d: %q %v, want %q", inst.Prefix, inst.DataSize, got, err, test.want)
			}
		})
	}
	// 48 is an actual DEC opcode in 32-bit mode. Never treat the same
	// byte string as an unsupported 64-bit far return in that mode.
	decoded, err := decodeX86RawDirectiveGroup([]byte{0x48, 0xcb}, 32, 0, "32-bit DEC then far return", nil)
	if err != nil || len(decoded) != 2 || decoded[0].Op != "DECL" || decoded[1].Op != "RETFL" {
		t.Fatalf("32-bit 48 CB changed instruction boundaries: %+v %v", decoded, err)
	}
	decoded, err = decodeX86RawDirectiveGroup([]byte{0x48, 0x66, 0xcb}, 32, 0, "32-bit DEC then 16-bit far return", nil)
	if err != nil || len(decoded) != 2 || decoded[0].Op != "DECL" || decoded[1].Op != "RETFW" {
		t.Fatalf("32-bit 48 66 CB changed instruction boundaries: %+v %v", decoded, err)
	}
}

func TestX86RawFarReturnRejectsUnprovedForms(t *testing.T) {
	for _, code := range [][]byte{
		{0xf0, 0xcb}, {0xf0, 0xcf}, {0xf2, 0xcb}, {0xf3, 0xcf},
		{0x67, 0xcb}, {0x64, 0xcf}, // Not a registered width-only prefix.
		{0xca}, {0xca, 0x01}, {0x66}, {0x48},
		{0x48, 0x66, 0xcb}, // Pinned decoder rejects nonadjacent REX.
	} {
		for _, mode := range []int{32, 64} {
			if mode == 32 && code[0] == 0x48 {
				continue // Valid DEC, not a REX prefix or prefix ordering.
			}
			_, err := decodeX86RawDirectiveGroup(code, mode, 0, "invalid or unregistered raw far return", nil)
			if err == nil {
				t.Errorf("accepted unproved %x mode%d", code, mode)
			}
		}
	}
	for _, inst := range []x86asm.Inst{
		{Op: x86asm.LRET, Mode: 16, DataSize: 16},
		{Op: x86asm.LRET, Mode: 32, DataSize: 64},
		{Op: x86asm.LRET, Mode: 64, DataSize: 8},
		{Op: x86asm.IRETQ, Mode: 64, DataSize: 32},
		{Op: x86asm.IRETD, Mode: 64, DataSize: 16},
		{Op: x86asm.LRET, Mode: 64, DataSize: 32, Args: x86asm.Args{x86asm.Imm(-1)}},
		{Op: x86asm.LRET, Mode: 64, DataSize: 32, Args: x86asm.Args{x86asm.Imm(65536)}},
		{Op: x86asm.LRET, Mode: 64, DataSize: 32, Args: x86asm.Args{x86asm.EAX}},
		{Op: x86asm.LRET, Mode: 64, DataSize: 32, Args: x86asm.Args{nil, x86asm.Imm(1)}},
		{Op: x86asm.IRETD, Mode: 64, DataSize: 32, Args: x86asm.Args{x86asm.Imm(1)}},
	} {
		if got, err := decodedX86GoSyntax(inst, nil); err == nil {
			t.Errorf("accepted inconsistent raw form %+v as %q", inst, got)
		}
	}
}

func TestX86FarReturnRejectsFloatingAndWidthlessOperands(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		instructions := []string{"LRET", "LRET $4", "RETFL $unknown"}
		for op := range amd64FarReturnSpecs {
			for _, argument := range []string{"$0.0", "$-0.0", "$1.5", "$-1.5"} {
				instructions = append(instructions, string(op)+" "+argument)
			}
		}
		for _, instruction := range instructions {
			source := "TEXT bad(SB),516,$0-0\n" + instruction + "\n"
			requireX86GoAssemblerResult(t, arch, source, false)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				continue
			}
			if _, err := Translate(file, Options{Goarch: arch, Sigs: map[string]FuncSig{"bad": {Name: "bad", Ret: Void}}}); err == nil {
				t.Errorf("accepted %s %q outside actual Go integer/width grammar", arch, instruction)
			}
		}
	}
}

func TestX86RawFarReturnRetainsDecodedWidthAndImmediate(t *testing.T) {
	for _, mode := range []int{32, 64} {
		for _, width := range []struct {
			bits   int
			prefix []byte
			suffix string
		}{
			{bits: 16, prefix: []byte{0x66}, suffix: "W"},
			{bits: 32, suffix: "L"},
			{bits: 64, prefix: []byte{0x48}, suffix: "Q"},
		} {
			if mode == 32 && width.bits == 64 {
				continue // 48 is DEC in 32-bit mode, not a width prefix.
			}
			for _, form := range []struct {
				name string
				code []byte
				args string
			}{
				{name: "IRET", code: []byte{0xcf}},
				{name: "RETF", code: []byte{0xcb}},
				{name: "RETF", code: []byte{0xca, 0x00, 0x00}, args: " $0"},
				{name: "RETF", code: []byte{0xca, 0x34, 0x12}, args: " $4660"},
				{name: "RETF", code: []byte{0xca, 0xff, 0xff}, args: " $65535"},
			} {
				code := append(append([]byte(nil), width.prefix...), form.code...)
				inst, err := x86asm.Decode(code, mode)
				if err != nil || inst.Len != len(code) || inst.DataSize != width.bits {
					t.Fatalf("actual decoder %x mode%d: %+v %v", code, mode, inst, err)
				}
				want := form.name + width.suffix + form.args
				got, err := decodedX86GoSyntax(inst, code)
				if err != nil || got != want {
					t.Errorf("%x mode%d DataSize%d: got %q %v, want %q", code, mode, inst.DataSize, got, err, want)
				}
				decoded, err := decodeX86RawDirectiveGroup(code, mode, 0, "raw far-return bytes", nil)
				if err != nil || len(decoded) != 1 || string(decoded[0].Op) != form.name+width.suffix {
					t.Errorf("whole raw group %x mode%d: %+v %v", code, mode, decoded, err)
				}
			}
		}
	}
}

func TestX86RawFarReturnCompleteFiveTargetObjectsMatchGo(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 is required")
	}
	for _, target := range []struct{ os, arch, triple string }{
		{os: "darwin", arch: "amd64", triple: "x86_64-apple-darwin"},
		{os: "linux", arch: "amd64", triple: "x86_64-unknown-linux-gnu"},
		{os: "windows", arch: "amd64", triple: "x86_64-pc-windows-msvc"},
		{os: "linux", arch: "386", triple: "i386-unknown-linux-gnu"},
		{os: "windows", arch: "386", triple: "i686-pc-windows-msvc"},
	} {
		t.Run(target.triple, func(t *testing.T) {
			var rawSource strings.Builder
			sigs := make(map[string]FuncSig)
			wantBytes := make(map[string][]byte)
			for op, spec := range amd64FarReturnSpecs {
				if target.arch == "386" && spec.bits == 64 {
					continue
				}
				forms := []amd64FarReturnForm{{}}
				if spec.allowImmediate {
					for _, value := range []uint16{0, 1, 0x1234, 0xffff} {
						forms = append(forms, amd64FarReturnForm{hasImmediate: true, immediate: value})
					}
				}
				for _, form := range forms {
					name := fmt.Sprintf("far_%s_%t_%d", op, form.hasImmediate, form.immediate)
					prefix := []byte(nil)
					if spec.bits == 16 {
						prefix = []byte{0x66}
					} else if spec.bits == 64 {
						prefix = []byte{0x48}
					}
					code := append(prefix, byte(0xcb))
					if spec.kind == amd64InterruptReturn {
						code[len(code)-1] = 0xcf
					} else if form.hasImmediate {
						code[len(code)-1] = 0xca
						code = append(code, byte(form.immediate), byte(form.immediate>>8))
					}
					raw := fmt.Sprintf("TEXT %s(SB),516,$0-0\n", name)
					for _, value := range code {
						raw += fmt.Sprintf("BYTE $0x%02x\n", value)
					}
					named := fmt.Sprintf("TEXT %s(SB),516,$0-0\n%s", name, op)
					if form.hasImmediate {
						named += fmt.Sprintf(" $%d", form.immediate)
					}
					named += "\n"
					// Independently authenticate the raw and canonical named
					// encodings with Go, not merely the LLVM assembly spelling.
					for _, source := range []string{raw, named} {
						dir := t.TempDir()
						path := filepath.Join(dir, "far.s")
						if err := os.WriteFile(path, []byte(source), 0600); err != nil {
							t.Fatal(err)
						}
						command := exec.Command("go", "tool", "asm", "-S", "-o", filepath.Join(dir, "far.o"), path)
						command.Env = append(os.Environ(), "GOOS="+target.os, "GOARCH="+target.arch, "GOTOOLCHAIN=local")
						output, err := command.CombinedOutput()
						parts := make([]string, len(code))
						for i, value := range code {
							parts[i] = fmt.Sprintf("%02x", value)
						}
						want := regexp.MustCompile(`(?m)^\s*0x0000 ` + strings.Join(parts, " ") + `(?:\s|$)`)
						if err != nil || !want.Match(output) {
							t.Fatalf("original Go bytes %x: %v\n%s\n%s", code, err, source, output)
						}
					}
					rawSource.WriteString(raw)
					sigs[name] = FuncSig{Name: name, Ret: Void}
					wantBytes[name] = code
				}
			}
			file, err := Parse(ArchAMD64, rawSource.String())
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{Goarch: target.arch, TargetTriple: target.triple, Sigs: sigs})
			if err != nil {
				t.Fatal(err)
			}
			for op, spec := range amd64FarReturnSpecs {
				if target.arch == "386" && spec.bits == 64 {
					continue
				}
				if !strings.Contains(ir, spec.encoding(amd64FarReturnForm{})) {
					t.Errorf("raw %s lost typed byte lowering", op)
				}
			}
			if strings.Count(ir, "unreachable") != len(sigs) {
				t.Fatal("raw far return lost terminal control semantics")
			}
			requireX86RawFarReturnObjectBytes(t, llc, target.triple, ir, wantBytes)
		})
	}
}

func requireX86RawFarReturnObjectBytes(t *testing.T, llc, triple, ir string, want map[string][]byte) {
	t.Helper()
	objdump := findLLVM22Tool("llvm-objdump")
	if objdump == "" {
		t.Fatal("LLVM22 llvm-objdump is required")
	}
	dir := t.TempDir()
	llPath := filepath.Join(dir, "far.ll")
	object := filepath.Join(dir, "far.o")
	if err := os.WriteFile(llPath, []byte(ir), 0600); err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command(llc, "-O0", "-mtriple="+triple, "-filetype=obj", llPath, "-o", object).CombinedOutput()
	if err != nil {
		t.Fatalf("LLVM22 object: %v\n%s", err, output)
	}
	output, err = exec.Command(objdump, "-d", object).CombinedOutput()
	if err != nil {
		t.Fatalf("LLVM22 disassembly: %v\n%s", err, output)
	}
	// Match each terminal instruction's complete bytes inside its own symbol,
	// not merely a coincidental sequence in another function or an IR string.
	sections := regexp.MustCompile(`(?m)^[0-9a-f]+ <_?(far_[^>]+)>:\n`).FindAllSubmatchIndex(output, -1)
	seen := make(map[string]bool)
	for index, section := range sections {
		name := string(output[section[2]:section[3]])
		code, ok := want[name]
		if !ok {
			t.Fatalf("unexpected emitted far-return symbol %s", name)
		}
		end := len(output)
		if index+1 < len(sections) {
			end = sections[index+1][0]
		}
		parts := make([]string, len(code))
		for i, value := range code {
			parts[i] = fmt.Sprintf("%02x", value)
		}
		instruction := regexp.MustCompile(`(?m)^\s*[0-9a-f]+:\s+` + strings.Join(parts, " ") + `\s+(?:iret|lret)`)
		if !instruction.Match(output[section[1]:end]) {
			t.Fatalf("LLVM22 symbol %s lacks exact terminal bytes %x:\n%s", name, code, output[section[1]:end])
		}
		seen[name] = true
	}
	if len(seen) != len(want) {
		t.Fatalf("LLVM22 object contains %d/%d authenticated far-return symbols", len(seen), len(want))
	}
}
