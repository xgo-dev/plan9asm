package plan9asm

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

func x86RawINSERTPSSource(name string, code []byte) string {
	var source strings.Builder
	fmt.Fprintf(&source, "TEXT %s(SB),4,$0-0\n", name)
	for _, value := range code {
		fmt.Fprintf(&source, "BYTE $%#02x\n", value)
	}
	source.WriteString("RET\n")
	return source.String()
}

func TestX86RawINSERTPSMode32CompleteRegisterGrammar(t *testing.T) {
	// Go's 386 frontend rejects four operands. BYTE acceptance is a distinct
	// source role, not permission to accept the equivalent named instruction.
	for _, row := range []string{
		"VINSERTPS $28,X7,X7,X7",
		"VINSERTPS $28,1(BX),X7,X7",
	} {
		goAssemblerOracleOutput(t, "386", "TEXT f(SB),4,$0-0\n"+row+"\nRET\n", "", false)
		file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		ins := file.Funcs[0].Instrs[1]
		ins.Raw += " /* decoded from BYTE $0xc4 */"
		if _, known, err := x86InsertExtractProperties(ins, "386"); !known || err == nil {
			t.Fatalf("a textual annotation granted physical mode32 identity: %+v", ins)
		}
	}
	goAssemblerOracleOutput(t, "386", x86RawINSERTPSSource("f", encodeX86RawVEXINSERTPS(7, 7, 7, 28)), "", true)

	count := 0
	for source := 0; source < 8; source++ {
		for base := 0; base < 8; base++ {
			for destination := 0; destination < 8; destination++ {
				immediate := byte(source*32 + base*4 + destination)
				code := encodeX86RawVEXINSERTPS(source, base, destination, immediate)
				ins, length, known, err := decodedX86InsertPSInstruction(code, 32)
				if err != nil || !known || length != len(code) || !ins.x86Encoded {
					t.Fatalf("physical mode32 decode %x: %+v, length=%d, known=%t, err=%v", code, ins, length, known, err)
				}
				form, known, err := x86InsertExtractProperties(ins, "386")
				if err != nil || !known || form.immediate != immediate || form.width != 16 || form.output != 16 || form.memory != -1 {
					t.Fatalf("physical mode32 grammar %x: %+v, known=%t, err=%v", code, form, known, err)
				}
				count++
			}
		}
	}
	if count != 512 {
		t.Fatalf("mode32 register axis has %d cases, want 512", count)
	}
}

func TestX86RawINSERTPSVEXIgnoredWLLVMOracle(t *testing.T) {
	mc := findLLVM22Tool("llvm-mc")
	if mc == "" {
		t.Fatal("LLVM 22 llvm-mc not found")
	}
	// Intel XED's VINSERTPS patterns do not constrain REXW, unlike adjacent
	// VINSERTF128 patterns: datafiles/avx/avx-isa.txt. Both VEX.W values decode
	// to the same instruction; Go's named encoder always chooses W=0.
	for _, mode := range []int{32, 64} {
		var input strings.Builder
		for _, w := range []byte{0, 0x80} {
			code := encodeX86RawVEXINSERTPS(7, 7, 7, 28)
			code[2] |= w
			for _, value := range code {
				fmt.Fprintf(&input, "%#02x ", value)
			}
			input.WriteByte('\n')
			ins, length, known, err := decodedX86InsertPSInstruction(code, mode)
			if err != nil || !known || length != len(code) || ins.Raw != "VINSERTPS $28, X7, X7, X7" {
				t.Fatalf("VEX.WIG mode%d decode %x: %+v, length=%d, known=%t, err=%v", mode, code, ins, length, known, err)
			}
		}
		triple := "i386-unknown-linux-gnu"
		if mode == 64 {
			triple = "x86_64-unknown-linux-gnu"
		}
		ctx, cancel := runtimeOracleStageContext(t)
		command := exec.CommandContext(ctx, mc, "--disassemble", "--triple="+triple, "--mattr=+avx")
		command.Stdin = strings.NewReader(input.String())
		output, err := runtimeOracleCombinedOutput(ctx, command)
		cancel()
		if err != nil || strings.Count(string(output), "vinsertps\t$28, %xmm7, %xmm7, %xmm7") != 2 {
			t.Fatalf("LLVM 22 independent VEX.WIG mode%d: %v\n%s", mode, err, output)
		}
	}
}

func TestX86RawINSERTPSMode32MemoryAndFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	// Independent ModRM/SIB axes: direct, signed disp8/disp32 and every scale.
	memory := [][]byte{
		{0x3b}, {0x7b, 0x80}, {0x7b, 0x7f},
		{0xbb, 0, 0, 0, 0x80}, {0xbb, 0xff, 0xff, 0xff, 0x7f},
		{0x7c, 0x33, 1}, {0x7c, 0x73, 1}, {0x7c, 0xb3, 1}, {0x7c, 0xf3, 1},
	}
	var source strings.Builder
	sigs := map[string]FuncSig{}
	for index, modRM := range memory {
		for _, w := range []byte{0, 0x80} {
			code := append([]byte{0xc4, 0xe3, 0x41 | w, 0x21}, modRM...)
			code = append(code, 0xff)
			ins, length, known, err := decodedX86InsertPSInstruction(code, 32)
			if err != nil || !known || length != len(code) {
				t.Fatalf("mode32 memory decode %x: %+v, length=%d, known=%t, err=%v", code, ins, length, known, err)
			}
			form, known, err := x86InsertExtractProperties(ins, "386")
			if err != nil || !known || form.memory != 1 || form.spec.chunk != 4 || form.immediate != 255 {
				t.Fatalf("mode32 memory grammar %x: %+v, known=%t, err=%v", code, form, known, err)
			}
			name := fmt.Sprintf("memory%d_w%d", index, w>>7)
			source.WriteString(x86RawINSERTPSSource(name, code))
			sigs[name] = FuncSig{Name: name, Ret: Void}
		}
	}
	for _, arch := range []string{"386", "amd64"} {
		goAssemblerOracleOutput(t, arch, source.String(), "", true)
		file, err := Parse(ArchAMD64, source.String())
		if err != nil {
			t.Fatal(err)
		}
		triples := []string{"i386-unknown-linux-gnu", "i686-pc-windows-msvc"}
		if arch == "amd64" {
			triples = []string{"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc"}
		}
		for _, triple := range triples {
			ir, err := Translate(file, Options{Goarch: arch, TargetTriple: triple, Sigs: sigs})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, triple, "raw-insertps-memory.ll", "raw-insertps-memory.o", ir)
		}
	}
}
