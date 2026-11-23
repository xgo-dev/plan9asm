package plan9asm

import (
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

func arm64RawSVEFloatUnaryNativeForms() []string {
	var lines []string
	for _, op := range []string{"fabs", "fneg", "frecpx", "frinta", "frinti", "frintm", "frintn", "frintp", "frintx", "frintz", "fsqrt", "frint32x", "frint32z", "frint64x", "frint64z", "frecpe", "frsqrte"} {
		widths := []string{"h", "s", "d"}
		if strings.HasPrefix(op, "frint32") || strings.HasPrefix(op, "frint64") {
			widths = widths[1:]
		}
		for _, width := range widths {
			if op == "frecpe" || op == "frsqrte" {
				lines = append(lines, fmt.Sprintf("%s z31.%s, z30.%s", op, width, width))
				continue
			}
			for _, mode := range []string{"m", "z"} {
				lines = append(lines, fmt.Sprintf("%s z31.%s, p7/%s, z30.%s", op, width, mode, width))
			}
		}
	}
	return lines
}

func TestARM64RawSVEFloatUnaryCompleteFormats(t *testing.T) {
	lines := arm64RawSVEFloatUnaryNativeForms()
	register := regexp.MustCompile(`\b([zp])[0-9]+\b`)
	sizedRound := regexp.MustCompile(`(?m)\bfrint(?:32|64)[xz]\s+z[^\r\n]+`)
	normalize := func(line string) string {
		return register.ReplaceAllString(strings.Join(strings.Fields(line), " "), "$1")
	}
	var wanted []string
	for _, line := range lines {
		if sizedRound.MatchString(line) {
			wanted = append(wanted, normalize(line))
		}
	}
	var source strings.Builder
	source.WriteString("TEXT rawunary(SB),$0-0\n")
	for _, word := range assembleARM64LLVMWords(t, lines, "+sve2p2,+fptoint") {
		fmt.Fprintf(&source, "WORD $%#08x\n", word)
	}
	source.WriteString("RET\n")
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	llc, objdump := findLLVM22Tool("llc"), findLLVM22Tool("llvm-objdump")
	if llc == "" || objdump == "" {
		t.Fatal("LLVM 22 llc and llvm-objdump are required")
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple,
				Sigs: map[string]FuncSig{"rawunary": {Name: "rawunary", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, triple, "rawunary.ll", "rawunary.o", ir)
			// The floating result has no user in this fixture. The native
			// rounding must survive because active lanes can update FPSR.
			object := compileLLVMToObject(t, llc, triple, "rawunary-opt.ll", "rawunary-opt.o", armFloatEffectOptimizedIR(t, ir))
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			code, err := runtimeOracleCombinedOutput(ctx, exec.CommandContext(ctx, objdump, "-d", "--mattr=+sve2p2", object))
			if err != nil {
				t.Fatalf("disassemble optimized sized rounding: %v\n%s", err, code)
			}
			got := sizedRound.FindAllString(string(code), -1)
			for i := range got {
				got[i] = normalize(got[i])
			}
			if strings.Join(got, "\n") != strings.Join(wanted, "\n") {
				t.Fatalf("optimized rounding encodings = %q, want %q", got, wanted)
			}
		})
	}
}

func TestARM64RawSVEFloatUnaryOperandFields(t *testing.T) {
	lines := arm64RawSVEFloatUnaryNativeForms()
	for i, word := range assembleARM64LLVMWords(t, lines, "+sve2p2,+fptoint") {
		got, ok := decodeARM64RawSVEFloatUnary(word)
		if !ok {
			t.Fatalf("%s: rejected %#08x", lines[i], word)
		}
		fields := strings.Fields(strings.ReplaceAll(lines[i], ",", ""))
		if got.Op != Op("Z"+strings.ToUpper(fields[0])) ||
			got.Args[0].Reg != Reg(strings.ToUpper(fields[len(fields)-1])) ||
			got.Args[len(got.Args)-1].Reg != Reg(strings.ToUpper(fields[1])) {
			t.Errorf("%s: wrong operands: %+v", lines[i], got)
		}
		if len(fields) == 4 && got.Args[1].Reg != Reg(strings.ToUpper(strings.ReplaceAll(fields[2], "/", "."))) {
			t.Errorf("%s: wrong predicate: %+v", lines[i], got.Args[1])
		}
	}
	for _, word := range []uint32{0x041da000, 0x6591a000, 0x658eb000, 0x658e3400, 0x049de000} {
		if got, ok := decodeARM64RawSVEFloatUnary(word); ok {
			t.Errorf("reserved/neighboring word %#08x decoded as %+v", word, got)
		}
	}
}
