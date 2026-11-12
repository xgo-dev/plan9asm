package plan9asm

import (
	"errors"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

var x86Mode32ObjectHighBank = regexp.MustCompile(`\b[XY](?:[89]|[12][0-9]|3[01])\b`)

// Keep the complete original source acceptance and its missing physical
// binding observable. The returned low-bank fixture tests object generation,
// not equivalence to the original high-bank machine code or runtime behavior.
func x86PhysicalMode32ObjectSource(t *testing.T, source, arch string) string {
	t.Helper()
	if arch != "386" {
		return source
	}
	goSource := strings.ReplaceAll(source, ",NOSPLIT", ",4")
	requireX86GoAssemblerResult(t, arch, goSource, true)
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	highRows := 0
	for _, function := range file.Funcs {
		for _, instruction := range function.Instrs {
			if !errors.Is(x86Mode32VectorRegisterContext(instruction, arch), ErrProbeNeedsContext) {
				continue
			}
			highRows++
			one, err := Parse(ArchAMD64, "TEXT highbank(SB),4,$0-0\n"+instruction.Raw+"\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(one, Options{
				Goarch: arch, TargetTriple: "i386-unknown-linux-gnu",
				Sigs: map[string]FuncSig{"highbank": {Name: "highbank", Ret: Void}},
			})
			if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
				t.Fatalf("original high bank acquired an unproved physical binding: %s: %v", instruction.Raw, err)
			}
		}
	}
	if highRows == 0 {
		t.Fatal("mode32 fixture lost its original high-bank source coverage")
	}
	physical := x86Mode32ObjectHighBank.ReplaceAllStringFunc(source, func(register string) string {
		index, err := strconv.Atoi(register[1:])
		if err != nil {
			t.Fatal(err)
		}
		return register[:1] + strconv.Itoa(index%8)
	})
	requireX86GoAssemblerResult(t, arch, strings.ReplaceAll(physical, ",NOSPLIT", ",4"), true)
	return physical
}
