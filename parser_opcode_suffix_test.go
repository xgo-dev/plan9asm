package plan9asm

import (
	"strings"
	"testing"
)

// The official line grammar consumes Ident ('.' Ident)* before operands,
// irrespective of spacing or CPP origins. An opcode-table probe alone does
// not exercise serialization followed by a second parser.
func TestParseOpcodeSuffixTokenGrammarGoAndLLVMObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, test := range []struct {
		name, goarch, triple, opcode, operands string
		arch                                   Arch
	}{
		{"arm64_postindex", "arm64", "aarch64-unknown-linux-gnu", "STP.P", "(ZR, ZR), 64(R4)", ArchARM64},
		{"arm64_preindex", "arm64", "aarch64-unknown-linux-gnu", "STP.W", "(R0, R1), -16(R4)", ArchARM64},
		{"arm_flags", "arm", "armv7-unknown-linux-gnueabihf", "ADD.S", "$255, R0, R1", ArchARM},
		{"arm_postindex", "arm", "armv7-unknown-linux-gnueabihf", "MOVW.P", "4(R1), R0", ArchARM},
		{"x86_multiple", "amd64", "x86_64-unknown-linux-gnu", "VADDPD.RN_SAE.Z", "Z3, Z2, K1, Z1", ArchAMD64},
	} {
		t.Run(test.name, func(t *testing.T) {
			base, suffix, _ := strings.Cut(test.opcode, ".")
			for _, variant := range []struct{ name, prefix, opcode string }{
				{"compact", "", test.opcode},
				{"spaced", "", strings.ReplaceAll(test.opcode, ".", " . ")},
				{"comments", "", strings.ReplaceAll(test.opcode, ".", " /*before*/ . /*after*/ ")},
				{"macro", "#define SUFFIX ." + suffix + "\n", base + " SUFFIX"},
			} {
				t.Run(variant.name, func(t *testing.T) {
					source := variant.prefix + "TEXT Probe(SB),4,$0-0\n" + variant.opcode + " " + test.operands + "\nRET\n"
					goAssemblerOracleOutput(t, test.goarch, source, "", true)
					expanded, err := PreprocessAssemblySource(source, AssemblyPreprocessOptions{FileName: "suffix.s"})
					if err != nil {
						t.Fatal(err)
					}
					goAssemblerOracleOutput(t, test.goarch, expanded, "", true)
					for index, input := range []string{source, expanded} {
						file, err := Parse(test.arch, input)
						if err != nil {
							t.Fatalf("suffix grammar path=%d: %v", index, err)
						}
						if len(file.Funcs) != 1 || len(file.Funcs[0].Instrs) != 3 || file.Funcs[0].Instrs[1].Op != Op(test.opcode) {
							t.Fatalf("suffix became an operand or was lost: path=%d file=%+v", index, file)
						}
						ir, err := Translate(file, Options{
							Goarch: test.goarch, TargetTriple: test.triple,
							Sigs: map[string]FuncSig{"Probe": {Name: "Probe", Ret: Void}},
						})
						if err != nil {
							t.Fatal(err)
						}
						compileLLVMToObject(t, llc, test.triple, "suffix.ll", "suffix.o", ir)
					}
				})
			}
		})
	}
}
