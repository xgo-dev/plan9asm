package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestIndirectMarkerGoBranchForms(t *testing.T) {
	// Go's shared operand parser accepts '*' before registers and register
	// memory, including ARM's numeric R(n) spelling. The encoder tables still
	// decide which operand classes each branch instruction accepts.
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range []struct {
		arch           Arch
		goarch, triple string
		ops, operands  []string
	}{
		{
			ArchAMD64, "386", "i386-unknown-linux-gnu",
			[]string{"CALL", "JMP"}, []string{"AX", "(BX)", "8(BX)"},
		},
		{
			ArchAMD64, "amd64", "x86_64-unknown-linux-gnu",
			[]string{"CALL", "JMP"}, []string{"AX", "R10", "(BX)", "8(BX)"},
		},
		{
			ArchARM, "arm", "armv7-unknown-linux-gnueabihf",
			[]string{"BL", "CALL", "B", "JMP", "BX"}, []string{"(R0)", "0(R(1))", "(g)"},
		},
		{
			ArchARM64, "arm64", "aarch64-unknown-linux-gnu",
			[]string{"BL", "CALL"}, []string{"R0", "R(1)", "g", "(R0)", "0(R(1))", "(g)", "(RSP)"},
		},
		{
			ArchARM64, "arm64", "aarch64-unknown-linux-gnu",
			[]string{"B", "JMP"}, []string{"(R0)", "0(R(1))", "(g)", "(RSP)"},
		},
	} {
		for _, op := range target.ops {
			for _, operand := range target.operands {
				t.Run(target.goarch+"/"+op+"/"+operand, func(t *testing.T) {
					var ir [2]string
					var parsed [2]Operand
					for i, marker := range []string{"", "*"} {
						source := fmt.Sprintf("TEXT indirect(SB),4,$0-0\n%s %s%s\nRET\n", op, marker, operand)
						requireIndirectMarkerGoAssembly(t, target.goarch, source, true)
						file, err := Parse(target.arch, source)
						if err != nil {
							t.Fatal(err)
						}
						if i == 1 {
							for _, extraTriple := range map[string][]string{
								"386":   {"i686-pc-windows-msvc"},
								"amd64": {"x86_64-apple-darwin", "x86_64-pc-windows-msvc"},
								"arm64": {"aarch64-apple-darwin", "aarch64-pc-windows-msvc"},
							}[target.goarch] {
								extraIR, err := Translate(file, Options{
									Goarch: target.goarch, TargetTriple: extraTriple,
									Sigs: map[string]FuncSig{"indirect": {Name: "indirect", Ret: Void}},
								})
								if err != nil {
									t.Fatal(err)
								}
								compileLLVMToObject(t, llc, extraTriple, "indirect.ll", "indirect.o", extraIR)
							}
						}
						parsed[i] = file.Funcs[0].Instrs[1].Args[0]
						// Raw source is diagnostic text in emitted IR comments.
						file.Funcs[0].Instrs[1].Raw = op + " " + operand
						ir[i], err = Translate(file, Options{
							Goarch: target.goarch, TargetTriple: target.triple,
							Sigs: map[string]FuncSig{"indirect": {Name: "indirect", Ret: Void}},
						})
						if err != nil {
							t.Fatal(err)
						}
					}
					if !reflect.DeepEqual(parsed[0], parsed[1]) {
						t.Fatalf("marker changes typed operand: %#v != %#v", parsed[0], parsed[1])
					}
					if indirectMarkerComparableIR(ir[0]) != indirectMarkerComparableIR(ir[1]) {
						t.Fatal("marker changes generated IR")
					}
					compileLLVMToObject(t, llc, target.triple, "indirect.ll", "indirect.o", ir[1])
				})
			}
		}
	}
}

func TestIndirectMarkerDoesNotRelaxBranchOperandClasses(t *testing.T) {
	for _, tc := range []struct {
		arch                    Arch
		goarch, triple, command string
	}{
		{ArchARM64, "arm64", "aarch64-unknown-linux-gnu", "CALL *8(R0)"},
		{ArchARM64, "arm64", "aarch64-unknown-linux-gnu", "BL *RSP"},
		{ArchARM64, "arm64", "aarch64-unknown-linux-gnu", "BL *V0"},
		{ArchARM64, "arm64", "aarch64-unknown-linux-gnu", "CALL *$1"},
		{ArchARM, "arm", "armv7-unknown-linux-gnueabihf", "BX *R0"},
	} {
		t.Run(tc.goarch+"/"+tc.command, func(t *testing.T) {
			source := "TEXT indirect(SB),4,$0-0\n" + tc.command + "\nRET\n"
			requireIndirectMarkerGoAssembly(t, tc.goarch, source, false)
			file, err := Parse(tc.arch, source)
			if err != nil {
				return
			}
			_, err = Translate(file, Options{
				Goarch: tc.goarch, TargetTriple: tc.triple,
				Sigs: map[string]FuncSig{"indirect": {Name: "indirect", Ret: Void}},
			})
			if err == nil {
				t.Fatal("accepted branch outside Go's operand classes")
			}
		})
	}
}

func indirectMarkerComparableIR(ir string) string {
	// LLVM embeds each independent translation's temporary input filename.
	var result strings.Builder
	for _, line := range strings.Split(ir, "\n") {
		if strings.HasPrefix(line, "; ModuleID =") || strings.HasPrefix(line, "source_filename =") {
			continue
		}
		result.WriteString(line)
		result.WriteByte('\n')
	}
	return result.String()
}

func TestIndirectMarkerDoesNotEraseSymbolOrImmediateMeaning(t *testing.T) {
	// Symbol indirection is not the same as a direct symbol call. Do not turn
	// unsupported forms into a seemingly valid direct branch by stripping '*'.
	for _, arch := range []Arch{ArchAMD64, ArchARM, ArchARM64, ArchWASM} {
		for _, source := range []string{"*target(SB)", "*target", "*$8", "**R0"} {
			t.Run(fmt.Sprintf("%v/%s", arch, source), func(t *testing.T) {
				operand, err := parseOperandForArch(arch, source)
				if err != nil {
					return
				}
				if operand.Kind == OpReg || operand.Kind == OpMem || operand.Kind == OpImm ||
					operand.Kind == OpSym && !strings.Contains(operand.Sym, "*") ||
					operand.Kind == OpIdent && !strings.Contains(operand.Ident, "*") {
					t.Fatalf("indirection erased: %#v", operand)
				}
			})
		}
	}
}

func requireIndirectMarkerGoAssembly(t *testing.T, goarch, source string, wantOK bool) {
	t.Helper()
	dir := t.TempDir()
	asm := filepath.Join(dir, "indirect.s")
	if err := os.WriteFile(asm, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("go", "tool", "asm", "-o", filepath.Join(dir, "indirect.o"), asm)
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+goarch)
	out, err := cmd.CombinedOutput()
	if (err == nil) != wantOK {
		t.Fatalf("Go assembler success=%v, want %v for %s:\n%s\n%s", err == nil, wantOK, goarch, source, out)
	}
}
