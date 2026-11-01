package plan9asm

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func x86TLSOriginalRegisterNames(t *testing.T) []string {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/list6.go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, declaration := range file.Decls {
		group, valid := declaration.(*ast.GenDecl)
		if !valid || group.Tok != token.VAR {
			continue
		}
		for _, specification := range group.Specs {
			value, valid := specification.(*ast.ValueSpec)
			if !valid || len(value.Names) != 1 || value.Names[0].Name != "Register" || len(value.Values) != 1 {
				continue
			}
			list, valid := value.Values[0].(*ast.CompositeLit)
			if !valid {
				t.Fatal("unknown complete Go x86 register-name registration")
			}
			for _, element := range list.Elts {
				literal, valid := element.(*ast.BasicLit)
				if !valid || literal.Kind != token.STRING {
					t.Fatal("nonliteral Go x86 register name")
				}
				name, err := strconv.Unquote(literal.Value)
				if err != nil || name == "" {
					t.Fatal("invalid original Go register name")
				}
				names = append(names, name)
			}
		}
	}
	if len(names) != 201 || names[16] != "AX" || names[31] != "R15" || names[len(names)-1] != "MAXREG" {
		t.Fatalf("complete Go x86 register-name inventory changed: %d names", len(names))
	}
	return names
}

func TestX86TLSMoveDirectNOPAllRegisteredDestinationClasses(t *testing.T) {
	originalNames := x86TLSOriginalRegisterNames(t)
	for _, profile := range []struct{ target, arch string }{{"linux", "amd64"}, {"freebsd", "386"}} {
		t.Run(profile.target+"/"+profile.arch, func(t *testing.T) {
			names := append(append([]string(nil), originalNames...), "SB", "FP", "PC", "UNREGISTERED")
			if profile.arch == "amd64" {
				names = append(names, "g") // The independently registered AMD64-only R14 alias.
			}
			accepted, rejected, contextual := 0, 0, 0
			for _, op := range []string{"MOVL", "MOVQ", "MOVD", "MOVDQ2Q"} {
				for index, register := range names {
					row := op + " TLS," + register
					wantNOP := index >= 16 && index <= 31 || register == "g"
					dir := t.TempDir()
					input, object := filepath.Join(dir, "bank.s"), filepath.Join(dir, "bank.o")
					if err := os.WriteFile(input, []byte("TEXT f(SB),4,$0-0\n"+row+"\nRET\n"), 0600); err != nil {
						t.Fatal(err)
					}
					args := []string{"tool", "asm", "-p", "tlsbanks", "-o", object}
					if wantNOP {
						args = append(args, "-S")
					}
					args = append(args, input)
					ctx, cancel := runtimeOracleStageContext(t)
					command := exec.CommandContext(ctx, "go", args...)
					command.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOOS="+profile.target, "GOARCH="+profile.arch,
						"GOENV=off", "GOWORK=off", "GOFLAGS=", "GOEXPERIMENT=", "GOAMD64=v1", "GO386=sse2")
					output, err := runtimeOracleCombinedOutput(ctx, command)
					contextErr := ctx.Err()
					cancel()
					if err == nil {
						if !wantNOP {
							t.Fatalf("unmodeled actual Go acceptance: %s %s\n%s", profile.arch, row, output)
						}
						if failure := goAssemblerOracleOutcome(input, object, output, err, contextErr, true, profile.arch); failure != nil {
							t.Fatal(failure)
						}
						noops := 0
						for _, line := range strings.Split(string(output), "\n") {
							record := goAMD64FrameRow.FindStringSubmatch(line)
							if record != nil && strings.TrimSpace(record[3]) == "NOP" {
								noops++
							}
						}
						if noops != 1 || !strings.Contains(string(output), "size=1 ") {
							t.Fatalf("accepted source is not one zero-width NOP and RET: %s\n%s", row, output)
						}
						if typed := x86SourceTLSMoveError(x86PureGPUnknownInstruction(t, row), profile.arch); !errors.Is(typed, ErrProbeNeedsContext) {
							t.Fatalf("actual source NOP lacks its explicit binding boundary: %s: %v", row, typed)
						}
						accepted++
						continue
					}
					if wantNOP {
						t.Fatalf("actual Go lost its registered source NOP: %s: %v\n%s", row, err, output)
					}
					if failure := goAssemblerOracleOutcome(input, object, output, err, contextErr, false, profile.arch); failure == nil {
						rejected++
						continue
					}
					// A compiler/backend diagnostic without a complete fixture-bound
					// rejection remains Context, never successful source coverage.
					exit, exited := err.(*exec.ExitError)
					if contextErr != nil || !exited || exit.ExitCode() != 1 || len(output) == 0 {
						t.Fatalf("unknown/infrastructure bank observation: %s: %v\n%s", row, err, output)
					}
					contextual++
					t.Logf("native bank Context: %s %s: %s", profile.arch, row, strings.TrimSpace(string(output)))
				}
			}
			want := 64
			if profile.arch == "amd64" {
				want = 68
			}
			if accepted != want || accepted+rejected+contextual != 4*len(names) {
				t.Fatal("complete destination-bank probe inventory changed")
			}
			t.Logf("%s: actual source NOPs=%d ordinary Go rejections=%d Context=%d total=%d",
				fmt.Sprint(profile), accepted, rejected, contextual, 4*len(names))
		})
	}
}
