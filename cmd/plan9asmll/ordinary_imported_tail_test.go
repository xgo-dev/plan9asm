package main

import (
	"debug/elf"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm"
)

func TestCompileOneOrdinaryImportedTails(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			ordinaryGlobalCLIProfile(t)
			directory, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			const module = "example.com/tailcli"
			const dependency = module + "/callee"
			const target = "example·com∕tailcli∕callee"
			resultOffset := 4
			if arch == "amd64" {
				resultOffset = 8
			}
			scale := fmt.Sprintf("TEXT ·Scale(SB),4,$0-%d\nMOVL value+0(FP),AX\nADDL $7,AX\nMOVL AX,ret+%d(FP)\nRET\n",
				resultOffset+4, resultOffset)
			nonzero := fmt.Sprintf("TEXT ·Nonzero(SB),4,$0-%d\nCMPL value+0(FP),$0\nSETNE ret+%d(FP)\nRET\n",
				resultOffset+1, resultOffset)
			flag := fmt.Sprintf("TEXT ·Flag(SB),4,$0-%d\nJMP %s·Nonzero(SB)\n", resultOffset+1, target)
			inputs := map[string]string{
				"go.mod":                      "module " + module + "\n\ngo 1.24\n",
				"callee/value.go":             "package callee\nfunc Scale(value uint32) uint32\nfunc Nonzero(value uint32) bool\n",
				"callee/value_" + arch + ".s": scale + nonzero,
				"caller/value.go":             "package caller\nimport _ \"" + dependency + "\"\nfunc Forward(value uint32) uint32\nfunc Flag(value uint32) bool\n",
				"caller/value_" + arch + ".s": "TEXT ·Forward(SB),4,$0\nJMP " + target + "·Scale(SB)\n" + flag,
				"cmd/main.go": "package main\nimport \"" + module + "/caller\"\n" +
					"func main() { if caller.Forward(1) != 8 || !caller.Flag(5) || caller.Flag(0) { panic(\"tail\") } }\n",
			}
			for name, text := range inputs {
				file := filepath.Join(directory, filepath.FromSlash(name))
				if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(file, []byte(text), 0600); err != nil {
					t.Fatal(err)
				}
			}
			ctx := arm64PrivateCLIContext(t)
			cmd := exec.CommandContext(ctx, filepath.Join(runtime.GOROOT(), "bin", "go"),
				"build", "-p=1", "-o", filepath.Join(directory, "original"), "./cmd")
			cmd.Dir = directory
			cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+arch)
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("original Go build/link: %v\n%s", err, output)
			}

			t.Chdir(filepath.Join(directory, "caller"))
			selected, environment, err := loadPkgsInEnvironment("linux", arch, []string{"."}, nil, "", true, false, nil)
			if err != nil || len(selected) != 1 || selected[0].PkgPath != module+"/caller" {
				t.Fatalf("selected package load: %v %+v", err, selected)
			}
			pkg := selected[0]
			callee := pkg.Imports[dependency]
			if callee == nil || callee.Types == nil || len(callee.Syntax) != 0 || len(pkg.Syntax) != 0 {
				t.Fatal("expected the actual type-only driver selection")
			}
			config, err := resolveCompileConfig(true, "", true, 2)
			if err != nil {
				t.Fatal(err)
			}
			config.Context = ctx
			config.x86CallerSelections = captureX86CallerSelectionsInEnvironment(selected, "linux/"+arch, environment)
			output := filepath.Join(t.TempDir(), "tails.ll")
			task := asmTask{PkgPath: pkg.PkgPath, AsmFile: filepath.Join(pkg.Dir, "value_"+arch+".s"), OutLL: output}
			if err := compileOne(pkg, plan9asm.ArchAMD64, "linux", arch, targetTriple("linux", arch), task, false, config); err != nil {
				t.Fatal("ordinary complete imported tails", err)
			}
			object, err := elf.Open(strings.TrimSuffix(output, ".ll") + ".o")
			if err != nil {
				t.Fatal(err)
			}
			defer object.Close()
			symbols, err := object.Symbols()
			if err != nil {
				t.Fatal(err)
			}
			wanted := map[string]bool{
				dependency + ".Scale": true, dependency + ".Nonzero": true,
				pkg.PkgPath + ".Forward": false, pkg.PkgPath + ".Flag": false,
			}
			for _, symbol := range symbols {
				if undefined, exists := wanted[symbol.Name]; exists {
					if undefined != (symbol.Section == elf.SHN_UNDEF) {
						t.Fatal("wrong definition/reference role for original symbol", symbol.Name)
					}
					delete(wanted, symbol.Name)
				}
			}
			if len(wanted) != 0 || len(callee.Syntax) != 0 || len(pkg.Syntax) != 0 {
				t.Fatal("missing original tail symbols or mutated the load selection", wanted)
			}
		})
	}
}
