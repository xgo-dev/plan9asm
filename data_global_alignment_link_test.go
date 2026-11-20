package plan9asm

import (
	"debug/elf"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func dataGlobalAlignmentCommand(t *testing.T, directory string, environment []string, executable string, arguments ...string) []byte {
	t.Helper()
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	command := exec.CommandContext(ctx, executable, arguments...)
	command.Dir = directory
	command.Env = append(os.Environ(), environment...)
	output, err := runtimeOracleCombinedOutput(ctx, command)
	if err != nil {
		t.Fatalf("%s %q: %v\n%s", filepath.Base(executable), arguments, err, output)
	}
	return output
}

func dataGlobalAlignmentGoProgram(goarch string, maximum int) (string, string) {
	var assembly, declarations, checks strings.Builder
	assembly.WriteString(dataGlobalAlignmentSource())
	declarations.WriteString("package main\nimport \"unsafe\"\n")
	ordinal := 0
	for _, row := range dataGlobalAlignmentSizes {
		alignment := row.alignment
		if alignment > maximum {
			alignment = maximum
		}
		for _, role := range []string{"rw", "ro", "local"} {
			name := fmt.Sprintf("asm_align_%s_n%d", role, row.size)
			if role == "local" {
				name += "<>"
			}
			word := 8
			if goarch == "386" || goarch == "arm" {
				word = 4
			}
			if goarch == "wasm" && role == "local" {
				// Go's wasm Const encoder relocates NAME_EXTERN, not
				// NAME_STATIC. Observe the real private symbol through a
				// source DATA relocation instead of a zero Const encoding.
				fmt.Fprintf(&assembly, "DATA private_address_%d(SB)/8,$%s(SB)\nGLOBL private_address_%d(SB),24,$8\n", ordinal, name, ordinal)
			}
			fmt.Fprintf(&assembly, "TEXT ·Address%d(SB),4,$0-%d\n", ordinal, word)
			switch goarch {
			case "amd64":
				fmt.Fprintf(&assembly, "LEAQ %s(SB),AX\nMOVQ AX,ret+0(FP)\n", name)
			case "386":
				fmt.Fprintf(&assembly, "MOVL $%s(SB),AX\nMOVL AX,ret+0(FP)\n", name)
			case "arm":
				fmt.Fprintf(&assembly, "MOVW $%s(SB),R0\nMOVW R0,ret+0(FP)\n", name)
			case "arm64":
				fmt.Fprintf(&assembly, "MOVD $%s(SB),R0\nMOVD R0,ret+0(FP)\n", name)
			case "wasm":
				assembly.WriteString("Get SP\n")
				if role == "local" {
					fmt.Fprintf(&assembly, "I32Const $private_address_%d(SB)\nI64Load $0\n", ordinal)
				} else {
					fmt.Fprintf(&assembly, "I64Const $%s(SB)\n", name)
				}
				assembly.WriteString("I64Store ret+0(FP)\n")
			}
			assembly.WriteString("RET\n")
			fmt.Fprintf(&declarations, "func Address%d() uintptr\n", ordinal)
			fmt.Fprintf(&checks, `{
    address := Address%d()
    if address == 0 || address%%%d != 0 { panic("%s alignment") }
    bytes := (*[%d]byte)(unsafe.Pointer(address))
    if bytes[0] != 0xa5 { panic("%s first byte") }
    for _, value := range bytes[1:] { if value != 0 { panic("%s zero tail") } }
}
`, ordinal, alignment, name, row.size, name, name)
			ordinal++
		}
	}
	declarations.WriteString("func main() {\n" + checks.String() + "println(\"actual Go assembly alignment and bytes PASS\")\n}\n")
	return assembly.String(), declarations.String()
}

func dataGlobalAlignmentGoBuild(t *testing.T, goarch, goos string, maximum int) string {
	t.Helper()
	directory := t.TempDir()
	assembly, program := dataGlobalAlignmentGoProgram(goarch, maximum)
	for name, source := range map[string]string{
		"go.mod": "module alignment_oracle\n\ngo 1.20\n", "main.go": program, "data.s": assembly,
	} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
	}
	executable := filepath.Join(directory, "original")
	environment := []string{"GOWORK=off", "GOENV=off", "GOTOOLCHAIN=local", "CGO_ENABLED=0", "GOARCH=" + goarch, "GOOS=" + goos}
	dataGlobalAlignmentCommand(t, directory, environment, "go", "build", "-p=2", "-o", executable, ".")
	return executable
}

func dataGlobalAlignmentELF(t *testing.T, path, goarch string, maximum int, relocated bool) {
	t.Helper()
	image, err := elf.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer image.Close()
	machine := map[string]elf.Machine{"386": elf.EM_386, "amd64": elf.EM_X86_64, "arm": elf.EM_ARM, "arm64": elf.EM_AARCH64}[goarch]
	if machine == elf.EM_NONE || image.Machine != machine ||
		!relocated && image.Type != elf.ET_REL || relocated && image.Type != elf.ET_EXEC && image.Type != elf.ET_DYN {
		t.Fatal("actual object target or link role changed", image.FileHeader)
	}
	symbols, err := image.Symbols()
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range dataGlobalAlignmentSizes {
		alignment := row.alignment
		if alignment > maximum {
			alignment = maximum
		}
		for _, role := range []string{"rw", "ro", "local"} {
			name := fmt.Sprintf("asm_align_%s_n%d", role, row.size)
			matches := 0
			for _, symbol := range symbols {
				if symbol.Name != name {
					continue
				}
				matches++
				if symbol.Section == elf.SHN_UNDEF || int(symbol.Section) >= len(image.Sections) || symbol.Size != uint64(row.size) {
					t.Fatalf("missing complete native definition: %+v", symbol)
				}
				section := image.Sections[symbol.Section]
				if symbol.Value%uint64(alignment) != 0 || relocated && symbol.Value == 0 ||
					!relocated && section.Addralign < uint64(alignment) {
					t.Errorf("%s: symbol address=%#x section alignment=%d, Go requires %d", name, symbol.Value, section.Addralign, alignment)
				}
				bytes, err := section.Data()
				start := symbol.Value - section.Addr
				if err != nil || start > uint64(len(bytes)) || symbol.Size > uint64(len(bytes))-start {
					t.Fatal("native symbol has no complete section bytes", symbol, err)
				}
				for index, value := range bytes[start : start+symbol.Size] {
					want := byte(0)
					if index == 0 {
						want = 0xa5
					}
					if value != want {
						t.Fatalf("%s byte%d=%#x, want %#x", name, index, value, want)
					}
				}
			}
			if matches != 1 {
				t.Fatalf("%s has %d native definitions, want one", name, matches)
			}
		}
	}
}

func TestDataGlobalAlignmentActualGoLinkedFiveArchitectures(t *testing.T) {
	for _, target := range dataGlobalAlignmentTargets {
		t.Run(target.goarch, func(t *testing.T) {
			executable := dataGlobalAlignmentGoBuild(t, target.goarch, target.goos, target.maximum)
			if target.arch != ArchWASM {
				dataGlobalAlignmentELF(t, executable, target.goarch, target.maximum, true)
				return
			}
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			command, err := wasmPackedGoRuntimeCommand(ctx, testGOROOT(t), wasmPackedNode(t), executable)
			if err != nil {
				t.Fatal(err)
			}
			output, err := runtimeOracleCombinedOutput(ctx, command)
			if err != nil || strings.TrimSpace(string(output)) != "actual Go assembly alignment and bytes PASS" {
				t.Fatalf("actual Go wasm linked addresses/bytes: %v\n%s", err, output)
			}
		})
	}
}

func dataGlobalAlignmentModule(t *testing.T, arch Arch, triple, route string) string {
	t.Helper()
	file, err := Parse(arch, dataGlobalAlignmentSource())
	if err != nil {
		t.Fatal(err)
	}
	options := Options{TargetTriple: triple, ResolveSym: dataGlobalAlignmentResolve}
	if route == "text" {
		ir, err := Translate(file, options)
		if err != nil {
			t.Fatal(err)
		}
		return ir
	}
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	module, err := translateModuleDirectInContext(ctx, file, options)
	if !module.IsNil() {
		defer module.Dispose()
	}
	if err != nil {
		t.Fatal("direct emitter must not fall back", err)
	}
	return module.String()
}

func TestDataGlobalAlignmentLLVMObjectsAndLinkedAddresses(t *testing.T) {
	llc, linker, wasmLinker := findLLVM22Tool("llc"), findLLVM22Tool("ld.lld"), findLLVM22Tool("wasm-ld")
	if llc == "" || linker == "" || wasmLinker == "" {
		t.Fatal("LLVM22 llc, ld.lld and wasm-ld required")
	}
	for _, target := range dataGlobalAlignmentTargets {
		for _, route := range []string{"text", "direct"} {
			t.Run(target.goarch+"/"+route, func(t *testing.T) {
				ir := dataGlobalAlignmentModule(t, target.arch, target.triple, route)
				if target.arch == ArchWASM {
					// Keep private source symbols alive and observable through
					// exported test consumers; export-all alone excludes them.
					for _, row := range dataGlobalAlignmentSizes {
						ir += fmt.Sprintf("define i32 @private_address_%d() {\n %%address = ptrtoint ptr @asm_align_local_n%d to i32\n ret i32 %%address\n}\n", row.size, row.size)
					}
				}
				directory := t.TempDir()
				input, object, linked := filepath.Join(directory, "data.ll"), filepath.Join(directory, "data.o"), filepath.Join(directory, "linked")
				if err := os.WriteFile(input, []byte(ir), 0600); err != nil {
					t.Fatal(err)
				}
				dataGlobalAlignmentCommand(t, directory, nil, llc, "-O0", "-filetype=obj", input, "-o", object)
				if target.arch != ArchWASM {
					dataGlobalAlignmentELF(t, object, target.goarch, target.maximum, false)
					// MinGW builds default ld.lld to PE unless -m explicitly
					// selects an ELF emulation. The object and linked symbols
					// are still independently checked by the ELF reader.
					emulation := map[string]string{
						"386": "elf_i386", "amd64": "elf_x86_64",
						"arm": "armelf_linux_eabi", "arm64": "aarch64linux",
					}[target.goarch]
					if emulation == "" {
						t.Fatal("missing explicit ELF linker target", target.goarch)
					}
					dataGlobalAlignmentCommand(t, directory, nil, linker, "-m", emulation, "-shared", object, "-o", linked)
					dataGlobalAlignmentELF(t, linked, target.goarch, target.maximum, true)
					return
				}
				dataGlobalAlignmentCommand(t, directory, nil, wasmLinker, "--no-entry", "--export-all", object, "-o", linked)
				var checks strings.Builder
				for _, row := range dataGlobalAlignmentSizes {
					for _, role := range []string{"rw", "ro", "local"} {
						name := fmt.Sprintf("asm_align_%s_n%d", role, row.size)
						address := fmt.Sprintf("e[%q].value", name)
						if role == "local" {
							address = fmt.Sprintf("e.private_address_%d()", row.size)
						}
						fmt.Fprintf(&checks, `{
  const address = %s;
  if (!address || address%%%d) throw Error(%q + " alignment=" + address);
  for (let i=0;i<%d;i++) if (bytes[address+i] !== (i ? 0 : 0xa5)) throw Error(%q + " bytes");
}
`, address, row.alignment, name, row.size, name)
					}
				}
				script := `const fs=require("fs");
WebAssembly.instantiate(fs.readFileSync(process.argv[1])).then(({instance})=>{
const e=instance.exports, bytes=new Uint8Array(e.memory.buffer);
` + checks.String() + `console.log("LLVM linked wasm alignment and bytes PASS");
}).catch(error=>{ console.error(error); process.exit(1); });`
				scriptPath := filepath.Join(directory, "observe.cjs")
				script = strings.Replace(script, "process.argv[1]", "process.argv[2]", 1)
				if err := os.WriteFile(scriptPath, []byte(script), 0600); err != nil {
					t.Fatal(err)
				}
				output := dataGlobalAlignmentCommand(t, directory, nil, wasmPackedNode(t), scriptPath, linked)
				if strings.TrimSpace(string(output)) != "LLVM linked wasm alignment and bytes PASS" {
					t.Fatal("linked wasm checks did not execute", string(output))
				}
			})
		}
	}
}
