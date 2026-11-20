package plan9asm

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func runtime386CoreGoObject(t *testing.T, body string) {
	t.Helper()
	driver, driverHash := x86LEAActualSDKDriver(t)
	include := filepath.Join(runtime.GOROOT(), "pkg", "include")
	header := filepath.Join(include, "textflag.h")
	before, err := os.ReadFile(header)
	if err != nil {
		t.Fatal(err)
	}
	// Only the actual selected SDK's header supplies the complete fixture's
	// existing NOSPLIT spelling. The observed body is never cropped.
	source := "#include \"textflag.h\"\n" + body
	directory := t.TempDir()
	input, object := filepath.Join(directory, "core.s"), filepath.Join(directory, "core.o")
	if err := os.WriteFile(input, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	command := exec.CommandContext(ctx, driver, "tool", "asm", "-I", include, "-p", "runtimecore", "-o", object, input)
	command.Env = append(os.Environ(), "GOOS=windows", "GOARCH=386", "CGO_ENABLED=0", "GOTOOLCHAIN=local", "GOENV=off", "GOWORK=off")
	output, err := runtimeOracleCombinedOutput(ctx, command)
	if failure := goAssemblerOracleOutcome(input, object, output, err, ctx.Err(), true, "386"); failure != nil {
		t.Fatalf("complete Windows386 Go assembly: %v\n%s", failure, output)
	}
	if after, err := os.ReadFile(header); err != nil || !bytes.Equal(before, after) {
		t.Fatal("selected SDK's original header changed during assembly", err)
	}
	x86LEAReadObjectReceipt(t, "386", "windows", source, input, driver, driverHash, object)
}

func runtime386CoreTranslate(t *testing.T, source, api string) (string, error) {
	t.Helper()
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		return "", err
	}
	options := runtime386CoreOptions()
	if api == "text" {
		return Translate(file, options)
	}
	if api != "module" {
		t.Fatal("unknown portable 386 transport API", api)
	}
	context := llvm.NewContext()
	defer context.Dispose()
	module, err := TranslateModuleInContext(context, file, options)
	if !module.IsNil() {
		defer module.Dispose()
		if err == nil {
			return module.String(), nil
		}
	}
	return "", err
}

// This portable owner observes all original source and manual transport
// signatures. It does not execute the Windows C driver or invent a GoModule
// ABI0 declaration for cas64's existing SI/AX/DX/BX/CX register convention.
func TestRuntimeExec386CoreCompleteSourceGoAndLLVMObjects(t *testing.T) {
	if got := fmt.Sprintf("%x", sha256.Sum256([]byte(runtime386CoreAssembly))); got != "8cfb20eb17f5105cb92fc184bffa1333007c80fcfe19865795ed15b0c6d1fbb2" {
		t.Fatal("original complete Windows386 source changed", got)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256([]byte(runtime386CoreCSource))); got != "50eb6e546b44eff9347c96721d22f49eb70e0be57b2be06b75c2324cae12916a" {
		t.Fatal("original Windows native C driver changed", got)
	}
	want := []string{"addCarry", "cpuidProbe", "frameAddress", "copyForward", "copyBackward", "copyBackwardRestoredDF",
		"fillWords", "findByte", "zeroLengthScanPreservesZF", "negateHasCarry", "floorValue", "uint32ToFloat64",
		"cas64", "xadd32", "identity64", "identityFloat64", "readFS", "roundNearest"}
	file, err := Parse(ArchAMD64, runtime386CoreAssembly)
	if err != nil {
		t.Fatal(err)
	}
	options := runtime386CoreOptions()
	if len(file.Funcs) != 18 || len(options.Sigs) != 18 || options.Goarch != "386" || options.TargetTriple != "i686-pc-windows-msvc" {
		t.Fatal("complete original source/signature/target inventory changed")
	}
	for index, function := range file.Funcs {
		if function.Sym != want[index] || options.Sigs[function.Sym].Name != want[index] {
			t.Fatal("original TEXT order or manual signature identity changed", function.Sym)
		}
	}
	if !reflect.DeepEqual(options.Sigs["cas64"].ArgRegs, []Reg{SI, AX, DX, BX, CX}) || options.Sigs["cas64"].Ret != I1 {
		t.Fatal("original custom-register cas64 transport was replaced by a fabricated Go ABI")
	}
	corrected := runtime386CoreCorrectedAssembly(t)
	const insertion = "\tMOVBLZX BX,BX\n"
	if strings.Count(corrected, insertion) != 1 || strings.Replace(corrected, insertion, "", 1) != runtime386CoreAssembly {
		t.Fatal("corrected complete fixture differs by more than the one byte-extension instruction")
	}
	changed, err := Parse(ArchAMD64, corrected)
	if err != nil || len(changed.Funcs) != len(file.Funcs) {
		t.Fatal("corrected complete fixture lost an original TEXT", err)
	}
	for index, function := range changed.Funcs {
		if function.Sym == "negateHasCarry" {
			if len(function.Instrs) != len(file.Funcs[index].Instrs)+1 {
				t.Fatal("corrected carry fixture changed another instruction")
			}
			found := -1
			for ordinal, instruction := range function.Instrs {
				if instruction.Op == "MOVBLZX" {
					found = ordinal
					if !reflect.DeepEqual(instruction.Args, []Operand{{Kind: OpReg, Reg: BX}, {Kind: OpReg, Reg: BX}}) {
						t.Fatal("byte extension changed the original carry-result register")
					}
				}
			}
			if found <= 0 || function.Instrs[found-1].Op != "SETCS" {
				t.Fatal("byte extension is not after the original carry-byte producer")
			}
			instructions := append([]Instr(nil), function.Instrs[:found]...)
			function.Instrs = append(instructions, function.Instrs[found+1:]...)
		}
		if !reflect.DeepEqual(function, file.Funcs[index]) {
			t.Fatal("corrected fixture changed an original TEXT, frame, operand or source effect", function.Sym)
		}
	}
	if !t.Run("original-Go-windows386", func(t *testing.T) { runtime386CoreGoObject(t, runtime386CoreAssembly) }) {
		return
	}
	for _, api := range []string{"text", "module"} {
		t.Run("original-undefined-BX/"+api, func(t *testing.T) {
			ir, err := runtime386CoreTranslate(t, runtime386CoreAssembly, api)
			if !errors.Is(err, ErrProbeNeedsContext) || ir != "" || !strings.Contains(err.Error(), "negateHasCarry") ||
				!strings.Contains(err.Error(), "instruction 3: MOVL BX, ret+4(FP)") {
				t.Fatal("original undefined upper BX bytes acquired a complete numerical result", err)
			}
		})
	}
	if !t.Run("corrected-Go-windows386", func(t *testing.T) { runtime386CoreGoObject(t, corrected) }) {
		return
	}
	for _, api := range []string{"text", "module"} {
		t.Run("BX-only-unbounded-scratch/"+api, func(t *testing.T) {
			ir, err := runtime386CoreTranslate(t, corrected, api)
			// The complete save/change/restore scope in floorValue now has
			// independent private-word proof. It supplies no incoming-SP
			// backing to the next original uint32 conversion function.
			if !errors.Is(err, ErrProbeNeedsContext) || ir != "" || !strings.Contains(err.Error(), "uint32ToFloat64") ||
				!strings.Contains(err.Error(), "requires complete bounded positive original TEXT") {
				t.Fatal("BX correction manufactured a backing frame for the original physical SP scratch", err)
			}
		})
	}
	bounded := runtime386BoundedScratchAssembly(t)
	if !t.Run("bounded-Go-windows386", func(t *testing.T) { runtime386CoreGoObject(t, bounded) }) {
		return
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("complete original Windows386 objects require LLVM22 llc")
	}
	for _, api := range []string{"text", "module"} {
		t.Run("bounded-complete18/"+api, func(t *testing.T) {
			ir, err := runtime386CoreTranslate(t, bounded, api)
			if err != nil || ir == "" {
				t.Fatal("complete corrected Windows386 source has an unclosed contract", err)
			}
			for _, name := range want {
				x86StringMemoryFunction(t, ir, name)
			}
			if !strings.Contains(ir, "target triple = \"i686-pc-windows-msvc\"") {
				t.Fatal("portable observation changed the original Windows386 target")
			}
			for _, level := range []string{"0", "2"} {
				input := ir
				if level == "2" {
					input = x86DwordProductIROptimize(t, input)
				}
				for _, backend := range []string{"0", "2"} {
					t.Run("IR"+level+"/backend"+backend, func(t *testing.T) {
						x86PackedStringCompileObject(t, llc, options.TargetTriple, input, "-O"+backend)
					})
				}
			}
		})
	}
}
