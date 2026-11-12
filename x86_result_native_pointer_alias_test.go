package plan9asm

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"go/types"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
	"golang.org/x/arch/x86/x86asm"
)

type x86ResultAliasObject struct {
	source, listing string
	symbolPrefix    string
	code            map[string][]byte
}

// This observes complete stock-Go objects only. Neither function is executed:
// the caller deliberately supplies a pointer to storage it has not initialized.
func x86ResultAliasGoObject(t *testing.T, arch, triple, source string) x86ResultAliasObject {
	t.Helper()
	goos := "linux"
	if strings.Contains(triple, "apple") {
		goos = "darwin"
	} else if strings.Contains(triple, "windows") {
		goos = "windows"
	}
	dir := t.TempDir()
	input, object := filepath.Join(dir, "alias.s"), filepath.Join(dir, "alias.o")
	if err := os.WriteFile(input, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	driver, driverHash := x86LEAActualSDKDriver(t)
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	command := exec.CommandContext(ctx, driver, "tool", "asm", "-S", "-p", "pointeralias", "-o", object, input)
	command.Env = append(os.Environ(), "GOOS="+goos, "GOARCH="+arch, "CGO_ENABLED=0", "GOTOOLCHAIN=local", "GOENV=off", "GOWORK=off")
	output, err := runtimeOracleCombinedOutput(ctx, command)
	if err != nil {
		t.Fatalf("original pointer-alias Go object: %v\n%s", err, output)
	}
	receipt := x86LEAReadObjectReceipt(t, arch, goos, source, input, driver, driverHash, object)
	data, err := os.ReadFile(object)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("ORIGINAL_POINTER_ALIAS_OBJECT: receipt=%+v source=%q listing=%q object=%x", receipt, source, output, data)
	result := x86ResultAliasObject{source: source, listing: string(output), code: make(map[string][]byte)}
	name, size := "", 0
	finish := func() {
		if name != "" && len(result.code[name]) != size {
			t.Fatalf("complete original %s size=%d bytes=%d", name, size, len(result.code[name]))
		}
	}
	for _, line := range strings.Split(result.listing, "\n") {
		fields := strings.Fields(line)
		if len(fields) > 1 && fields[1] == "SSEHUNWINDINFO" {
			finish()
			if goos != "windows" || arch != "amd64" || !strings.HasPrefix(fields[0], "go:sehuw.") {
				t.Fatal("unexpected original auxiliary data", line)
			}
			// Stock Windows unwind bytes are retained in the complete object
			// and raw listing, never mistaken for either function's code.
			name, size = "", 0
			continue
		}
		if len(fields) > 1 && fields[1] == "STEXT" {
			finish()
			name = strings.TrimPrefix(fields[0], "pointeralias.")
			if name == fields[0] {
				// The old SDK's lex.Make rewrites local · to the literal
				// "" placeholder. The current parser substitutes ctxt.Pkgpath.
				name = strings.TrimPrefix(fields[0], `"".`)
			}
			if name != "Caller" && name != "Value" {
				t.Fatalf("unexpected original TEXT: %s", line)
			}
			prefix := strings.TrimSuffix(fields[0], name)
			if result.symbolPrefix != "" && result.symbolPrefix != prefix {
				t.Fatal("original Caller and Value have different local namespaces")
			}
			result.symbolPrefix = prefix
			if _, duplicate := result.code[name]; duplicate {
				t.Fatal("duplicate original TEXT", name)
			}
			result.code[name] = nil
			size = -1
			for _, field := range fields[2:] {
				if strings.HasPrefix(field, "size=") {
					size, err = strconv.Atoi(strings.TrimPrefix(field, "size="))
					if err != nil || size <= 0 {
						t.Fatal("invalid original TEXT size", line)
					}
				}
			}
			continue
		}
		if name == "" || len(fields) < 2 || !strings.HasPrefix(fields[0], "0x") || len(fields[1]) != 2 {
			continue
		}
		offset, err := strconv.ParseInt(fields[0][2:], 16, 32)
		if err != nil || offset != int64(len(result.code[name])) {
			t.Fatal("noncontiguous original code bytes", line)
		}
		// obj.printSym emits exactly sixteen hex columns per line, except
		// the final partial line; its ASCII suffix can itself be two letters.
		count := size - len(result.code[name])
		if count > 16 {
			count = 16
		}
		if count <= 0 || len(fields) < count+1 {
			t.Fatal("original byte row exceeds or truncates declared TEXT", line)
		}
		for _, field := range fields[1 : count+1] {
			if len(field) != 2 {
				t.Fatal("invalid original byte column", line)
			}
			value, err := strconv.ParseUint(field, 16, 8)
			if err != nil {
				t.Fatal("invalid original byte", line)
			}
			result.code[name] = append(result.code[name], byte(value))
		}
	}
	finish()
	if len(result.code) != 2 {
		t.Fatal("original object must contain both actual ABI0 functions")
	}
	return result
}

func x86ResultAliasDecode(t *testing.T, code []byte, arch string) []x86asm.Inst {
	t.Helper()
	mode := 64
	if arch == "386" {
		mode = 32
	}
	var decoded []x86asm.Inst
	for offset := 0; offset < len(code); {
		instruction, err := x86asm.Decode(code[offset:], mode)
		if err != nil || instruction.Len <= 0 || instruction.Op == 0 {
			t.Fatalf("original instruction at %d: %+v %v", offset, instruction, err)
		}
		decoded = append(decoded, instruction)
		offset += instruction.Len
	}
	return decoded
}

// Derive the entry-relative cell from this SDK's real prologue and native
// memory operand. PUSH-BP and spill-BP producers are distinct observations.
func x86ResultAliasEntryCell(t *testing.T, object x86ResultAliasObject, arch, kind string) int64 {
	t.Helper()
	sp, bp, ax, word := x86asm.RSP, x86asm.RBP, x86asm.RAX, int64(8)
	if arch == "386" {
		sp, bp, ax, word = x86asm.ESP, x86asm.EBP, x86asm.EAX, 4
	}
	delta, pointerSeen, cellSeen := int64(0), false, false
	var prologueWrites []int64
	cell := int64(0)
	for _, ins := range x86ResultAliasDecode(t, object.code["Value"], arch) {
		if !pointerSeen {
			if memory, ok := ins.Args[1].(x86asm.Mem); ins.Op == x86asm.MOV && ins.Args[0] == ax && ok && memory.Base == sp {
				if delta+memory.Disp != word || memory.Index != 0 {
					t.Fatalf("original incoming ABI0 slot disagrees with declaration: delta=%d %+v", delta, ins)
				}
				pointerSeen = true
				continue
			}
			switch ins.Op {
			case x86asm.PUSH:
				if ins.Args[0] != bp {
					t.Fatal("unknown original prologue PUSH", ins)
				}
				delta -= word
				prologueWrites = append(prologueWrites, delta)
			case x86asm.SUB:
				immediate, ok := ins.Args[1].(x86asm.Imm)
				if ins.Args[0] != sp || !ok || immediate <= 0 || immediate > 4096 {
					t.Fatal("unknown original prologue SUB", ins)
				}
				delta -= int64(immediate)
			case x86asm.MOV, x86asm.LEA:
				memory, memoryDestination := ins.Args[0].(x86asm.Mem)
				if ins.Args[0] != bp && !(ins.Op == x86asm.MOV && memoryDestination && memory.Base == sp && ins.Args[1] == bp) {
					t.Fatal("unknown original BP producer", ins)
				}
				if memoryDestination {
					prologueWrites = append(prologueWrites, delta+memory.Disp)
				}
			default:
				t.Fatal("unknown original prologue", ins)
			}
			continue
		}
		memory, memorySource := ins.Args[1].(x86asm.Mem)
		if kind == "AUTO" && ins.Op == x86asm.MOV && ins.Args[0] == x86asm.ECX && memorySource && memory.Base == sp {
			cell, cellSeen = delta+memory.Disp, true
			break // Before this dead layout observer, no original SP effect exists.
		}
		memory, memoryDestination := ins.Args[0].(x86asm.Mem)
		if kind == "result" && ins.Op == x86asm.MOV && memoryDestination && memory.Base == sp && ins.Args[1] == x86asm.EBX {
			cell, cellSeen = delta+memory.Disp, true
			break // Frame-zero result source has no intervening SP effect.
		}
	}
	if !pointerSeen || !cellSeen {
		t.Fatalf("missing original %s ABI0 address observation", kind)
	}
	for _, offset := range prologueWrites {
		if cell < offset+word && offset < cell+4 {
			t.Fatal("native alias cell was initialized by an automatic BP save", cell, offset)
		}
	}
	return cell
}

func x86ResultNativeAliasFixture(t *testing.T, arch, triple, kind string) (GoPackage, *File, FuncSig, string) {
	t.Helper()
	word, move, lea, frame := int64(8), "MOVQ", "LEAQ", int64(0)
	if arch == "386" {
		word, move, lea = 4, "MOVL", "LEAL"
	}
	declarations := "package pointeralias\nfunc Caller() uint32\nfunc Value(x *uint32) uint32\n"
	pkg := mustGoPackage(t, "pointeralias", declarations)
	sig, err := DeriveGoFuncABI0Signature("Value", pkg.Types.Scope().Lookup("Value").(*types.Func), arch, types.SizesFor("gc", arch))
	if err != nil || sig.Frame.Results[0].Offset != word {
		t.Fatalf("actual typed ABI0 declaration: %+v %v", sig, err)
	}
	body := move + " x+0(FP),AX\n"
	if kind == "AUTO" {
		frame = 16
		// Dead source binds the actual named AUTO displacement in the very same
		// object. It does not initialize the local or execute on the read path.
		body += "JMP read\nlocalLayout:\nMOVL cell-8(SP),CX\nRET\nread:\n"
	}
	body += fmt.Sprintf("MOVL (AX),BX\nMOVL BX,ret0+%d(FP)\nRET\n", word)
	value := fmt.Sprintf("TEXT ·Value(SB),4,$%d-%d\n%s", frame, word+4, body)
	caller := func(offset int64) string {
		return fmt.Sprintf("TEXT ·Caller(SB),4,$16-4\n%s %d(SP),AX\n%s AX,0(SP)\nCALL ·Value(SB)\nMOVL %d(SP),AX\nMOVL AX,ret0+0(FP)\nRET\n", lea, offset, move, word)
	}
	probe := x86ResultAliasGoObject(t, arch, triple, caller(0)+value)
	cell := x86ResultAliasEntryCell(t, probe, arch, kind)
	if kind == "result" && cell != word+sig.Frame.Results[0].Offset {
		t.Fatal("original result displacement differs from actual typed slot", cell)
	}
	if kind == "AUTO" && (cell >= 0 || cell < -4096) {
		t.Fatal("original local is not inside a bounded callee-private frame", cell)
	}
	// CALL pushes one native return word. The relative address comes from
	// actual code, not from TEXT autosize or a presumed SDK prologue.
	aliasOffset := cell - word
	source := caller(aliasOffset) + value
	actual := x86ResultAliasGoObject(t, arch, triple, source)
	if !bytes.Equal(probe.code["Value"], actual.code["Value"]) || x86ResultAliasEntryCell(t, actual, arch, kind) != cell {
		t.Fatal("rebuilt complete object changed the original callee layout")
	}
	leaSeen, pointerStored, callSeen := false, false, false
	for _, instruction := range x86ResultAliasDecode(t, actual.code["Caller"], arch) {
		if memory, ok := instruction.Args[1].(x86asm.Mem); instruction.Op == x86asm.LEA && ok &&
			(memory.Base == x86asm.RSP || memory.Base == x86asm.ESP) && (instruction.Args[0] == x86asm.RAX || instruction.Args[0] == x86asm.EAX) {
			if leaSeen || memory.Disp != aliasOffset || memory.Index != 0 {
				t.Fatal("original caller pointer differs from observed callee cell", instruction)
			}
			leaSeen = true
		}
		if memory, ok := instruction.Args[0].(x86asm.Mem); instruction.Op == x86asm.MOV && ok &&
			(memory.Base == x86asm.RSP || memory.Base == x86asm.ESP) && (instruction.Args[1] == x86asm.RAX || instruction.Args[1] == x86asm.EAX) && !callSeen {
			if !leaSeen || pointerStored || memory.Disp != 0 || memory.Index != 0 {
				t.Fatal("original outgoing pointer slot is not exactly ABI0 slot zero", instruction)
			}
			pointerStored = true
		}
		if instruction.Op == x86asm.CALL {
			if callSeen || !leaSeen || !pointerStored {
				t.Fatal("original caller has an unbound CALL")
			}
			callSeen = true
		}
	}
	// Both actual objabi tables assign R_CALL=7; old listings print its
	// number while current listings print the name. No other role is allowed.
	relocation := regexp.MustCompile(`(?m)^\s*rel [0-9]+\+4 t=(?:7|R_CALL) ` + regexp.QuoteMeta(actual.symbolPrefix+"Value") + `\+0\s*$`)
	if !leaSeen || !callSeen || len(relocation.FindAllString(actual.listing, -1)) != 1 {
		t.Fatalf("complete caller lacks one original relocated Value CALL:\n%s", actual.listing)
	}
	t.Logf("ORIGINAL_POINTER_ALIAS_LAYOUT: kind=%s target=%s cell-entry=%d caller-SP=%d call-word=%d source=%x value-code=%x; compile-only, never executed", kind, triple, cell, aliasOffset, word, sha256.Sum256([]byte(source)), actual.code["Value"])
	file, err := Parse(ArchAMD64, value)
	if err != nil || len(file.Funcs) != 1 {
		t.Fatalf("unchanged original callee parse: %v", err)
	}
	return pkg, file, sig, value
}

func TestX86ABI0ResultNativeAliasOriginalGoAndLLVMObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc is required")
	}
	for _, target := range x86RawReturnTargets {
		for _, kind := range []string{"result", "AUTO"} {
			t.Run(target.triple+"/"+kind, func(t *testing.T) {
				pkg, file, sig, source := x86ResultNativeAliasFixture(t, target.arch, target.triple, kind)
				resolve := func(symbol string) string { return strings.TrimPrefix(symbol, "·") }
				options := Options{Goarch: target.arch, TargetTriple: target.triple, ResolveSym: resolve, Sigs: map[string]FuncSig{"Value": sig}}
				text, err := Translate(file, options)
				if err != nil {
					t.Fatal(err)
				}
				x86ResultInitializationObject(t, llc, target.triple, text, "text")
				ctx := llvm.NewContext()
				defer ctx.Dispose()
				module, err := TranslateModuleInContext(ctx, file, options)
				if !module.IsNil() {
					defer module.Dispose()
				}
				if err != nil {
					t.Fatal(err)
				}
				x86ResultInitializationObject(t, llc, target.triple, module.String(), "module")
				typed, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{GOARCH: target.arch, TargetTriple: target.triple, ResolveSym: resolve})
				if typed != nil && !typed.Module.IsNil() {
					defer typed.Module.Dispose()
				}
				if err != nil {
					t.Fatal(err)
				}
				x86ResultInitializationObject(t, llc, target.triple, typed.Module.String(), "typed-go")
				t.Log("THREE_API_CALLEE_OBJECTS: compile-only; original assembly Caller is not translated or executed, no initialized-pointee/runtime claim")
			})
		}
	}
}

func TestX86ABI0ResultNativeAliasesCannotProveInitialization(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, kind := range []string{"result", "AUTO"} {
			t.Run(target.triple+"/"+kind, func(t *testing.T) {
				_, file, sig, _ := x86ResultNativeAliasFixture(t, target.arch, target.triple, kind)
				if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, target.arch); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("uninitialized original native %s alias acquired public numerical/result-byte initialization: %v", kind, err)
				}
			})
		}
	}
}
