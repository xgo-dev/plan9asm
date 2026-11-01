package plan9asm

import (
	"errors"
	"fmt"
	"go/types"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

// This directory is independent of the production effect descriptor. Source
// register spellings that select the same physical byte have the same zeroing
// effect, but different bytes of one GP bank still require initialized input.
func x86ScalarXORZeroOracleRows(arch string) []string {
	registers := []string{"AX", "BX", "CX", "DX", "SI", "DI"}
	widths := "BWL"
	if arch == "amd64" {
		registers = append(registers, "R8", "R9", "R14", "R15")
		widths += "Q"
	}
	var rows []string
	for _, width := range widths {
		for _, register := range registers {
			rows = append(rows, fmt.Sprintf("XOR%c %s,%s", width, register, register))
		}
	}
	for _, pair := range [][2]string{
		{"AL", "AL"}, {"AH", "AH"}, {"BL", "BL"}, {"BH", "BH"},
		{"CL", "CL"}, {"CH", "CH"}, {"DL", "DL"}, {"DH", "DH"},
		{"AX", "AL"}, {"AL", "AX"}, {"BX", "BL"}, {"BL", "BX"},
		{"CX", "CL"}, {"CL", "CX"}, {"DX", "DL"}, {"DL", "DX"},
	} {
		rows = append(rows, "XORB "+pair[0]+","+pair[1])
	}
	return rows
}

func TestX86ScalarXORZeroCompleteGoRoles(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	// The carrier binds complete yxorb/yaddl ordered rows, opcode bytes,
	// prefix, zcase and offsets, not only the four XOR mnemonic names.
	if err := x86LockScalarEncoderCarrier(data); err != nil {
		t.Fatal(err)
	}
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range x86ScalarXORZeroOracleRows(arch) {
			t.Run(arch+"/"+row, func(t *testing.T) {
				source := "TEXT ·Value(SB),4,$0-0\n" + row + "\nRET\n"
				goAssemblerOracleOutput(t, arch, source, "", true)
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				ins := file.Funcs[0].Instrs[1]
				original := append([]Operand(nil), ins.Args...)
				effect, known, err := x86TypedInstructionByteEffect(ins.Op, ins, arch)
				if err != nil || !known || len(effect.operands) != 2 {
					t.Fatal("actual Go XOR register row lacks its typed effect", err)
				}
				width := map[byte]int64{'B': 1, 'W': 2, 'L': 4, 'Q': 8}[row[3]]
				for index, operand := range effect.operands {
					if operand.index != index || operand.width != width || operand.read || operand.write != (index == 1) {
						t.Fatalf("self-XOR retained undefined input or changed its written bytes: %#v", effect)
					}
				}
				if effect.flagsRead != 0 || effect.flagsDefined != x86ByteFlagsAll&^x86ByteFlagAF ||
					effect.flagsKilled != x86ByteFlagAF || effect.dynamicMemory || !reflect.DeepEqual(ins.Args, original) {
					t.Fatal("self-XOR inherited undefined AF, memory permission or altered source")
				}
			})
		}
	}
}

func TestX86ScalarXORZeroInitializesOnlyWrittenBytesAndCarry(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range x86ScalarXORZeroOracleRows(arch) {
			t.Run(arch+"/"+row, func(t *testing.T) {
				width := row[3]
				typ := map[byte]string{'B': "uint8", 'W': "uint16", 'L': "uint32", 'Q': "uint64"}[width]
				register := strings.Split(row[5:], ",")[1]
				body := row + fmt.Sprintf("\nMOV%c %s,ret0+0(FP)\nRET", width, register)
				_, file, sig, source := x86ResultInitializationFixture(t, arch, "func Value() "+typ, body)
				goAssemblerOracleOutput(t, arch, source, "", true)
				if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, arch); err != nil {
					t.Fatal("actual self-XOR numerical result remains undefined", err)
				}
				ctx, _ := newAMD64CtxWithFuncForTest(t, Func{}, FuncSig{Ret: Void}, nil)
				ctx.goarch = arch
				state := ctx.lockCarryTransfer(file.Funcs[0].Instrs[1], x86LockCarryState{})
				if !state.carry || state.stackUnbound || !ctx.lockCarryRead(file.Funcs[0].Instrs[1].Args[1],
					map[byte]int64{'B': 1, 'W': 2, 'L': 4, 'Q': 8}[width], state) {
					t.Fatal("self-XOR lost its defined CF or exact numeric destination")
				}
			})
		}
	}
}

func TestX86ScalarXORZeroDoesNotInventOtherBytesOrMemory(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for name, body := range map[string]string{
			"different register":       "XORL AX,BX\nMOVL BX,ret0+0(FP)\nRET",
			"different byte alias":     "XORB AH,AL\nMOVB AL,ret0+0(FP)\nRET",
			"only low byte cleared":    "XORB AX,AX\nMOVL AX,ret0+0(FP)\nRET",
			"only word cleared":        "XORW AX,AX\nMOVL AX,ret0+0(FP)\nRET",
			"memory still read":        "XORL ret0+0(FP),AX\nMOVL AX,ret0+0(FP)\nRET",
			"uninitialized AUTO input": "XORL $0,value-16(SP)\nMOVL value-16(SP),AX\nMOVL AX,ret0+0(FP)\nRET",
			"AND is not a zero idiom":  "ANDL AX,AX\nMOVL AX,ret0+0(FP)\nRET",
			"OR is not a zero idiom":   "ORL AX,AX\nMOVL AX,ret0+0(FP)\nRET",
		} {
			t.Run(arch+"/"+name, func(t *testing.T) {
				typ := "uint32"
				if name == "different byte alias" {
					typ = "uint8"
				}
				file, sig, _ := x86ResultAUTOFixture(t, arch, "func Value() "+typ, 32, body)
				if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, arch); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("self-XOR granted unrelated numerical or memory inputs", err)
				}
			})
		}
	}
}

func TestX86ScalarXORZeroRequiresCanonicalRegisterMetadata(t *testing.T) {
	file, err := Parse(ArchAMD64, "TEXT ·Value(SB),4,$0-0\nXORB AX,AL\nRET\n")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"extension", "shift", "immediate", "memory", "register-list"} {
		t.Run(name, func(t *testing.T) {
			ins := file.Funcs[0].Instrs[1]
			ins.Args = append([]Operand(nil), ins.Args...)
			for index := range ins.Args {
				switch name {
				case "extension":
					ins.Args[index].Ext = "UXTW"
				case "shift":
					ins.Args[index].ShiftAmount = 1
				case "immediate":
					ins.Args[index].Imm = 1
				case "memory":
					ins.Args[index].Mem.Base = AX
				case "register-list":
					ins.Args[index].RegList = []Reg{AX}
				}
			}
			// Consumer-input mutation only, not additional Go syntax.
			effect, known, err := x86TypedInstructionByteEffect(ins.Op, ins, "amd64")
			if err != nil || !known || len(effect.operands) != 2 ||
				!effect.operands[0].read || !effect.operands[1].read {
				t.Fatal("uncanonical constructed register acquired input-independent zeroing", err)
			}
		})
	}
}

func TestX86ScalarXORZeroThreeAPIFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc is required")
	}
	for _, target := range []struct{ arch, triple string }{
		{"amd64", "x86_64-apple-darwin"}, {"amd64", "x86_64-unknown-linux-gnu"},
		{"amd64", "x86_64-pc-windows-msvc"}, {"386", "i386-unknown-linux-gnu"},
		{"386", "i686-pc-windows-msvc"},
	} {
		t.Run(target.triple, func(t *testing.T) {
			var declarations, source strings.Builder
			declarations.WriteString("package xorzero\n")
			for index, row := range x86ScalarXORZeroOracleRows(target.arch) {
				name := fmt.Sprintf("Zero%03d", index)
				width := row[3]
				typ := map[byte]string{'B': "uint8", 'W': "uint16", 'L': "uint32", 'Q': "uint64"}[width]
				bytes := map[byte]int{'B': 1, 'W': 2, 'L': 4, 'Q': 8}[width]
				register := strings.Split(row[5:], ",")[1]
				fmt.Fprintf(&declarations, "func %s() %s\n", name, typ)
				fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n%s\nMOV%c %s,ret0+0(FP)\nRET\n",
					name, bytes, row, width, register)
			}
			pkg := mustGoPackage(t, "example.invalid/xorzero", declarations.String())
			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			goAssemblerOracleOutput(t, target.arch, source.String(), "", true)
			sigs := make(map[string]FuncSig)
			for _, fn := range file.Funcs {
				name := strings.TrimPrefix(fn.Sym, "·")
				sig, err := DeriveGoFuncABI0Signature(name, pkg.Types.Scope().Lookup(name).(*types.Func),
					target.arch, types.SizesFor("gc", target.arch))
				if err != nil {
					t.Fatal(err)
				}
				if err := CheckX86ABI0ResultInitialization(fn, sig, target.arch); err != nil {
					t.Fatal(err)
				}
				sigs[name] = sig
			}
			options := Options{Goarch: target.arch, TargetTriple: target.triple, Sigs: sigs,
				ResolveSym: func(symbol string) string { return strings.TrimPrefix(symbol, "·") }}
			ir, err := Translate(file, options)
			if err != nil {
				t.Fatal(err)
			}
			x86ResultInitializationObject(t, llc, target.triple, ir, "text")
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
			translated, err := translateGoModuleInContext(ctx, pkg, []byte(source.String()), GoModuleOptions{
				GOARCH: target.arch, TargetTriple: target.triple, ResolveSym: options.ResolveSym,
			})
			if translated != nil && !translated.Module.IsNil() {
				defer translated.Module.Dispose()
			}
			if err != nil {
				t.Fatal(err)
			}
			x86ResultInitializationObject(t, llc, target.triple, translated.Module.String(), "typed-go")
		})
	}
}
