package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func TestX86GoCallerVectorZeroOriginalSource(t *testing.T) {
	for _, body := range []string{
		"VMOVUPS (DI),Z0\nVZEROUPPER\nVMOVSS X0,(DX)",
		"VZEROALL\nVMOVSS X0,(DX)",
		"VMOVUPS (DI),Z0\nWORD $0xf8c5\nBYTE $0x77\nVMOVSS X0,(DX)",
		"WORD $0xfcc5\nBYTE $0x77\nVMOVSS X0,(DX)",
	} {
		t.Run(strings.ReplaceAll(body, "\n", "_"), func(t *testing.T) {
			assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
			goAssemblerOracleOutput(t, "amd64", assembly, "", true)
			pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
			if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestX86GoCallerVectorZeroInitializedBytesAndUnaffectedState(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, opcode := range []Op{"VZEROUPPER", "VZEROALL"} {
			for _, initial := range []uint64{0, 1, 0xffff, 0xaaaaaaaaaaaaaaaa, ^uint64(0)} {
				state := x86SourceStackState{
					vectors: map[Reg]uint64{}, masks: map[Reg]bool{"K1": true, "K2": false},
					known: map[Reg]uint8{AX: 0xff}, numericFlags: true, gOriginal: true,
				}
				for register := 0; register < 32; register++ {
					state.vectors[Reg(fmt.Sprintf("Z%d", register))] = initial
				}
				known, masks := x86CloneCallerKnown(state.known), map[Reg]bool{"K1": true, "K2": false}
				form, recognized, err := x86VectorZeroProperties(Instr{Op: opcode}, arch)
				if !recognized || err != nil || !x86CallerVectorZeroStep(form, &state) {
					t.Fatalf("%s/%s grammar/effect: %t/%v", arch, opcode, recognized, err)
				}
				limit, added := 16, ^uint64(0xffff)
				if arch == "386" {
					limit = 8
				}
				if opcode == "VZEROALL" {
					added = ^uint64(0)
				}
				for register := 0; register < 32; register++ {
					want := initial
					if register < limit {
						want |= added
					}
					if state.vectors[Reg(fmt.Sprintf("Z%d", register))] != want {
						t.Fatalf("%s/%s invented/lost register%d byte knowledge", arch, opcode, register)
					}
				}
				if !reflect.DeepEqual(state.known, known) || !reflect.DeepEqual(state.masks, masks) || !state.numericFlags || !state.gOriginal {
					t.Fatal("vector zero changed GP/mask/flags/g source state")
				}
			}
		}
	}
}

func TestX86GoCallerVectorZeroDoesNotInventPreservedLowOrHighRegisters(t *testing.T) {
	for _, body := range []string{
		"VZEROUPPER\nVMOVSS X0,(DX)",
		"VZEROALL\nVMOVSS X16,(DX)",
		"VZEROUPPER\nVMOVSS X31,(DX)",
		"VZEROALL\nKMOVQ K1,AX\nMOVL AX,(DX)",
	} {
		t.Run(strings.ReplaceAll(body, "\n", "_"), func(t *testing.T) {
			assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
			goAssemblerOracleOutput(t, "amd64", assembly, "", true)
			pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
			if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("unknown low/high/mask source acquired return proof: %v", err)
			}
		})
	}
}

func TestX86GoCallerVectorZeroCompleteFamilyThreeAPIs(t *testing.T) {
	const body = "VMOVUPS (DI),Z0\nVMOVUPS (SI),Z16\nVZEROUPPER\nVMOVSS X0,(DX)\nVZEROALL\nVMOVSS X15,(DX)\nVMOVSS X16,(DX)\nWORD $0xfcc5\nBYTE $0x77\nVMOVSS X1,(DX)\n"
	assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
	goAssemblerOracleOutput(t, "amd64", assembly, "", true)
	pkg, file := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
	resolve := func(symbol string) string { return strings.Replace(symbol, "·", "caller.", 1) }
	sigs, err := goSigsForAsmFile(pkg, file, resolve, "amd64", nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, triple := range []string{"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			options := Options{Goarch: "amd64", TargetTriple: triple, Sigs: sigs, ResolveSym: resolve}
			ir, err := Translate(file, options)
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, triple, "zero-caller.ll", "zero-caller.o", ir)
			ctx := llvm.NewContext()
			defer ctx.Dispose()
			module, err := TranslateModuleInContext(ctx, file, options)
			if err != nil {
				t.Fatal(err)
			}
			defer module.Dispose()
			compileLLVMToObject(t, llc, triple, "zero-module.ll", "zero-module.o", module.String())
			if err := x86CallerCoreTranslate(t, pkg, assembly, triple); err != nil {
				t.Fatal(err)
			}
		})
	}
}
