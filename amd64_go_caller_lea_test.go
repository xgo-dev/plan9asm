package plan9asm

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func x86LEAActualTargetGoObject(t *testing.T, arch, triple, source string) *x86LEAGoObjectReceipt {
	t.Helper()
	goos := "linux"
	if strings.Contains(triple, "apple") {
		goos = "darwin"
	} else if strings.Contains(triple, "windows") {
		goos = "windows"
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "lea.s")
	if err := os.WriteFile(path, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	driver, driverHash := x86LEAActualSDKDriver(t)
	include := filepath.Join(filepath.Dir(filepath.Dir(driver)), "pkg", "include")
	command := exec.CommandContext(ctx, driver, "tool", "asm", "-I", include,
		"-p", "sourceframe", "-o", filepath.Join(dir, "lea.o"), path)
	command.Env = append(os.Environ(), "GOOS="+goos, "GOARCH="+arch, "CGO_ENABLED=0", "GOTOOLCHAIN=local", "GOENV=off", "GOWORK=off")
	if output, err := runtimeOracleCombinedOutput(ctx, command); err != nil {
		t.Fatalf("actual Go %s/%s LEA object: %v\n%s", goos, arch, err, output)
	}
	return x86LEAReadObjectReceipt(t, arch, goos, source, path, driver, driverHash, filepath.Join(dir, "lea.o"))
}

// These raw LEAL instructions are the original forms in Weaviate's
// dot_avx256_amd64.s. The address base is a loaded numerical length, not the
// caller's pointer to that length. LEA does not dereference either register.
func TestX86GoCallerLEANumericalLengthOriginalRawForms(t *testing.T) {
	for _, form := range []struct {
		name, instructions string
	}{
		{"minus-one", "LONG $0xff418d45\nMOVL R8,AX"},
		{"minus-thirty-two", "LONG $0xe0498d41\nMOVL CX,AX"},
	} {
		t.Run(form.name, func(t *testing.T) {
			assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL $7,AX",
				"MOVQ (CX),R9\n"+form.instructions, 1)
			requireLEANativeGoObject(t, "amd64", assembly, true)
			pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
			if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestX86GoCallerLEACompleteNumericalWidthsAndAddressForms(t *testing.T) {
	for _, width := range []struct{ suffix, copy string }{
		{"W", "MOVW"}, {"L", "MOVL"}, {"Q", "MOVQ"},
	} {
		for _, address := range []string{
			"-1(R9)", "19(R9)", "-7(R9)(BX*1)", "-7(R9)(BX*2)",
			"-7(R9)(BX*4)", "-7(R9)(BX*8)", "-7(BX*4)",
		} {
			for _, triple := range []string{
				"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc",
			} {
				t.Run(width.suffix+"/"+address+"/"+triple, func(t *testing.T) {
					body := "MOVQ (CX),R9\nMOVQ $19,BX\nLEA" + width.suffix + " " + address + ",R8\n" + width.copy + " R8,AX\nMOVL AX,(DX)"
					assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
					requireLEANativeGoObject(t, "amd64", assembly, true)
					pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
					if err := x86CallerCoreTranslate(t, pkg, assembly, triple); err != nil {
						t.Fatal(err)
					}
				})
			}
		}
	}
}

func TestX86GoCallerLEADefinedBytesAndPointerTaint(t *testing.T) {
	for _, test := range []struct {
		name, body string
		accepted   bool
	}{
		{"word-low-input", "MOVW $9,BX\nLEAW -7(BX),R8\nMOVW R8,AX", true},
		{"word-unknown-upper", "MOVW $9,BX\nLEAW -7(BX),R8\nMOVL R8,AX", false},
		{"word-preserves-upper", "MOVQ $19,R8\nMOVW $9,BX\nLEAW -7(BX),R8\nMOVQ R8,AX", true},
		{"word-pointer-upper", "LEAW -7(R9),DX", false},
		{"word-pointer-source", "LEAW -7(DI),R8\nMOVW R8,AX", false},
		{"long-word-only-input", "MOVW $9,BX\nLEAL -7(BX),R8\nMOVL R8,AX", false},
		{"long-zeroes-upper", "MOVL $9,BX\nLEAL -7(BX),R8\nMOVQ R8,AX", true},
		{"long-pointer-alias", "LEAL -7(DI),DI\nMOVL DI,AX", false},
		{"long-pointer-copy", "MOVQ DI,BX\nLEAL -7(BX),R8\nMOVL R8,AX", false},
		{"long-clobbers-pointer", "MOVL $9,BX\nLEAL -7(BX),CX\nMOVQ CX,AX", true},
		{"long-encoding-truncates-disp", "MOVL $9,BX\nLEAL 0x100000002(BX),R8\nMOVQ R8,AX", true},
		{"quad-word-only-input", "MOVW $9,BX\nLEAQ -7(BX),R8\nMOVL R8,AX", false},
		{"quad-zeroextended-input", "MOVL $9,BX\nLEAQ -7(BX),R8\nMOVL R8,AX", true},
		{"quad-numeric-alias", "LEAQ -7(R9),R9\nMOVL R9,AX", true},
		{"unknown-base", "LEAL -7(BX),R8\nMOVL R8,AX", false},
		{"unknown-index", "LEAL -7(R9)(BX*4),R8\nMOVL R8,AX", false},
		{"pointer-index", "LEAL -7(R9)(DI*4),R8\nMOVL R8,AX", false},
		{"pointer-affine-index", "MOVL $0,BX\nLEAQ (DI)(BX*4),R8\nMOVL (R8),AX", false},
		{"pointer-affine-origin", "LEAQ 1(DX),BX\nMOVB $7,AX\nMOVB AX,(BX)", true},
		{"pointer-affine-out-of-envelope", "LEAQ 4(DX),BX\nMOVL AX,(BX)", false},
		{"pointer-affine-input-write", "LEAQ 1(DI),BX\nMOVB AX,(BX)", false},
		{"pointer-as-data", "LEAQ 1(DI),BX\nMOVL BX,AX", false},
		{"word-SP-escape", "LEAW (SP),R8\nMOVW R8,AX", false},
		{"long-SP-escape", "LEAL (SP),R8\nMOVL R8,AX", false},
		{"quad-SP-escape", "LEAQ (SP),R8\nMOVL R8,AX", false},
		{"word-BP-escape", "LEAW (BP),R8\nMOVW R8,AX", false},
		{"long-stack-index", "LEAL (R9)(SP*1),R8\nMOVL R8,AX", false},
		{"word-SP-write", "LEAW 0(SP),SP", false},
		{"long-SP-write", "LEAL 0(SP),SP", false},
		{"quad-caller-to-SP", "LEAQ 0(DI),SP", false},
		{"quad-caller-to-BP", "LEAQ 0(DI),BP", false},
		{"typed-FP-address", "LEAQ a+0(FP),R8\nMOVL R8,AX", false},
		{"unknown-symbol", "LEAQ outsider(SB),R8\nMOVL R8,AX", false},
		{"raw-RIP-code-address", "LONG $0x00058d48\nWORD $0\nBYTE $0\nMOVL AX,(DX)", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := "MOVQ (CX),R9\n" + test.body + "\nMOVL AX,(DX)"
			assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
			// SP is not an encodable SIB index. All other negative cases are
			// actual Go inputs rejected for missing semantic provenance.
			requireLEANativeGoObject(t, "amd64", assembly, test.name != "long-stack-index")
			pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
			err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu")
			if test.name == "raw-RIP-code-address" {
				if err == nil || !strings.Contains(err.Error(), "raw x86 local address target byte 7") {
					t.Fatalf("out-of-group raw RIP address lost its existing decoder rejection: %v", err)
				}
				return
			}
			if test.accepted && err != nil {
				t.Fatal(err)
			}
			if !test.accepted && !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("unproved address acquired numeric/pointer permission: %v", err)
			}
		})
	}
}

func TestX86RawReturnSourceStackLEANativeOrCallerContractAcrossFiveTargets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range x86RawReturnTargets {
		for _, suffix := range []string{"W", "L", "Q"} {
			if x86LEAWidth(Op("LEA"+suffix), target.arch) == 0 {
				continue // Go has no 64-bit LEA encoding in 386 mode.
			}
			t.Run(target.triple+"/"+suffix, func(t *testing.T) {
				push, pop := "PUSHQ", "POPQ"
				if target.arch == "386" {
					push, pop = "PUSHL", "POPL"
				}
				body := "@MOV x+0(FP),AX\n" + push + " BP\n@MOV SP,BP\n@MOV $19,BX\nLEA" + suffix +
					" -7(AX)(BX*4),AX\n@MOV BP,SP\n" + pop + " BP\n@MOV AX,ret+@WORD(FP)\nBYTE $0xc3"
				source, sig, pkg := x86SourceStackNumericalFixture(target.arch, body)
				x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				options := x86SourceStackOptions(target.arch, target.triple, sig)
				ir, err := Translate(file, options)
				if suffix != strings.TrimPrefix(push, "PUSH") {
					if !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatalf("ordinary types/stack proof invented numerical GP permissions: %v", err)
					}
					ctx := llvm.NewContext()
					defer ctx.Dispose()
					module, err := TranslateModuleInContext(ctx, file, options)
					if err == nil {
						module.Dispose()
					}
					if !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatalf("module API invented numerical GP permissions: %v", err)
					}
					translation, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{
						GOARCH: target.arch, TargetTriple: target.triple,
					})
					if translation != nil {
						translation.Module.Dispose()
					}
					if !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatalf("actual declaration API invented numerical GP permissions: %v", err)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				compileLLVMToObject(t, llc, target.triple, "source-lea.ll", "source-lea.o", ir)
				ctx := llvm.NewContext()
				defer ctx.Dispose()
				module, err := TranslateModuleInContext(ctx, file, options)
				if err != nil {
					t.Fatal(err)
				}
				defer module.Dispose()
				compileLLVMToObject(t, llc, target.triple, "source-lea-module.ll", "source-lea-module.o", module.String())
				translation, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{
					GOARCH: target.arch, TargetTriple: target.triple,
				})
				if err != nil {
					t.Fatal(err)
				}
				defer translation.Module.Dispose()
				compileLLVMToObject(t, llc, target.triple, "source-lea-go-module.ll", "source-lea-go-module.o", translation.Module.String())
			})
		}
	}
}

func TestX86CallerLEAStatePreservesExactDefinitionAndPointerOrigin(t *testing.T) {
	for _, test := range []struct {
		instruction string
		known       uint8
		pointer     bool
		accepted    bool
	}{
		{"LEAW -7(AX),BX", 0xa3, false, true},
		{"LEAL -7(AX),BX", 0xff, false, true},
		{"LEAQ -7(AX),BX", 0xff, false, true},
		{"LEAL -7(AX),AX", 0xff, false, true},
		{"LEAW -7(AX),DX", 0, true, false},
		{"LEAL -7(DX),DX", 0, true, false},
		{"LEAQ -7(DX),BX", 0, true, true},
	} {
		t.Run(test.instruction, func(t *testing.T) {
			file, err := Parse(ArchAMD64, "TEXT kernel(SB),4,$0-0\n"+test.instruction+"\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			state := x86SourceStackState{
				callers: map[Reg]x86CallerPointerValue{DX: {argument: 2, offset: 8}},
				known:   map[Reg]uint8{AX: 0xff, BX: 0xa0}, numericFlags: true,
			}
			instruction := &file.Funcs[0].Instrs[1]
			if got := x86CallerLEAStep(instruction, &state); got != test.accepted {
				t.Fatalf("LEA acceptance = %v, want %v", got, test.accepted)
			}
			if !test.accepted {
				if state.callers[DX] != (x86CallerPointerValue{argument: 2, offset: 8}) || state.known[BX] != 0xa0 {
					t.Fatal("rejected LEA mutated provenance")
				}
				return
			}
			destination := instruction.Args[1].Reg
			pointer, present := state.callers[destination]
			if state.known[destination] != test.known || present != test.pointer || !state.numericFlags {
				t.Fatalf("wrong byte/flags definition: %+v", state)
			}
			if present && pointer != (x86CallerPointerValue{argument: 2, offset: 1}) {
				t.Fatalf("affine LEA changed caller origin: %+v", pointer)
			}
		})
	}
}

func TestX86LEADisplacementEncodingUsesActualGoRules(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, suffix := range []string{"W", "L", "Q"} {
			for _, displacement := range []int64{-1 << 31, 1<<31 - 1, 1 << 31, 1<<32 - 1, 1 << 32, -1<<31 - 1} {
				t.Run(fmt.Sprintf("%s/%s/%d", target.triple, suffix, displacement), func(t *testing.T) {
					width := x86LEAWidth(Op("LEA"+suffix), target.arch)
					accepted := width != 0 && (displacement == int64(int32(displacement)) ||
						target.arch == "amd64" && suffix == "L" || target.arch == "386" && displacement == int64(uint32(displacement)))
					source := fmt.Sprintf("TEXT Value(SB),4,$0-0\nMOVL $9,AX\nLEA%s %d(AX),BX\nRET\n", suffix, displacement)
					requireLEANativeGoObject(t, target.arch, source, accepted)
					file, err := Parse(ArchAMD64, source)
					if err != nil {
						t.Fatal(err)
					}
					ir, err := Translate(file, Options{Goarch: target.arch, TargetTriple: target.triple,
						Sigs: map[string]FuncSig{"Value": {Name: "Value", Ret: Void}}})
					if !accepted {
						if err == nil {
							t.Fatal("accepted displacement rejected by actual Go")
						}
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					llc := findLLVM22Tool("llc")
					if llc == "" {
						t.Fatal("LLVM 22 llc not found")
					}
					compileLLVMToObject(t, llc, target.triple, "lea-displacement.ll", "lea-displacement.o", ir)
				})
			}
		}
	}
}

func TestX86LEASharedGrammarRejectsGoInvalidSIBFields(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, address := range []string{"8(AX)(BX*0)", "8(AX)(BX*3)", "8(AX)(BX*16)", "8(AX)(SP*1)", "outsider", "$outsider(SB)"} {
			t.Run(arch+"/"+address, func(t *testing.T) {
				source := "TEXT Value(SB),4,$0-0\nLEAL " + address + ",CX\nRET\n"
				requireLEANativeGoObject(t, arch, source, false)
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					return
				}
				triple := "x86_64-unknown-linux-gnu"
				if arch == "386" {
					triple = "i386-unknown-linux-gnu"
				}
				if _, err := Translate(file, Options{Goarch: arch, TargetTriple: triple,
					Sigs: map[string]FuncSig{"Value": {Name: "Value", Ret: Void}}}); err == nil {
					t.Fatal("shared LEA grammar accepted Go-invalid SIB index/scale")
				}
			})
		}
	}
}

func TestX86RawReturnLEANewWidthsCannotInventNumericGPInitialization(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		suffixes := []string{"W", "L"}
		push, pop, native := "PUSHQ", "POPQ", "Q"
		if target.arch == "386" {
			push, pop, native = "PUSHL", "POPL", "L"
		}
		for _, suffix := range suffixes {
			if suffix == native {
				continue // This test guards this batch's newly admitted widths.
			}
			t.Run(target.triple+"/"+suffix, func(t *testing.T) {
				body := push + " BP\n@MOV SP,BP\nLEA" + suffix + " (BX),AX\n@MOV BP,SP\n" +
					pop + " BP\n@MOV AX,ret+@WORD(FP)\nBYTE $0xc3"
				source, sig, _ := x86SourceStackNumericalFixture(target.arch, body)
				x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := Translate(file, x86SourceStackOptions(target.arch, target.triple, sig)); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("a frame/type declaration invented unknown BX/upper-AX inputs: %v", err)
				}
			})
		}
	}
}
