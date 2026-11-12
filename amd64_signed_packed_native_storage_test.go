package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

// These are independent original Go corpus examples, not strings generated
// from the translator's form table. The native opcode needs original storage;
// a software SP/BP allocation must not impersonate its fault/alignment contract.
func TestX86SignedPackedFloatOfficialStackStorageContext(t *testing.T) {
	for _, row := range []string{
		"VCVTDQ2PD -17(BP), K7, Y6",
		"VCVTDQ2PS -17(BP)(SI*4), K4, X31",
		"VCVTDQ2PS 17(SP)(BP*2), K1, Y19",
		"VCVTDQ2PS 17(SP), K4, X31",
	} {
		t.Run(row, func(t *testing.T) {
			source := "TEXT f(SB),4,$0-0\n" + row + "\nRET\n"
			goAssemblerOracleOutput(t, "amd64", source, "", true)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			options := Options{
				Goarch:       "amd64",
				TargetTriple: "x86_64-unknown-linux-gnu",
				Sigs:         map[string]FuncSig{"f": {Ret: Void}},
			}
			assertX86PackedFloatStorageContext(t, file, options)
		})
	}
}

func TestX86SignedPackedFloatAllWidthsZeroMaskStorageContext(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		t.Run(arch, func(t *testing.T) {
			var original strings.Builder
			index := 0
			for _, op := range []string{"CVTPL2PS", "CVTPL2PD", "VCVTDQ2PS", "VCVTDQ2PD"} {
				banks, modes := []string{"X"}, []string{""}
				if strings.HasPrefix(op, "V") {
					banks = []string{"X", "Y", "Z"}
					modes = []string{"", "K1,", ".Z K1,", ".BCST.Z K1,"}
				}
				for _, bank := range banks {
					for _, address := range []string{"16(SP)", "16(BP)", "16(AX)(BP*2)"} {
						for _, mode := range modes {
							mnemonic, mask := op, mode
							if split := strings.IndexByte(mode, ' '); split >= 0 {
								mnemonic += mode[:split]
								mask = mode[split+1:]
							}
							for _, maskValue := range []int{0, 1} {
								row := fmt.Sprintf("%s %s,%s%s1", mnemonic, address, mask, bank)
								name := fmt.Sprintf("storage%d", index)
								index++
								source, sig, _ := x86OrdinaryBPNativeFixture(t, arch, name, row, address, 0)
								// Keep the typed pointer in AX. Initialize the entire merging
								// destination bank, not just its low XMM bytes, and use CX
								// independently for the explicit mask input.
								setup := ""
								if bank == "Y" {
									setup = "VPXOR Y1,Y1,Y1\n"
								} else if bank == "Z" {
									setup = "VPXORD Z1,Z1,Z1\n"
								}
								setup += fmt.Sprintf("MOVL $%d,CX\nKMOVW CX,K1\n", maskValue)
								source = strings.Replace(source, row+"\nRET", setup+row+"\nRET", 1)
								original.WriteString(source)
								t.Run(fmt.Sprintf("%s/mask=%d", row, maskValue), func(t *testing.T) {
									file, err := Parse(ArchAMD64, source)
									if err != nil {
										t.Fatal(err)
									}
									triple := "x86_64-unknown-linux-gnu"
									if arch == "386" {
										triple = "i386-unknown-linux-gnu"
									}
									options := x86SourceStackOptions(arch, triple, sig)
									for _, api := range []string{"Translate", "TranslateModule", "TranslateModuleInContext"} {
										t.Run(api, func(t *testing.T) {
											ir, err := x86PackedFloatStorageAPI(api, file, options)
											x86RequireOrdinaryBPNativeOutcome(t, arch, address, ir, err)
										})
									}
								})
							}
						}
					}
				}
			}
			if index != 156 {
				t.Fatalf("storage boundary denominator changed: %d", index)
			}
			goAssemblerOracleOutput(t, arch, original.String(), "", true)
			t.Logf("%d complete original Go forms; all three APIs distinguish ordinary386 BP from physical SP/AMD64 BP", index)
		})
	}
}

func assertX86PackedFloatStorageContext(t *testing.T, file *File, options Options) {
	t.Helper()
	for _, api := range []string{"Translate", "TranslateModule", "TranslateModuleInContext"} {
		_, err := x86PackedFloatStorageAPI(api, file, options)
		if !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatalf("%s authorized unbound native stack storage: %v", api, err)
		}
	}
}

func x86PackedFloatStorageAPI(api string, file *File, options Options) (string, error) {
	if api == "Translate" {
		return Translate(file, options)
	}
	var module llvm.Module
	var err error
	if api == "TranslateModule" {
		module, err = TranslateModule(file, options)
	} else {
		context := llvm.NewContext()
		defer context.Dispose()
		module, err = TranslateModuleInContext(context, file, options)
	}
	if module.IsNil() {
		return "", err
	}
	defer module.Dispose()
	return module.String(), err
}
