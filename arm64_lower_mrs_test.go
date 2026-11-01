package plan9asm

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

var arm64FeatureRegisters = []struct {
	name string
	word uint32
}{
	{"MIDR_EL1", 0xd5380000},
	{"ID_AA64PFR0_EL1", 0xd5380400},
	{"ID_AA64ISAR0_EL1", 0xd5380600},
	{"ID_AA64ISAR1_EL1", 0xd5380620},
	{"ID_AA64ZFR0_EL1", 0xd5380480},
}

func arm64MRSFeatureFixture(t *testing.T, raw, cfg bool) (*File, map[string]FuncSig) {
	t.Helper()
	var source strings.Builder
	sigs := make(map[string]FuncSig)
	for index, register := range arm64FeatureRegisters {
		name := fmt.Sprintf("read_feature_%d", index)
		fmt.Fprintf(&source, "TEXT %s(SB),$0-8\n", name)
		if cfg {
			source.WriteString("B read\nread:\n")
		}
		if raw {
			fmt.Fprintf(&source, "WORD $%#08x\n", register.word)
		} else {
			fmt.Fprintf(&source, "MRS %s, R0\n", register.name)
		}
		source.WriteString("MOVD R0, ret+0(FP)\nRET\n")
		sigs[name] = FuncSig{Name: name, Ret: I64, Frame: FrameLayout{
			Results: []FrameSlot{{Offset: 0, Type: I64, Index: 0, Field: -1}},
		}}
	}
	requireARM64GoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	return file, sigs
}

func translateARM64MRSModule(t *testing.T, file *File, options Options) string {
	t.Helper()
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	mod, err := TranslateModuleInContext(ctx, file, options)
	if err != nil {
		t.Fatal(err)
	}
	defer mod.Dispose()
	return mod.String()
}

func TestARM64MRSFeatureReadsAreNotCompileOnlyConstants(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, form := range []struct {
		name     string
		raw, cfg bool
	}{
		{"text_linear", false, false},
		{"text_cfg", false, true},
		{"raw_linear", true, false},
		{"raw_cfg", true, true},
	} {
		file, sigs := arm64MRSFeatureFixture(t, form.raw, form.cfg)
		for _, triple := range []string{
			"aarch64-unknown-linux-gnu", "aarch64-apple-darwin", "aarch64-pc-windows-msvc",
		} {
			for _, module := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/module=%v", form.name, triple, module), func(t *testing.T) {
					options := Options{Goarch: "arm64", TargetTriple: triple, Sigs: sigs}
					var ir string
					if module {
						ir = translateARM64MRSModule(t, file, options)
					} else {
						var err error
						ir, err = Translate(file, options)
						if err != nil {
							t.Fatal(err)
						}
					}
					for _, register := range arm64FeatureRegisters {
						physical := arm64EncodedSystemRegisterName(uint16((register.word >> 5) & 0x7fff))
						want := `asm sideeffect "mrs $0, ` + physical + `"`
						if !strings.Contains(ir, want) {
							t.Errorf("missing real, observable %s read; constants are not assembly semantics", register.name)
						}
					}
					if !t.Failed() {
						compileLLVMToObject(t, llc, triple, "mrs.ll", "mrs.o", ir)
					}
				})
			}
		}
	}
}

func TestARM64MRSCompleteGoSystemRegisterTable(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(testGOROOT(t), "src", "cmd", "internal", "obj", "arm64", "sysRegEnc.go"))
	if err != nil {
		t.Fatal(err)
	}
	rows := regexp.MustCompile(`\{"([A-Za-z0-9_]+)", REG_\w+, (0x[0-9a-f]+), ([^}]+)\}`).FindAllStringSubmatch(string(data), -1)
	if len(rows) == 0 {
		t.Fatal("Go system register table was not enumerated")
	}
	var source strings.Builder
	source.WriteString("TEXT system_registers(SB),$0-0\n")
	var native []string
	var expected []uint32
	reads, writes := 0, 0
	for _, row := range rows {
		encoding, err := strconv.ParseUint(row[2], 0, 32)
		if err != nil {
			t.Fatal(err)
		}
		spec, ok := arm64GoSystemRegisters[row[1]]
		if !ok || spec.encoding != uint16((encoding>>5)&0x7fff) ||
			spec.readable != strings.Contains(row[3], "SR_READ") ||
			spec.writable != strings.Contains(row[3], "SR_WRITE") {
			t.Fatalf("typed register metadata disagrees with Go: %s", row[0])
		}
		if spec.readable {
			if row[1] == "NZCV" {
				// Other system-register callouts above do not supply source
				// NZCV. Seed this exact modeled read without granting entry flags.
				source.WriteString("CMP R0,R0\n")
			}
			fmt.Fprintf(&source, "MRS %s, R0\n", row[1])
			native = append(native, "mrs x0, "+arm64CanonicalSysReg(row[1]))
			expected = append(expected, 0xd5300000|uint32(encoding))
			reads++
		}
		if spec.writable {
			fmt.Fprintf(&source, "MSR R0, %s\n", row[1])
			native = append(native, "msr "+arm64CanonicalSysReg(row[1])+", x0")
			expected = append(expected, 0xd5100000|uint32(encoding))
			writes++
		}
	}
	source.WriteString("RET\n")
	requireARM64GoAssemblerResult(t, source.String(), true)
	actual := assembleARM64LLVMWords(t, native, "")
	for index, word := range expected {
		if actual[index] != word {
			t.Errorf("%s: LLVM word %#08x, want Go word %#08x", native[index], actual[index], word)
		}
	}
	t.Logf("Go system-register table: names=%d readable=%d writable=%d", len(rows), reads, writes)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{
		"aarch64-unknown-linux-gnu", "aarch64-apple-darwin", "aarch64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple,
				Sigs: map[string]FuncSig{"system_registers": {Name: "system_registers", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			// NZCV is the modeled flag state; RNDR/RNDRRS use observable
			// intrinsics that also define NZCV. Every other read is native MRS.
			if count := strings.Count(ir, `asm sideeffect "mrs $0, `); count != reads-3 {
				t.Fatalf("real reads=%d, Go-readable registers=%d", count, reads)
			}
			for _, intrinsic := range []string{"rndr", "rndrrs"} {
				want := "call { i64, i1 } @llvm.aarch64." + intrinsic + "()"
				if count := strings.Count(ir, want); count != 1 {
					t.Fatalf("%s native RNG reads=%d, want 1", intrinsic, count)
				}
			}
			if count := strings.Count(ir, `asm sideeffect "msr `); count != writes-1 {
				t.Fatalf("real writes=%d, Go-writable registers=%d", count, writes)
			}
			compileLLVMToObject(t, llc, triple, "mrs-table.ll", "mrs-table.o", ir)
		})
	}
}

func TestARM64MRSMSRRejectGoRegisterAccessViolations(t *testing.T) {
	for _, instruction := range []string{
		"MRS OSLAR_EL1, R0", "MSR R0, MIDR_EL1", "MSR $0, MIDR_EL1",
	} {
		for _, cfg := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/cfg=%v", instruction, cfg), func(t *testing.T) {
				source := "TEXT bad_access(SB),$0-0\n"
				if cfg {
					source += "B access\naccess:\n"
				}
				source += instruction + "\nRET\n"
				requireARM64GoAssemblerResult(t, source, false)
				file, err := Parse(ArchARM64, source)
				if err != nil {
					t.Fatal(err)
				}
				options := Options{Goarch: "arm64", TargetTriple: "aarch64-unknown-linux-gnu",
					Sigs: map[string]FuncSig{"bad_access": {Name: "bad_access", Ret: Void}},
				}
				_, err = Translate(file, options)
				if err == nil || !strings.Contains(err.Error(), "is not") {
					t.Fatalf("Go-rejected access became successful translation: %v", err)
				}
			})
		}
	}
}
