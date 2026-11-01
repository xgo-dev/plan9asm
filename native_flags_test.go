package plan9asm

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"

	llvm "github.com/xgo-dev/llvm"
)

func TestNativeFlagsAcceptGoIntegerGrammar(t *testing.T) {
	for _, row := range []struct {
		source  string
		allowed []string
		want    map[string]bool
	}{
		{"4", []string{"NOSPLIT", "NOFRAME"}, map[string]bool{"NOSPLIT": true}},
		{"512", []string{"NOSPLIT", "NOFRAME"}, map[string]bool{"NOFRAME": true}},
		{"516", []string{"NOSPLIT", "NOFRAME"}, map[string]bool{"NOSPLIT": true, "NOFRAME": true}},
		{"0x204", []string{"NOSPLIT", "NOFRAME"}, map[string]bool{"NOSPLIT": true, "NOFRAME": true}},
		{"0X204", []string{"NOSPLIT", "NOFRAME"}, map[string]bool{"NOSPLIT": true, "NOFRAME": true}},
		{"01004", []string{"NOSPLIT", "NOFRAME"}, map[string]bool{"NOSPLIT": true, "NOFRAME": true}},
		{"0b1000000100", []string{"NOSPLIT", "NOFRAME"}, map[string]bool{"NOSPLIT": true, "NOFRAME": true}},
		{"(1 << 9) + 4", []string{"NOSPLIT", "NOFRAME"}, map[string]bool{"NOSPLIT": true, "NOFRAME": true}},
		{"NOSPLIT | 0x200", []string{"NOSPLIT", "NOFRAME"}, map[string]bool{"NOSPLIT": true, "NOFRAME": true}},
		{"NOSPLIT | NOSPLIT", []string{"NOSPLIT", "NOFRAME"}, map[string]bool{"NOSPLIT": true}},
		{"(4 * 3) & ~8", []string{"NOSPLIT", "NOFRAME"}, map[string]bool{"NOSPLIT": true}},
		{"8", []string{"RODATA", "NOPTR"}, map[string]bool{"RODATA": true}},
		{"0x10", []string{"RODATA", "NOPTR"}, map[string]bool{"NOPTR": true}},
		{"24", []string{"RODATA", "NOPTR"}, map[string]bool{"RODATA": true, "NOPTR": true}},
		{"(RODATA | NOPTR)", []string{"RODATA", "NOPTR"}, map[string]bool{"RODATA": true, "NOPTR": true}},
		{"RODATA & ~RODATA", []string{"RODATA", "NOPTR"}, map[string]bool{}},
		{"0x0", []string{"RODATA", "NOPTR"}, map[string]bool{}},
	} {
		t.Run(row.source, func(t *testing.T) {
			got, err := nativeFlags(row.source, row.allowed...)
			if err != nil || !reflect.DeepEqual(got, row.want) {
				t.Fatalf("native flags %q: got %v, %v; want %v", row.source, got, err, row.want)
			}
		})
	}
}

func TestNativeFlagsRejectEveryForeignBitAndMalformedExpression(t *testing.T) {
	for _, role := range []struct {
		name    string
		allowed []string
		bits    map[string]uint64
		mask    uint64
	}{
		{"TEXT", []string{"NOSPLIT", "NOFRAME"}, map[string]uint64{"NOSPLIT": 4, "NOFRAME": 512}, 516},
		{"GLOBL", []string{"RODATA", "NOPTR"}, map[string]uint64{"RODATA": 8, "NOPTR": 16}, 24},
	} {
		t.Run(role.name, func(t *testing.T) {
			for value := uint64(0); value < 1024; value++ {
				for _, source := range []string{strconv.FormatUint(value, 10), fmt.Sprintf("0x%x", value)} {
					got, err := nativeFlags(source, role.allowed...)
					if value & ^role.mask != 0 {
						if err == nil || got != nil {
							t.Fatalf("foreign %s bits accepted: %s => %v, %v", role.name, source, got, err)
						}
						continue
					}
					want := map[string]bool{}
					for name, bit := range role.bits {
						if value&bit != 0 {
							want[name] = true
						}
					}
					if err != nil || !reflect.DeepEqual(got, want) {
						t.Fatalf("complete %s mask %s: got %v, %v; want %v", role.name, source, got, err, want)
					}
				}
			}
			for bit := uint(10); bit < 64; bit++ {
				source := fmt.Sprintf("0x%x", role.mask|uint64(1)<<bit)
				if got, err := nativeFlags(source, role.allowed...); err == nil || got != nil {
					t.Fatalf("high foreign %s bit accepted: %s => %v, %v", role.name, source, got, err)
				}
			}
			for _, source := range []string{"", "4|", "|4", "4||512", "4.0", "unknown", "NOSPLIT_extra", "0x204junk", "18446744073709551616", "-4", "~0"} {
				if got, err := nativeFlags(source, role.allowed...); err == nil || got != nil {
					t.Fatalf("malformed/foreign %s flags accepted: %q => %v, %v", role.name, source, got, err)
				}
			}
		})
	}
}

func TestNativeFlagsStrictCPPFeedsBothNativeConsumers(t *testing.T) {
	const source = "#include \"textflag.h\"\nTEXT tail(SB),NOSPLIT|NOFRAME,$0\nJMP imported(SB)\n" +
		"GLOBL ·entry(SB),RODATA|NOPTR,$8\nDATA ·entry(SB)/8,$tail(SB)\n"
	// Independent Go textflag.h values: neither the preprocessor's producer
	// nor the native decoder's implementation supplies this oracle.
	const header = "#define NOSPLIT 4\n#define NOFRAME 512\n#define RODATA 8\n#define NOPTR 16\n"
	expanded, err := PreprocessAssemblySource(source, AssemblyPreprocessOptions{
		FileName: "callback.s",
		ReadInclude: func(parent, name string) (string, []byte, error) {
			if parent != "callback.s" || name != "textflag.h" {
				return "", nil, fmt.Errorf("unexpected native include %q from %q", name, parent)
			}
			return "textflag.h", []byte(header), nil
		},
	})
	if err != nil || strings.Contains(expanded, "NOSPLIT") || strings.Contains(expanded, "RODATA") {
		t.Fatal("strict CPP did not produce its actual numeric flag source", expanded, err)
	}
	for _, goos := range []string{"linux", "darwin"} {
		for _, arch := range []string{"amd64", "arm64"} {
			t.Run(goos+"/"+arch, func(t *testing.T) {
				options := NativeOptions{GOOS: goos, GOARCH: arch, PackagePath: "probe",
					Imports: map[string]string{"imported": "body"}, CodeEntries: map[string]string{"tail": "probe.tail"}}
				want, wantData, err := TranslateNativeSource([]byte(source), options)
				if err != nil {
					t.Fatal("unchanged named-flag native source", err)
				}
				got, gotData, err := TranslateNativeSource([]byte(expanded), options)
				if err != nil || got != want || !reflect.DeepEqual(gotData, wantData) {
					t.Fatal("strict CPP flags changed complete native source/data", got, gotData, err)
				}
				ctx := llvm.NewContext()
				defer ctx.Dispose()
				module, err := TranslateNativeModule(ctx, []byte(expanded), options)
				if err != nil {
					t.Fatal("strict CPP flags were not consumed by the native module", err)
				}
				defer module.Dispose()
				entry := module.NamedGlobal("probe.entry")
				if entry.IsNil() || !entry.IsGlobalConstant() || module.NamedFunction("probe.tail").IsNil() {
					t.Fatal("numeric flags lost readonly storage or the explicitly bound native entry", module.String())
				}
			})
		}
	}
}

func TestNativeNumericFlagsKeepRequiredEntryBits(t *testing.T) {
	for _, arch := range []string{"amd64", "arm64"} {
		for _, flags := range []string{"0", "512", "4", "8", "516|32", "0x100000204"} {
			t.Run(arch+"/"+flags, func(t *testing.T) {
				source := "TEXT tail(SB)," + flags + ",$0\nJMP imported(SB)\n"
				options := NativeOptions{GOOS: "linux", GOARCH: arch, PackagePath: "probe",
					Imports: map[string]string{"imported": "body"}, CodeEntries: map[string]string{"tail": "probe.tail"}}
				if output, data, err := TranslateNativeSource([]byte(source), options); err == nil || output != "" || data != nil {
					t.Fatal("native code entry ignored missing/foreign flag bits", output, data, err)
				}
			})
		}
	}
}
