package plan9asm

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

// Independent source spellings and values, including rounding, subnormal,
// underflow, signed-zero and finite-f64-to-infinite-f32 transitions.
var dataFloatLiteralCases = []struct {
	source string
	value  float64
}{
	{"0.0", 0},
	{"-0.0", math.Copysign(0, -1)},
	{"1.25", 1.25},
	{"-(1.25)", -1.25},
	{"--1.25", 1.25},
	{"+(-(+1.25))", -1.25},
	{"1.000000059604644775390625", 1 + math.Ldexp(1, -24)},
	{"1.000000178813934326171875", 1 + math.Ldexp(3, -24)},
	{"0x1p-149", math.Ldexp(1, -149)},
	{"0x1p-150", math.Ldexp(1, -150)},
	{"-0x1p-150", -math.Ldexp(1, -150)},
	{"0x1p-126", math.Ldexp(1, -126)},
	{"1.7976931348623157e308", math.MaxFloat64},
	{"0x1p-1074", math.SmallestNonzeroFloat64},
}

func dataFloatLiteralBytes(value float64, width int) []byte {
	result := make([]byte, width)
	if width == 4 {
		binary.LittleEndian.PutUint32(result, math.Float32bits(float32(value)))
	} else {
		binary.LittleEndian.PutUint64(result, math.Float64bits(value))
	}
	return result
}

func TestDataFloatLiteralWidthAndGrammar(t *testing.T) {
	for _, target := range dataGlobalAlignmentTargets {
		for _, width := range []int{4, 8} {
			for _, test := range dataFloatLiteralCases {
				statement := fmt.Sprintf("value(SB)/%d,$%s", width, test.source)
				data, err := parseDATAStmt(target.arch, statement)
				if err != nil {
					t.Errorf("%s %s: %v", target.goarch, statement, err)
					continue
				}
				got, err := dataStmtPayload(data)
				want := dataFloatLiteralBytes(test.value, width)
				if err != nil || !bytes.Equal(got, want) {
					t.Errorf("%s %s: bytes=%x want=%x err=%v", target.goarch, statement, got, want, err)
				}
			}
		}
		for _, statement := range []string{
			"value(SB)/1,$1.0", "value(SB)/2,$1.0", "value(SB)/16,$1.0",
			"value(SB)/4,$(1.0+2.0)", "value(SB)/8,$(1.0*2.0)",
			"value(SB)/4,$(1.0", "value(SB)/8,$(1+2.0)",
			"value(SB)/4,$NaN", "value(SB)/8,$Inf",
			"value(SB)/16,$1", "value(SB)/4,$(unresolved+1)",
		} {
			goAssemblerOracleOutput(t, target.goarch, "DATA "+statement+"\nGLOBL value(SB),24,$32\n", "", false)
			if _, err := parseDATAStmt(target.arch, statement); err == nil {
				t.Errorf("%s accepted non-Go float DATA: %s", target.goarch, statement)
			}
		}
	}
}

func TestDataFloatLiteralActualGoAndLLVMFiveArchitectures(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	var assembly strings.Builder
	wants := make(map[string][]byte)
	for _, width := range []int{4, 8} {
		for index, test := range dataFloatLiteralCases {
			name := fmt.Sprintf("float_data_%d_%d", width, index)
			fmt.Fprintf(&assembly, "DATA %s(SB)/%d,$%s\nGLOBL %s(SB),24,$%d\n", name, width, test.source, name, width)
			wants[name] = dataFloatLiteralBytes(test.value, width)
		}
	}
	for _, target := range dataGlobalAlignmentTargets {
		t.Run(target.goarch, func(t *testing.T) {
			directory := t.TempDir()
			filename := filepath.Join(directory, "data.s")
			if err := os.WriteFile(filename, []byte(assembly.String()), 0600); err != nil {
				t.Fatal(err)
			}
			environment := []string{"GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local", "GOOS=" + target.goos, "GOARCH=" + target.goarch}
			listing := dataGlobalAlignmentCommand(t, directory, environment, "go", "tool", "asm", "-S", "-o", filepath.Join(directory, "data.o"), filename)
			seen := make(map[string]bool)
			lines := strings.Split(string(listing), "\n")
			for line, text := range lines {
				fields := strings.Fields(text)
				if len(fields) < 3 {
					continue
				}
				want, exists := wants[fields[0]]
				if !exists {
					continue
				}
				if seen[fields[0]] || fields[1] != "SRODATA" || fields[2] != fmt.Sprintf("size=%d", len(want)) || line+1 >= len(lines) {
					t.Fatal("actual Go symbol identity/extent changed", text)
				}
				row := strings.Fields(lines[line+1])
				if len(row) < len(want)+1 || row[0] != "0x0000" {
					t.Fatal("actual Go DATA bytes absent", lines[line+1])
				}
				got, err := hex.DecodeString(strings.Join(row[1:len(want)+1], ""))
				if err != nil || !bytes.Equal(got, want) {
					t.Fatalf("original Go %s bytes=%x want=%x: %v", fields[0], got, want, err)
				}
				seen[fields[0]] = true
			}
			if len(seen) != len(wants) {
				t.Fatalf("original Go DATA inventory %d != %d\n%s", len(seen), len(wants), listing)
			}
			file, err := Parse(target.arch, assembly.String())
			if err != nil {
				t.Fatal(err)
			}
			options := Options{Goarch: target.goarch, TargetTriple: target.triple, ResolveSym: dataGlobalAlignmentResolve}
			pkg := x86AddSubLiteralPackage(t, target.goarch, "")
			for _, api := range []string{"text", "module", "GoModule"} {
				t.Run(api, func(t *testing.T) {
					ctx := llvm.NewContext()
					defer ctx.Dispose()
					var module llvm.Module
					var err error
					switch api {
					case "text":
						var ir string
						ir, err = Translate(file, options)
						if err == nil {
							module, err = parseIRModuleInContext(ctx, ir)
						}
					case "module":
						module, err = TranslateModuleInContext(ctx, file, options)
					case "GoModule":
						var result *GoModuleTranslation
						result, err = translateGoModuleInContext(ctx, pkg, []byte(assembly.String()), GoModuleOptions{
							GOARCH: target.goarch, TargetTriple: target.triple, ResolveSym: dataGlobalAlignmentResolve})
						if result != nil {
							module = result.Module
						}
					}
					if !module.IsNil() {
						defer module.Dispose()
					}
					if err != nil || module.IsNil() {
						t.Fatal(err)
					}
					for name, want := range wants {
						global := module.NamedGlobal(name)
						// LLVM uniques constants within a context, independent of
						// whether IR prints a byte string or a zero initializer.
						if global.IsNil() || !global.IsGlobalConstant() || global.Initializer() != ctx.ConstString(string(want), false) {
							t.Errorf("LLVM initializer differs from actual Go: %s want=%x", name, want)
						}
					}
					compileLLVMToObject(t, llc, target.triple, "float-data.ll", "float-data.o", module.String())
				})
			}
		})
	}
}
