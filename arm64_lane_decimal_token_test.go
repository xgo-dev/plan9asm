package plan9asm

import (
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func TestARM64LaneTokenDecimalDecoderMatchesGoLimits(t *testing.T) {
	for _, tc := range []struct {
		source string
		value  int
		valid  bool
	}{
		{source: "0", valid: true},
		{source: "00015", value: 15, valid: true},
		{source: " 17\t", value: 17, valid: true},
		{source: "32767", value: 32767, valid: true},
		{source: "32768"},
		{source: "999999999999999999999999999999"},
		{source: ""},
		{source: " \t"},
		{source: "+0"},
		{source: "-0"},
		{source: "0xf"},
		{source: "0_1"},
		{source: "1+1"},
		{source: "(1<<3)"},
		{source: "1 5"},
		{source: "١"},
		{source: "１"},
		{source: "LANE"},
	} {
		t.Run(tc.source, func(t *testing.T) {
			value, valid := arm64ParseLaneDecimalToken(tc.source)
			if valid != tc.valid || valid && value != tc.value {
				t.Fatalf("decimal token %q: (%d,%v), want (%d,%v)", tc.source, value, valid, tc.value, tc.valid)
			}
		})
	}
}

func TestARM64LaneTokenRejectedFormatsFailEveryAPI(t *testing.T) {
	pkg := mustGoPackage(t, "test/lanetokennegative", "package tokennegative\nfunc Pass(uint64) uint64\n")
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	base, err := translateGoModuleInContext(ctx, pkg, []byte("TEXT ·Pass<ABIInternal>(SB),4,$0-16\nRET\n"),
		GoModuleOptions{GOARCH: "arm64", ResolveSym: testResolveSym(pkg.Path)})
	if err != nil {
		t.Fatal(err)
	}
	defer base.Module.Dispose()
	options := Options{Goarch: "arm64", Sigs: base.Signatures, ResolveSym: testResolveSym(pkg.Path)}
	for _, tc := range arm64LaneTokenCases() {
		if tc.accepted {
			continue
		}
		for form := 0; form < 3; form++ {
			t.Run(fmt.Sprintf("%s/%d", tc.name, form), func(t *testing.T) {
				source := tc.prefix + "TEXT ·Pass<ABIInternal>(SB),4,$0-16\nVDUP R0,V21.B16\n" +
					arm64LaneTokenInstruction(form, tc.index) + "\nRET\n"
				file, err := Parse(ArchARM64, source)
				if err != nil {
					return
				}
				if _, err := Translate(file, options); err == nil {
					t.Fatal("text API accepted a Go-rejected index")
				}
				module, err := TranslateModuleInContext(ctx, file, options)
				if !module.IsNil() {
					module.Dispose()
				}
				if err == nil {
					t.Fatal("module API accepted a Go-rejected index")
				}
				result, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{GOARCH: "arm64", ResolveSym: testResolveSym(pkg.Path)})
				if result != nil {
					result.Module.Dispose()
				}
				if err == nil {
					t.Fatal("Go-module API accepted a Go-rejected index")
				}
			})
		}
	}
}

type arm64LaneTokenCase struct {
	name, prefix, index string
	value               int
	accepted            bool
}

func arm64LaneTokenCases() []arm64LaneTokenCase {
	return []arm64LaneTokenCase{
		{name: "decimal", index: "15", value: 15, accepted: true},
		{name: "hex", index: "0xf"},
		{name: "octal-looking", index: "017"},
		{name: "leading-zero-decimal", index: "015", value: 15, accepted: true},
		{name: "plus", index: "+15"},
		{name: "sum", index: "1+1"},
		{name: "shift", index: "(1<<3)"},
		{name: "spaces", index: " 15 ", value: 15, accepted: true},
		{name: "tabs", index: "\t15\t", value: 15, accepted: true},
		{name: "zero", index: "0", accepted: true},
		{name: "plus-zero", index: "+0"},
		{name: "negative-zero", index: "-0"},
		{name: "underscores", index: "0_1"},
		{name: "macro-decimal", prefix: "#define LANE 15\n", index: "LANE", value: 15, accepted: true},
		{name: "macro-alias", prefix: "#define INDEX 15\n#define LANE INDEX\n", index: "LANE", value: 15, accepted: true},
		{name: "macro-function", prefix: "#define LANE(x) x\n", index: "LANE(15)", value: 15, accepted: true},
		{name: "macro-space", prefix: "#define LANE  15 \n", index: "LANE", value: 15, accepted: true},
		{name: "macro-parenthesis", prefix: "#define LANE (15)\n", index: "LANE"},
		{name: "macro-hex", prefix: "#define LANE 0xf\n", index: "LANE"},
		{name: "macro-expression", prefix: "#define LANE 1+1\n", index: "LANE"},
		{name: "named-unbound", index: "LANE"},
		{name: "named-assignment", prefix: "LANE = 15\n", index: "LANE"},
	}
}

func arm64LaneTokenInstruction(form int, index string) string {
	switch form {
	case 0:
		return fmt.Sprintf("VMOV R0,V21.B[%s]", index)
	case 1:
		return fmt.Sprintf("VMOV V21.B[%s],R0", index)
	default:
		return fmt.Sprintf("VDUP V21.D[%s],V22.B16", index)
	}
}

func arm64LaneTokenBody(tc arm64LaneTokenCase, form int) string {
	instruction := arm64LaneTokenInstruction(form, tc.index)
	switch form {
	case 0:
		return instruction + fmt.Sprintf("\nVMOV V21.B[%d],R0\n", tc.value)
	case 1:
		return fmt.Sprintf("VMOV R0,V21.B[%d]\n", tc.value) + instruction + "\n"
	default:
		return fmt.Sprintf("VMOV R0,V21.B[%d]\n", tc.value) + instruction + "\nVMOV V22.D[0],R0\n"
	}
}

func TestARM64LaneTokenActualGoAndTypedGrammar(t *testing.T) {
	// Each SDK actually assembles all 66 formats. Go's registerExtension
	// consumes scanner.Int then ParseInt(base 10, bits 16), not p.expr().
	for _, tc := range arm64LaneTokenCases() {
		for form := 0; form < 3; form++ {
			t.Run(fmt.Sprintf("%s/%d", tc.name, form), func(t *testing.T) {
				instruction := arm64LaneTokenInstruction(form, tc.index)
				source := tc.prefix + "TEXT token(SB),4,$0-0\n" + instruction + "\nRET\n"
				goAssemblerOracleOutput(t, "arm64", source, "", tc.accepted)
				file, err := Parse(ArchARM64, source)
				if err != nil {
					if tc.accepted {
						t.Fatal(err)
					}
					return
				}
				found := false
				for _, ins := range file.Funcs[0].Instrs {
					if ins.Op != "VMOV" && ins.Op != "VDUP" {
						continue
					}
					found = true
					_, err := parseARM64VectorTransfer(ins.Op, ins)
					if (err == nil) != tc.accepted {
						t.Errorf("typed lane format disagrees with actual Go: %s: %v", instruction, err)
					}
				}
				if !found {
					t.Fatal("fixture did not retain its instruction")
				}
				body := tc.prefix + "VDUP R0,V21.B16\n" + instruction + "\n"
				if form == 2 {
					body += "VMOV V22.D[0],R0\n"
				} else {
					body += "VMOV V21.D[0],R0\n"
				}
				_, err = arm64VectorLaneTranslation(t, "func Pass(uint64) uint64", body+"RET\n")
				if (err == nil) != tc.accepted {
					t.Errorf("full typed translation disagrees with actual Go: %s: %v", instruction, err)
				}
			})
		}
	}
}

func TestARM64LaneTokenCannotChangePhysicalSpanOrBank(t *testing.T) {
	for _, kind := range []string{"B", "H", "S", "D"} {
		bits := map[string]int{"B": 8, "H": 16, "S": 32, "D": 64}[kind]
		limit := 128 / bits
		for _, index := range []string{" +0 ", " -0 ", fmt.Sprint(limit), "32768", "١", "１", "1 5"} {
			instruction := fmt.Sprintf("VMOV R0,V21.%s[%s]", kind, index)
			t.Run(instruction, func(t *testing.T) {
				goAssemblerOracleOutput(t, "arm64", "TEXT invalid(SB),4,$0-0\n"+instruction+"\nRET\n", "", false)
				if _, err := arm64VectorLaneTranslation(t, "func Pass(uint64) uint64", instruction+"\nRET\n"); err == nil {
					t.Fatal("invalid lexical index or lane bound acquired authority")
				}
			})
		}
		index := fmt.Sprintf("\t%03d ", limit-1)
		body := fmt.Sprintf("VMOV R0,V21.%s[%s]\nVMOV V21.%s[%s],R0\nRET\n", kind, index, kind, index)
		arm64ImmediateOriginalGoBytes(t, "TEXT valid(SB),4,$0-0\n"+body, "linux")
		if _, err := arm64VectorLaneTranslation(t, "func Pass(uint64) uint64", body); err != nil {
			t.Fatal(err)
		}
	}
	for _, instruction := range []string{
		"VMOV R0,V32.B[ 0 ]", "VMOV R0,V21.Q[ 0 ]",
		"VMOV V21.D[ 15 ],R0", "VDUP V21.D[ 15 ],V22",
	} {
		goAssemblerOracleOutput(t, "arm64", "TEXT invalid(SB),4,$0-0\n"+instruction+"\nRET\n", "", false)
		if _, err := arm64VectorLaneTranslation(t, "func Pass(uint64) uint64", instruction+"\nRET\n"); err == nil {
			t.Fatalf("lexical decoder replaced an independent bank/width bound: %s", instruction)
		}
	}
	// Unknown input bytes and CFG joins remain independent of legal syntax.
	for _, body := range []string{
		"VMOV R0,V21.D[ 0 ]\nVMOV V21.D[ 1 ],R0\nRET\n",
		"VMOV R9,V21.D[ 0 ]\nVMOV V21.D[ 0 ],R0\nRET\n",
		"CBZ R0,join\nVMOV R0,V21.D[ 0 ]\njoin:\nVMOV V21.D[ 0 ],R0\nRET\n",
	} {
		if _, err := arm64VectorLaneTranslation(t, "func Pass(uint64) uint64", body); err == nil {
			t.Fatal("legal whitespace supplied unknown input bits")
		}
	}
}

func arm64LaneTokenProgram() (declarations, ordinary, internal string) {
	var decl, abi0, reg strings.Builder
	number := 0
	for _, tc := range arm64LaneTokenCases() {
		if !tc.accepted {
			continue
		}
		for form := 0; form < 3; form++ {
			name := fmt.Sprintf("Token%d", number)
			number++
			// cmd/asm rejects even identical macro redefinitions. Each program
			// function keeps the fixture's original expansion shape with unique
			// names, rather than changing replacement tokens or sharing state.
			local := tc
			replace := strings.NewReplacer("LANE", name+"_LANE", "INDEX", name+"_INDEX")
			local.prefix, local.index = replace.Replace(tc.prefix), replace.Replace(tc.index)
			fmt.Fprintf(&decl, "func %s(uint64) uint64\n", name)
			fmt.Fprintf(&abi0, "%sTEXT ·%s(SB),4,$0-16\nMOVD a+0(FP),R0\n%sMOVD R0,ret+8(FP)\nRET\n", local.prefix, name, arm64LaneTokenBody(local, form))
			fmt.Fprintf(&reg, "%sTEXT ·%s<ABIInternal>(SB),4,$0-16\n%sRET\n", local.prefix, name, arm64LaneTokenBody(local, form))
		}
	}
	return decl.String(), abi0.String(), reg.String()
}

func TestARM64LaneTokenAllAPIsAndFiveLLVMObjects(t *testing.T) {
	decl, ordinary, source := arm64LaneTokenProgram()
	if bytes := arm64ImmediateOriginalGoBytes(t, ordinary, "linux"); len(bytes) < 27*12 {
		t.Fatal("original Go object omitted accepted format functions")
	}
	pkg := mustGoPackage(t, "test/lanetoken", "package lanetoken\n"+decl)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc missing")
	}
	for _, target := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-unknown-linux-musl", "aarch64-pc-windows-msvc", "aarch64-pc-windows-gnu"} {
		t.Run(target, func(t *testing.T) {
			ctx := llvm.NewContext()
			defer ctx.Dispose()
			result, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{GOARCH: "arm64", TargetTriple: target, ResolveSym: testResolveSym(pkg.Path)})
			if err != nil {
				t.Fatal(err)
			}
			defer result.Module.Dispose()
			options := Options{Goarch: "arm64", TargetTriple: target, Sigs: result.Signatures, ResolveSym: testResolveSym(pkg.Path)}
			ir, err := Translate(file, options)
			if err != nil {
				t.Fatal(err)
			}
			module, err := TranslateModuleInContext(ctx, file, options)
			if err != nil {
				t.Fatal(err)
			}
			defer module.Dispose()
			for api, text := range []string{result.Module.String(), ir, module.String()} {
				compileLLVMToObject(t, llc, target, fmt.Sprintf("token-%d.ll", api), fmt.Sprintf("token-%d.o", api), text)
			}
		})
	}
}
