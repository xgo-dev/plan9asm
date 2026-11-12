package plan9asm

import (
	"bytes"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

// The spelling/value directory is an independent source oracle, not an
// invocation of the production immediate conversion or effect descriptor.
type x86IMULImmediateCase struct {
	name, literal string
	value         int64
	only386       bool
}

var x86IMULImmediateCases = []x86IMULImmediateCase{
	{"Zero", "0", 0, false}, {"One", "1", 1, false},
	{"MinusOne", "-1", -1, false}, {"Min8", "-128", -128, false},
	{"Below8", "-129", -129, false}, {"Max8", "127", 127, false},
	{"Above8", "128", 128, false}, {"MaxU8", "255", 255, false},
	{"Min16", "-32768", -32768, false}, {"Below16", "-32769", -32769, false},
	{"Max16", "32767", 32767, false}, {"Above16", "32768", 32768, false},
	{"MaxU16", "65535", 65535, false}, {"AboveU16", "65536", 65536, false},
	{"Min32", "-2147483648", -2147483648, false},
	{"Max32", "2147483647", 2147483647, false},
	{"Above32", "2147483648", 2147483648, false},
	{"MaxU32", "4294967295", 4294967295, false},
	{"Hex32", "0x80000000", 2147483648, false},
	{"HexU32", "0xffffffff", 4294967295, false},
	{"NegativeHex32", "-0x80000000", -2147483648, false},
	{"Binary", "0b11111111", 255, false}, {"Octal", "0377", 255, false},
	{"ShiftExpression", "(1<<31)", 2147483648, false},
	{"Uint64MinusOne", "18446744073709551615", -1, false},
	{"HexUint64MinusOne", "0xffffffffffffffff", -1, false},
	{"WrappedZero", "4294967296", 4294967296, true},
	{"WrappedOne", "4294967297", 4294967297, true},
	{"WrappedMinusOne", "8589934591", 8589934591, true},
	{"Below32", "-2147483649", -2147483649, true},
	{"WrappedNegativeZero", "-4294967296", -4294967296, true},
	{"Max64", "9223372036854775807", 9223372036854775807, true},
	{"Min64", "-9223372036854775808", -9223372036854775808, true},
	{"UnsignedSign64", "9223372036854775808", -9223372036854775808, true},
}

func TestX86ExplicitIMULImmediateCompleteActualGoBytesAndEffects(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, bits := range []int{16, 32, 64} {
			for _, three := range []bool{false, true} {
				for _, literal := range x86IMULImmediateCases {
					suffix := map[int]string{16: "W", 32: "L", 64: "Q"}[bits]
					op, operands := "IMUL"+suffix, "$"+literal.literal+",AX"
					if three {
						op, operands = "IMUL3"+suffix, "$"+literal.literal+",AX,BX"
					}
					instruction := op + " " + operands
					t.Run(arch+"/"+op+"/"+literal.name, func(t *testing.T) {
						source := "TEXT ·Value(SB),4,$0-0\n" + instruction + "\nRET\n"
						accepted := !(arch == "386" && bits == 64 || arch == "amd64" && literal.only386)
						goAssemblerOracleOutput(t, arch, source, "", accepted)
						file, err := Parse(ArchAMD64, source)
						if err != nil {
							t.Fatal(err)
						}
						ins := file.Funcs[0].Instrs[1]
						before := fmt.Sprintf("%#v", ins)
						form, recognized, err := x86ExplicitIMULProperties(ins.Op, ins, arch)
						if !accepted {
							if !recognized || err == nil {
								t.Fatal("rejected Go row acquired a typed immediate", form, err)
							}
							return
						}
						if !recognized || err != nil {
							t.Fatal("accepted Go row lost its typed immediate", form, err)
						}
						value := int64(int32(literal.value))
						if bits == 16 {
							value = int64(int16(literal.value))
						}
						immediate := form.source
						if three {
							immediate = form.immediate
						}
						if immediate.Kind != OpImm || immediate.Imm != value {
							t.Fatalf("descriptor disagrees with encoded immediate: %#v want %d", immediate, value)
						}
						effect, recognized, err := x86TypedGPByteEffect(ins.Op, ins, arch)
						if !recognized || err != nil || effect.operands[0].operand.Imm != value ||
							effect.flagsDefined != x86ByteFlagCF|x86ByteFlagOF || effect.flagsKilled != x86ByteFlagsAll {
							t.Fatalf("numeric/flag effect did not consume the same encoded immediate: %#v %v", effect, err)
						}
						classValue := literal.value
						if arch == "386" {
							classValue = int64(int32(classValue))
						}
						var want []byte
						if bits == 16 {
							want = append(want, 0x66)
						} else if bits == 64 {
							want = append(want, 0x48)
						}
						opcode, count := byte(0x69), bits/8
						if count == 8 {
							count = 4
						}
						if classValue >= -128 && classValue <= 127 {
							opcode, count = 0x6b, 1
						}
						modrm := byte(0xc0)
						if three {
							modrm = 0xd8
						}
						want = append(want, opcode, modrm)
						for i := 0; i < count; i++ {
							want = append(want, byte(uint64(literal.value)>>(8*i)))
						}
						want = append(want, 0xc3)
						code := x86PackedShiftActualGoBytes(t, arch, source)
						if !bytes.Equal(code, want) {
							t.Fatalf("actual Go instruction width/value changed: %x want %x", code, want)
						}
						if after := fmt.Sprintf("%#v", ins); before != after {
							t.Fatal("encoded immediate normalization mutated the original instruction")
						}
					})
				}
			}
		}
	}
}

func TestX86ExplicitIMULImmediateThreeAPIFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range []struct{ arch, triple string }{
		{"amd64", "x86_64-apple-darwin"}, {"amd64", "x86_64-unknown-linux-gnu"}, {"amd64", "x86_64-pc-windows-msvc"},
		{"386", "i386-unknown-linux-gnu"}, {"386", "i686-pc-windows-msvc"},
	} {
		t.Run(target.triple, func(t *testing.T) {
			word, typ, move := 8, "uint64", "MOVQ"
			if target.arch == "386" {
				word, typ, move = 4, "uint32", "MOVL"
			}
			var body strings.Builder
			fmt.Fprintf(&body, "%s x+0(FP),AX\n%s $3,BX\n", move, move)
			for _, bits := range []int{16, 32, 64} {
				if bits == 64 && target.arch == "386" {
					continue
				}
				suffix := map[int]string{16: "W", 32: "L", 64: "Q"}[bits]
				for _, literal := range x86IMULImmediateCases {
					if literal.only386 && target.arch != "386" {
						continue
					}
					fmt.Fprintf(&body, "IMUL%s $%s,BX\nIMUL3%s $%s,AX,BX\n", suffix, literal.literal, suffix, literal.literal)
				}
			}
			fmt.Fprintf(&body, "%s BX,ret0+%d(FP)\nRET", move, word)
			pkg, file, sig, source := x86ResultInitializationFixture(t, target.arch, "func Value(x "+typ+") "+typ, body.String())
			goAssemblerOracleOutput(t, target.arch, source, "", true)
			if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, target.arch); err != nil {
				t.Fatal(err)
			}
			options := Options{Goarch: target.arch, TargetTriple: target.triple, Sigs: map[string]FuncSig{"Value": sig},
				ResolveSym: func(symbol string) string { return strings.TrimPrefix(symbol, "·") }}
			before := fmt.Sprintf("%#v %#v", file, sig)
			ir, err := Translate(file, options)
			if err != nil {
				t.Fatal(err)
			}
			x86ResultInitializationObject(t, llc, target.triple, ir, "immediate-text")
			ctx := llvm.NewContext()
			defer ctx.Dispose()
			module, err := TranslateModuleInContext(ctx, file, options)
			if !module.IsNil() {
				defer module.Dispose()
			}
			if err != nil {
				t.Fatal(err)
			}
			x86ResultInitializationObject(t, llc, target.triple, module.String(), "immediate-module")
			translated, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{
				GOARCH: target.arch, TargetTriple: target.triple, ResolveSym: options.ResolveSym,
			})
			if translated != nil && !translated.Module.IsNil() {
				defer translated.Module.Dispose()
			}
			if err != nil {
				t.Fatal(err)
			}
			x86ResultInitializationObject(t, llc, target.triple, translated.Module.String(), "immediate-typed-go")
			if !reflect.DeepEqual(before, fmt.Sprintf("%#v %#v", file, sig)) {
				t.Fatal("API consumed immediate semantics by rewriting source or signature")
			}
		})
	}
}
