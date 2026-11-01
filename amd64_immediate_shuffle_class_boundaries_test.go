package plan9asm

import (
	"bytes"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func TestX86ImmediateShuffleRejectsNonIntegerClassesEveryConsumer(t *testing.T) {
	for _, op := range []string{"PSHUFW", "PSHUFL", "PSHUFD", "PSHUFHW", "PSHUFLW", "VPSHUFD", "VPSHUFHW", "VPSHUFLW"} {
		for _, literal := range []string{"$0.0", "$1.0", "$UNKNOWN"} {
			bank := "X"
			if op == "PSHUFW" {
				bank = "M"
			}
			row := fmt.Sprintf("%s %s,%s0,%s1", op, literal, bank, bank)
			t.Run(row, func(t *testing.T) {
				assembly := "TEXT f(SB),4,$0-0\n" + row + "\nRET\n"
				for _, arch := range []string{"amd64", "386"} {
					goAssemblerOracleOutput(t, arch, assembly, "", false)
					ins := x86YMMReadSource(t, row)
					if _, known, err := x86ImmediateShuffleProperties(ins, arch); !known || err == nil {
						t.Error("non-integer class acquired integer grammar", arch, literal, err)
					}
					var output strings.Builder
					ctx := &amd64Ctx{goarch: arch, b: &output}
					if known, _, err := ctx.lowerPackedWordShuffle(ins.Op, ins); !known || err == nil || output.Len() != 0 {
						t.Error("non-integer class emitted IR", arch, err, output.String())
					}
					state := x86CloneCallerState(x86SourceStackState{vectors: map[Reg]uint64{"Z0": ^uint64(0), "Z1": ^uint64(0)}})
					before := x86CloneCallerState(state)
					if x86CallerVectorMoveKnown(ins) || x86CallerVectorMoveStep(&ins, &state, nil) || !reflect.DeepEqual(state, before) {
						t.Error("non-integer class acquired caller effects or changed state", arch)
					}
					result := x86ResultState{}
					result.writeVector(0, 64, ^uint64(0), false)
					result.writeVector(1, 64, ^uint64(0), false)
					beforeResult := result.clone()
					if x86ResultTransfer(ins, &result, nil, 0, arch) || !reflect.DeepEqual(result, beforeResult) {
						t.Error("non-integer class acquired result effects or changed state", arch)
					}
				}
				file, err := Parse(ArchAMD64, assembly)
				if err != nil {
					t.Fatal(err)
				}
				options := Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu", Sigs: map[string]FuncSig{"f": {Name: "f", Ret: Void}}}
				if _, err := Translate(file, options); err == nil {
					t.Error("text API accepted non-integer immediate")
				}
				ctx := llvm.NewContext()
				defer ctx.Dispose()
				module, err := TranslateModuleInContext(ctx, file, options)
				if !module.IsNil() {
					defer module.Dispose()
				}
				if err == nil {
					t.Error("module API accepted non-integer immediate")
				}
				pkg := mustGoPackage(t, "example.invalid/shuffle", "package shuffle\nfunc f()\n")
				translated, err := translateGoModuleInContext(ctx, pkg, []byte(assembly), GoModuleOptions{
					GOARCH: "amd64", TargetTriple: options.TargetTriple,
				})
				if translated != nil && !translated.Module.IsNil() {
					defer translated.Module.Dispose()
				}
				if err == nil {
					t.Error("actual typed declaration API accepted non-integer immediate")
				}
			})
		}
	}
}

func TestX86ImmediateShuffleGoMode32ConstantClassification(t *testing.T) {
	// Go's oclass truncates TYPE_CONST to int32 only in I386 mode. This is
	// source classification, not permission to invent an encoded raw operand.
	values := []int64{4294967296, -4294967296, 4294967168, 4294967423, 4294967424, 4294967551, 4294967552, -4294967297}
	for _, arch := range []string{"amd64", "386"} {
		t.Run(arch, func(t *testing.T) {
			for _, op := range []string{"PSHUFW", "PSHUFL", "PSHUFD", "PSHUFHW", "PSHUFLW", "VPSHUFD", "VPSHUFHW", "VPSHUFLW"} {
				banks := []string{"X"}
				if op == "PSHUFW" {
					banks = []string{"M"}
				} else if strings.HasPrefix(op, "V") {
					banks = append(banks, "Z")
				}
				for _, bank := range banks {
					for _, value := range values {
						classified := value
						if arch == "386" {
							classified = int64(int32(value))
						}
						accepted := classified >= 0 && classified <= 255
						if op == "PSHUFW" {
							accepted = classified >= -128 && classified <= 127
						} else if strings.HasPrefix(op, "V") && bank == "X" {
							accepted = classified >= -128 && classified <= 255
						}
						row := fmt.Sprintf("%s $%d,%s0,%s1", op, value, bank, bank)
						goAssemblerOracleOutput(t, arch, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n", "", accepted)
						ins := x86YMMReadSource(t, row)
						before := fmt.Sprintf("%#v", ins)
						form, known, err := x86ImmediateShuffleProperties(ins, arch)
						if !known || accepted != (err == nil) || accepted && form.immediate != uint8(classified) {
							t.Errorf("Go %s accepted=%v for %s, grammar=%+v error=%v", arch, accepted, row, form, err)
						}
						if before != fmt.Sprintf("%#v", ins) {
							t.Fatal("classification changed original constant/source")
						}
					}
				}
			}
		})
	}
}

func TestX86ImmediateShuffleRawMMXCompleteImmediateBits(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		t.Run(arch, func(t *testing.T) {
			var source strings.Builder
			source.WriteString("TEXT f(SB),4,$0-0\n")
			var expected []byte
			for value := 0; value < 256; value++ {
				code := []byte{0x0f, 0x70, 0xc8, byte(value)}
				fmt.Fprintf(&source, "PSHUFW $%d,M0,M1\n", int8(value))
				expected = append(expected, code...)
				decoded, err := decodeX86RawDirectives(rawX86Function(code), arch)
				if err != nil || len(decoded.Instrs) != 1 {
					t.Fatalf("physical imm8 %x lost instruction identity: %+v %v", code, decoded, err)
				}
				form, known, err := x86ImmediateShuffleProperties(decoded.Instrs[0], arch)
				if !known || err != nil || form.immediate != uint8(value) || !form.spec.mmx {
					t.Errorf("raw PSHUFW imm8=%d lost Go Yi8 spelling: %+v %v", value, form, err)
				}
			}
			source.WriteString("RET\n")
			expected = append(expected, 0xc3)
			if got := assembleX87ControlBytes(t, arch, source.String()); !bytes.HasPrefix(got, expected) {
				t.Fatal("independent Go signed source did not encode the original physical imm8 bytes")
			}
		})
	}
}
