package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

type x86DwordProductDisplacementOracle struct {
	row   string
	width int
	tuple int
	units int
	mask  bool
	high  bool
	mem   MemRef
	code  []byte
}

// These tuples and offsets are independently prescribed from the actual
// Go encoder's Full/N16,N32,N64 and BcstN8 rows, not production properties.
func x86DwordProductDisplacementOracles(t *testing.T) []x86DwordProductDisplacementOracle {
	t.Helper()
	var result []x86DwordProductDisplacementOracle
	addresses := []MemRef{
		{Base: AX}, {Base: BP}, {Base: SP, Index: CX, Scale: 2},
		{Base: AX, Index: CX, Scale: 4}, {Base: "R13", Index: "R12", Scale: 8},
	}
	for _, name := range []string{"VPMULDQ", "VPMULUDQ"} {
		for _, width := range []int{16, 32, 64} {
			for _, broadcast := range []bool{false, true} {
				for masking := 0; masking < 3; masking++ {
					for _, units := range []int{-129, -128, -1, 1, 127, 128} {
						for _, memory := range addresses {
							tuple, op := width, name
							if broadcast {
								tuple, op = 8, name+".BCST"
							}
							if masking == 2 {
								op += ".Z"
							}
							memory.Off = int64(units * tuple)
							bank := map[int]string{16: "X", 32: "Y", 64: "Z"}[width]
							second, destination := bank+"1", bank+"2"
							high := masking == 0 && !broadcast && width != 64
							if high {
								second, destination = bank+"17", bank+"18" // Force actual EVEX.
							}
							args := (Operand{Kind: OpMem, Mem: memory}).String() + "," + second
							if masking == 1 {
								args += ",K1"
							} else if masking == 2 {
								args += ",K7"
							}
							row := op + " " + args + "," + destination
							code := x86OrderingHintGoBytes(t, "amd64", "TEXT probe(SB),4,$0-0\n"+row+"\nRET\n")
							if len(code) < 8 || code[0] != 0x62 || code[2]&0x80 == 0 || code[len(code)-1] != 0xc3 {
								t.Fatalf("independent original EVEX.W1 object changed: %s %x", row, code)
							}
							mod, end := code[5]>>6, 6
							if code[5]&7 == 4 {
								end++ // Independently observe SIB, not decoded source.
							}
							if units >= -128 && units <= 127 {
								if mod != 1 || int(int8(code[end])) != units || len(code) != end+2 {
									t.Fatalf("original compressed disp8/%d changed: %s %x", tuple, row, code)
								}
							} else if mod != 2 || len(code) != end+5 {
								t.Fatalf("original unscaled disp32 boundary changed: %s %x", row, code)
							}
							result = append(result, x86DwordProductDisplacementOracle{row, width, tuple, units, masking != 0, high, memory, code[:len(code)-1]})
						}
					}
				}
			}
		}
	}
	return result
}

func TestX86DwordProductCompressedDisp8IndependentPhysicalSource(t *testing.T) {
	fixtures := x86DwordProductDisplacementOracles(t)
	for _, fixture := range fixtures {
		for _, mode := range []int{32, 64} {
			for _, prefix := range []struct {
				byte    byte
				segment Reg
			}{{0, ""}, {0x64, FS}, {0x65, GS}} {
				t.Run(fmt.Sprintf("%s/mode%d/prefix%x", fixture.row, mode, prefix.byte), func(t *testing.T) {
					code := append([]byte(nil), fixture.code...)
					if prefix.byte != 0 {
						code = append([]byte{prefix.byte}, code...)
					}
					ins, length, known, err := decodedX86DwordToQwordMultiplyInstruction(code, mode)
					if mode == 32 && (fixture.high || fixture.mem.Base == "R13") {
						if !known || err == nil {
							t.Fatal("extended physical mode32 bank/address acquired permission", ins, err)
						}
						return
					}
					want := fixture.mem
					want.Segment = prefix.segment
					if !known || err != nil || length != len(code) || !ins.x86Encoded || len(ins.Args) == 0 || ins.Args[0].Kind != OpMem || !reflect.DeepEqual(ins.Args[0].Mem, want) {
						t.Fatalf("native physical tuple source changed: %x got=%+v length%d known%t err%v want=%+v", code, ins, length, known, err, want)
					}
				})
			}
			for _, bad := range [][]byte{
				append([]byte{0x67}, fixture.code...),
				append([]byte{0x64, 0x67}, fixture.code...),
				append([]byte{0x65, 0x67}, fixture.code...),
			} {
				if _, _, known, err := decodedX86DwordToQwordMultiplyInstruction(bad, mode); !known || err == nil {
					t.Fatal("address override acquired unbound source permission", fixture.row, mode, err)
				}
			}
		}
		wrongW := append([]byte(nil), fixture.code...)
		wrongW[2] &^= 0x80
		if _, _, known, err := decodedX86DwordToQwordMultiplyInstruction(wrongW, 64); !known || err == nil {
			t.Fatal("full/broadcast EVEX.W0 accepted", fixture.row, err)
		}
	}
	t.Logf("%d independently assembled full/broadcast,unmasked/merge/zero,disp8/disp32,SIB/bank witnesses ×two modes ×three segment prefixes; address/W rejection retained", len(fixtures))
}

func x86DwordProductDirectives(code []byte) string {
	var out strings.Builder
	for _, value := range code {
		fmt.Fprintf(&out, "BYTE $%d\n", value)
	}
	return out.String()
}

func TestX86DwordProductTupleOffsetsThreeAPIsFiveTargetObjects(t *testing.T) {
	fixtures := x86DwordProductDisplacementOracles(t)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 required")
	}
	for _, triple := range []string{"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc", "i386-unknown-linux-gnu", "i686-pc-windows-msvc"} {
		for _, raw := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/raw%t", triple, raw), func(t *testing.T) {
				arch := "amd64"
				if strings.HasPrefix(triple, "i") {
					arch = "386"
				}
				var source, declarations strings.Builder
				declarations.WriteString("package tuples\n")
				count := 0
				for _, fixture := range fixtures {
					// SP/BP decoder identity is proved above, without using it
					// to confer an unbound native frame in this object fixture.
					if fixture.mem.Base == SP || fixture.mem.Base == BP || arch == "386" && (fixture.high || fixture.mem.Base == "R13" || !raw && fixture.mask) {
						continue
					}
					row := fixture.row
					if raw {
						row = x86DwordProductDirectives(fixture.code)
					}
					fmt.Fprintf(&source, "TEXT ·F%d(SB),4,$0-0\n%s\nRET\n", count, row)
					fmt.Fprintf(&declarations, "func F%d()\n", count)
					count++
				}
				goAssemblerOracleOutput(t, arch, source.String(), "", true)
				ir := x86DwordProductOriginalFormatObject(t, source.String(), declarations.String(), arch, triple, 0)
				for _, level := range []string{"-O0", "-O2"} {
					x86PackedStringCompileObject(t, llc, triple, ir, level)
				}
				t.Logf("%d original tuple/disp32 forms: three public Context checks plus emitter objects", count)
			})
		}
	}
}

func TestX86DwordProductTupleRawRejectedPrefixesThreeAPIs(t *testing.T) {
	for _, name := range []string{"VPMULDQ", "VPMULUDQ"} {
		for _, width := range []int{16, 32, 64} {
			for _, broadcast := range []bool{false, true} {
				op, tuple := name, width
				if broadcast {
					op, tuple = name+".BCST", 8
				}
				bank := map[int]string{16: "X", 32: "Y", 64: "Z"}[width]
				row := fmt.Sprintf("%s %d(AX),%s1,K1,%s2", op, tuple, bank, bank)
				code := x86OrderingHintGoBytes(t, "amd64", "TEXT probe(SB),4,$0-0\n"+row+"\nRET\n")
				wrongW := append([]byte(nil), code[:len(code)-1]...)
				wrongW[2] &^= 0x80
				for _, bad := range [][]byte{append([]byte{0x67}, code[:len(code)-1]...), append([]byte{0x64, 0x67}, code[:len(code)-1]...), wrongW} {
					for _, triple := range []string{"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc", "i386-unknown-linux-gnu", "i686-pc-windows-msvc"} {
						t.Run(fmt.Sprintf("%s/%x/%s", row, bad, triple), func(t *testing.T) {
							arch := "amd64"
							if strings.HasPrefix(triple, "i") {
								arch = "386"
							}
							source := "TEXT ·F(SB),4,$0-0\n" + x86DwordProductDirectives(bad) + "RET\n"
							file, err := Parse(ArchAMD64, source)
							if err != nil {
								t.Fatal(err)
							}
							options := Options{Goarch: arch, TargetTriple: triple, Sigs: map[string]FuncSig{"F": {Name: "F", Ret: Void}}, ResolveSym: func(name string) string { return strings.TrimPrefix(name, "·") }}
							if ir, err := Translate(file, options); err == nil || ir != "" {
								t.Fatal("reserved tuple/address text accepted", err)
							}
							ctx := llvm.NewContext()
							defer ctx.Dispose()
							module, err := TranslateModuleInContext(ctx, file, options)
							if !module.IsNil() {
								defer module.Dispose()
							}
							if err == nil || !module.IsNil() {
								t.Fatal("reserved tuple/address module accepted", err)
							}
							pkg := mustGoPackage(t, "tuples", "package tuples\nfunc F()\n")
							result, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{GOARCH: arch, TargetTriple: triple, ResolveSym: options.ResolveSym})
							if result != nil && !result.Module.IsNil() {
								defer result.Module.Dispose()
							}
							if err == nil || result != nil {
								t.Fatal("reserved tuple/address Go module accepted", err)
							}
						})
					}
				}
			}
		}
	}
}

func TestX86DwordProductVEXDisplacementsRemainUnscaled(t *testing.T) {
	for _, name := range []string{"VPMULDQ", "VPMULUDQ"} {
		for _, bank := range []string{"X", "Y"} {
			for _, units := range []int{-129, -128, -1, 1, 127, 128} {
				for _, memory := range []MemRef{{Base: AX}, {Base: BP}, {Base: AX, Index: CX, Scale: 4}, {Base: SP, Index: CX, Scale: 2}, {Base: "R13", Index: "R12", Scale: 8}} {
					memory.Off = int64(units)
					row := fmt.Sprintf("%s %s,%s1,%s2", name, (Operand{Kind: OpMem, Mem: memory}).String(), bank, bank)
					original := x86OrderingHintGoBytes(t, "amd64", "TEXT original(SB),4,$0-0\n"+row+"\nRET\n")
					if original[0] != 0xc4 && original[0] != 0xc5 {
						t.Fatal("actual Go no longer emitted VEX", row, original)
					}
					for _, mode := range []int{32, 64} {
						for _, segment := range []Reg{"", FS, GS} {
							t.Run(fmt.Sprintf("%s/mode%d/segment%s", row, mode, segment), func(t *testing.T) {
								code := append([]byte(nil), original[:len(original)-1]...)
								if segment != "" {
									prefix := byte(0x64)
									if segment == GS {
										prefix = 0x65
									}
									code = append([]byte{prefix}, code...)
								}
								ins, length, known, err := decodedX86DwordToQwordMultiplyInstruction(code, mode)
								if mode == 32 && memory.Base == "R13" {
									if !known || err == nil {
										t.Fatal("VEX extended address acquired mode32 binding")
									}
									return
								}
								want := memory
								want.Segment = segment
								if !known || err != nil || length != len(code) || !ins.x86Encoded || ins.Args[0].Kind != OpMem || !reflect.DeepEqual(ins.Args[0].Mem, want) {
									t.Fatal("VEX source displacement incorrectly scaled", row, ins, err, want)
								}
							})
						}
					}
				}
			}
		}
	}
}
