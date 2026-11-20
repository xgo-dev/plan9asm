package plan9asm

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestX86ScalarLiteralMode32ObjectFixtureKeepsPhysicalBank(t *testing.T) {
	for _, wide := range []int{32, 64} {
		t.Run(fmt.Sprint(wide), func(t *testing.T) {
			original := x86ScalarLiteralForms(wide == 64)
			if !reflect.DeepEqual(x86ScalarLiteralTargetForms(wide, "amd64"), original) {
				t.Fatal("AMD64 original literal/value/mask denominator changed")
			}
			var expected []x86ScalarLiteralForm
			for _, form := range original {
				if form.register == 31 {
					if form.value.zero && form.masked {
						continue
					}
					form.register = 7
				}
				expected = append(expected, form)
			}
			if !reflect.DeepEqual(x86ScalarLiteralTargetForms(wide, "386"), expected) {
				t.Fatal("physical controls changed original literal/value/mask axes beyond the explicit register/source-role split")
			}
			file, err := Parse(ArchAMD64, x86ScalarLiteralAssembly(wide, "386"))
			if err != nil {
				t.Fatal(err)
			}
			for _, function := range file.Funcs {
				for _, instruction := range function.Instrs {
					for _, operand := range instruction.Args {
						if operand.Kind != OpReg {
							continue
						}
						index, vector := amd64VectorRegisterIndex(operand.Reg, amd64VectorByteWidth(operand.Reg))
						if vector && index >= 8 {
							t.Errorf("LLVM object fixture borrowed unbound mode32 bank: %s / %s", function.Sym, instruction.Raw)
						}
					}
				}
			}
			want := 28
			if wide == 64 {
				want = 46 // six low-bank masked positive-zero literals are Go-invalid.
			}
			if len(file.Funcs) != want {
				t.Fatalf("physical fixture functions=%d, want %d with rejected source axes retained separately", len(file.Funcs), want)
			}
		})
	}
}

func TestX86ScalarLiteralMode32HighSourceRetainsContext(t *testing.T) {
	vectorLiterals := x86ScalarLiteralActualGoRewriteSet(t)
	for _, bank := range []string{"X", "Y"} {
		t.Run("originalCarrier"+bank, func(t *testing.T) {
			source := fmt.Sprintf("TEXT literal(SB),4,$0-0\nVMOVUPS (AX),%s31\nRET\n", bank)
			// Both historical/current assemblers must actually emit this
			// accepted high-bank carrier; a V literal rejection on old Go
			// is separate and cannot stand in for this original object.
			x86ScalarLiteralGoListing(t, "386", source)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			if _, recognized, err := amd64PackedVectorMoveProperties(file.Funcs[0].Instrs[1], "386"); !recognized || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("accepted original carrier acquired physical mode32 identity: recognized=%t err=%v", recognized, err)
			}
		})
	}
	checked := 0
	for _, form := range x86ScalarLiteralForms(true) {
		if form.register != 31 {
			continue
		}
		checked++
		t.Run(form.name, func(t *testing.T) {
			// This is the exact high-bank source from the original object
			// fixture, including its packed input/output carriers. Frontend
			// acceptance is not a physical mode32 bank certificate.
			source := x86ScalarLiteralAssemblyForForms(64, "386", []x86ScalarLiteralForm{form})
			listing, err := x86ScalarLiteralExpectedGoListing(t, "386", source, vectorLiterals)
			if (err == nil) != vectorLiterals {
				t.Fatalf("actual selected SDK high-bank source: %v\n%s", err, listing)
			}
			t.Logf("original high-bank sourceSHA=%x listingSHA=%x accepted=%t\n%s", sha256.Sum256([]byte(source)), sha256.Sum256([]byte(listing)), vectorLiterals, source)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			name := "literal." + form.name
			sig := FuncSig{Name: name, Args: []LLVMType{Ptr, Ptr}, Ret: Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
					{Offset: 4, Type: Ptr, Index: 1, Field: -1},
				}},
			}
			for _, triple := range []string{"i386-unknown-linux-gnu", "i386-pc-windows-msvc"} {
				ir, err := Translate(file, Options{Goarch: "386", TargetTriple: triple,
					Sigs:       map[string]FuncSig{name: sig},
					ResolveSym: func(symbol string) string { return strings.Replace(symbol, "·", "literal.", 1) },
				})
				if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
					t.Fatalf("%s original high-bank carrier acquired a physical binding or IR: %v", triple, err)
				}
			}
		})
	}
	if checked != 24 {
		t.Fatalf("original high-bank denominator=%d, want 24", checked)
	}
}

func TestX86ScalarLiteralMode32ZeroMaskSourceEncoding(t *testing.T) {
	vectorLiterals := x86ScalarLiteralActualGoRewriteSet(t)
	for _, op := range []string{"VMOVSS", "VMOVSD"} {
		for _, value := range x86ScalarLiteralValues[:3] {
			for _, register := range []int{7, 8, 31} {
				for _, shape := range []struct{ suffix, mask string }{
					{}, {mask: "K1,"}, {suffix: ".Z", mask: "K1,"},
				} {
					instruction := fmt.Sprintf("%s%s $%s,%sX%d", op, shape.suffix, value.text, shape.mask, register)
					t.Run(instruction, func(t *testing.T) {
						zeroRewrite := value.zero && register < 16
						accepted := vectorLiterals && !(zeroRewrite && (register >= 8 || shape.mask != ""))
						source := "TEXT literal(SB),4,$0-0\n" + instruction + "\nRET\n"
						listing, err := x86ScalarLiteralExpectedGoListing(t, "386", source, accepted)
						if (err == nil) != accepted {
							t.Fatalf("selected SDK zero/mask rewrite: %v\n%s", err, listing)
						}
						t.Logf("actual zero/mask sourceSHA=%x listingSHA=%x accepted=%t\n%s", sha256.Sum256([]byte(source)), sha256.Sum256([]byte(listing)), accepted, source)
						if !accepted {
							return // an actual source rejection, not an object or Skip.
						}
						prefix := "c5"
						if register >= 16 || shape.mask != "" {
							prefix = "62"
						} else if zeroRewrite {
							prefix = "0f"
						}
						found := false
						for _, line := range strings.Split(listing, "\n") {
							fields := strings.Fields(line)
							if len(fields) >= 2 && fields[0] == "0x0000" && len(fields[1]) == 2 {
								found = true
								if fields[1] != prefix {
									t.Fatalf("actual encoder prefix=%s, want %s\n%s", fields[1], prefix, listing)
								}
								break
							}
						}
						if !found {
							t.Fatalf("accepted object lost its actual instruction bytes\n%s", listing)
						}
					})
				}
			}
		}
	}
}
