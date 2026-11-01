package plan9asm

import (
	"regexp"
	"strings"
	"testing"
)

func TestX86FPMovNativeDwordStoreExactValueAndDestination(t *testing.T) {
	for _, destination := range []string{"8(DI)", "example.i32(SB)"} {
		t.Run(destination, func(t *testing.T) {
			file, err := Parse(ArchAMD64, "TEXT native(SB),$0-0\nMOVL AX,"+destination+"\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			consumer, output := newAMD64CtxWithFuncForTest(t, file.Funcs[0], FuncSig{Name: "native", Ret: Void}, nil)
			consumer.goarch, consumer.targetTriple = "amd64", "x86_64-unknown-linux-gnu"
			if err := consumer.storeReg(AX, "81985529216486895"); err != nil {
				t.Fatal(err)
			}
			if destination == "8(DI)" {
				if err := consumer.storeReg(DI, "4096"); err != nil {
					t.Fatal(err)
				}
			}
			before := output.Len()
			instruction := file.Funcs[0].Instrs[1]
			known, terminated, err := consumer.lowerMov(instruction.Op, instruction)
			if !known || terminated || err != nil {
				t.Fatal("original native MOVL store was not lowered", err)
			}
			fragment := output.String()[before:]
			source := regexp.MustCompile(`(?m)^  (%[A-Za-z0-9_]+) = load i64, ptr ` + regexp.QuoteMeta(consumer.regSlot[AX]) + `$`).FindStringSubmatch(fragment)
			if source == nil {
				t.Fatal("native store lost its actual AX value", fragment)
			}
			value := regexp.MustCompile(`(?m)^  (%[A-Za-z0-9_]+) = trunc i64 ` + regexp.QuoteMeta(source[1]) + ` to i32$`).FindStringSubmatch(fragment)
			if value == nil {
				t.Fatal("native MOVL store lost its low-dword value", fragment)
			}
			pointer := `@"example.i32"`
			if destination == "8(DI)" {
				base := regexp.MustCompile(`(?m)^  (%[A-Za-z0-9_]+) = load i64, ptr ` + regexp.QuoteMeta(consumer.regSlot[DI]) + `$`).FindStringSubmatch(fragment)
				if base == nil {
					t.Fatal("native store lost its DI address", fragment)
				}
				offset := regexp.MustCompile(`(?m)^  (%[A-Za-z0-9_]+) = add i64 ` + regexp.QuoteMeta(base[1]) + `, 8$`).FindStringSubmatch(fragment)
				if offset == nil {
					t.Fatal("native store changed its eight-byte displacement", fragment)
				}
				address := regexp.MustCompile(`(?m)^  (%[A-Za-z0-9_]+) = inttoptr i64 ` + regexp.QuoteMeta(offset[1]) + ` to ptr$`).FindStringSubmatch(fragment)
				if address == nil {
					t.Fatal("native store lost its computed destination", fragment)
				}
				pointer = address[1]
			}
			want := "  store volatile i32 " + value[1] + ", ptr " + pointer + ", align 1\n"
			if strings.Count(fragment, "  store ") != 1 || !strings.HasSuffix(fragment, want) {
				t.Fatal("native store lost its exact value, destination, width, volatility or unaligned effect", fragment)
			}
		})
	}
}
