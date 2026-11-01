package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// These controls belong to the existing private-role owner, not another source
// observer. Every case still uses an actual typed declaration and all three
// translation APIs. O2 constants are logical byte/value checks, not execution.
func x86X87FloatingStoresUseOnlyCheckedByteRoles(t *testing.T) {
	t.Helper()
	for _, target := range x86RawReturnTargets {
		for _, op := range []string{"FMOVF", "FMOVFP", "FMOVD", "FMOVDP"} {
			width, scalar, tuple := 4, "float", "{ i16, i16 }"
			want := []uint64{0, 0x3f80}
			declaration := "func Value(gate uint64) (lo,hi uint16)"
			if strings.HasPrefix(op, "FMOVD") {
				width, scalar, tuple = 8, "double", "{ i32, i32 }"
				want, declaration = []uint64{0, 0x3ff00000}, "func Value(gate uint64) (lo,hi uint32)"
			}
			pop := "FMOVDP F0,F0\n"
			if strings.HasSuffix(op, "P") {
				pop = ""
			}
			body := "MOVL gate+4(FP),AX\nFLD1\n" + op + " F0,lo+8(FP)\n" + pop + "RET"
			_, _, _, source := x86ResultInitializationFixture(t, target.arch, declaration, body)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(target.triple+"/"+op+"/cross-fields/"+api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("checked x87 store did not span every independent numerical field", err)
					}
					probe := fmt.Sprintf("\ndefine %s @Probe() {\n %%r = call %s @Value(i64 0)\n ret %s %%r\n}\n", tuple, tuple, tuple)
					x86ScalarFPNamedConstantResult(t, ir+probe, "Probe", want)
				})
			}
			if width == 4 {
				for _, interior := range []int{0, 1, 4} {
					declaration := "func Value(gate uint64) float64"
					body := fmt.Sprintf("MOVL gate+4(FP),AX\nMOVL $0,ret+8(FP)\nMOVL $0,ret+12(FP)\nFLD1\n%s F0,ret+%d(FP)\n%sRET",
						op, 8+interior, pop)
					_, _, _, source := x86ResultInitializationFixture(t, target.arch, declaration, body)
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(fmt.Sprintf("%s/%s/interior-%d/%s", target.triple, op, interior, api), func(t *testing.T) {
							ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, api)
							if err != nil || ir == "" {
								t.Fatal("checked x87 store lost the untouched double-result bytes", err)
							}
							probe := "\ndefine i64 @Probe() {\n %r = call double @Value(i64 0)\n %b = bitcast double %r to i64\n ret i64 %b\n}\n"
							x86ScalarFPNamedConstantResult(t, ir+probe, "Probe", []uint64{uint64(0x3f800000) << uint(8*interior)})
						})
					}
				}
			}
			// A source-defined F0 is necessary but never supplies permission to
			// write padding, pointers, parameters or an incomplete result.
			paddedOffset := 16
			if target.arch == "386" {
				paddedOffset = 12
			}
			paddedTail := fmt.Sprintf("MOVB $0,a+8(FP)\nMOVL $0,b+%d(FP)\nMOVL $0,b+%d(FP)\n", paddedOffset, paddedOffset+4)
			partialDeclaration := "func Value(gate uint64) uint64"
			if width == 8 {
				partialDeclaration = "func Value(gate uint64) (a,b,c uint32)"
			}
			for _, row := range []struct{ name, declaration, body string }{
				{"padding", "func Value(gate uint64) (a byte,b uint64)", "FLD1\n" + op + " F0,padding+9(FP)\n" + pop + paddedTail},
				{"pointer", "func Value(gate uint64) *byte", "FLD1\n" + op + " F0,ret+8(FP)\n" + pop},
				{"parameter-write", "func Value(gate uint64) uint64", "FLD1\n" + op + " F0,gate+0(FP)\n" + pop + "MOVL $0,ret+8(FP)\nMOVL $0,ret+12(FP)\n"},
				{"unknown-F0", "func Value(gate uint64) float64", op + " F0,ret+8(FP)\n" + pop + "MOVL $0,ret+12(FP)\n"},
				{"partial-result", partialDeclaration, "FLD1\n" + op + " F0,ret+8(FP)\n" + pop},
				{"outside-result", "func Value(gate uint64) uint64", fmt.Sprintf("FLD1\n%s F0,ret+%d(FP)\n%sMOVL $0,ret+8(FP)\nMOVL $0,ret+12(FP)\n", op, 17-width, pop)},
			} {
				body := "MOVL gate+4(FP),AX\n" + row.body + "RET"
				_, _, _, source := x86ResultInitializationFixture(t, target.arch, row.declaration, body)
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(target.triple+"/"+op+"/reject-"+row.name+"/"+api, func(t *testing.T) {
						ir, err := x86ScalarFPBitViewAPI(t, source, row.declaration, target.arch, target.triple, api)
						if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
							t.Fatalf("%s store supplied missing %s authority: output=%t error=%v", scalar, row.name, ir != "", err)
						}
					})
				}
			}
		}
	}
}
