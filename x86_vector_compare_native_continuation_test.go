package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// Independent ymm/yxm_q4, _yvpcmpeqb and _yvpcmpb native-source shapes.
// MMX's physical state and raw mode32 EVEX entries have separate owners.
func x86CompareNativeRows(arch string) []string {
	var rows []string
	for _, op := range []string{"PCMPEQB", "PCMPEQW", "PCMPEQL", "PCMPEQQ", "PCMPGTB", "PCMPGTW", "PCMPGTL", "PCMPGTQ"} {
		rows = append(rows, op+" 3(AX)(DX*2),X2")
	}
	for _, op := range []string{"VPCMPEQB", "VPCMPEQW", "VPCMPEQD", "VPCMPEQQ", "VPCMPGTB", "VPCMPGTW", "VPCMPGTD", "VPCMPGTQ",
		"VPCMPB", "VPCMPW", "VPCMPD", "VPCMPQ", "VPCMPUB", "VPCMPUW", "VPCMPUD", "VPCMPUQ"} {
		immediate := !strings.HasPrefix(op, "VPCMPEQ") && !strings.HasPrefix(op, "VPCMPGT")
		if arch == "386" && immediate {
			continue // Go's named mode32 frontend rejects the leading-immediate arity.
		}
		prefix := ""
		if immediate {
			prefix = "$4,"
		}
		for _, bank := range []string{"X", "Y", "Z"} {
			if bank != "Z" && !immediate {
				rows = append(rows, fmt.Sprintf("%s 3(AX)(DX*2),%s1,%s2", op, bank, bank))
			}
			for _, mask := range []string{"", "K1,"} {
				if arch == "386" && mask != "" {
					continue // A fourth named operand has no mode32 Go source encoding.
				}
				operands := fmt.Sprintf("%s3(AX)(DX*2),%s1,%sK2", prefix, bank, mask)
				rows = append(rows, op+" "+operands)
				if strings.HasSuffix(op, "D") || strings.HasSuffix(op, "Q") {
					rows = append(rows, op+".BCST "+operands)
				}
			}
		}
	}
	return rows
}

func x86CompareNativeFixture(arch, row string) (string, string) {
	word, move, maskMove := 8, "MOVQ", "KMOVQ"
	if arch == "386" {
		word, move, maskMove = 4, "MOVL", "KMOVD"
	}
	finish := "PEXTRD $0,X2,AX\n"
	if strings.HasSuffix(row, "K2") {
		finish = "KMOVD K2,AX\n"
	}
	return fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s p+0(FP),AX\n%s mask+%d(FP),CX\n%s CX,K1\n"+
			"MOVL $1,DX\nVPXORD Z1,Z1,Z1\nVPXORD Z2,Z2,Z2\n%s\n%sMOVL AX,ret+%d(FP)\nRET\n",
			2*word+4, move, move, word, maskMove, row, finish, 2*word),
		"func Value(p *[128]byte,mask uintptr) uint32"
}

func TestX86CompareNativeCompleteObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			rows := x86CompareNativeRows(target.arch)
			want := 168
			if target.arch == "386" {
				want = 60
			}
			if len(rows) != want {
				t.Fatal("complete independent native compare inventory changed", len(rows), want)
			}
			for start := 0; start < len(rows); start += 64 {
				end := start + 64
				if end > len(rows) {
					end = len(rows)
				}
				t.Run(fmt.Sprint(start/64), func(t *testing.T) {
					var source, declarations strings.Builder
					var names []string
					for index := start; index < end; index++ {
						body, declaration := x86CompareNativeFixture(target.arch, rows[index])
						name := fmt.Sprintf("CompareNative%d", index)
						names = append(names, name)
						source.WriteString(strings.ReplaceAll(body, "Value", name))
						declarations.WriteString(strings.ReplaceAll(declaration, "Value", name) + "\n")
					}
					x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(api, func(t *testing.T) {
							ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
							if err != nil {
								t.Fatal("initialized native compare cannot publish its result", err)
							}
							for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
								x86CompactExpandRequireAllDefinitions(t, text, names)
								for _, level := range []string{"-O0", "-O2"} {
									x86PackedStringCompileObject(t, llc, target.triple, text, level)
								}
							}
						})
					}
				})
			}
		})
	}
}

func TestX86CompareNativeCannotBorrowInputFacts(t *testing.T) {
	for _, row := range x86CompareNativeRows("amd64") {
		source, declaration := x86CompareNativeFixture("amd64", row)
		pkg := mustGoPackage(t, "compare", "package compare\n"+declaration)
		file := mustParseX86RawReturn(t, source)
		signatures, err := goSigsForAsmFile(pkg, file, func(name string) string {
			return strings.TrimPrefix(name, "·")
		}, "amd64", nil, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := CheckX86ABI0ResultInitialization(file.Funcs[0], signatures["Value"], "amd64"); !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("declaration-only compare borrowed its paired native emitter", row, err)
		}
		variants := map[string]string{
			"unknown-pointer": strings.Replace(source, "p+0(FP),AX", "p+0(FP),DI", 1),
			"unknown-index":   strings.Replace(source, "MOVL $1,DX\n", "", 1),
			"numeric-pointer": strings.Replace(source, "MOVL $1,DX", "MOVL $42,AX\nMOVL $1,DX", 1),
		}
		if strings.Contains(row, "K1,") {
			variants["unknown-mask"] = strings.Replace(source, "KMOVQ CX,K1\n", "", 1)
		}
		vector := "Z1"
		if !strings.HasPrefix(row, "V") {
			vector = "Z2"
		}
		variants["unknown-vector"] = strings.Replace(source, fmt.Sprintf("VPXORD %s,%s,%s\n", vector, vector, vector), "", 1)
		for name, changed := range variants {
			t.Run(row+"/"+name, func(t *testing.T) {
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, changed, declaration, "amd64", "x86_64-unknown-linux-gnu", api)
					if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("compare acquired missing native/vector/mask inputs", api, err)
					}
				}
			})
		}
	}
}
