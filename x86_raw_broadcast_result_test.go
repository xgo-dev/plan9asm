package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

type x86RawBroadcastResultCase struct {
	name string
	code []byte
}

// Independent physical witnesses cover all scalar integer/float VEX and EVEX
// widths, no mask / merge / zero, plus both VEX 128-bit block broadcasts.
func x86RawBroadcastResultCases() []x86RawBroadcastResultCase {
	var rows []x86RawBroadcastResultCase
	for _, encoding := range []string{"VEX", "EVEX"} {
		for _, width := range []int{128, 256, 512} {
			for _, mask := range []int{0, 3, 7} {
				if encoding == "VEX" && (width == 512 || mask != 0) {
					continue
				}
				for _, op := range []Op{"VPBROADCASTB", "VPBROADCASTW", "VPBROADCASTD", "VPBROADCASTQ", "VBROADCASTSS", "VBROADCASTSD"} {
					if op == "VBROADCASTSD" && width == 128 {
						continue
					}
					var code []byte
					if strings.HasPrefix(string(op), "VP") {
						code, _ = x86RawBroadcastLiteral(op, encoding, width, mask, mask == 7)
					} else {
						code, _ = x86RawScalarFloatBroadcastLiteral(op == "VBROADCASTSD", encoding == "EVEX", width, mask, mask == 7)
					}
					rows = append(rows, x86RawBroadcastResultCase{
						name: fmt.Sprintf("%s_%s_%d_%d", op, encoding, width, mask), code: code,
					})
				}
			}
		}
	}
	return append(rows,
		x86RawBroadcastResultCase{"VBROADCASTF128", x86RawVBROADCASTF128Literal()},
		x86RawBroadcastResultCase{"VBROADCASTI128", x86RawVBROADCASTI128Literal()},
	)
}

func x86RawBroadcastResultSource(row x86RawBroadcastResultCase, initialized bool) string {
	var source strings.Builder
	fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-0\n", row.name)
	if initialized {
		source.WriteString("MOVL $5,AX\nKMOVD AX,K3\nKMOVD AX,K7\nVPXORD Z0,Z0,Z0\nVPXORD Z2,Z2,Z2\n")
	}
	for _, value := range row.code {
		fmt.Fprintf(&source, "BYTE $%#02x\n", value)
	}
	return source.String()
}

func TestX86RawBroadcastLiteralInitializedCompleteFamily(t *testing.T) {
	rows := x86RawBroadcastResultCases()
	if len(rows) != 64 {
		t.Fatal("independent literal family changed", len(rows))
	}
	var source, declarations strings.Builder
	for _, row := range rows {
		source.WriteString(x86RawBroadcastResultSource(row, true))
		fmt.Fprintf(&declarations, "func %s()\n", row.name)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		if target.arch != "amd64" {
			continue // RIP-relative addressing is an actual mode64 encoding role.
		}
		t.Run(target.triple, func(t *testing.T) {
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
					if err != nil {
						t.Fatal("source-local broadcast lost exact literal/mask/merge inputs", err)
					}
					for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
						for _, level := range []string{"-O0", "-O2"} {
							x86PackedStringCompileObject(t, llc, target.triple, text, level)
						}
					}
				})
			}
		})
	}
}

func TestX86RawBroadcastLiteralKeepsMissingInputsAndSourceIdentity(t *testing.T) {
	for _, row := range x86RawBroadcastResultCases() {
		source := x86RawBroadcastResultSource(row, true)
		declaration := "func " + row.name + "()"
		file, err := normalizeX86RawFile(mustParseX86RawReturn(t, source), "amd64")
		if err != nil {
			t.Fatal(err)
		}
		if err := checkX86ScalarFPResultInitialization(file.Funcs[0], FuncSig{Name: row.name, Ret: Void}, "amd64"); !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("standalone declaration query acquired a source-literal role", row.name, err)
		}
		for _, instruction := range file.Funcs[0].Instrs {
			if !instruction.x86RIPLiteral {
				continue
			}
			if instruction.Args[0].Kind == OpImm {
				instruction.Args[0].Imm ^= 1
			} else {
				instruction.Args[0].Sym += "changed"
			}
			options := Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu",
				Sigs:       map[string]FuncSig{row.name: {Name: row.name, Ret: Void}},
				ResolveSym: func(name string) string { return strings.TrimPrefix(name, "·") }}
			if ir, err := Translate(file, options); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("changed normalized literal borrowed original source", row.name, err)
			}
			break
		}
		if !strings.HasSuffix(row.name, "_3") && !strings.HasSuffix(row.name, "_7") {
			continue
		}
		variants := []string{
			x86RawBroadcastResultSource(row, false),
			strings.NewReplacer("KMOVD AX,K3\n", "", "KMOVD AX,K7\n", "").Replace(source),
		}
		if strings.HasSuffix(row.name, "_3") {
			variants = append(variants, strings.NewReplacer("VPXORD Z0,Z0,Z0\n", "", "VPXORD Z2,Z2,Z2\n", "").Replace(source))
		}
		for _, changed := range variants {
			for _, api := range []string{"text", "module", "Go"} {
				if ir, err := x86ScalarFPBitViewAPI(t, changed, declaration,
					"amd64", "x86_64-unknown-linux-gnu", api); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("constant input invented a missing mask or merge vector", row.name, api, err)
				}
			}
		}
	}
}

func TestX86RawBroadcastLiteralKeepsReturnAndDataBoundaries(t *testing.T) {
	for _, row := range x86RawBroadcastResultCases() {
		source := x86RawBroadcastResultSource(row, true)
		declaration := "func " + row.name + "()"
		for _, changed := range []string{
			strings.Replace(source, "$0-0", "$16-0", 1),
			strings.Replace(source, "MOVL $5,AX", "MOVQ $0,SP\nMOVL $5,AX", 1),
		} {
			for _, api := range []string{"text", "module", "Go"} {
				if ir, err := x86ScalarFPBitViewAPI(t, changed, declaration, "amd64", "x86_64-unknown-linux-gnu", api); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("literal broadcast waived an independent raw-return frame", row.name, api, err)
				}
			}
		}
		if !strings.HasSuffix(row.name, "128") {
			continue // Only the block forms materialize a separate DATA object.
		}
		file, err := normalizeX86RawFile(mustParseX86RawReturn(t, source), "amd64")
		if err != nil || len(file.Data) != 1 {
			t.Fatal("block literal lost its actual data object", row.name, err)
		}
		file.Data[0].Payload[0] ^= 1
		options := Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu",
			Sigs:       map[string]FuncSig{row.name: {Name: row.name, Ret: Void}},
			ResolveSym: func(name string) string { return strings.TrimPrefix(name, "·") }}
		if ir, err := Translate(file, options); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("changed DATA borrowed the original literal bytes", row.name, err)
		}
	}
}
