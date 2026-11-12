package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

// Keep the original complete module's four BYTE streams, raw RETs and literal
// tails. Its scalar upper-copy inputs are unbound; that must not hide packed
// source-local literal regressions, which are tested independently below.
func x86RawRoundOriginalModuleObjects(t *testing.T, file *File, source, triple string, signatures map[string]FuncSig) string {
	t.Helper()
	if len(file.Funcs) != 4 || len(signatures) != 4 {
		t.Fatal("original raw ROUND module changed")
	}
	var declarations strings.Builder
	for _, function := range file.Funcs {
		if signature, found := signatures[function.Sym]; !found || signature.Ret != Void {
			t.Fatal("original raw ROUND signature changed", function.Sym)
		}
		fmt.Fprintf(&declarations, "func %s()\n", function.Sym)
	}
	for _, api := range []string{"text", "module", "Go"} {
		if ir, err := x86ScalarFPBitViewAPI(t, source, declarations.String(), "amd64", triple, api); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("whole raw ROUND module borrowed its bare scalar upper input", api, err)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for index, function := range file.Funcs {
		var one strings.Builder
		for _, instruction := range function.Instrs {
			one.WriteString(instruction.Raw + "\n")
		}
		name := function.Sym
		x86LEAActualTargetGoObject(t, "amd64", triple, one.String())
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(fmt.Sprintf("original-%d/%s", index, api), func(t *testing.T) {
				ir, err := x86ScalarFPBitViewAPI(t, one.String(), "func "+name+"()", "amd64", triple, api)
				if index >= 2 {
					if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("bare raw scalar ROUND invented its upper-copy bytes", err)
					}
					return
				}
				if err != nil {
					t.Fatal("self-contained packed RIP literal must retain public translation", err)
				}
				for _, level := range []string{"-O0", "-O2"} {
					x86PackedStringCompileObject(t, llc, triple, ir, level)
				}
			})
		}
	}
	return x86UnboundVoidRawScalarFormatObject(t, source, "amd64", triple)
}

func TestX86RoundInitializedRawLiteralAndNamedCounterparts(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, triple := range []string{"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc"} {
		for _, kind := range []string{"raw-initialized", "named-initialized"} {
			t.Run(triple+"/"+kind, func(t *testing.T) {
				var source, declarations strings.Builder
				for index, op := range []string{"VROUNDPS", "VROUNDPD", "VROUNDSS", "VROUNDSD"} {
					name := fmt.Sprint("InitializedRawRound", index)
					if kind == "raw-initialized" {
						fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-0\nVPXOR Y0,Y0,Y0\n", name)
						for _, value := range x86RawVEXRoundConstant(byte(0x08+index), index < 2) {
							fmt.Fprintf(&source, "BYTE $%#02x\n", value)
						}
						fmt.Fprintf(&declarations, "func %s()\n", name)
					} else {
						fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-24\nMOVQ out+0(FP),DX\nMOVQ a+8(FP),AX\n", name)
						if index < 2 {
							fmt.Fprintf(&source, "%s $9,(AX),Y2\n", op)
						} else {
							source.WriteString("MOVQ upper+16(FP),BX\nVMOVUPS (BX),X0\n")
							fmt.Fprintf(&source, "%s $9,(AX),X0,X2\n", op)
						}
						source.WriteString("VMOVUPS Z2,(DX)\nRET\n")
						fmt.Fprintf(&declarations, "func %s(out *[64]byte,a *[32]byte,upper *[16]byte)\n", name)
					}
				}
				x86LEAActualTargetGoObject(t, "amd64", triple, source.String())
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(api, func(t *testing.T) {
						ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), "amd64", triple, api)
						if err != nil {
							t.Fatal("complete initialized ROUND literal/named counterpart rejected", kind, err)
						}
						for _, level := range []string{"-O0", "-O2"} {
							x86PackedStringCompileObject(t, llc, triple, ir, level)
						}
					})
				}
			})
		}
	}
}

func TestX86RawRoundLiteralRetainsSourceDataAndReturnBoundaries(t *testing.T) {
	for index, op := range []string{"VROUNDPS", "VROUNDPD", "VROUNDSS", "VROUNDSD"} {
		t.Run(op, func(t *testing.T) {
			var source strings.Builder
			source.WriteString("TEXT RawRoundBound(SB),4,$0-0\nVPXOR Y0,Y0,Y0\n")
			for _, value := range x86RawVEXRoundConstant(byte(0x08+index), index < 2) {
				fmt.Fprintf(&source, "BYTE $%#02x\n", value)
			}
			for _, change := range []string{"DATA", "immediate", "raw-origin", "read-width", "frame", "unbound-upper"} {
				file, err := Parse(ArchAMD64, source.String())
				if err != nil {
					t.Fatal(err)
				}
				normalized, err := normalizeX86RawFile(file, "amd64")
				if err != nil || len(normalized.Data) != 1 {
					t.Fatal("original literal lost its bound source DATA", err)
				}
				var raw *Instr
				for ordinal := range normalized.Funcs[0].Instrs {
					if normalized.Funcs[0].Instrs[ordinal].Op == Op(op) {
						raw = &normalized.Funcs[0].Instrs[ordinal]
					}
				}
				if raw == nil {
					t.Fatal("original raw ROUND disappeared")
				}
				switch change {
				case "DATA":
					normalized.Data[0].Payload[0] ^= 1
				case "immediate":
					raw.Args[0].Imm ^= 1
				case "raw-origin":
					raw.x86SourceRaw = nil
				case "read-width":
					raw.x86RIPMemoryRead.width++
				case "frame":
					normalized.Funcs[0].FrameSize = 16
				case "unbound-upper":
					if index < 2 {
						return
					} // These packed forms have no upper input.
					// A changed scalar upper source must not inherit the original
					// decoded identity, even when its memory literal is unchanged.
					raw.Args[2].Reg = "X1"
				}
				for _, api := range []string{"text", "module"} {
					options := Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu", Sigs: map[string]FuncSig{"RawRoundBound": {Name: "RawRoundBound", Ret: Void}}}
					var ir string
					var err error
					if api == "text" {
						ir, err = Translate(normalized, options)
					} else {
						context := llvm.NewContext()
						module, moduleErr := TranslateModuleInContext(context, normalized, options)
						err = moduleErr
						if !module.IsNil() {
							ir = module.String()
							module.Dispose()
						}
						context.Dispose()
					}
					if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("edited literal/source/return borrowed raw ROUND authority", change, api, err)
					}
				}
			}
		})
	}
}
