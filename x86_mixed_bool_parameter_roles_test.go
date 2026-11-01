package plan9asm

import (
	"errors"
	"fmt"
	"testing"

	"github.com/xgo-dev/llvm"
)

// A typed pointer occupies its ABI0 parameter slot even when the function
// returns only numbers and a bool. The slot is not a numerical input, and the
// declaration alone supplies no pointee contents or physical caller frame.
func TestX86MixedBoolResultPointerAndAggregateParametersThreeAPIs(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		word, move, triple := int64(8), "MOVQ", "x86_64-unknown-linux-gnu"
		if arch == "386" {
			word, move, triple = 4, "MOVL", "i386-unknown-linux-gnu"
		}
		for _, row := range []struct {
			name, parameter, result string
			parameterWords          int64
			read                    string
		}{
			{name: "unused-pointer", parameter: "p *uint64", result: "uint64", parameterWords: 1},
			{name: "read-pointer", parameter: "p *uint64", result: "uint64", parameterWords: 1, read: "pointer"},
			{name: "unused-slice", parameter: "s []uint64", result: "uintptr", parameterWords: 3},
			{name: "slice-length", parameter: "s []uint64", result: "uintptr", parameterWords: 3, read: "length"},
			{name: "unused-string", parameter: "s string", result: "uintptr", parameterWords: 2},
			{name: "string-length", parameter: "s string", result: "uintptr", parameterWords: 2, read: "length"},
		} {
			declaration := fmt.Sprintf("func Value(%s) (n %s, ok bool)", row.parameter, row.result)
			_, _, sig, _ := x86ResultInitializationFixture(t, arch, declaration, "RET")
			resultBytes := word
			if row.result == "uint64" {
				resultBytes = 8
			}
			resultOffset := row.parameterWords * word
			if len(sig.Args) != 1 || len(sig.Frame.Params) != int(row.parameterWords) ||
				len(sig.Frame.Results) != 2 || sig.Frame.Params[0].Type != Ptr ||
				sig.Frame.Params[0].Offset != 0 || sig.Frame.Results[0].Offset != resultOffset ||
				sig.Frame.Results[1].Offset != resultOffset+resultBytes {
				t.Fatalf("%s/%s: actual typed parameter/result layout changed: %+v", arch, row.name, sig)
			}
			if row.parameterWords > 1 {
				expected := LLVMType(fmt.Sprintf("{ ptr, i%d }", 8*word))
				if row.parameterWords == 3 {
					expected = LLVMType(fmt.Sprintf("{ ptr, i%d, i%d }", 8*word, 8*word))
				}
				if sig.Args[0] != expected {
					t.Fatalf("%s/%s: aggregate parameter was scalarized: %s", arch, row.name, sig.Args[0])
				}
			}
			var body string
			switch row.read {
			case "pointer":
				body = fmt.Sprintf("%s p+0(FP),AX\n", move)
				for offset := int64(0); offset < resultBytes; offset += word {
					body += fmt.Sprintf("%s %d(AX),BX\n%s BX,n+%d(FP)\n", move, offset, move, resultOffset+offset)
				}
			case "length":
				body = fmt.Sprintf("%s s_len+%d(FP),AX\n%s AX,n+%d(FP)\n", move, word, move, resultOffset)
			default:
				for offset := int64(0); offset < resultBytes; offset += word {
					body += fmt.Sprintf("%s $5,n+%d(FP)\n", move, resultOffset+offset)
				}
			}
			body += fmt.Sprintf("MOVB $1,ok+%d(FP)\nRET", resultOffset+resultBytes)
			_, _, _, source := x86ResultInitializationFixture(t, arch, declaration, body)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(arch+"/"+row.name+"/"+api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, declaration, arch, triple, api)
					if err != nil || ir == "" {
						t.Fatalf("ordinary typed mixed result rejected: output=%t error=%v", ir != "", err)
					}
					context := llvm.NewContext()
					defer context.Dispose()
					module, err := parseIRModuleInContext(context, ir)
					if !module.IsNil() {
						defer module.Dispose()
					}
					if err != nil {
						t.Fatal("typed result module did not parse", err)
					}
					if err := llvm.VerifyModule(module, llvm.ReturnStatusAction); err != nil {
						t.Fatal("typed result module did not verify", err)
					}
				})
			}
		}
	}
}

func TestX86MixedBoolResultPointerParameterDoesNotGrantNumericalAuthority(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		word, move, triple := int64(8), "MOVQ", "x86_64-unknown-linux-gnu"
		if arch == "386" {
			word, move, triple = 4, "MOVL", "i386-unknown-linux-gnu"
		}
		declaration := "func Value(p *uint32) (n uintptr, ok bool)"
		for _, row := range []struct{ name, body string }{
			{"pointer-bits-as-number", fmt.Sprintf("%s p+0(FP),AX\n%s AX,n+%d(FP)\nMOVB $1,ok+%d(FP)\nRET", move, move, word, 2*word)},
			{"unknown-address", fmt.Sprintf("%s $7,AX\n%s (AX),BX\n%s BX,n+%d(FP)\nMOVB $1,ok+%d(FP)\nRET", move, move, move, word, 2*word)},
			{"noncanonical-bool", fmt.Sprintf("%s $5,n+%d(FP)\nMOVB $2,ok+%d(FP)\nRET", move, word, 2*word)},
			{"missing-number", fmt.Sprintf("MOVB $1,ok+%d(FP)\nRET", 2*word)},
		} {
			_, _, _, source := x86ResultInitializationFixture(t, arch, declaration, row.body)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(arch+"/"+row.name+"/"+api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, declaration, arch, triple, api)
					if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatalf("pointer layout granted unrelated NUM/canonical authority: output=%t error=%v", ir != "", err)
					}
				})
			}
		}
	}
}
