package plan9asm

import (
	"errors"
	"testing"
)

func TestX86CustomHelperBoolConsumerRequiresExactGraphAndTransport(t *testing.T) {
	for _, mutation := range []string{
		"unchanged", "missing-graph", "source", "declaration", "emitted-registers",
		"emitted-return", "attributes", "supplied-attributes", "mode", "target", "unowned-helper",
	} {
		t.Run(mutation, func(t *testing.T) {
			file, options := x86CustomHelperBoolFixture(t, "CMPL SI,DI\nSETLT (AX)", "i386-unknown-linux-gnu")
			source, err := prepareX86ABI0BoolCalls(file, options)
			if err != nil || source == nil {
				t.Fatal("complete actual custom-helper producer failed", err)
			}
			sig := options.Sigs["comparebody"]
			consumer := &amd64Ctx{
				fpScalarSource: file.Funcs[1], fpSourceSig: sig, sig: sig,
				fpBoolCallSource: source, goarch: "386", targetTriple: options.TargetTriple,
			}
			switch mutation {
			case "missing-graph":
				consumer.fpBoolCallSource = nil
			case "source":
				consumer.fpScalarSource.Instrs = append([]Instr(nil), file.Funcs[1].Instrs...)
				consumer.fpScalarSource.Instrs[1].Raw += " // different original helper"
			case "declaration":
				consumer.fpSourceSig.ArgRegs = []Reg{CX, DI, AX}
			case "emitted-registers":
				consumer.sig.ArgRegs = []Reg{CX, DI, AX}
			case "emitted-return":
				consumer.sig.Ret = I1
			case "attributes":
				consumer.sig.Attrs = "nounwind"
			case "supplied-attributes":
				consumer.fpSourceSig.Attrs = "nounwind"
			case "mode":
				consumer.goarch = "amd64"
			case "target":
				consumer.targetTriple = "i686-pc-windows-msvc"
			case "unowned-helper":
				consumer.fpScalarSource.Sym = "foreign<>"
			}
			err = consumer.checkLoweredScalarFPResultInitialization()
			if mutation == "unchanged" {
				if err != nil {
					t.Fatal("proved helper was reinterpreted as ordinary ABI0", err)
				}
			} else if !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("changed or missing graph/transport supplied a helper proof", err)
			}
		})
	}
}
