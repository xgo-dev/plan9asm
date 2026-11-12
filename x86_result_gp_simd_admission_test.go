package plan9asm

import (
	"errors"
	"fmt"
	"go/types"
	"strings"
	"testing"
)

// This is the original no-probe failure, not the separately observed PEXTRD
// route. Both byte observers already reject the result; ordinary admission
// must not forget to invoke that whole-function proof.
func TestX86ResultGPSIMDPlainUnknownReturnNeedsWholeFunctionProof(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		move, word, triple := "MOVD", 8, "x86_64-unknown-linux-gnu"
		if arch == "386" {
			move, word, triple = "MOVL", 4, "i386-unknown-linux-gnu"
		}
		declaration := "func view(c byte) uint32\n"
		source := fmt.Sprintf("TEXT ·view(SB),4,$0-%d\nMOVB c+0(FP),AX\n%s AX,X0\nMOVL $0,BX\nMOVL X0,BX\nMOVL BX,ret+%d(FP)\nRET\n", word+4, move, word)
		pkg := mustGoPackage(t, "bitview", "package bitview\n"+declaration)
		sig, err := DeriveGoFuncABI0Signature("view", pkg.Types.Scope().Lookup("view").(*types.Func), arch, types.SizesFor("gc", arch))
		if err != nil {
			t.Fatal(err)
		}
		file, err := Parse(ArchAMD64, source)
		if err != nil {
			t.Fatal(err)
		}
		for _, check := range []func(Func, FuncSig, string) error{CheckX86ABI0ResultInitialization, checkX86ScalarFPResultInitialization} {
			if err := check(file.Funcs[0], sig, arch); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("leaf incorrectly initialized unknown result bytes", err)
			}
		}
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(arch+"/"+api, func(t *testing.T) {
				ir, err := x86ScalarFPBitViewAPI(t, source, declaration, arch, triple, api)
				if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
					t.Fatalf("plain GP/X bypassed complete result proof: IR bytes=%d error=%v", len(ir), err)
				}
			})
		}
	}
}

func x86ResultGPSIMDAdmissionSource(t *testing.T, arch, declaration, body string) string {
	t.Helper()
	pkg := mustGoPackage(t, "bitview", "package bitview\n"+declaration)
	sig, err := DeriveGoFuncABI0Signature("view", pkg.Types.Scope().Lookup("view").(*types.Func), arch, types.SizesFor("gc", arch))
	if err != nil || len(sig.Frame.Results) != 1 {
		t.Fatal("actual scalar result layout is unavailable", err)
	}
	slot := sig.Frame.Results[0]
	body = strings.ReplaceAll(body, "RESULT", fmt.Sprint(slot.Offset))
	return fmt.Sprintf("TEXT ·view(SB),4,$0-%d\n%s\nRET\n", slot.Offset+x86FrameScalarBytes(slot.Type, arch), body)
}

func x86ResultGPSIMDAdmissionAPIs(t *testing.T, arch, source, declaration string, pass bool) {
	t.Helper()
	triple := "x86_64-unknown-linux-gnu"
	if arch == "386" {
		triple = "i386-unknown-linux-gnu"
	}
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source, declaration, arch, triple, api)
			if pass {
				if err != nil || ir == "" {
					t.Fatal("complete numerical result rejected", err)
				}
			} else if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
				t.Fatalf("uninitialized result admitted: IR bytes=%d error=%v", len(ir), err)
			}
		})
	}
}

func TestX86ResultGPSIMDAdmissionScalarReturnFamilyThreeAPIs(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, op := range []string{"MOVL", "MOVQ", "MOVD", "MOVDQ2Q", "VMOVD", "VMOVQ"} {
			if arch == "386" && (op == "MOVQ" || op == "MOVD" || op == "MOVDQ2Q") {
				continue // The complete Go grammar has no such GP mode32 row.
			}
			for _, result := range []struct{ typ, store string }{
				{"uint8", "MOVB"}, {"uint16", "MOVW"}, {"uint32", "MOVL"}, {"uint64", "MOVQ"},
			} {
				for _, input := range []struct{ name, body string }{
					{"complete", "MOVL $0x11223344,AX\n"},
					{"low byte only", "MOVB c+0(FP),AX\n"},
					{"unknown", ""},
				} {
					t.Run(arch+"/"+op+"/"+result.typ+"/"+input.name, func(t *testing.T) {
						declaration := "func view(c byte) " + result.typ + "\n"
						finish := result.store + " BX,ret+RESULT(FP)"
						if arch == "386" && result.typ == "uint64" {
							// There is no qword GP in mode32. The original X low
							// qword is the same typed full-width numerical value.
							finish = "MOVQ X0,ret+RESULT(FP)"
						}
						body := input.body + op + " AX,X0\n" + op + " X0,BX\n" + finish
						source := x86ResultGPSIMDAdmissionSource(t, arch, declaration, body)
						pass := input.name == "complete" || input.name == "low byte only" && result.typ == "uint8"
						x86ResultGPSIMDAdmissionAPIs(t, arch, source, declaration, pass)
					})
				}
			}
		}
	}
}

func TestX86ResultGPSIMDAdmissionCompleteOfficialRegisterRows(t *testing.T) {
	rows := x86OfficialGPSIMDTransferRows(t)
	for _, op := range []string{"MOVL", "MOVQ", "MOVD", "MOVDQ2Q"} {
		rows = append(rows, op+" AX,X0", op+" X0,AX")
		if op != "MOVL" {
			rows = append(rows, op+" X0,X1")
		}
	}
	if len(rows) != 23 {
		t.Fatal("complete official register-row denominator changed", len(rows))
	}
	for _, row := range rows {
		for _, complete := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/complete%t", row, complete), func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, row)
				form, known, err := x86GPSIMDTransferProperties(ins, "amd64")
				if !known || err != nil {
					t.Fatal("original typed row is unavailable", known, err)
				}
				body := "MOVB c+0(FP),AX\n"
				if complete {
					body = "MOVL $0x11223344,AX\n"
				}
				if form.sourceX {
					seed := "MOVL"
					if index, _ := amd64ParseXReg(ins.Args[0].Reg); index >= 16 {
						seed = "VMOVD"
					}
					body += seed + " AX," + string(ins.Args[0].Reg) + "\n"
				}
				body += row + "\n"
				destination := ins.Args[1].Reg
				if form.destinationX {
					sink := "MOVL"
					if index, _ := amd64ParseXReg(destination); index >= 16 {
						sink = "VMOVD"
					}
					body += sink + " " + string(destination) + ",BX\n"
					destination = BX
				}
				body += "MOVL " + string(destination) + ",ret+RESULT(FP)"
				declaration := "func view(c byte) uint32\n"
				source := x86ResultGPSIMDAdmissionSource(t, "amd64", declaration, body)
				x86ResultGPSIMDAdmissionAPIs(t, "amd64", source, declaration, complete)
			})
		}
	}
}

func TestX86ResultGPSIMDAdmissionOrdinaryRolesAndCachedProof(t *testing.T) {
	for _, test := range []struct {
		name, row, typ string
		change         func(*Instr)
		proof          bool
	}{
		{"ordinary GP to X", "MOVL AX,X0", "uint32", nil, true},
		{"ordinary X to GP", "MOVQ X0,AX", "uint32", nil, true},
		{"ordinary X to X", "MOVD X0,X1", "uint32", nil, true},
		// MMX has its own mandatory whole-source obligation. It must reject
		// this uninitialized, unclosed source rather than bypass preflight.
		{"physical MMX", "MOVQ X0,M0", "uint32", nil, true},
		{"decoder origin", "VMOVD AX,X0", "uint32", func(ins *Instr) { ins.x86Encoded = true }, false},
		{"raw source origin", "MOVL AX,X0", "uint32", func(ins *Instr) { ins.x86SourceRaw = &x86SourceRawInstruction{} }, false},
		{"raw only", "VMOVW AX,X0", "uint32", func(ins *Instr) { ins.x86Encoded = true }, false},
		// Bool has its independent mandatory canonical-byte proof even when
		// no instruction happens to trigger the ordinary integer result route.
		{"bool canonical proof", "MOVL AX,X0", "bool", nil, true},
		{"floating is separate", "MOVL AX,X0", "float32", nil, false},
		{"pointer is separate", "MOVL AX,X0", "*byte", nil, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			declaration := "func view() " + test.typ + "\n"
			pkg := mustGoPackage(t, "bitview", "package bitview\n"+declaration)
			sig, err := DeriveGoFuncABI0Signature("view", pkg.Types.Scope().Lookup("view").(*types.Func), "amd64", types.SizesFor("gc", "amd64"))
			if err != nil {
				t.Fatal(err)
			}
			source := x86ResultGPSIMDAdmissionSource(t, "amd64", declaration, test.row)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			if test.change != nil {
				test.change(&file.Funcs[0].Instrs[1])
			}
			original := fmt.Sprintf("%#v", file)
			consumer := &amd64Ctx{fpScalarSource: file.Funcs[0], sig: sig, fpResults: sig.Frame.Results, goarch: "amd64"}
			first := consumer.validateScalarFPSourceViews()
			second := consumer.validateScalarFPSourceViews()
			if test.proof {
				if !consumer.fpScalarChecked || !errors.Is(first, ErrProbeNeedsContext) || first != second {
					t.Fatal("ordinary numerical result omitted or repeated its cached whole proof", first, second)
				}
			} else if consumer.fpScalarChecked || first != nil || second != nil {
				t.Fatal("new ordinary trigger borrowed a disjoint result or native role", first, second)
			}
			if fmt.Sprintf("%#v", file) != original {
				t.Fatal("preflight mutated original source")
			}
		})
	}
}

func TestX86ResultGPSIMDAdmissionWholeSourcePathsWithoutProbe(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, test := range []struct {
			name, body string
			pass       bool
		}{
			{"one unknown branch", "MOVB c+0(FP),AX\nCMPB AX,$0\nJE joined\nMOVL $42,AX\njoined:\nMOVL AX,X0\nMOVL X0,BX\nMOVL BX,ret+RESULT(FP)", false},
			{"all branches define", "MOVB c+0(FP),AX\nCMPB AX,$0\nJE other\nMOVL $42,AX\nJMP joined\nother:\nMOVL $43,AX\njoined:\nMOVL AX,X0\nMOVL X0,BX\nMOVL BX,ret+RESULT(FP)", true},
			{"undefined result read", "MOVL ret+RESULT(FP),AX\nMOVL AX,X0\nMOVL X0,BX\nMOVL BX,ret+RESULT(FP)", false},
			{"unknown transfer subsequently cleared", "MOVL AX,X0\nPXOR X0,X0\nMOVL X0,BX\nMOVL BX,ret+RESULT(FP)", true},
		} {
			t.Run(arch+"/"+test.name, func(t *testing.T) {
				declaration := "func view(c byte) uint32\n"
				source := x86ResultGPSIMDAdmissionSource(t, arch, declaration, test.body)
				x86ResultGPSIMDAdmissionAPIs(t, arch, source, declaration, test.pass)
			})
		}
	}
}
