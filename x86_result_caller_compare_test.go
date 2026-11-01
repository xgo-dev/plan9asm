package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestX86CallerAddressCMPCompleteTypedParticipants(t *testing.T) {
	for _, width := range []string{"B", "W", "L", "Q"} {
		for _, alias := range []string{"MOVQ", "MOVD", "MOVDQ2Q"} {
			for _, operands := range []string{"AX,BX", "DX,AX", "DX,$0xf8"} {
				body := alias + " AX,DX\nCMP" + width + " " + operands + "\nSETEQ AX"
				for _, api := range []string{"text", "module", "Go"} {
					if _, err := x86ScalarFPBitViewAPI(t, x86CallerAddressRegisterSource(body), "func view(p,q *byte) bool\n", "amd64", "x86_64-unknown-linux-gnu", api); err != nil {
						t.Errorf("%s/%s/%s/%s: actual caller CMP rejected: %v", width, alias, operands, api, err)
					}
				}
			}
		}
	}
	for _, body := range []string{
		"CMPB AH,BH\nSETCS AX",
		"MOVQ AX,DI\nMOVQ BX,R8\nCMPB BH,R8\nSETEQ AX", // REX BH is physical DI low byte.
		"MOVQ AX,DX\nLEAQ 16(DX),DX\nCMPQ DX,BX\nSETGT AX",
		"CMPQ AX,BX\nJE other\nMOVQ AX,DX\nJMP joined\nother:\nMOVQ BX,DX\njoined:\nCMPB DX,$0xf8\nSETHI AX",
		"MOVQ AX,DX\nagain:\nCMPQ DX,BX\nJE done\nMOVQ BX,DX\nJMP again\ndone:\nSETEQ AX",
	} {
		for _, api := range []string{"text", "module", "Go"} {
			if _, err := x86ScalarFPBitViewAPI(t, x86CallerAddressRegisterSource(body), "func view(p,q *byte) bool\n", "amd64", "x86_64-unknown-linux-gnu", api); err != nil {
				t.Error(api, body, err)
			}
		}
	}
}

func TestX86CallerAddressCMPOnlyDefinesOriginalFlags(t *testing.T) {
	for _, width := range []string{"B", "W", "L", "Q"} {
		file, err := Parse(ArchAMD64, "TEXT ·view(SB),4,$0-0\nCMP"+width+" AX,BX\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		state := x86ResultState{}
		state.callerAddressGP[0], state.callerAddressGP[3] = true, true
		before := state
		accepted, known := x86ResultCallerAddressTest(file.Funcs[0].Instrs[1], &state, nil, "amd64")
		defined := state.flags
		state.flags = before.flags
		if !accepted || !known || defined != x86ByteFlagsAll || !reflect.DeepEqual(before, state) {
			t.Fatal("CMP address predicate changed a non-FLAGS must-domain", width, accepted, known, state)
		}
	}
}

func TestX86CallerAddressCMPCompleteExistingFlagConsumers(t *testing.T) {
	check := func(body string) {
		t.Helper()
		for _, api := range []string{"text", "module", "Go"} {
			if _, err := x86ScalarFPBitViewAPI(t, x86CallerAddressRegisterSource(body), "func view(p,q *byte) bool\n", "amd64", "x86_64-unknown-linux-gnu", api); err != nil {
				t.Error(api, body, err)
			}
		}
	}
	for _, op := range amd64RegisterBoolConditions {
		check("CMPQ AX,BX\n" + op + " AX")
	}
	for op := range x86ConditionalMoveSpecs {
		check("CMPQ AX,BX\nMOVQ $1,CX\nMOVQ $0,DX\n" + string(op) + " CX,DX\nMOVQ DX,AX")
	}
	for _, op := range []string{"JCC", "JCS", "JO", "JNO", "JE", "JNE", "JS", "JNS", "JP", "JNP", "JGE", "JL", "JG", "JLE", "JHI", "JLS"} {
		check("CMPQ AX,BX\n" + op + " yes\nMOVB $0,AX\nJMP done\nyes:\nMOVB $1,AX\ndone:")
	}
	check("CMPQ AX,BX\nLAHF\nSETEQ AX") // AH is now a modeled numerical output, not a caller address.
}

func TestX86CallerAddressCMPCompleteGoRegisterViews(t *testing.T) {
	wordRegisters := strings.Fields("AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R14 R15")
	byteRegisters := append(append([]string(nil), wordRegisters...), strings.Fields("AL AH BL BH CL CH DL DH BPB SIB DIB R8B R9B R10B R11B R12B R13B R14B R15B")...)
	for _, width := range []string{"B", "W", "L", "Q"} {
		registers := wordRegisters
		if width == "B" {
			registers = byteRegisters
		}
		for _, name := range registers {
			t.Run(width+"/"+name, func(t *testing.T) {
				root, valid := amd64FullRegBase(Reg(name))
				if !valid {
					t.Fatal("registered Go view lost its physical bank", name)
				}
				body := "CMP" + width + " " + name + ",AX\nSETEQ AX"
				ordinary := root != SP && root != BP
				if ordinary {
					body = "MOVQ BX," + string(root) + "\n" + body
				}
				source := x86CallerAddressRegisterSource(body)
				requireAMD64RegisterResultGoObject(t, source)
				for _, api := range []string{"text", "module", "Go"} {
					_, err := x86ScalarFPBitViewAPI(t, source, "func view(p,q *byte) bool\n", "amd64", "x86_64-unknown-linux-gnu", api)
					if ordinary && err != nil || !ordinary && !errors.Is(err, ErrProbeNeedsContext) {
						t.Error(api, "registered address view vs native SP/BP role differs", err)
					}
				}
			})
		}
	}
}

func TestX86CallerAddressCMPRejectsOtherParticipantsAndContracts(t *testing.T) {
	for name, body := range map[string]string{
		"unknown DX": "CMPQ AX,DX\nSETEQ AX", "native g": "CMPQ AX,R14\nSETEQ AX",
		"numeric register":    "MOVQ $1,DX\nCMPQ AX,DX\nSETEQ AX",
		"partial copy":        "MOVW AX,DX\nCMPW AX,DX\nSETEQ AX",
		"partial overwrite":   "MOVQ BX,DX\nMOVB $1,DX\nCMPB AX,DX\nSETEQ AX",
		"one lost join":       "CMPQ AX,BX\nJE other\nMOVQ AX,DX\nJMP joined\nother:\nMOVW BX,DX\njoined:\nCMPB DX,AX\nSETEQ AX",
		"wrong REX high byte": "MOVQ BX,R8\nCMPB AH,R8\nSETEQ AX",
		"immediate direction": "CMPQ $1,AX\nSETEQ AX",
		"pointer vector":      "CMPQ AX,BX\nMOVQ AX,X0\nSETEQ AX",
		"pointer result":      "CMPQ AX,BX", "noncanonical result": "CMPQ AX,BX\nMOVB $2,AX",
		"memory participant":                  "CMPQ AX,(BX)\nSETEQ AX",
		"unknown call":                        "CMPQ AX,BX\nCALL external(SB)\nSETEQ AX",
		"raw entry":                           "BYTE $0x90\nCMPQ AX,BX\nSETEQ AX",
		"AH overwrite revokes caller address": "CMPQ AX,BX\nLAHF\nCMPQ AX,BX\nSETEQ AX",
	} {
		t.Run(name, func(t *testing.T) {
			for _, api := range []string{"text", "module", "Go"} {
				if _, err := x86ScalarFPBitViewAPI(t, x86CallerAddressRegisterSource(body), "func view(p,q *byte) bool\n", "amd64", "x86_64-unknown-linux-gnu", api); err == nil {
					t.Error(api, "CMP predicate granted another source/entry/result role")
				}
			}
		})
	}
	file, err := Parse(ArchAMD64, "TEXT ·view(SB),4,$0-0\nCMPQ AX,BX\nRET\n")
	if err != nil {
		t.Fatal(err)
	}
	state := x86ResultState{}
	state.callerAddressGP[0], state.pointerGP[3] = true, true // Literal/closure/native identity is not caller provenance.
	if accepted, _ := x86ResultCallerAddressTest(file.Funcs[0].Instrs[1], &state, nil, "amd64"); accepted || state.flags != 0 {
		t.Fatal("opaque non-caller participant acquired physical address comparison")
	}
}

func TestX86CallerAddressCMPActualABI0Imports(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		word, move := x86ResultPointerWord(arch), "MOVQ"
		widths := []string{"B", "W", "L", "Q"}
		if arch == "386" {
			move, widths = "MOVL", widths[:3]
		}
		for _, width := range widths {
			body := fmt.Sprintf("%s x+0(FP),AX\n%s y+%d(FP),BX\nCMP%s AX,BX\nSETEQ DX\nMOVBLZX DX,DX\nMOVL DX,ret0+%d(FP)\nRET", move, move, word, width, 2*word)
			_, file, sig, source := x86ResultInitializationFixture(t, arch, "func Value(x,y *byte) uint32", body)
			goAssemblerOracleOutput(t, arch, source, "", true)
			if err := checkX86ScalarFPResultInitialization(file.Funcs[0], sig, arch); err != nil {
				t.Error(arch, width, err)
			}
			changed, err := Parse(Arch(arch), strings.Replace(source, move+" y+", "MOVB y+", 1))
			if err != nil {
				t.Fatal(err)
			}
			if err := checkX86ScalarFPResultInitialization(changed.Funcs[0], sig, arch); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("partial caller pointer field acquired a CMP participant", err)
			}
		}
	}
}
