package plan9asm

import (
	"errors"
	"strings"
	"testing"
)

func TestTranslate386BoundCompleteGoAssemblerForms(t *testing.T) {
	for _, target := range []struct {
		name   string
		triple string
	}{
		{name: "linux-386", triple: "i386-unknown-linux-gnu"},
		{name: "windows-386", triple: "i686-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			source := "TEXT boundforms(SB),4,$16-0\n"
			for _, op := range []string{"BOUNDW", "BOUNDL"} {
				if op == "BOUNDW" {
					source += "\tMOVL $0x00100000, 0(SP)\n"
				} else {
					source += "\tMOVL $0, 0(SP)\n\tMOVL $16, 4(SP)\n"
				}
				for _, reg := range []string{"AX", "BX", "CX", "DX", "BP", "SI", "DI"} {
					source += "\tMOVL $3, " + reg + "\n\t" + op + " " + reg + ", 0(SP)\n"
				}
				source += "\tLEAL 0(SP), BX\n\t" + op + " AX, 0(BX)\n"
			}
			source += "\tRET\n"
			// The official Yrl row also encodes SP. Its numerical value is
			// unavailable when translating a frame into private storage.
			original := strings.Replace(source, "\tRET\n", "\tBOUNDW SP, 0(SP)\n\tBOUNDL SP, 0(SP)\n\tRET\n", 1)
			requireX86GoAssemblerResult(t, "386", original, true)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				TargetTriple: target.triple,
				Goarch:       "386",
				Sigs:         map[string]FuncSig{"boundforms": {Name: "boundforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{".byte 0x66, 0x62, 0x01", ".byte 0x62, 0x01", `"{ax},{cx},~{memory},~{dirflag},~{fpsr},~{flags}"`} {
				if !strings.Contains(ll, want) {
					t.Fatalf("translated BOUND family missing %q:\n%s", want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "bound-"+target.name+".ll", "bound-"+target.name+".o", ll)
		})
	}
}

func TestTranslate386BoundRequiresInitializedInputs(t *testing.T) {
	const triple = "i386-unknown-linux-gnu"
	const source = "TEXT ·check(SB),4,$8-0\nMOVL $3,AX\nMOVL $0,0(SP)\nMOVL $16,4(SP)\nBOUNDL AX,0(SP)\nRET\n"
	for _, row := range []struct {
		name, old, replacement string
	}{
		{"non-numerical SP", "BOUNDL AX", "BOUNDL SP"},
		{"undefined value", "MOVL $3,AX", "NOP"},
		{"undefined upper bound", "MOVL $16,4(SP)", "NOP"},
		{"out of range bounds", "BOUNDL AX,0(SP)", "BOUNDL AX,4(SP)"},
	} {
		t.Run(row.name, func(t *testing.T) {
			bad := strings.Replace(source, row.old, row.replacement, 1)
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, bad, "func check()", "386", triple, api)
				if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("%s: unbound BOUND input: %v", api, err)
				}
			}
		})
	}
}

func TestTranslate386BoundNamedFrameReadsBothEndpoints(t *testing.T) {
	const source = `TEXT ·check(SB),4,$8-0
MOVL $3, AX
MOVL $0x00100000, short-4(SP)
BOUNDW AX, short-4(SP)
MOVL $0, bounds-8(SP)
MOVL $16, bounds-4(SP)
BOUNDL AX, bounds-8(SP)
RET
`
	goAssemblerOracleOutput(t, "386", source, "", true)
	for _, triple := range []string{"i386-unknown-linux-gnu", "i686-pc-windows-msvc"} {
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(triple+"/"+api, func(t *testing.T) {
				ir, err := x86ScalarFPBitViewAPI(t, source, "func check()", "386", triple, api)
				if err != nil {
					t.Fatal(err)
				}
				x86NumericNativeAddressObject(t, ir, triple)
			})
		}
	}
}

func TestTranslateX86BoundRejectsFormsOutsideGoAssemblerTables(t *testing.T) {
	tests := []struct {
		goarch      string
		triple      string
		instruction string
	}{
		{goarch: "amd64", triple: "x86_64-unknown-linux-gnu", instruction: "BOUNDW AX, 0(BX)"},
		{goarch: "amd64", triple: "x86_64-unknown-linux-gnu", instruction: "BOUNDL AX, 0(BX)"},
		{goarch: "386", triple: "i386-unknown-linux-gnu", instruction: "BOUNDL X0, 0(BX)"},
		{goarch: "386", triple: "i386-unknown-linux-gnu", instruction: "BOUNDW $1, 0(BX)"},
		{goarch: "386", triple: "i386-unknown-linux-gnu", instruction: "BOUNDL AX, BX"},
		{goarch: "386", triple: "i386-unknown-linux-gnu", instruction: "BOUNDL.Z AX, 0(BX)"},
	}
	for _, test := range tests {
		t.Run(test.goarch+"_"+strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(test.instruction), func(t *testing.T) {
			file, err := Parse(ArchAMD64, "TEXT bad(SB),NOSPLIT,$0-0\n\t"+test.instruction+"\n\tRET\n")
			if err == nil {
				_, err = Translate(file, Options{
					TargetTriple: test.triple,
					Goarch:       test.goarch,
					Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
				})
			}
			if err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's BOUND tables for %s", test.instruction, test.goarch)
			}
		})
	}
}
