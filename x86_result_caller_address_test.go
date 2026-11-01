package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func x86CallerAddressRegisterSource(body string) string {
	return "TEXT ·view<ABIInternal>(SB),4,$0-17\n" + body + "\nRET\n"
}

func TestX86ResultCallerAddressPredicateActualTypedEntry(t *testing.T) {
	for _, width := range []string{"B", "W", "L", "Q"} {
		for _, move := range []string{"MOVQ", "MOVD", "MOVDQ2Q"} {
			body := move + " AX,DX\nLEAQ 16(DX),AX\nTEST" + width + " $0x70,AX\nSETEQ AX"
			for _, api := range []string{"text", "module", "Go"} {
				if _, err := x86ScalarFPBitViewAPI(t, x86CallerAddressRegisterSource(body), "func view(p *byte,n uint64) bool\n", "amd64", "x86_64-unknown-linux-gnu", api); err != nil {
					t.Errorf("%s/%s/%s actual typed caller address predicate: %v", width, move, api, err)
				}
			}
		}
	}
	for _, body := range []string{
		"TESTB $0xf0,AH\nSETEQ AX",
		"MOVOU (AX),X0\nTESTW $0xff0,AX\nSETEQ AX",
		"TESTW $0xff0,AX\nMOVOU (AX),X0\nSETEQ AX",
		"MOVQ AX,AX\nTESTW $0xff0,AX\nSETEQ AX",
		"MOVD AX,AX\nTESTW $0xff0,AX\nSETEQ AX",
		"MOVDQ2Q AX,AX\nTESTW $0xff0,AX\nSETEQ AX",
		"ADDQ $16,AX\nTESTW $0xff0,AX\nJE yes\nMOVB $0,AX\nJMP done\nyes:\nMOVB $1,AX\ndone:",
		"MOVQ AX,DX\nSUBQ $16,DX\nTESTQ BX,DX\nSETNE AX",
		"LEAQ (AX)(BX*8),DX\nTESTB DX,DX\nSETPS AX",
	} {
		for _, api := range []string{"text", "module", "Go"} {
			if _, err := x86ScalarFPBitViewAPI(t, x86CallerAddressRegisterSource(body), "func view(p *byte,n uint64) bool\n", "amd64", "x86_64-unknown-linux-gnu", api); err != nil {
				t.Errorf("%s complete MOV/LEA/TEST/branch source: %v", api, err)
			}
		}
	}
}

func TestX86ResultCallerAddressDomainIsNotOpaquePointerOrNumericalBytes(t *testing.T) {
	file, err := Parse(ArchAMD64, "TEXT ·view(SB),4,$0-0\nTESTW $0xff0,AX\nRET\n")
	if err != nil {
		t.Fatal(err)
	}
	ins := file.Funcs[0].Instrs[1]
	state := x86ResultState{}
	state.pointerGP[0] = true // An SDK literal/OR opaque carrier alone has no caller role.
	if accepted, _ := x86ResultCallerAddressTest(ins, &state, nil, "amd64"); accepted || state.flags != 0 {
		t.Fatal("opaque pointerGP supplied actual caller address bits")
	}
	state.callerAddressGP[0] = true
	state.pointerGP[0] = false
	if accepted, known := x86ResultCallerAddressTest(ins, &state, nil, "amd64"); !accepted || !known || state.gp[0] != 0 || state.flags&x86ByteFlagAF != 0 {
		t.Fatal("actual caller address observation manufactured GP bytes or AF", state)
	}
	if state.pointerGP[0] || x86ResultIncomingPointerAddressIdentity(Operand{Kind: OpMem, Mem: MemRef{Base: AX}}, &state, "amd64") {
		t.Fatal("address-bit observation created a native read identity")
	}
	state.pointerGP[0] = true
	other := state
	other.callerAddressGP[0] = false
	if merged := state.intersect(other); merged.callerAddressGP[0] || !merged.pointerGP[0] {
		t.Fatal("caller address and opaque pointer must-domains were conflated", merged)
	}
}

func TestX86ResultCallerAddressAllTypedFlagConsumersAndKills(t *testing.T) {
	check := func(body string) {
		t.Helper()
		for _, api := range []string{"text", "module", "Go"} {
			if _, err := x86ScalarFPBitViewAPI(t, x86CallerAddressRegisterSource(body), "func view(p *byte,n uint64) bool\n", "amd64", "x86_64-unknown-linux-gnu", api); err != nil {
				t.Error(api, body, err)
			}
		}
	}
	for _, op := range []string{"JCC", "JCS", "JO", "JNO", "JE", "JNE", "JS", "JNS", "JP", "JNP", "JGE", "JL", "JG", "JLE", "JHI", "JLS"} {
		check("TESTQ BX,AX\n" + op + " yes\nMOVB $0,AX\nJMP done\nyes:\nMOVB $1,AX\ndone:")
	}
	for op := range x86ConditionalMoveSpecs {
		check("TESTQ BX,AX\nMOVQ $1,CX\nMOVQ $0,DX\n" + string(op) + " CX,DX\nMOVQ DX,AX")
	}
	for _, body := range []string{"MOVB $1,AX", "MOVW $1,AX", "MOVL $1,AX", "MOVQ $1,AX", "MOVBQZX CX,AX", "PEXTRB $0,X0,M0", "PEXTRD $0,X0,M0", "PEXTRQ $0,X0,M0", "PEXTRW $0,X0,M0", "PEXTRW $0,X0,AX", "MOVQ X0,AX", "RDTSC", "LAHF"} {
		file, err := Parse(ArchAMD64, "TEXT ·effect(SB),4,$0-0\n"+body+"\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		if after := x86ResultCallerAddressesAfter(file.Funcs[0].Instrs[1], [16]bool{true}, nil, "amd64"); after[0] {
			t.Error("typed partial/full/implicit GP output kept stale caller address provenance", body)
		}
	}
}

func TestX86ResultCallerAddressSurvivesTypedUnwrittenGP(t *testing.T) {
	file, err := Parse(ArchAMD64, "TEXT ·independent(SB),4,$0-0\nMOVQ BX,X0\nPINSRW $4,CX,X0\nPSHUFHW $0,X0,X0\nMOVO X0,X1\nPXOR ·independent(SB),X0\nAESENC X0,X0\nCMPQ CX,$16\nSAHF\nRET\n")
	if err != nil {
		t.Fatal(err)
	}
	before := [16]bool{true}
	for _, ins := range file.Funcs[0].Instrs[1 : len(file.Funcs[0].Instrs)-1] {
		if after := x86ResultCallerAddressesAfter(ins, before, nil, "amd64"); after != before {
			t.Errorf("complete typed GP-unwritten shape unnecessarily lost a caller address: %s", ins.Raw)
		}
	}
	// This private effect query grants no numerical source/load permission:
	// original source/result transfer must already have accepted the effect.
}

func TestX86ResultCallerAddressPredicateCannotGrantAnotherContract(t *testing.T) {
	for name, body := range map[string]string{
		"partial-word":              "MOVW AX,DX\nTESTW $0xff0,DX\nSETEQ AX",
		"partial-byte":              "MOVB AX,DX\nTESTB $0x70,DX\nSETEQ AX",
		"partial-pointer-write":     "MOVW $0,AX\nTESTQ $0xff0,AX\nSETEQ AX",
		"pointer-as-numeric-result": "TESTW $0xff0,AX",
		"pointer-vector-escape":     "MOVQ AX,X0\nTESTW $0xff0,AX\nSETEQ AX",
		"unknown-memory":            "TESTW $0xff0,(DX)\nSETEQ AX",
		"unknown-index":             "LEAQ (AX)(DX*8),AX\nTESTW $0xff0,AX\nSETEQ AX",
		"unknown-callee":            "CALL external(SB)\nTESTW $0xff0,AX\nSETEQ AX",
		"unbound-flags":             "SETEQ AX",
		"unknown-AF":                "TESTW $0xff0,AX\nLAHF\nMOVB AH,AX",
		"stale-after-SET":           "TESTW $0xff0,AX\nSETEQ AX\nTESTQ $0xff0,AX\nSETEQ AX",
		"mixed-origin":              "TESTQ BX,BX\nJE preserve\nMOVQ $7,AX\npreserve:\nTESTW $0xff0,AX\nSETEQ AX",
		"raw":                       "BYTE $0x90\nTESTW $0xff0,AX\nSETEQ AX",
	} {
		t.Run(name, func(t *testing.T) {
			for _, api := range []string{"text", "module", "Go"} {
				if _, err := x86ScalarFPBitViewAPI(t, x86CallerAddressRegisterSource(body), "func view(p *byte,n uint64) bool\n", "amd64", "x86_64-unknown-linux-gnu", api); !errors.Is(err, ErrProbeNeedsContext) {
					t.Errorf("%s caller address observation granted another contract: %v", api, err)
				}
			}
		})
	}
}

func TestX86ResultCallerAddressPredicateTypedFPImport(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		word, move := x86ResultPointerWord(arch), "MOVQ"
		widths := []string{"B", "W", "L", "Q"}
		if arch == "386" {
			move, widths = "MOVL", widths[:3]
		}
		for _, width := range widths {
			body := fmt.Sprintf("%s x+0(FP),AX\nTEST%s $0x70,AX\nSETEQ DX\nMOVBLZX DX,DX\nMOVL DX,ret0+%d(FP)\nRET", move, width, word)
			_, file, sig, source := x86ResultInitializationFixture(t, arch, "func Value(x *byte) uint32", body)
			goAssemblerOracleOutput(t, arch, source, "", true)
			for _, check := range []func(Func, FuncSig, string) error{CheckX86ABI0ResultInitialization, checkX86ScalarFPResultInitialization} {
				if err := check(file.Funcs[0], sig, arch); err != nil {
					t.Errorf("%s TEST%s typed caller FP import: %v", arch, width, err)
				}
			}
			bad := strings.Replace(source, move+" x+0(FP),AX", "MOVB x+0(FP),AX", 1)
			changed, err := Parse(Arch(arch), bad)
			if err != nil {
				t.Fatal(err)
			}
			if err := checkX86ScalarFPResultInitialization(changed.Funcs[0], sig, arch); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("partial pointer FP bytes became an actual address", err)
			}
		}
	}
}
