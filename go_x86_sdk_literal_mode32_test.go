package plan9asm

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

const x86SDKLiteral386Predicate = `TEXT ·entry(SB),4,$0-1
MOVL $first<>(SB),AX
MOVL $second<>(SB),BX
ORL BX,AX
TESTL $15,AX
SETEQ ret+0(FP)
RET
`

func x86SDKLiteral386Signature() FuncSig {
	return FuncSig{Name: "example.invalid/independent.entry", Ret: I1,
		Frame: FrameLayout{Results: []FrameSlot{{Type: I1, Index: 0, Field: -1}}}}
}

func TestGoX86SDKLiteral386MinimumMaskedABI0Predicate(t *testing.T) {
	for _, view := range []string{"TESTB $15,AX", "TESTB $15,AL", "TESTB $0,AH", "TESTW $15,AX", "TESTL $15,AX"} {
		for _, condition := range amd64RegisterBoolConditions {
			t.Run(view+"/"+condition, func(t *testing.T) {
				text := strings.ReplaceAll(strings.ReplaceAll(x86SDKLiteral386Predicate, "TESTL $15,AX", view), "SETEQ", condition)
				file, err := Parse(ArchAMD64, text)
				if err != nil {
					t.Fatal(err)
				}
				before, err := Parse(ArchAMD64, text)
				if err != nil {
					t.Fatal(err)
				}
				facts, err := proveX86SDKLiteralAccessesWithMinima(file.Funcs[0], x86SDKLiteral386Signature(), "386",
					map[string]int64{"first<>": 256, "second<>": 256}, map[string]uint32{"first<>": 32, "second<>": 32})
				if err != nil || len(facts) != 4 || !reflect.DeepEqual(file, before) {
					t.Fatal("complete 32-bit minimum/ABI0 predicate did not retain original source", facts, err)
				}
				if _, err := proveX86SDKLiteralAccesses(file.Funcs[0], x86SDKLiteral386Signature(), "386",
					map[string]int64{"first<>": 256, "second<>": 256}); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("ordinary literal binder gained a linked minimum", err)
				}
			})
		}
	}
}

func TestGoX86SDKLiteral386MinimumDoesNotGrantOtherRoles(t *testing.T) {
	for name, text := range map[string]string{
		"high-mask":   strings.ReplaceAll(x86SDKLiteral386Predicate, "$15,AX", "$32,AX"),
		"high-byte":   strings.ReplaceAll(x86SDKLiteral386Predicate, "TESTL $15,AX", "TESTB $1,AH"),
		"qword":       strings.ReplaceAll(x86SDKLiteral386Predicate, "ORL BX,AX", "ORQ BX,AX"),
		"partial":     strings.ReplaceAll(x86SDKLiteral386Predicate, "ORL BX,AX", "MOVB $0,AL\nORL BX,AX"),
		"vector":      strings.ReplaceAll(x86SDKLiteral386Predicate, "ORL BX,AX", "MOVL AX,X0\nORL BX,AX"),
		"memory":      strings.ReplaceAll(x86SDKLiteral386Predicate, "TESTL $15,AX", "MOVOU (AX),X0\nTESTL $15,AX"),
		"escape":      strings.ReplaceAll(x86SDKLiteral386Predicate, "TESTL $15,AX", "MOVL AX,ret+0(FP)\nTESTL $15,AX"),
		"mixed":       strings.ReplaceAll(x86SDKLiteral386Predicate, "MOVL $second<>(SB),BX", "MOVL $1,BX"),
		"raw":         strings.ReplaceAll(x86SDKLiteral386Predicate, "ORL BX,AX", "BYTE $0x90\nORL BX,AX"),
		"stale-flags": strings.ReplaceAll(x86SDKLiteral386Predicate, "TESTL $15,AX\n", ""),
		"loop":        strings.ReplaceAll(x86SDKLiteral386Predicate, "ORL BX,AX", "again:\nORL BX,AX\nJMP again"),
		"internal":    strings.ReplaceAll(x86SDKLiteral386Predicate, "·entry(SB)", "·entry<ABIInternal>(SB)"),
	} {
		t.Run(name, func(t *testing.T) {
			file, err := Parse(ArchAMD64, text)
			if err != nil {
				t.Fatal(err)
			}
			facts, err := proveX86SDKLiteralAccessesWithMinima(file.Funcs[0], x86SDKLiteral386Signature(), "386",
				map[string]int64{"first<>": 256, "second<>": 256}, map[string]uint32{"first<>": 32, "second<>": 32})
			if facts != nil || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("32-bit linked minimum invented a different source/address/result role", facts, err)
			}
		})
	}
}

func TestGoX86SDKLiteral386MinimumTypedEffectsAndCost(t *testing.T) {
	file, err := Parse(ArchAMD64, x86SDKLiteral386Predicate+"GLOBL first<>(SB),8,$256\nGLOBL second<>(SB),8,$256\n")
	if err != nil {
		t.Fatal(err)
	}
	options := Options{Goarch: "386", Sigs: map[string]FuncSig{file.Funcs[0].Sym: x86SDKLiteral386Signature()}}
	if !GoX86SDKLiteralAlignmentRequested(file, options) {
		t.Fatal("typed 32-bit original masked predicate did not request its independent producer")
	}
	for _, view := range []string{"TESTB $15,AX", "TESTB $15,AL", "TESTB $0,AH", "TESTW $15,AX", "TESTL $15,AX"} {
		text := strings.ReplaceAll(x86SDKLiteral386Predicate, "TESTL $15,AX", view)
		candidate, err := Parse(ArchAMD64, text+"GLOBL first<>(SB),8,$256\nGLOBL second<>(SB),8,$256\n")
		if err != nil || !GoX86SDKLiteralAlignmentRequested(candidate, options) {
			t.Fatal("original typed view did not request its independent producer", view, err)
		}
	}
	state := x86ResultState{}
	state.pointerGP[0], state.pointerGP[3] = true, true
	for _, row := range []struct {
		op    Op
		bytes int64
	}{{"ORL", 4}, {"TESTB", 1}, {"TESTW", 2}, {"TESTL", 4}} {
		text := string(row.op) + " $15,AX"
		if row.op == "ORL" {
			text = "ORL BX,AX"
		}
		parsed, err := Parse(ArchAMD64, "TEXT ·probe(SB),4,$0-0\n"+text+"\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		bits := &x86SDKLiteralLowBits{Operation: row.op, Mask: 15, Bytes: row.bytes, Symbol: "first<>"}
		if !x86ResultSDKLiteralLowBitStep(parsed.Funcs[0].Instrs[1], bits, &state, "386") {
			t.Fatal("typed 32-bit low-bit effect rejected", row.op)
		}
		if state.gp != [16]uint8{} || !state.pointerGP[0] {
			t.Fatal("minimum effect initialized numerical GP bytes or lost opaque identity")
		}
	}
}

func TestGoX86SDKLiteral386MinimumCopiesResiduesAndFloors(t *testing.T) {
	for name, materialize := range map[string]string{
		"MOVL":    "MOVL $first<>(SB),AX",
		"LEAL":    "LEAL first<>(SB),AX",
		"copy":    "MOVL $first<>(SB),CX\nMOVL CX,AX",
		"residue": "MOVL $first<>+3(SB),AX",
	} {
		t.Run(name, func(t *testing.T) {
			text := strings.ReplaceAll(x86SDKLiteral386Predicate, "MOVL $first<>(SB),AX", materialize)
			file, err := Parse(ArchAMD64, text)
			if err != nil {
				t.Fatal(err)
			}
			facts, err := proveX86SDKLiteralAccessesWithMinima(file.Funcs[0], x86SDKLiteral386Signature(), "386",
				map[string]int64{"first<>": 256, "second<>": 256}, map[string]uint32{"first<>": 32, "second<>": 32})
			if err != nil || len(facts) != 4 {
				t.Fatal("complete dword carrier lost its original minimum/residue", facts, err)
			}
			if name == "residue" && facts[3].LowBits.Value != 3 {
				t.Fatal("literal displacement lost guaranteed masked low bits")
			}
		})
	}
	file, err := Parse(ArchAMD64, x86SDKLiteral386Predicate)
	if err != nil {
		t.Fatal(err)
	}
	for _, floors := range []map[string]uint32{nil, {"first<>": 32}, {"first<>": 32, "second<>": 8}, {"first<>": 31, "second<>": 32}, {"first<>": 64, "second<>": 32}} {
		facts, err := proveX86SDKLiteralAccessesWithMinima(file.Funcs[0], x86SDKLiteral386Signature(), "386",
			map[string]int64{"first<>": 256, "second<>": 256}, floors)
		if facts != nil || !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("missing/insufficient/invented 32-bit floor created an address fact", facts, err)
		}
	}
}
