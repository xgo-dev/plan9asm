package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

const x86SDKLiteralLowBitFixture = `TEXT ·entry<ABIInternal>(SB),4,$0-1
MOVQ $first<>(SB),AX
MOVQ $second<>(SB),BX
ORQ BX,AX
TESTQ $15,AX
SETEQ AX
RET
`

func TestGoX86SDKLiteralGuaranteedMinimumMaskedPredicate(t *testing.T) {
	sig := FuncSig{Name: "example.invalid/independent.entry", Ret: I1,
		Frame: FrameLayout{Results: []FrameSlot{{Type: I1, Index: 0, Field: -1}}}}
	for _, alias := range []string{"MOVQ", "MOVD", "MOVDQ2Q"} {
		for _, offset := range []string{"", "+1"} {
			source := strings.ReplaceAll(strings.ReplaceAll(x86SDKLiteralLowBitFixture, "MOVQ", alias), "$first<>(SB)", "$first<>"+offset+"(SB)")
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			original, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			facts, err := proveX86SDKLiteralAccessesWithMinima(file.Funcs[0], sig, "amd64", map[string]int64{"first<>": 256, "second<>": 256}, map[string]uint32{"first<>": 32, "second<>": 32})
			if err != nil || len(facts) != 4 || !reflect.DeepEqual(file, original) {
				t.Fatalf("sealed minimum low bits did not close complete unchanged predicate (%s/%s): %v %+v", alias, offset, err, facts)
			}
			if _, err := proveX86SDKLiteralAccesses(file.Funcs[0], sig, "amd64", map[string]int64{"first<>": 256, "second<>": 256}); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("ordinary literal bytes acquired a linked minimum", err)
			}
		}
	}
	for _, op := range []string{"TESTB", "TESTW", "TESTL", "TESTQ"} {
		for _, condition := range amd64RegisterBoolConditions {
			source := strings.ReplaceAll(strings.ReplaceAll(x86SDKLiteralLowBitFixture, "TESTQ", op), "SETEQ", condition)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			if facts, err := proveX86SDKLiteralAccessesWithMinima(file.Funcs[0], sig, "amd64", map[string]int64{"first<>": 256, "second<>": 256}, map[string]uint32{"first<>": 32, "second<>": 32}); err != nil || len(facts) != 4 {
				t.Fatal("complete TEST width/SETcc predicate row rejected", op, condition, err)
			}
		}
	}
	for _, floor := range []uint32{1, 2, 4, 8, 16, 32} {
		text := strings.ReplaceAll(x86SDKLiteralLowBitFixture, "TESTQ $15,AX", fmt.Sprintf("TESTQ $%d,AX", floor-1))
		file, err := Parse(ArchAMD64, text)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := proveX86SDKLiteralAccessesWithMinima(file.Funcs[0], sig, "amd64", map[string]int64{"first<>": int64(floor), "second<>": int64(floor)}, map[string]uint32{"first<>": floor, "second<>": floor}); err != nil {
			t.Fatal("genuine finite minimum including mask-zero floor rejected", floor, err)
		}
	}
}

func TestGoX86SDKLiteralMinimumDoesNotGrantGeneralAddressBits(t *testing.T) {
	sig := FuncSig{Name: "example.invalid/independent.entry", Ret: I1,
		Frame: FrameLayout{Results: []FrameSlot{{Type: I1, Index: 0, Field: -1}}}}
	for name, changed := range map[string]string{
		"high mask":            strings.ReplaceAll(x86SDKLiteralLowBitFixture, "$15,AX", "$32,AX"),
		"arbitrary comparison": strings.ReplaceAll(x86SDKLiteralLowBitFixture, "TESTQ $15,AX", "CMPQ AX,$15"),
		"general and":          strings.ReplaceAll(x86SDKLiteralLowBitFixture, "TESTQ $15,AX", "ANDQ $15,AX"),
		"mixed incoming OR":    strings.ReplaceAll(x86SDKLiteralLowBitFixture, "MOVQ $second<>(SB),BX", "MOVQ $123,BX"),
		"vector escape":        strings.ReplaceAll(x86SDKLiteralLowBitFixture, "TESTQ $15,AX", "MOVQ AX,X0\nTESTQ $15,AX"),
		"frame escape":         strings.ReplaceAll(x86SDKLiteralLowBitFixture, "TESTQ $15,AX", "MOVQ AX,ret+0(FP)\nTESTQ $15,AX"),
		"mixed OR memory":      strings.ReplaceAll(x86SDKLiteralLowBitFixture, "TESTQ $15,AX", "MOVOU (AX),X0\nTESTQ $15,AX"),
		"partial carrier":      strings.ReplaceAll(x86SDKLiteralLowBitFixture, "ORQ BX,AX", "MOVB $0,AL\nORQ BX,AX"),
		"cyclic carrier":       strings.ReplaceAll(x86SDKLiteralLowBitFixture, "ORQ BX,AX", "again:\nORQ BX,AX\nJMP again"),
		"arbitrary raw":        strings.ReplaceAll(x86SDKLiteralLowBitFixture, "ORQ BX,AX", "BYTE $0x90\nORQ BX,AX"),
		"address return":       strings.ReplaceAll(x86SDKLiteralLowBitFixture, "SETEQ AX", ""),
		"ABI0 context":         strings.ReplaceAll(x86SDKLiteralLowBitFixture, "<ABIInternal>", ""),
	} {
		t.Run(name, func(t *testing.T) {
			file, err := Parse(ArchAMD64, changed)
			if err != nil {
				t.Fatal(err)
			}
			facts, err := proveX86SDKLiteralAccessesWithMinima(file.Funcs[0], sig, "amd64", map[string]int64{"first<>": 256, "second<>": 256}, map[string]uint32{"first<>": 32, "second<>": 32})
			if facts != nil || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("minimum-floor predicate invented other address/entry/memory permission", facts, err)
			}
		})
	}
	file, err := Parse(ArchAMD64, x86SDKLiteralLowBitFixture)
	if err != nil {
		t.Fatal(err)
	}
	for _, minima := range []map[string]uint32{
		nil, {"first<>": 32}, {"first<>": 32, "second<>": 8}, {"first<>": 31, "second<>": 32}, {"first<>": 64, "second<>": 32},
	} {
		facts, err := proveX86SDKLiteralAccessesWithMinima(file.Funcs[0], sig, "amd64", map[string]int64{"first<>": 256, "second<>": 256}, minima)
		if facts != nil || !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("missing, insufficient or claimed-higher floor granted a predicate", minima, facts, err)
		}
	}
}

func TestGoX86SDKLiteralMinimumAddressFLAGSReaders(t *testing.T) {
	sig := FuncSig{Name: "example.invalid/independent.entry", Ret: I1, Frame: FrameLayout{Results: []FrameSlot{{Type: I1, Index: 0, Field: -1}}}}
	check := func(body string, accepted bool) {
		t.Helper()
		file, err := Parse(ArchAMD64, body)
		if err != nil {
			t.Fatal(err)
		}
		facts, err := proveX86SDKLiteralAccessesWithMinima(file.Funcs[0], sig, "amd64", map[string]int64{"first<>": 256, "second<>": 256}, map[string]uint32{"first<>": 32, "second<>": 32})
		if accepted && err != nil || !accepted && (facts != nil || !errors.Is(err, ErrProbeNeedsContext)) {
			t.Errorf("full address FLAG reader accepted=%v: %s: %v", accepted, body, err)
		}
	}
	for _, op := range amd64RegisterBoolConditions {
		body := strings.ReplaceAll(strings.ReplaceAll(x86SDKLiteralLowBitFixture, "TESTQ $15,AX\n", ""), "SETEQ", op)
		check(body, op == "SETCC" || op == "SETCS" || op == "SETOC" || op == "SETOS")
	}
	for _, op := range []string{"JCC", "JCS", "JO", "JNO", "JE", "JNE", "JS", "JNS", "JP", "JNP", "JGE", "JL", "JG", "JLE", "JHI", "JLS"} {
		body := strings.ReplaceAll(x86SDKLiteralLowBitFixture, "TESTQ $15,AX\nSETEQ AX\nRET", op+" alternative\nSETCC AX\nRET\nalternative:\nSETCS AX\nRET")
		check(body, op == "JCC" || op == "JCS" || op == "JO" || op == "JNO")
	}
	for op, spec := range x86ConditionalMoveSpecs {
		body := strings.ReplaceAll(x86SDKLiteralLowBitFixture, "TESTQ $15,AX\nSETEQ AX", "MOVQ $0,DX\nMOVQ $1,CX\n"+string(op)+" CX,DX\nMOVQ DX,AX")
		check(body, spec.condition == "CC" || spec.condition == "CS" || spec.condition == "OC" || spec.condition == "OS")
	}
	check(strings.ReplaceAll(x86SDKLiteralLowBitFixture, "TESTQ $15,AX", "MOVQ $0,CX\nMOVQ $1,DX\nCMPQ CX,DX"), true)
	check(strings.ReplaceAll(x86SDKLiteralLowBitFixture, "TESTQ $15,AX", "MOVQ $0,CX\nMOVQ $1,DX\nCMPQ CX,DX\nJCC skipped\nTESTQ $15,AX\nskipped:"), true)
	check(strings.ReplaceAll(x86SDKLiteralLowBitFixture, "TESTQ $15,AX", "JCC skipped\nTESTQ $15,AX\nskipped:"), false)
	check(strings.ReplaceAll(x86SDKLiteralLowBitFixture, "TESTQ $15,AX", "LAHF\nTESTQ $15,AX"), false)
}
