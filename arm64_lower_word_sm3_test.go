package plan9asm

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Independent Arm DDI 0602/LLVM MC rows, not derived from the production spec.
var arm64SM3OracleRows = []struct {
	name       string
	base, mask uint32
	registers  int
	lanes      int
}{
	{name: "sm3partw1", base: 0xce60c000, mask: 0xffe0fc00, registers: 3, lanes: 1},
	{name: "sm3partw2", base: 0xce60c400, mask: 0xffe0fc00, registers: 3, lanes: 1},
	{name: "sm3ss1", base: 0xce400000, mask: 0xffe08000, registers: 4, lanes: 1},
	{name: "sm3tt1a", base: 0xce408000, mask: 0xffe0cc00, registers: 3, lanes: 4},
	{name: "sm3tt1b", base: 0xce408400, mask: 0xffe0cc00, registers: 3, lanes: 4},
	{name: "sm3tt2a", base: 0xce408800, mask: 0xffe0cc00, registers: 3, lanes: 4},
	{name: "sm3tt2b", base: 0xce408c00, mask: 0xffe0cc00, registers: 3, lanes: 4},
}

type arm64SM3OracleCase struct {
	name, native string
	word         uint32
	kind         int
	d, n, m, a   int
	lane         int
}

func arm64SM3Case(kind, d, n, m, a, lane int) arm64SM3OracleCase {
	row := arm64SM3OracleRows[kind]
	word := row.base | uint32(d) | uint32(n)<<5 | uint32(m)<<16
	native := fmt.Sprintf("%s v%d.4s, v%d.4s, v%d.4s", row.name, d, n, m)
	if row.registers == 4 {
		word |= uint32(a) << 10
		native += fmt.Sprintf(", v%d.4s", a)
	} else if row.lanes == 4 {
		word |= uint32(lane) << 12
		native = fmt.Sprintf("%s v%d.4s, v%d.4s, v%d.s[%d]", row.name, d, n, m, lane)
	}
	return arm64SM3OracleCase{
		word: word, native: native, kind: kind, d: d, n: n, m: m, a: a, lane: lane,
	}
}

func arm64SM3AliasCases() []arm64SM3OracleCase {
	triples := [][4]int{{0, 0, 0}, {0, 0, 1}, {0, 1, 0}, {0, 1, 1}, {0, 1, 2}}
	// Every set partition of the four encoded SS1 registers, including all
	// three destination aliases, both source pairs and all-equal registers.
	quadruples := [][4]int{
		{0, 0, 0, 0}, {0, 0, 0, 1}, {0, 0, 1, 0}, {0, 0, 1, 1}, {0, 0, 1, 2},
		{0, 1, 0, 0}, {0, 1, 0, 1}, {0, 1, 0, 2}, {0, 1, 1, 0}, {0, 1, 1, 1},
		{0, 1, 1, 2}, {0, 1, 2, 0}, {0, 1, 2, 1}, {0, 1, 2, 2}, {0, 1, 2, 3},
	}
	var cases []arm64SM3OracleCase
	for kind, row := range arm64SM3OracleRows {
		aliases := triples
		if row.registers == 4 {
			aliases = quadruples
		}
		for lane := 0; lane < row.lanes; lane++ {
			for _, alias := range aliases {
				offset := len(cases) % 32
				tc := arm64SM3Case(kind, (offset+alias[0])%32, (offset+alias[1])%32,
					(offset+alias[2])%32, (offset+alias[3])%32, lane)
				tc.name = fmt.Sprintf("sm3case%d", len(cases))
				cases = append(cases, tc)
			}
		}
	}
	return cases
}

func TestARM64RawSM3CompleteEncodingSpace(t *testing.T) {
	if len(arm64RawSM3Specs) != 7 {
		t.Fatal("SM3 family is not the complete seven Arm operations")
	}
	count := 0
	for kind, row := range arm64SM3OracleRows {
		extraCount := row.lanes
		if row.registers == 4 {
			extraCount = 32
		}
		for d := 0; d < 32; d++ {
			for n := 0; n < 32; n++ {
				for m := 0; m < 32; m++ {
					for extra := 0; extra < extraCount; extra++ {
						a, lane := 0, 0
						if row.registers == 4 {
							a = extra
						} else if row.lanes == 4 {
							lane = extra
						}
						word := row.base | uint32(d) | uint32(n)<<5 | uint32(m)<<16
						if row.registers == 4 {
							word |= uint32(a) << 10
						} else if row.lanes == 4 {
							word |= uint32(lane) << 12
						}
						form, ok := decodeARM64RawSM3(word)
						if !ok || int(form.spec.kind) != kind || form.destination != d || form.first != n ||
							form.second != m || form.third != a || form.lane != lane {
							t.Fatalf("%s %#08x: %+v, %v", row.name, word, form, ok)
						}
						count++
					}
				}
			}
		}
	}
	if count != 1638400 {
		t.Fatalf("checked %d encodings, want 1638400", count)
	}
	for _, row := range arm64SM3OracleRows {
		for bit := uint(0); bit < 32; bit++ {
			if row.mask&(1<<bit) == 0 {
				continue
			}
			word := row.base ^ (1 << bit)
			expected := -1
			for kind, candidate := range arm64SM3OracleRows {
				if word&candidate.mask == candidate.base {
					expected = kind // A legitimate sibling is not a reserved encoding.
				}
			}
			form, ok := decodeARM64RawSM3(word)
			if ok != (expected >= 0) || ok && int(form.spec.kind) != expected {
				t.Fatalf("mutated fixed bit %d in %#08x: %+v, %v; expected kind %d", bit, word, form, ok, expected)
			}
		}
	}
	for _, word := range []uint32{0xce60c800, 0xcec08400, 0xce608c00, 0xce000000, 0xce40c000, 0xce608000} {
		if _, ok := decodeARM64RawSM3(word); ok {
			t.Fatalf("SM3 decoder captured adjacent or reserved encoding %#08x", word)
		}
	}
}

func TestARM64RawSM3LLVMEncodingAndOperandAxes(t *testing.T) {
	cases := arm64SM3AliasCases()
	for kind, row := range arm64SM3OracleRows {
		for lane := 0; lane < row.lanes; lane++ {
			for register := 0; register < 32; register++ {
				cases = append(cases, arm64SM3Case(kind, register, (register+1)%32,
					(register+2)%32, (register+3)%32, lane))
			}
		}
	}
	lines := make([]string, len(cases))
	for index, tc := range cases {
		lines[index] = tc.native
	}
	words := assembleARM64LLVMWords(t, lines, "+sm4")
	for index, word := range words {
		if word != cases[index].word {
			t.Fatalf("LLVM22 %q: word %#08x, want Arm encoding %#08x", lines[index], word, cases[index].word)
		}
		effects, known := arm64RawContinuationEffectsForWord(word)
		if !known || effects != (arm64RawContinuationEffects{}) {
			t.Fatalf("SM3 has GP/SP or memory effects: %#08x %+v %v", word, effects, known)
		}
	}
}

func TestARM64RawSM3GoFrontendNamespace(t *testing.T) {
	for _, file := range []string{"anames.go", "asm7.go"} {
		body, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src", "cmd", "internal", "obj", "arm64", file))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(body), "SM3PARTW1") || strings.Contains(string(body), "SM3TT1A") {
			t.Fatal("Go added named SM3 forms; audit its full encoder before retaining a WORD-only contract")
		}
	}
	for _, row := range arm64SM3OracleRows {
		instruction := strings.ToUpper(row.name) + " V0.S4,V1.S4,V2.S4"
		if row.registers == 4 {
			instruction += ",V3.S4"
		} else if row.lanes == 4 {
			instruction = strings.ToUpper(row.name) + " V0.S4,V1.S4,V2.S[0]"
		}
		requireARM64GoAssemblerResult(t, "TEXT invalid(SB),4,$0-0\n"+instruction+"\nRET\n", false)
	}
}

func TestARM64RawSM3AliasesLanesAndLLVM22Objects(t *testing.T) {
	cases := arm64SM3AliasCases()
	if len(cases) != 105 {
		t.Fatalf("generated %d alias/lane cases, want 105", len(cases))
	}
	var source strings.Builder
	sigs := make(map[string]FuncSig)
	for _, tc := range cases {
		source.WriteString(arm64SM3Fixture(tc.name, tc.word))
		sigs[tc.name] = arm64SM3Signature(tc.name)
	}
	requireARM64GoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range append(append([]string(nil), arm64TypedNativeTargets...), "aarch64-w64-windows-gnu") {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple, Sigs: sigs})
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(ir, "@llvm.aarch64.crypto.sm3") {
				t.Fatal("portable SM3 arithmetic acquired a host-feature-gated intrinsic")
			}
			compileLLVMToObject(t, llc, triple, "raw-sm3-aliases.ll", "raw-sm3-aliases.o", ir)
		})
	}
}

func arm64SM3Signature(name string) FuncSig {
	return FuncSig{
		Name: name, Args: []LLVMType{Ptr, Ptr}, Ret: Void,
		Frame: FrameLayout{Params: []FrameSlot{
			{Offset: 0, Type: Ptr, Index: 0, Field: -1},
			{Offset: 8, Type: Ptr, Index: 1, Field: -1},
		}},
	}
}

func arm64SM3Fixture(name string, word uint32) string {
	var source strings.Builder
	fmt.Fprintf(&source, "TEXT %s(SB),4,$0-16\nMOVD in+0(FP),R0\nMOVD out+8(FP),R1\n", name)
	for register := 0; register < 32; register++ {
		fmt.Fprintf(&source, "VLD1.P 16(R0),[V%d.S4]\n", register)
	}
	// Independent 64-bit input words seed arithmetic NZCV states. The vector
	// operation must preserve every flag, not only one conditional sentinel.
	source.WriteString("MOVD -512(R0),R2\nMOVD -504(R0),R3\nADDS R3,R2,R2\n")
	fmt.Fprintf(&source, "WORD $%#08x\n", word)
	for register := 0; register < 32; register++ {
		fmt.Fprintf(&source, "VST1.P [V%d.S4],16(R1)\n", register)
	}
	source.WriteString("CSET MI,R2\nCSET EQ,R3\nORR R3<<1,R2,R2\n")
	source.WriteString("CSET CS,R3\nORR R3<<2,R2,R2\nCSET VS,R3\nORR R3<<3,R2,R2\n")
	source.WriteString("MOVD R2,(R1)\nRET\n")
	return source.String()
}

func TestARM64RawSM3FixtureObservesEveryNZCVFlag(t *testing.T) {
	source := arm64SM3Fixture("sm3flags", 0xce63c004)
	for _, instruction := range []string{"CSET MI,R2", "CSET EQ,R3", "CSET CS,R3", "CSET VS,R3"} {
		if !strings.Contains(source, instruction) {
			t.Errorf("runtime fixture does not observe %s", instruction)
		}
	}
}

func TestARM64RawSM3OriginalAndCompleteFamily(t *testing.T) {
	words := []uint32{
		0xce63c004,             // Original gmsm SM3PARTW1.
		0xce66c4e4,             // Original gmsm SM3PARTW2.
		0xce4b2505,             // Original gmsm SM3SS1.
		0xce4a80a8, 0xce4ab4a8, // SM3TT1A / SM3TT1B, lanes 0 / 3.
		0xce4088a9, 0xce40bca9, // SM3TT2A / SM3TT2B, lanes 0 / 3.
	}
	var source strings.Builder
	sigs := make(map[string]FuncSig)
	for index, word := range words {
		name := fmt.Sprintf("sm3original%d", index)
		source.WriteString(arm64SM3Fixture(name, word))
		sigs[name] = arm64SM3Signature(name)
	}
	requireARM64GoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range arm64TypedNativeTargets {
		t.Run(target, func(t *testing.T) {
			ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: target, Sigs: sigs})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target, "raw-sm3.ll", "raw-sm3.o", ir)
		})
	}
}
