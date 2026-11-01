package plan9asm

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// These independent witnesses distinguish scalar, packed, broadcast and mask
// accesses. The pointer q is not used by any producer: a producer fault cannot
// hide a missing FMA read. Register-only counterparts have identical inputs.
// This is an access contract, not an x86 MXCSR or original-Go execution oracle.
type x86FMA3PortableAccessCase struct {
	name, format string
	mask         int // -1 means no mask; otherwise K1 receives this constant.
	bytes        int // Highest selected byte, independently specified below.
}

func x86FMA3PortableAccessCases() []x86FMA3PortableAccessCase {
	return []x86FMA3PortableAccessCase{
		{"scalar32", "VFMADD132SS %s,X1,X2", -1, 4},
		{"scalar64", "VFMSUB213SD %s,X1,X2", -1, 8},
		{"packed32", "VFNMADD231PS %s,X1,X2", -1, 16},
		{"packed64", "VFNMSUB132PD %s,X1,X2", -1, 16},
		{"scalar32-merge", "VFMADD213SS %s,X1,K1,X2", 1, 4},
		{"scalar64-zero", "VFMSUB231SD.Z %s,X1,K1,X2", 1, 8},
		{"packed32-merge", "VFMADD132PS %s,X1,K1,X2", 1, 4},
		{"packed64-zero", "VFMSUB213PD.Z %s,X1,K1,X2", 1, 8},
		{"packed32-suppressed", "VFNMADD231PS %s,X1,K1,X2", 0, 0},
		{"scalar64-suppressed", "VFNMSUB132SD.Z %s,X1,K1,X2", 0, 0},
		{"broadcast32", "VFMADD132PS.BCST %s,X1,X2", -1, 4},
		{"broadcast64", "VFMSUB213PD.BCST %s,X1,X2", -1, 8},
		{"broadcast32-merge", "VFNMADD231PS.BCST %s,X1,K1,X2", 1, 4},
		{"broadcast64-suppressed", "VFNMSUB132PD.BCST.Z %s,X1,K1,X2", 0, 0},
	}
}

func x86FMA3PortableAccessSource(row x86FMA3PortableAccessCase, name string, memory bool) (string, string, string) {
	format, first := row.format, "(AX)"
	if !memory {
		format, first = strings.ReplaceAll(format, ".BCST", ""), "X0"
	}
	instruction := fmt.Sprintf(format, first)
	var source strings.Builder
	fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-8\nMOVQ q+0(FP),AX\n", name)
	source.WriteString("PXOR X0,X0\nPXOR X1,X1\nPXOR X2,X2\n")
	if row.mask >= 0 {
		fmt.Fprintf(&source, "MOVL $%d,CX\nKMOVW CX,K1\n", row.mask)
	}
	source.WriteString(instruction + "\nRET\n")
	return source.String(), fmt.Sprintf("func %s(q *byte)\n", name), instruction
}

func x86FMA3PortableAccessGoPrior(t *testing.T) {
	t.Helper()
	var source strings.Builder
	for index, row := range x86FMA3PortableAccessCases() {
		for _, memory := range []bool{false, true} {
			program, _, _ := x86FMA3PortableAccessSource(row, fmt.Sprintf("Prior%d_%t", index, memory), memory)
			source.WriteString(program)
		}
	}
	// These are real stock-Go x86 objects. They are not executed on AArch64.
	x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", source.String())
}

func x86FMA3PortableAccessContext(t *testing.T, ir string, err error, instruction string) bool {
	t.Helper()
	if err == nil {
		if ir == "" {
			t.Fatal("successful public translation returned no module")
		}
		return false
	}
	if ir != "" || !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), instruction) {
		t.Fatalf("not a closed, original-FMA-bound Context: instruction=%q err=%v IR=%q", instruction, err, ir)
	}
	t.Log("original FMA access explicitly remains Context:", instruction)
	return true
}

func TestX86FMA3AArch64AdmissionAndIndependentAddressSources(t *testing.T) {
	x86FMA3PortableAccessGoPrior(t)
	const triple = "aarch64-unknown-linux-gnu"
	for _, row := range x86FMA3PortableAccessCases() {
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(row.name+"/"+api, func(t *testing.T) {
				source, declaration, _ := x86FMA3PortableAccessSource(row, "Probe", false)
				ir, err := x86ScalarFPBitViewAPI(t, source, declaration, "amd64", triple, api)
				if err != nil || !strings.Contains(ir, "target triple = \""+triple+"\"") {
					t.Fatal("public source-architecture/target combination is not actually admitted", err)
				}
				if strings.Contains(ir, "asm sideeffect \"vfm") || strings.Contains(ir, "asm sideeffect \"vfnm") {
					t.Fatal("AArch64 control accidentally used an original x86 native instruction")
				}
				memory, _, instruction := x86FMA3PortableAccessSource(row, "Probe", true)
				for _, missing := range []string{"MOVQ q+0(FP),AX\n", "PXOR X1,X1\n", "PXOR X2,X2\n"} {
					changed := strings.Replace(memory, missing, "", 1)
					ir, err := x86ScalarFPBitViewAPI(t, changed, declaration, "amd64", triple, api)
					if !x86FMA3PortableAccessContext(t, ir, err, instruction) {
						t.Fatal("dead FMA borrowed a missing actual pointer/arithmetic input", missing)
					}
				}
			})
		}
	}
}

var x86FMA3PortableVolatileLoad = regexp.MustCompile(`\bload volatile (i[0-9]+|float|double|<[0-9]+ x (?:i[0-9]+|float|double)>),`)

func x86FMA3PortableVolatileBytes(t *testing.T, ir string) int {
	t.Helper()
	bytes := 0
	for _, match := range x86FMA3PortableVolatileLoad.FindAllStringSubmatch(ir, -1) {
		element, lanes := match[1], 1
		if strings.HasPrefix(element, "<") {
			var count string
			count, element, _ = strings.Cut(strings.Trim(element, "<>"), " x ")
			var err error
			lanes, err = strconv.Atoi(count)
			if err != nil {
				t.Fatal(err)
			}
		}
		bits := map[string]int{"float": 32, "double": 64}[element]
		if bits == 0 {
			var err error
			bits, err = strconv.Atoi(strings.TrimPrefix(element, "i"))
			if err != nil || bits%8 != 0 {
				t.Fatal("unexpected volatile access type", element, err)
			}
		}
		bytes += lanes * bits / 8
	}
	return bytes
}

func TestX86FMA3AArch64DeadInputAccessCannotDisappear(t *testing.T) {
	x86FMA3PortableAccessGoPrior(t)
	const triple = "aarch64-unknown-linux-gnu"
	for _, row := range x86FMA3PortableAccessCases() {
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(row.name+"/"+api, func(t *testing.T) {
				register, declaration, _ := x86FMA3PortableAccessSource(row, "Probe", false)
				if ir, err := x86ScalarFPBitViewAPI(t, register, declaration, "amd64", triple, api); err != nil || ir == "" {
					t.Fatal("register counterpart did not establish actual public target admission", err)
				}
				source, _, instruction := x86FMA3PortableAccessSource(row, "Probe", true)
				ir, err := x86ScalarFPBitViewAPI(t, source, declaration, "amd64", triple, api)
				if x86FMA3PortableAccessContext(t, ir, err, instruction) {
					return
				}
				// Constant-mask simplification removes inactive guarded loads.
				// The separate runtime root observes O0 and O2 as well as IR O2;
				// counting an unoptimized guarded load would misclassify mask=0.
				text := x86DwordProductIROptimize(t, ir)
				if got := x86FMA3PortableVolatileBytes(t, text); got != row.bytes {
					t.Errorf("IR_O2: dead q access has %d observable bytes, want exactly %d; pure arithmetic/masked.load is not a fault-preserving continuation\n%s",
						got, row.bytes, text)
				}
			})
		}
	}
}
