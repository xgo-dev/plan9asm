package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestGoAMD64FixedLocalNativeVectorConsumers(t *testing.T) {
	// Independent semantic/transport witnesses. The complete spelling and
	// format inventories remain with each family's original Go-table owners.
	type witness struct {
		family, instruction string
		operand             int
		width               int64
		write               bool
	}
	rows := []witness{
		{"wrapping-add", "PADDQ (%s),X1", 0, 16, false},
		{"subtract", "PSUBQ (%s),X1", 0, 16, false},
		{"logical", "PAND (%s),X1", 0, 16, false},
		{"word-multiply", "PMULLW (%s),X1", 0, 16, false},
		{"word-madd", "PMADDWL (%s),X1", 0, 16, false},
		{"average", "PAVGB (%s),X1", 0, 16, false},
		{"compare", "PCMPEQB (%s),X1", 0, 16, false},
		{"shuffle-bytes", "PSHUFB (%s),X1", 0, 16, false},
		{"shuffle-words", "PSHUFD $0,(%s),X1", 1, 16, false},
		{"unpack", "PUNPCKLBW (%s),X1", 0, 16, false},
		{"pack", "PACKSSWB (%s),X1", 0, 16, false},
		{"integer-minmax", "PMINUB (%s),X1", 0, 16, false},
		{"horizontal", "PHADDW (%s),X1", 0, 16, false},
		{"SAD", "PSADBW (%s),X1", 0, 16, false},
		{"AES", "AESENC (%s),X1", 0, 16, false},
		{"CLMUL", "PCLMULQDQ $0,(%s),X1", 1, 16, false},
		{"packed-conversion-X", "VCVTTPS2DQ (%s),X1", 0, 16, false},
		{"packed-conversion-Y", "VCVTDQ2PD (%s),Y1", 0, 16, false},
	}
	for _, bank := range []struct {
		name  string
		width int64
	}{{"X", 16}, {"Y", 32}, {"Z", 64}} {
		rows = append(rows,
			witness{"aligned-masked-load-" + bank.name, "VMOVDQA64.Z (%s),K1," + bank.name + "1", 0, bank.width, false},
			witness{"aligned-masked-store-" + bank.name, "VMOVDQA64 " + bank.name + "1,K1,(%s)", 2, bank.width, true})
	}
	for _, row := range rows {
		for _, base := range []string{"AX", "BP"} {
			t.Run(row.family+"/"+base, func(t *testing.T) {
				operation := fmt.Sprintf(row.instruction, base)
				body := "VMOVDQU8 (SI),Z0\nVMOVDQU8 (SI),Z1\nVMOVDQU8 (SI),Z2\n" +
					"MOVQ $1,CX\nKMOVQ CX,K1\nMOVQ AX," + base + "\n" + operation + "\nMOVQ $0,AX"
				fn, sig, assembly := fixedLocalInputFixture(t, body)
				switch row.family {
				case "SAD", "horizontal", "integer-minmax", "pack", "unpack":
					// These legal instructions retain a separate fixed-local
					// owner boundary, before this native-address consumer.
					x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", assembly)
					if _, err := proveX86FixedLocal(fn, sig); !errors.Is(err, ErrProbeNeedsContext) ||
						!strings.Contains(err.Error(), "unregistered instruction shape") {
						t.Fatal("unregistered private family acquired a source owner", err)
					}
					return
				}
				emitted := strings.ToLower(strings.Split(operation, " ")[0])
				emitted, _, _ = strings.Cut(emitted, ".")
				if emitted == "pmaddwl" {
					emitted = "pmaddwd" // Go's Plan 9 word-to-long spelling.
				}
				fixedLocalRequireNumericControl(t, fn, sig, assembly,
					"func Value(p,q *uint64,a uint64) uint64", operation, row.operand, row.width, row.write,
					emitted)
			})
		}
	}
}

func TestGoAMD64FixedLocalNativeMemoryRoleGuards(t *testing.T) {
	const operation = "PADDQ (BP),X1"
	body := "VMOVDQU8 (SI),Z1\nMOVQ AX,BP\n" + operation + "\nMOVQ $0,AX"
	fn, sig, _ := fixedLocalInputFixture(t, body)
	proved, err := proveX86FixedLocal(fn, sig)
	if err != nil {
		t.Fatal(err)
	}
	ctx := amd64Ctx{fixedLocal: proved.x86FixedLocal, goarch: "amd64"}
	var original Instr
	for _, ins := range proved.Instrs {
		if ins.Raw == operation {
			original = ins
		}
	}
	if original.Op == "" || x86OrdinaryNativeMemoryOperand(original.Args[0], "amd64") ||
		!ctx.nativeMemoryOperand(original, 0) || ctx.fixedLocalMemoryCertified(original, 0) {
		t.Fatal("the exact native BP role became ordinary or private storage")
	}
	for _, row := range []struct {
		name   string
		change func(*amd64Ctx, *Instr)
	}{
		{"missing-owner", func(c *amd64Ctx, _ *Instr) { c.fixedLocal = nil }},
		{"other-owner", func(c *amd64Ctx, _ *Instr) { c.fixedLocal = new(x86FixedLocalProof) }},
		{"missing-record", func(_ *amd64Ctx, i *Instr) { i.x86FixedLocalMemory = nil }},
		{"changed-shape", func(_ *amd64Ctx, i *Instr) { i.Args[0].Mem.Off++ }},
		{"raw", func(_ *amd64Ctx, i *Instr) { i.x86Encoded = true }},
		{"address-size", func(_ *amd64Ctx, i *Instr) { i.x86AddressBits = 32 }},
		{"changed-role", func(_ *amd64Ctx, i *Instr) {
			access := i.x86FixedLocalMemory[0]
			access.nativeInput = false
			i.x86FixedLocalMemory = map[int]x86FixedLocalAccess{0: access}
		}},
	} {
		t.Run(row.name, func(t *testing.T) {
			consumer, changed := ctx, original
			changed.Args = append([]Operand(nil), original.Args...)
			row.change(&consumer, &changed)
			if consumer.nativeMemoryOperand(changed, 0) || consumer.fixedLocalMemoryCertified(changed, 0) {
				t.Fatal("a stale native record acquired an address or private certificate")
			}
		})
	}
	for _, prefix := range []string{"", "MOVW AX,BP\n"} {
		changed, layout, _ := fixedLocalInputFixture(t,
			"VMOVDQU8 (SI),Z1\n"+prefix+operation+"\nMOVQ $0,AX")
		if _, err := proveX86FixedLocal(changed, layout); !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("unknown or partial BP bits acquired a native memory role", prefix, err)
		}
	}
	private, layout, _ := fixedLocalVEXFixture(t, "PADDQ 64(BP),X1")
	private, err = proveX86FixedLocal(private, layout)
	if err != nil {
		t.Fatal(err)
	}
	consumer := amd64Ctx{fixedLocal: private.x86FixedLocal, goarch: "amd64"}
	for _, ins := range private.Instrs {
		if ins.Raw == "PADDQ 64(BP),X1" {
			if consumer.nativeMemoryOperand(ins, 0) || !consumer.fixedLocalMemoryCertified(ins, 0) {
				t.Fatal("a private BP extent was reclassified as native input")
			}
			return
		}
	}
	t.Fatal("missing original private BP control")
}
