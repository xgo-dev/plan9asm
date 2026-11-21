package plan9asm

import (
	"encoding/binary"
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestARM64AtomicRMWOriginalWordsAndOrdering(t *testing.T) {
	const name = "atomicMatrix"
	var source strings.Builder
	source.WriteString("TEXT " + name + "(SB),4,$0-0\n")
	var effects []string
	var zeroDestinations []bool
	for _, family := range []struct{ name, operation string }{
		{"SWP", "xchg"}, {"LDADD", "add"}, {"LDCLR", "and"}, {"LDOR", "or"}, {"LDEOR", "xor"},
	} {
		for _, order := range []struct{ suffix, value, discard string }{
			{"", "monotonic", "monotonic"},
			{"A", "acquire", "monotonic"},
			{"L", "release", "release"},
			{"AL", "acq_rel", "release"},
		} {
			for size, suffix := range []string{"B", "H", "W", "D"} {
				for _, variant := range []struct{ operands, ordering string }{
					{"R5,(R6),R7", order.value},
					{"R5,(RSP),ZR", order.discard},
					{"ZR,(ZR),R7", order.value},
				} {
					fmt.Fprintf(&source, "%s%s%s %s\n", family.name, order.suffix, suffix, variant.operands)
					effects = append(effects, fmt.Sprintf("%s i%d %s", family.operation, 8<<size, variant.ordering))
					zeroDestinations = append(zeroDestinations, strings.HasSuffix(variant.operands, ",ZR"))
				}
			}
		}
	}
	source.WriteString("RET\n")
	oracleSource := source.String()
	legacyAssembler := !goToolchainAtLeast(runtime.Version(), 1, 27)
	if legacyAssembler {
		// Older Go assemblers reject some valid Rt=31 combinations. Assemble
		// the identical operation with Rt=7, then select the architectural
		// zero register in that field. Check every translation on both SDKs.
		oracleSource = strings.ReplaceAll(oracleSource, ",ZR\n", ",R7\n")
	}
	code := arm64ImmediateOriginalGoBytes(t, oracleSource, "linux")
	end := 4 * (len(effects) + 1)
	if len(code) < end || len(code) >= end+16 || binary.LittleEndian.Uint32(code[end-4:end]) != 0xd65f03c0 {
		t.Fatalf("original Go object has %d bytes, want %d including RET plus alignment", len(code), end)
	}
	for _, pad := range code[end:] {
		if pad != 0 {
			t.Fatal("nonzero Go TEXT padding")
		}
	}
	var raw strings.Builder
	raw.WriteString("TEXT " + name + "(SB),4,$0-0\n")
	for i := range effects {
		word := binary.LittleEndian.Uint32(code[4*i:])
		if legacyAssembler && zeroDestinations[i] {
			if word&31 != 7 {
				t.Fatalf("expected Rt=7 in original word 0x%08x", word)
			}
			word |= 31
			binary.LittleEndian.PutUint32(code[4*i:], word)
		}
		fmt.Fprintf(&raw, "WORD $0x%08x\n", word)
	}
	raw.WriteString("RET\n")
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc is required")
	}
	for _, fixture := range []struct{ kind, source string }{{"named", source.String()}, {"original-words", raw.String()}} {
		t.Run(fixture.kind, func(t *testing.T) {
			file, err := Parse(ArchARM64, fixture.source)
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				Goarch: "arm64", TargetTriple: arm64LinuxGNUTriple,
				Sigs: map[string]FuncSig{name: {Name: name, Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			var observed []string
			for _, line := range strings.Split(ir, "\n") {
				if _, rmw, found := strings.Cut(line, " = atomicrmw "); found {
					parts := strings.Fields(rmw)
					if len(parts) < 6 {
						t.Fatal("incomplete atomicrmw", line)
					}
					observed = append(observed, parts[0]+" "+parts[3]+" "+strings.TrimSuffix(parts[5], ","))
				}
			}
			if len(observed) != len(effects) {
				t.Fatalf("got %d atomic operations, want %d", len(observed), len(effects))
			}
			for i, want := range effects {
				if observed[i] != want {
					t.Errorf("original word 0x%08x: got %q, want %q", binary.LittleEndian.Uint32(code[4*i:]), observed[i], want)
				}
			}
			compileLLVMToObject(t, llc, arm64LinuxGNUTriple, "lse-rmw.ll", "lse-rmw.o", ir)
		})
	}
}

func arm64AtomicRMWCompleteForms() string {
	var source strings.Builder
	source.WriteString("TEXT atomicRMWComplete(SB),$0-0\n")
	for _, family := range []string{"SWP", "LDADD", "LDCLR", "LDOR", "LDEOR"} {
		for _, order := range []string{"", "A", "L", "AL"} {
			for _, width := range []string{"B", "H", "W", "D"} {
				opcode := family + order + width
				source.WriteString("\t" + opcode + " R5, (R6), R7\n")
				source.WriteString("\t" + opcode + " R5, (RSP), ZR\n")
			}
		}
	}
	source.WriteString("\tRET\n")
	return source.String()
}

func TestTranslateARM64AtomicRMWCompleteFormats(t *testing.T) {
	source := arm64AtomicRMWCompleteForms()
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: arm64LinuxGNUTriple,
		Goarch:       "arm64",
		Sigs: map[string]FuncSig{
			"atomicRMWComplete": {Name: "atomicRMWComplete", Ret: Void},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"atomicrmw xchg", "atomicrmw add", "atomicrmw and", "atomicrmw or", "atomicrmw xor",
		" i8 ", " i16 ", " i32 ", " i64 ", " monotonic", " acquire", " release", " acq_rel",
	} {
		if !strings.Contains(ll, want) {
			t.Fatalf("ARM64 complete atomic RMW lowering omitted %q:\n%s", want, ll)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, arm64LinuxGNUTriple, "arm64-atomic-rmw-complete.ll", "arm64-atomic-rmw-complete.o", ll)
}

func TestTranslateARM64AtomicRMWRejectsFormsOutsideGoOptab(t *testing.T) {
	for _, instruction := range []string{"SWPD R0, 8(R1), R2", "LDADDW R0, (R1)", "LDCLRQ R0, (R1), R2"} {
		source := "TEXT bad(SB),$0-0\n\t" + instruction + "\n\tRET\n"
		requireARM64GoAssemblerResult(t, source, false)
		file, err := Parse(ArchARM64, source)
		if err != nil {
			continue
		}
		if _, err := Translate(file, Options{
			TargetTriple: arm64LinuxGNUTriple,
			Goarch:       "arm64",
			Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
		}); err == nil {
			t.Fatalf("Translate accepted %q outside Go 1.27's ARM64 LSE atomic RMW optab", instruction)
		}
	}
}
