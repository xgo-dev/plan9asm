package plan9asm

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

func TestARM64RawSM4DecoderCompleteRegisterSpace(t *testing.T) {
	count := 0
	for d := 0; d < 32; d++ {
		for n := 0; n < 32; n++ {
			word := uint32(0xcec08400 | n<<5 | d)
			form, ok := decodeARM64RawSM4(word)
			if !ok || form.spec.intrinsic != "sm4e" || form.first != d || form.second != n || form.destination != d {
				t.Fatalf("SM4E %#08x decoded as %+v, %v", word, form, ok)
			}
			count++
			for m := 0; m < 32; m++ {
				word := uint32(0xce60c800 | m<<16 | n<<5 | d)
				form, ok := decodeARM64RawSM4(word)
				if !ok || form.spec.intrinsic != "sm4ekey" || form.first != n || form.second != m || form.destination != d {
					t.Fatalf("SM4EKEY %#08x decoded as %+v, %v", word, form, ok)
				}
				count++
			}
		}
	}
	if count != 33792 {
		t.Fatalf("tested %d encodings, want 33792", count)
	}
	// Every non-register bit is fixed, including the fixed .4S arrangement.
	for _, spec := range arm64RawSM4Specs {
		for bit := uint(0); bit < 32; bit++ {
			if spec.mask&(1<<bit) == 0 {
				continue
			}
			word := spec.base ^ (1 << bit)
			if form, ok := decodeARM64RawSM4(word); ok {
				t.Fatalf("accepted mutated fixed bit %d in %#08x: %+v", bit, word, form)
			}
		}
	}
}

func TestARM64RawSM4LLVMAssemblerOracle(t *testing.T) {
	mc := findLLVM22Tool("llvm-mc")
	if mc == "" {
		t.Fatal("LLVM 22 llvm-mc not found")
	}
	for _, tc := range []struct{ instruction, encoding string }{
		{"sm4e v2.4s, v15.4s", "[0xe2,0x85,0xc0,0xce]"},
		{"sm4ekey v11.4s, v11.4s, v19.4s", "[0x6b,0xc9,0x73,0xce]"},
		{"sm4e v31.4s, v31.4s", "[0xff,0x87,0xc0,0xce]"},
		{"sm4ekey v31.4s, v0.4s, v31.4s", "[0x1f,0xc8,0x7f,0xce]"},
	} {
		cmd := exec.Command(mc, "-triple=aarch64", "-mattr=+sm4", "-show-encoding")
		cmd.Stdin = strings.NewReader(tc.instruction + "\n")
		output, err := cmd.CombinedOutput()
		if err != nil || !strings.Contains(string(output), tc.encoding) {
			t.Fatalf("LLVM oracle %q: %v\n%s", tc.instruction, err, output)
		}
	}
}

func TestARM64RawSM4CompleteForms(t *testing.T) {
	// NEON SM4 is WORD-only in Go; ZSM4E/ZSM4EKEY are separate SVE forms.
	// Include the independent LLVM MC fixtures and the discovering library.
	words := []uint32{0xce73c96b, 0xcec085e2, 0xce60c928, 0xcec08560, 0xcec08660, 0xcec08408}
	for r := uint32(0); r < 32; r++ {
		words = append(words, 0xcec08400|r<<5|r)
		words = append(words, 0xce60c800|r<<16|((r+1)%32)<<5|((r+2)%32))
	}
	var source strings.Builder
	sigs := make(map[string]FuncSig)
	for index, word := range words {
		name := fmt.Sprintf("sm4form%d", index)
		fmt.Fprintf(&source, "TEXT %s(SB),4,$0-16\nMOVD in+0(FP),R0\nMOVD out+8(FP),R1\n", name)
		for r := 0; r < 32; r++ {
			fmt.Fprintf(&source, "VLD1.P 16(R0),[V%d.S4]\n", r)
		}
		fmt.Fprintf(&source, "WORD $%#08x\n", word)
		// Keep each instruction's result live so llc must select its encoding.
		fmt.Fprintf(&source, "VST1 [V%d.S4],(R1)\nRET\n", word&31)
		sigs[name] = FuncSig{
			Name: name, Args: []LLVMType{Ptr, Ptr}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1},
				{Offset: 8, Type: Ptr, Index: 1, Field: -1},
			}},
		}
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
	for _, triple := range []string{"aarch64-unknown-linux-gnu", "aarch64-apple-darwin", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{
				Goarch: "arm64", TargetTriple: triple,
				Sigs: sigs,
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, expected := range []string{
				"call <4 x i32> @llvm.aarch64.crypto.sm4e(",
				"call <4 x i32> @llvm.aarch64.crypto.sm4ekey(",
				`"target-features"="+sm4"`,
			} {
				if !strings.Contains(ir, expected) {
					t.Fatalf("missing %q", expected)
				}
			}
			compileLLVMToObject(t, llc, triple, "sm4.ll", "sm4.o", ir)
		})
	}
}

func TestARM64SM4RejectsInventedNamedNEONForms(t *testing.T) {
	for _, instruction := range []string{
		"SM4E V1.S4, V2.S4", "VSM4E V1.S4, V2.S4",
		"SM4EKEY V1.S4, V2.S4, V3.S4", "VSM4EKEY V1.S4, V2.S4, V3.S4",
	} {
		t.Run(instruction, func(t *testing.T) {
			source := "TEXT invalidsm4(SB),4,$0-0\n" + instruction + "\nRET\n"
			requireARM64GoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			_, err = Translate(file, Options{
				Goarch: "arm64", TargetTriple: "aarch64-unknown-linux-gnu",
				Sigs: map[string]FuncSig{"invalidsm4": {Name: "invalidsm4", Ret: Void}},
			})
			if err == nil {
				t.Fatalf("accepted Go-rejected form %q", instruction)
			}
		})
	}
}
