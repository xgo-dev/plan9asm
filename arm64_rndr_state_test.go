package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

type arm64RNDRFixtureForm struct {
	name string
	bank int
	kind int
	word uint32
}

func arm64RNDRFixtureForms() []arm64RNDRFixtureForm {
	var forms []arm64RNDRFixtureForm
	for operation, name := range []string{"RNDR", "RNDRRS"} {
		for bank := 0; bank < 32; bank++ {
			if bank == 18 || bank == 28 || bank == 29 || bank == 30 {
				continue // Syntax/objects alone do not supply these physical entry roles.
			}
			forms = append(forms, arm64RNDRFixtureForm{name, bank, 0, uint32(0xd53b2400 + operation*32 + bank)})
		}
		for kind := 1; kind < 3; kind++ {
			for _, bank := range []int{0, 31} {
				forms = append(forms, arm64RNDRFixtureForm{name, bank, kind, uint32(0xd53b2400 + operation*32 + bank)})
			}
		}
	}
	return forms
}

func arm64RNDRStateFixture(forms []arm64RNDRFixtureForm) (source, declarations, original, driver string) {
	var assembly, goDeclarations, cDeclarations, goTable, cTable strings.Builder
	for index, form := range forms {
		name := fmt.Sprintf("compareRNG%d", index)
		fmt.Fprintf(&goDeclarations, "func %s(*uint64,*uint64)\n", name)
		fmt.Fprintf(&cDeclarations, "extern void %s(uint64_t*,uint64_t*);\n", name)
		fmt.Fprintf(&goTable, "{%s,%t},\n", name, form.bank == 31)
		fmt.Fprintf(&cTable, "{%s,%d},\n", name, map[bool]int{false: 0, true: 1}[form.bank == 31])
		var safe []int
		for _, register := range []int{19, 20, 21, 22, 23, 24} {
			if register != form.bank {
				safe = append(safe, register)
			}
		}
		in, out, flags, temporary, canary := safe[0], safe[1], safe[2], safe[3], safe[4]
		fmt.Fprintf(&assembly, "TEXT %s(SB),516,$0-16\nMOVD in+0(FP),R%d\nMOVD out+8(FP),R%d\n", name, in, out)
		fmt.Fprintf(&assembly, "MOVD (R%d),R%d\nMOVD $0x123456789abcdef0,R%d\nMSR R%d,NZCV\n", in, flags, canary, flags)
		register := fmt.Sprintf("R%d", form.bank)
		if form.bank == 31 {
			register = "ZR"
		}
		line := "MRS " + form.name + "," + register
		if form.kind == 1 {
			line = "MOVD " + form.name + "," + register
		} else if form.kind == 2 {
			line = fmt.Sprintf("WORD $%#08x", form.word)
		}
		fmt.Fprintln(&assembly, line)
		fmt.Fprintf(&assembly, "MOVD %s,(R%d)\nMRS NZCV,R%d\nMOVD R%d,8(R%d)\n", register, out, temporary, temporary, out)
		fmt.Fprintf(&assembly, "MOVD R%d,16(R%d)\nRET\n", canary, out)
	}
	original = `package main
import "fmt"
` + goDeclarations.String() + `
func main() {
 forms := []struct{ fn func(*uint64,*uint64); discard bool }{
` + goTable.String() + `}
 successes, failures, rows := 0,0,0
 for index, form := range forms {
  for flags:=uint64(0);flags<16;flags++ {
   for trial:=0;trial<2;trial++ {
    input:=flags<<28
    var out [3]uint64
    form.fn(&input,&out[0])
    if (out[1]!=0 && out[1]!=0x40000000) || out[2]!=0x123456789abcdef0 || ((form.discard || out[1]!=0) && out[0]!=0) {
     panic(fmt.Sprintf("RNG form=%d flags=%x result=%x",index,flags,out))
    }
    if out[1]==0 { successes++ } else { failures++ }
    rows++
   }
  }
 }
 if successes==0 { panic("no actual RNG success observed") }
 fmt.Printf("ARM64_COMPARE_ORIGINAL_PASS RNG rows=%d successes=%d failures=%d; no forced-failure claim\n",rows,successes,failures)
}
`
	driver = `#include <stdint.h>
#include <stdio.h>
` + cDeclarations.String() + `
int main(void) {
 struct { void (*fn)(uint64_t*,uint64_t*); int discard; } forms[]={
` + cTable.String() + `};
 unsigned successes=0, failures=0;
 for(unsigned index=0;index<sizeof(forms)/sizeof(forms[0]);index++) {
  for(uint64_t flags=0;flags<16;flags++) {
   for(unsigned trial=0;trial<2;trial++) {
    uint64_t input=flags<<28, out[3]={0};
    forms[index].fn(&input,out);
    if((out[1]!=0 && out[1]!=UINT64_C(0x40000000)) || out[2]!=UINT64_C(0x123456789abcdef0) ||
       ((forms[index].discard || out[1]!=0) && out[0]!=0)) {
     fprintf(stderr,"RNG form=%u flags=%llx result=%llx/%llx/%llx\n",index,
      (unsigned long long)flags,(unsigned long long)out[0],(unsigned long long)out[1],(unsigned long long)out[2]);
     return 1;
    }
    if(out[1]==0) successes++; else failures++;
   }
  }
 }
 printf("RNG successes=%u failures=%u; no forced-failure claim\n",successes,failures);
 return successes==0 ? 2 : 0;
}
`
	return assembly.String(), "package compare\n" + goDeclarations.String(), original, driver
}

func TestARM64RNDRCompleteConsumerObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	forms := arm64RNDRFixtureForms()
	if len(forms) != 64 {
		t.Fatal("RNG independent-axis matrix lost forms", len(forms))
	}
	for batch := 0; batch < len(forms); batch += 32 {
		source, declarations, _, _ := arm64RNDRStateFixture(forms[batch : batch+32])
		for _, triple := range []string{"aarch64-unknown-linux-gnu", "aarch64-apple-darwin", "aarch64-pc-windows-msvc"} {
			for _, consumer := range arm64NZCVConsumerIRs(t, source, declarations, triple) {
				t.Run(fmt.Sprintf("batch%d/%s/%s", batch/32, triple, consumer.name), func(t *testing.T) {
					compileLLVMToObject(t, llc, triple, "rng.ll", "rng.o", consumer.ir)
				})
			}
		}
	}
}

func TestARM64RNDRDeadCallsSurviveOptimization(t *testing.T) {
	for _, line := range []string{"MRS RNDR,ZR", "MOVD RNDRRS,ZR", "WORD $0xd53b241f", "WORD $0xd53b243f"} {
		source := "TEXT deadRandom(SB),516,$0-0\n" + line + "\nRET\n"
		for _, consumer := range arm64NZCVConsumerIRs(t, source, "package compare\nfunc deadRandom()\n", "aarch64-unknown-linux-gnu") {
			if optimized := armFloatEffectOptimizedIR(t, consumer.ir); !strings.Contains(optimized, "call { i64, i1 } @llvm.aarch64.rndr") {
				t.Errorf("%s discarded RNG side effect in %s", consumer.name, line)
			}
		}
	}
}

func arm64RNDRFullStateRuntime(t *testing.T, llc string, compiler, runner []string) {
	t.Helper()
	forms := arm64RNDRFixtureForms()
	if len(forms) != 64 {
		t.Fatal("RNG runtime matrix lost forms", len(forms))
	}
	for batch := 0; batch < len(forms); batch += 32 {
		t.Run(fmt.Sprintf("batch%d", batch/32), func(t *testing.T) {
			source, declarations, original, driver := arm64RNDRStateFixture(forms[batch : batch+32])
			arm64ScalarCompareActualGo(t, source, original, "linux", runner)
			arm64NZCVRunConsumers(t, llc, compiler, "rng_state", "aarch64-unknown-linux-gnu", source, declarations, driver, runner)
		})
	}
	// Independent allowed-state invariants, not equality of nondeterministic
	// random values from separate original-Go and LLVM executions.
	t.Log("64 forms × 16 initial NZCV states × 2 trials = 2048 rows per executable; 4 consumers × 4 optimization axes")
}
