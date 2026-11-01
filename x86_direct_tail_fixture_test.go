package plan9asm

import (
	"fmt"
	"strings"
)

// Test-owned complete source used by the original-Go, five-target object and
// runtime counterparts. It grants no source, entry or machine-state authority.
type x86DirectTailRuntimeFixture struct {
	assembly, declarations, prototypes, goCalls, cCalls string
}

func x86DirectTailRuntimeSources(arch string) x86DirectTailRuntimeFixture {
	var assembly, declarations, prototypes, goCalls, cCalls strings.Builder
	assembly.WriteString("#include \"textflag.h\"\n")
	rows := []struct{ name, effect, body string }{
		{"shared", "NOP", "MOVQ SI,AX\n ADDQ DI,AX"},
		{"renamed", "NOP", "MOVQ SI,AX\n ADDQ DI,AX"},
		{"flags", "CMPQ SI,DI", "SETEQ AL\n MOVBLZX AL,AX"},
		{"vector_flags", "MOVQ SI,X0\n CMPQ SI,DI", "MOVQ X0,AX\n ADCQ DI,AX"},
		{"zero_extension", "MOVL SI,X0", "MOVQ X0,AX\n ADDQ DI,AX"},
		{"chain", "NOP", "JMP last%d<>(SB)\nTEXT last%d<>(SB),NOSPLIT,$0-0\n MOVQ SI,AX\n ADDQ DI,AX"},
		{"diamond", "CMPQ SI,DI", "JE left\n ADDQ $3,DI\n JMP joined%d<>(SB)\nleft:\n ADDQ $5,DI\n JMP joined%d<>(SB)\nTEXT joined%d<>(SB),NOSPLIT,$0-0\n MOVQ SI,AX\n ADDQ DI,AX"},
	}
	for index, row := range rows {
		body := row.body
		if row.name == "chain" {
			body = fmt.Sprintf(body, index, index)
		} else if row.name == "diamond" {
			body = fmt.Sprintf(body, index, index, index)
		}
		fmt.Fprintf(&assembly, `TEXT ·First%d(SB),NOSPLIT,$0-16
 MOVQ a+0(FP),SI
 MOVQ $7,DI
 %s
 JMP %s%d<>(SB)
TEXT ·Second%d(SB),NOSPLIT,$0-16
 MOVL a+0(FP),SI
 MOVL b+4(FP),DI
 %s
 JMP %s%d<>(SB)
TEXT %s%d<>(SB),NOSPLIT,$0-0
 %s
 MOVQ AX,ret+8(FP)
 RET
`, index, row.effect, row.name, index, index, row.effect, row.name, index, row.name, index, body)
		fmt.Fprintf(&declarations, "func First%d(a uint64) uint64\nfunc Second%d(a,b uint32) uint64\n", index, index)
		fmt.Fprintf(&prototypes, "extern uint64_t First%d(uint64_t);\nextern uint64_t Second%d(uint32_t,uint32_t);\n", index, index)
		fmt.Fprintf(&goCalls, `
  if got:=First%d(a); got!=reference(%d,a,7) { panic(fmt.Sprintf("First%d: got=%%x want=%%x",got,reference(%d,a,7))) }
  for _,value:=range values {
   x,y:=uint32(a),uint32(value)
   if got:=Second%d(x,y); got!=reference(%d,uint64(x),uint64(y)) { panic(fmt.Sprintf("Second%d: got=%%x want=%%x",got,reference(%d,uint64(x),uint64(y)))) }
   calls++
  }
  calls++
`, index, index, index, index, index, index, index, index)
		fmt.Fprintf(&cCalls, `
    {uint64_t got=First%d(a),want=reference(%d,a,7);
     if(got!=want) {fprintf(stderr,"First%d transport failure sample=%%u got=%%llx want=%%llx\n",i,(unsigned long long)got,(unsigned long long)want);return 1;}}
    for(unsigned j=0;j<sizeof(values)/sizeof(values[0]);j++) {
        uint32_t x=(uint32_t)a,y=(uint32_t)values[j];
        uint64_t got=Second%d(x,y),want=reference(%d,x,y);
        if(got!=want) {fprintf(stderr,"Second%d transport failure samples=%%u,%%u got=%%llx want=%%llx\n",i,j,(unsigned long long)got,(unsigned long long)want);return 1;}
        calls++;
    }
    calls++;
`, index, index, index, index, index, index)
	}
	fixture := x86DirectTailRuntimeFixture{assembly.String(), declarations.String(), prototypes.String(), goCalls.String(), cCalls.String()}
	if arch == "386" {
		fixture.assembly = strings.NewReplacer("$0-16", "$0-8", "ret+8(FP)", "ret+4(FP)",
			"MOVQ", "MOVL", "ADDQ", "ADDL", "ADCQ", "ADCL", "CMPQ", "CMPL").Replace(fixture.assembly)
		fixture.assembly = strings.ReplaceAll(fixture.assembly, "MOVL a+0(FP),SI\n MOVL b+4(FP),DI", "MOVWLZX a+0(FP),SI\n MOVWLZX b+2(FP),DI")
		fixture.declarations = strings.ReplaceAll(fixture.declarations, "a,b uint32", "a,b uint16")
		fixture.declarations = strings.ReplaceAll(fixture.declarations, "uint64", "uint32")
		// The i386 execution oracle has its own u32/u16 reference and caller
		// transport. Do not reuse this AMD64-only C/Go driver by type guessing.
		fixture.prototypes, fixture.goCalls, fixture.cCalls = "", "", ""
	}
	return fixture
}
