package plan9asm

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"
)

type x86IntegerTestMaskValueCase struct {
	op, bank, destination string
	width, bits, negative int
	first, masked, pair   int
}

func x86IntegerTestMaskValueCases() []x86IntegerTestMaskValueCase {
	var cases []x86IntegerTestMaskValueCase
	positions := make(map[string]int)
	key := func(row x86IntegerTestMaskValueCase, negative int) string {
		return fmt.Sprintf("%d/%d/%d/%d/%d/%s", negative, row.width, row.bits, row.first, row.masked, row.destination)
	}
	for _, negative := range []int{0, 1} {
		for _, lane := range []struct {
			letter string
			bits   int
		}{{"B", 8}, {"W", 16}, {"D", 32}, {"Q", 64}} {
			op := "VPTESTM" + lane.letter
			if negative != 0 {
				op = "VPTESTNM" + lane.letter
			}
			for index, bank := range []string{"X", "Y", "Z"} {
				for first := 0; first < 3; first++ {
					if first == 2 && lane.bits < 32 {
						continue
					}
					for _, masked := range []int{0, 1} {
						for _, destination := range []string{"K0", "K2"} {
							row := x86IntegerTestMaskValueCase{op: op, bank: bank, destination: destination,
								width: 16 << index, bits: lane.bits, negative: negative, first: first, masked: masked}
							positions[key(row, negative)] = len(cases)
							cases = append(cases, row)
						}
					}
				}
			}
		}
	}
	for index := range cases {
		cases[index].pair = positions[key(cases[index], 1-cases[index].negative)]
	}
	return cases
}

func TestX86IntegerTestMaskTypedPortableValuesAndMaskRoles(t *testing.T) {
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("test-to-mask values require LLVM22 llc/clang")
	}
	cases := x86IntegerTestMaskValueCases()
	if len(cases) != 240 {
		t.Fatal("lost an official source/width/mask shape or K0/K2 result", len(cases))
	}
	for index, row := range cases {
		if row.pair < 0 || row.pair >= len(cases) || row.pair == index || cases[row.pair].pair != index ||
			cases[row.pair].negative == row.negative {
			t.Fatal("M/NM source catalogue lost its independent complement partner", index, row)
		}
	}
	var source, declarations, prototypes, rows strings.Builder
	for index, row := range cases {
		name := fmt.Sprint("IntegerTestMask", index)
		first, op, predicate := row.bank+"0", row.op, ""
		if row.first != 0 {
			first = "(AX)"
		}
		if row.first == 2 {
			op += ".BCST"
		}
		maskInput := ""
		if row.masked != 0 {
			maskInput, predicate = "KMOVQ mask+16(FP),K1\n", "K1,"
		}
		// The destination K0/K2 is never initialized. An output K does not
		// acquire a merge/old-result dependency from an optional write mask.
		fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-40\nMOVQ a+0(FP),AX\nMOVQ b+8(FP),DX\nMOVQ flags+24(FP),DI\n"+
			"VMOVUPS (AX),Z0\nVMOVUPS (DX),Z1\n%sSTC\n%s %s,%s1,%s%s\nKMOVQ %s,AX\nSETCS (DI)\nMOVQ AX,ret+32(FP)\nRET\n",
			name, maskInput, op, first, row.bank, predicate, row.destination, row.destination)
		fmt.Fprintf(&declarations, "func %s(a,b *[64]byte,mask uint64,flags *byte) uint64\n", name)
		fmt.Fprintf(&prototypes, "extern uint64_t %s(const uint8_t*,const uint8_t*,uint64_t,uint8_t*);\n", name)
		fmt.Fprintf(&rows, "{%s,%d,\"%s\",%d,%d,%d,%d,%d},\n", name, row.pair, op,
			row.width, row.bits, row.negative, row.first, row.masked)
	}
	x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", source.String())
	driver := "#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\n" + prototypes.String() + `
typedef struct {
 uint64_t (*run)(const uint8_t*,const uint8_t*,uint64_t,uint8_t*);
 unsigned pair;
 const char *op;
 unsigned width,bits,negative,first,masked;
} Row;
static const Row rows[]={
` + rows.String() + `};
static uint64_t load_lane(const uint8_t *p,unsigned bytes) {
 uint64_t value=0;
 for(unsigned byte=0;byte<bytes;byte++) value|=(uint64_t)p[byte]<<(8*byte);
 return value;
}
int main(void) {
 for(unsigned r=0;r<sizeof(rows)/sizeof(rows[0]);r++) {
  const Row *p=rows+r;
  unsigned lane=p->bits/8,lanes=p->width/lane;
  uint64_t relevant=lanes==64?UINT64_MAX:(UINT64_C(1)<<lanes)-1;
  const uint64_t masks[]={0,1,UINT64_C(0xa55a9c63f00fc33c),UINT64_MAX,lanes<64?UINT64_C(1)<<lanes:0};
  for(unsigned sample=0;sample<32;sample++) {
   uint8_t a[66],b[66],saved_a[66],saved_b[66];
   memset(a,0xa7,sizeof(a));memset(b,0x91,sizeof(b));
   for(unsigned byte=0;byte<64;byte++) {
    uint8_t x=(uint8_t)(byte*13+sample*17+1),y=(uint8_t)(byte*29+sample*37+3);
    switch(sample&7) {
     case 0:x=0;y=255;break;
     case 1:x=255;y=255;break;
     case 2:y=(uint8_t)~x;break;
     case 3:y=x;break;
     case 4:x=128;y=128;break;
     case 5:x=1;y=1;break;
     case 6:y=0;break;
    }
    a[byte+1]=x;b[byte+1]=y;
   }
   memcpy(saved_a,a,sizeof(a));memcpy(saved_b,b,sizeof(b));
   for(unsigned m=0;m<sizeof(masks)/sizeof(masks[0]);m++) {
    uint64_t want=0,active=p->masked?masks[m]&relevant:relevant;
    for(unsigned j=0;j<lanes;j++) {
     uint64_t x=load_lane(a+1+(p->first==2?0:j*lane),lane),y=load_lane(b+1+j*lane,lane);
     unsigned bit=p->negative?(x&y)==0:(x&y)!=0;
     if((active>>j&1)&&bit) want|=UINT64_C(1)<<j;
    }
    uint8_t carry=0xa7,opposite_carry=0x91;
    uint64_t actual=p->run(a+1,b+1,masks[m],&carry);
    uint64_t opposite=rows[p->pair].run(a+1,b+1,masks[m],&opposite_carry);
    if(actual!=want||(actual^opposite)!=active||carry!=1||opposite_carry!=1||
       memcmp(a,saved_a,sizeof(a))||memcmp(b,saved_b,sizeof(b))) {
     fprintf(stderr,"test-to-mask row=%u op=%s sample=%u mask=%u got=%llx want=%llx active=%llx\n",
      r,p->op,sample,m,(unsigned long long)actual,(unsigned long long)want,(unsigned long long)active);
     return 1;
    }
   }
  }
 }
 return 0;
}
`
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), "amd64", triple, api)
			if err != nil {
				t.Fatal("initialized test-to-mask rejected before numerical comparison", err)
			}
			x86ConflictFunnelPortableRuntime(t, llc, clang, "integer-test-mask", triple, ir, driver)
		})
	}
}

func TestX86IntegerTestMaskUnknownInputsDoNotBorrowCompareIdentities(t *testing.T) {
	for _, op := range strings.Fields("VPTESTMB VPTESTMW VPTESTMD VPTESTMQ VPTESTNMB VPTESTNMW VPTESTNMD VPTESTNMQ") {
		for _, change := range []string{"first", "second", "write mask", "identical unknown"} {
			body := "VMOVUPS (AX),Z0\nVMOVUPS (AX),Z1\n"
			instruction := op + " X0,X1,K0\n"
			switch change {
			case "first":
				body = strings.Replace(body, "VMOVUPS (AX),Z0\n", "", 1)
			case "second":
				body = strings.Replace(body, "VMOVUPS (AX),Z1\n", "", 1)
			case "write mask":
				instruction = op + " X0,X1,K1,K0\n"
			case "identical unknown":
				body, instruction = "", op+" X0,X0,K0\n"
			}
			source := "TEXT ·UnknownTestMask(SB),4,$0-16\nMOVQ p+0(FP),AX\n" + body + instruction +
				"KMOVQ K0,AX\nMOVQ AX,ret+8(FP)\nRET\n"
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source, "func UnknownTestMask(p *[64]byte) uint64\n", "amd64", "x86_64-unknown-linux-gnu", api)
				if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("test-to-mask invented numerical inputs or used an EQ/GT identity", op, change, api, err)
				}
			}
		}
	}
}
