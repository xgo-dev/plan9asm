package plan9asm

const x86ANDNOriginalRuntimeDriver = `
#include <stdint.h>
#include <string.h>
extern void andnsemantics(uint8_t *);
int main(void) {
  uint8_t out[40] = {0};
  andnsemantics(out);
  const uint64_t want[3] = {UINT64_C(0x30), 0, UINT64_C(0x80000000)};
  for (int i = 0; i < 3; i++) {
    uint64_t got;
    memcpy(&got, out + i * 8, sizeof(got));
    if (got != want[i]) return 10 + i;
  }
  const uint8_t flags[12] = {0,0,0,0, 0,1,0,0, 0,0,1,0};
  for (int i = 0; i < 12; i++) if (out[24+i] != flags[i]) return 30+i;
  return 0;
}
`

func x86ParallelBitsOriginalRuntimeDriver(declarations, checks string) string {
	return `#include <stdint.h>
#include <stdio.h>
#include <string.h>
` + declarations + `
static uint64_t reference(uint64_t value,uint64_t mask,int bits,int deposit) {
 if(bits==32) {value=(uint32_t)value;mask=(uint32_t)mask;}
 uint64_t result=0,cursor=1;
 while(mask) {uint64_t low=mask&(-mask);if(deposit ? (value&cursor)!=0 : (value&low)!=0) result|=deposit?low:cursor;mask&=mask-1;cursor<<=1;}
 return result;
}
static int check(void (*fn)(uint64_t,const void *,void *),int bits,int deposit) {
 uint64_t state=0x9e3779b97f4a7c15ULL;
 for(int i=0;i<256;i++) {
  state^=state<<13;state^=state>>7;state^=state<<17;uint64_t value=state;
  state^=state<<13;state^=state>>7;state^=state<<17;uint64_t mask=state;
  if(i==0)mask=0;if(i==1)mask=~(uint64_t)0;if(i>=2&&i<66)mask=(uint64_t)1<<(i-2);
  uint8_t storage[9],out[16]={0};memcpy(storage+1,&mask,8);
  fn(value,storage+1,out);uint64_t actual;memcpy(&actual,out,8);
  const uint8_t flags[5]={0,0,1,1,1};
  if(actual!=reference(value,mask,bits,deposit)||memcmp(out+8,flags,5)) {fprintf(stderr,"parallel bits mismatch bits=%d deposit=%d case=%d\n",bits,deposit,i);return 1;}
 }
 return 0;
}
int main(void) {
` + checks + "return 0;\n}\n"
}
