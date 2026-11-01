package plan9asm

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func arm64SM3RuntimeFixture(t *testing.T) (*File, map[string]FuncSig, string, string, string) {
	t.Helper()
	var source, goDeclarations, goChecks, cDeclarations, cChecks strings.Builder
	sigs := make(map[string]FuncSig)
	for _, tc := range arm64SM3AliasCases() {
		source.WriteString(arm64SM3Fixture(tc.name, tc.word))
		sigs[tc.name] = arm64SM3Signature(tc.name)
		fmt.Fprintf(&goDeclarations, "func %s(*[128]uint32, *[132]uint32)\n", tc.name)
		fmt.Fprintf(&goChecks, "check(%s,%d,%d,%d,%d,%d,%d)\n", tc.name, tc.kind, tc.d, tc.n, tc.m, tc.a, tc.lane)
		fmt.Fprintf(&cDeclarations, "extern void %s(const uint32_t *, uint32_t *);\n", tc.name)
		fmt.Fprintf(&cChecks, "if(check(%s,%d,%d,%d,%d,%d,%d)) return 1;\n", tc.name, tc.kind, tc.d, tc.n, tc.m, tc.a, tc.lane)
	}
	requireARM64GoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	goMain := arm64SM3OracleGo + goDeclarations.String() + "func main(){\n" + goChecks.String() + "}\n"
	cMain := arm64SM3OracleC + cDeclarations.String() + "int main(void){\n" + cChecks.String() + "return 0;\n}\n"
	return file, sigs, source.String(), goMain, cMain
}

func TestARM64RawSM3PortableRuntimeSemantics(t *testing.T) {
	// This executes the lowered arithmetic, not the original SM3 instruction.
	// The separate mandatory Linux/QEMU test executes the original Go WORD.
	if runtime.GOARCH != "arm64" || runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("portable ARM64 execution is also covered by the required cross matrix")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	file, sigs, _, _, main := arm64SM3RuntimeFixture(t)
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	compileAndRunRuntimeTestForTarget(t, llc, clang, "raw_sm3_portable", triple, ir, main, nil)
	t.Log("LLVM arithmetic / independent C: 105 register-alias/lane cases x 256 inputs, all vectors/NZCV/canaries")
}

func TestCrossLinuxRuntimeMatrixARM64SM3(t *testing.T) {
	if os.Getenv("PLAN9ASM_CROSS_EXEC") != "1" {
		t.Skip("original SM3 WORD execution belongs to the required Linux/QEMU matrix")
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Fatal("SM3 cross-runtime driver requires Linux/amd64")
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, tool := range []string{"qemu-aarch64", "aarch64-linux-gnu-gcc"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatalf("required SM3 cross-runtime tool %s: %v", tool, err)
		}
	}
	t.Setenv("QEMU_CPU", "max")
	file, sigs, source, goMain, cMain := arm64SM3RuntimeFixture(t)
	dir := t.TempDir()
	for name, body := range map[string]string{
		"go.mod": "module sm3raworacle\n\ngo 1.20\n", "main.go": goMain,
		"oracle_arm64.s": strings.ReplaceAll(source, "TEXT sm3case", "TEXT ·sm3case"),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "run", "-p=1", "-exec=qemu-aarch64", ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=arm64", "CGO_ENABLED=0", "GOTOOLCHAIN=local")
	if output, err := runtimeOracleCombinedOutput(ctx, cmd); err != nil {
		t.Fatalf("actual Go SM3 raw WORD / independent Go scalar oracle: %v\n%s", err, output)
	}
	t.Log("actual Go raw WORD / independent Go scalar: 105 alias/lane cases x 256 inputs, all vectors/NZCV/canaries")
	const triple = "aarch64-unknown-linux-gnu"
	ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	compileAndRunRuntimeTestWithCompiler(t, llc, []string{"aarch64-linux-gnu-gcc"}, "raw_sm3_cross", triple, ir, cMain,
		[]string{"qemu-aarch64", "-cpu", "max", "-L", "/usr/aarch64-linux-gnu"})
	t.Log("LLVM22 / independent C scalar oracle passed the same 26880 cases")
}

const arm64SM3OracleGo = `package main
import "math/bits"
func reference(kind,lane int,d,n,m,a [4]uint32) (out [4]uint32) {
 rol:=bits.RotateLeft32
 p1:=func(x uint32)uint32{return x^rol(x,15)^rol(x,23)}
 switch kind {
 case 0:
  for i:=0;i<3;i++ {out[i]=p1(d[i]^n[i]^rol(m[i+1],15))}
  out[3]=p1(d[3]^n[3]^rol(out[0],15))
 case 1:
  var x [4]uint32
  for i:=range x {x[i]=n[i]^rol(m[i],7);out[i]=d[i]^x[i]}
  out[3]^=p1(rol(x[0],15))
 case 2: out[3]=rol(rol(n[3],12)+m[3]+a[3],7)
 default:
  x:=d[3]^d[2]^d[1]
  if kind==4 {x=(d[3]&d[2])|(d[3]&d[1])|(d[2]&d[1])}
  if kind==6 {x=(d[3]&d[2])|(^d[3]&d[1])}
  ss:=n[3]; rotation:=19
  if kind==3||kind==4 {ss^=rol(d[3],12);rotation=9}
  x+=d[0]+ss+m[lane]
  if rotation==19 {x^=rol(x,9)^rol(x,17)}
  out=[4]uint32{d[1],rol(d[2],rotation),d[3],x}
 }
 return
}
func check(fn func(*[128]uint32,*[132]uint32),kind,d,n,m,a,lane int) {
 var input [128]uint32
 var got,want [132]uint32
 seed:=uint32(0x12345678)
 var seenZero,seenOne uint32
 for trial:=0;trial<256;trial++ {
  for i:=range input {
   seed=seed*1664525+1013904223
   input[i]=seed
   if trial==0 {input[i]=0}
   if trial==1 {input[i]=0xffffffff}
   if trial>=2&&trial<130 {input[i]=0;if i==trial-2 {input[i]=1<<uint(i%32)}}
  }
  for i:=range got {got[i]=0xa5a5a5a5;want[i]=0xa5a5a5a5}
  copy(want[:128],input[:])
  vector:=func(r int)(v [4]uint32){copy(v[:],input[r*4:r*4+4]);return}
  out:=reference(kind,lane,vector(d),vector(n),vector(m),vector(a))
  copy(want[d*4:d*4+4],out[:])
  left:=uint64(input[0])|uint64(input[1])<<32
  right:=uint64(input[2])|uint64(input[3])<<32
  sum,carry:=bits.Add64(left,right,0)
  flags:=uint32(sum>>63)|uint32(carry)<<2|uint32(((left^sum)&(right^sum))>>63)<<3
  if sum==0 {flags|=2}
  want[128]=flags;want[129]=0
  seenZero|=(^flags)&15;seenOne|=flags
  fn(&input,&got)
  if got!=want {println(kind,d,n,m,a,lane,trial);panic("Go SM3 raw result/source/NZCV/canary mismatch")}
 }
 if seenZero!=15||seenOne!=15 {panic("SM3 oracle did not exercise both values of every NZCV flag")}
}
`

const arm64SM3OracleC = `
#include <stdint.h>
#include <stdio.h>
#include <string.h>
static uint32_t rol(uint32_t x,unsigned n){return (x<<n)|(x>>(32-n));}
static uint32_t p1(uint32_t x){return x^rol(x,15)^rol(x,23);}
static void reference(uint32_t out[4],int kind,int lane,const uint32_t d[4],
                      const uint32_t n[4],const uint32_t m[4],const uint32_t a[4]) {
 if(kind==0) {
  for(unsigned i=0;i<3;i++) out[i]=p1(d[i]^n[i]^rol(m[i+1],15));
  out[3]=p1(d[3]^n[3]^rol(out[0],15));
 } else if(kind==1) {
  uint32_t x[4];
  for(unsigned i=0;i<4;i++){x[i]=n[i]^rol(m[i],7);out[i]=d[i]^x[i];}
  out[3]^=p1(rol(x[0],15));
 } else if(kind==2) {
  out[0]=out[1]=out[2]=0;
  out[3]=rol(rol(n[3],12)+m[3]+a[3],7);
 } else {
  uint32_t boolean=d[3]^d[2]^d[1],ss=n[3];
  if(kind==4) boolean=(d[3]&d[2])|(d[3]&d[1])|(d[2]&d[1]);
  if(kind==6) boolean=(d[3]&d[2])|(~d[3]&d[1]);
  unsigned rotation=19;
  if(kind==3||kind==4){ss^=rol(d[3],12);rotation=9;}
  uint32_t x=boolean+d[0]+ss+m[lane];
  out[0]=d[1];out[1]=rol(d[2],rotation);out[2]=d[3];
  out[3]=rotation==19 ? x^rol(x,9)^rol(x,17) : x;
 }
}
static int check(void(*fn)(const uint32_t *,uint32_t *),int kind,int d,int n,int m,int a,int lane) {
 uint32_t input[128],got[132],want[132],out[4],seed=0x12345678;
 uint32_t seen_zero=0,seen_one=0;
 for(unsigned trial=0;trial<256;trial++) {
  for(unsigned i=0;i<128;i++) {
   seed=seed*1664525U+1013904223U;
   input[i]=seed;
   if(trial==0) input[i]=0;
   if(trial==1) input[i]=UINT32_MAX;
   if(trial>=2&&trial<130) input[i]=i==trial-2 ? UINT32_C(1)<<(i%32) : 0;
  }
  for(unsigned i=0;i<132;i++) got[i]=want[i]=UINT32_C(0xa5a5a5a5);
  memcpy(want,input,sizeof(input));
  reference(out,kind,lane,input+4*d,input+4*n,input+4*m,input+4*a);
  memcpy(want+4*d,out,sizeof(out));
  uint64_t left=(uint64_t)input[0]|(uint64_t)input[1]<<32;
  uint64_t right=(uint64_t)input[2]|(uint64_t)input[3]<<32;
  uint64_t sum=left+right;
  uint32_t flags=(uint32_t)(sum>>63)|((uint32_t)(sum==0)<<1)|
                 ((uint32_t)(sum<left)<<2)|((uint32_t)(((left^sum)&(right^sum))>>63)<<3);
  want[128]=flags;want[129]=0;
  seen_zero|=(~flags)&15;seen_one|=flags;
  fn(input,got);
  if(memcmp(got,want,sizeof(got))) {
   fprintf(stderr,"SM3 kind=%d d=%d n=%d m=%d a=%d lane=%d trial=%u\n",kind,d,n,m,a,lane,trial);
   return 1;
  }
 }
 if(seen_zero!=15||seen_one!=15){fprintf(stderr,"SM3 NZCV inputs lack flag coverage\n");return 1;}
 return 0;
}
`
