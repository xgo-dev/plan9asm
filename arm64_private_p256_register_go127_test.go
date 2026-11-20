//go:build go1.27

package plan9asm

import (
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

// Use the current Go helper's complete body. The test's scalar-only ABI0
// wrapper supplies each real register input and exposes all four outputs plus
// an independent check that the helper preserves R0/R2. No pointer/frame
// nonalias promise, library-name registry or scalar helper signature is used.
func arm64PrivateP256Source(t *testing.T, helper string, inputCount int, outputs []Reg) string {
	t.Helper()
	path := filepath.Join(runtime.GOROOT(), "src", "crypto", "internal", "fips140", "nistec", "p256_asm_arm64.s")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	prefix := source[:strings.Index(source, "DATA p256const0<>")]
	start := strings.Index(source, "TEXT "+helper+"<>(SB)")
	if start < 0 {
		t.Fatalf("current Go source has no helper %s", helper)
	}
	body := source[start:]
	if end := strings.Index(body[1:], "\nTEXT "); end >= 0 {
		body = body[:end+1]
	}
	// Mul is the final private helper but precedes more public TEXT bodies.
	var wrapper strings.Builder
	fmt.Fprintf(&wrapper, "TEXT ·Run(SB),4,$0-%d\n", (inputCount+5)*8)
	for i := 0; i < inputCount; i++ {
		fmt.Fprintf(&wrapper, "MOVD a%d+%d(FP),R%d\n", i, i*8, 19+i)
	}
	wrapper.WriteString("MOVD $0x00000000ffffffff,R15\nMOVD $0xffffffff00000001,R16\n")
	wrapper.WriteString("MOVD $0x123456789abcdef0,R0\nMOVD $7,R2\n")
	fmt.Fprintf(&wrapper, "CALL %s<>(SB)\n", helper)
	for i, reg := range outputs {
		fmt.Fprintf(&wrapper, "MOVD %s,r%d+%d(FP)\n", reg, i, (inputCount+i)*8)
	}
	wrapper.WriteString("MOVD $0x123456789abcdef0,R11\nEOR R11,R0\nSUB $7,R2\nORR R2,R0\n")
	fmt.Fprintf(&wrapper, "MOVD R0,bad+%d(FP)\nRET\n", (inputCount+4)*8)
	return prefix + wrapper.String() + body
}

func arm64P256Words(value *big.Int) [4]uint64 {
	var out [4]uint64
	n := new(big.Int).Set(value)
	mask := new(big.Int).SetUint64(^uint64(0))
	for i := range out {
		out[i] = new(big.Int).And(n, mask).Uint64()
		n.Rsh(n, 64)
	}
	return out
}

func TestCrossLinuxRuntimeMatrixARM64PrivateP256RegisterHelpers(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	p, ok := new(big.Int).SetString("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16)
	if !ok {
		t.Fatal("invalid independent P256 modulus")
	}
	rinv := new(big.Int).ModInverse(new(big.Int).Lsh(big.NewInt(1), 256), p)
	for _, test := range []struct {
		helper string
		inputs int
		output []Reg
	}{
		{"p256SqrInternal", 4, []Reg{"R23", "R24", "R25", "R26"}},
		{"p256MulInternal", 8, []Reg{"R23", "R24", "R25", "R26"}},
		{"p256SubInternal", 8, []Reg{"R19", "R20", "R21", "R22"}},
	} {
		t.Run(test.helper, func(t *testing.T) {
			source := arm64PrivateP256Source(t, test.helper, test.inputs, test.output)
			parameters := strings.TrimSuffix(strings.Repeat("uint64,", test.inputs), ",")
			decl := fmt.Sprintf("func Run(%s)(uint64,uint64,uint64,uint64,uint64)\n", parameters)
			var goRows, cRows strings.Builder
			seed := uint64(0x123456789abcdef0)
			for row := 0; row < 64; row++ {
				x, y := new(big.Int), new(big.Int)
				if row == 0 {
					x.SetInt64(0)
					y.SetInt64(0)
				} else if row == 1 {
					x.SetInt64(1)
					y.SetInt64(1)
				} else if row == 2 {
					x.Sub(p, big.NewInt(1))
					y.SetInt64(1)
				} else if row == 3 {
					x.SetInt64(1)
					y.Sub(p, big.NewInt(1))
				} else {
					for limb := 0; limb < 4; limb++ {
						seed = seed*6364136223846793005 + 1
						x.Or(x, new(big.Int).Lsh(new(big.Int).SetUint64(seed), uint(limb*64)))
						seed = seed*6364136223846793005 + 1
						y.Or(y, new(big.Int).Lsh(new(big.Int).SetUint64(seed), uint(limb*64)))
					}
					x.Mod(x, p)
					y.Mod(y, p)
				}
				want := new(big.Int)
				switch test.helper {
				case "p256SqrInternal":
					want.Mul(x, x).Mul(want, rinv).Mod(want, p)
				case "p256MulInternal":
					want.Mul(x, y).Mul(want, rinv).Mod(want, p)
				case "p256SubInternal":
					want.Sub(y, x).Mod(want, p)
				}
				xw, yw, ww := arm64P256Words(x), arm64P256Words(y), arm64P256Words(want)
				args := append([]uint64(nil), xw[:]...)
				if test.inputs == 8 {
					args = append(args, yw[:]...)
				}
				all := append(append([]uint64(nil), args...), ww[:]...)
				goRows.WriteString("{")
				cRows.WriteString("{")
				for i, value := range all {
					if i != 0 {
						goRows.WriteString(",")
						cRows.WriteString(",")
					}
					fmt.Fprintf(&goRows, "0x%x", value)
					fmt.Fprintf(&cRows, "UINT64_C(0x%x)", value)
				}
				goRows.WriteString("},\n")
				cRows.WriteString("},\n")
			}
			var args strings.Builder
			for i := 0; i < test.inputs; i++ {
				if i != 0 {
					args.WriteString(",")
				}
				fmt.Fprintf(&args, "row[%d]", i)
			}
			runARM64LocalRegisterGoOracle(t, source, "package main\n"+decl+fmt.Sprintf(`func main() {
  rows:=[][ %d ]uint64{
%s}
  for _,row:=range rows {
    a,b,c,d,bad:=Run(%s)
    if a!=row[%d] || b!=row[%d] || c!=row[%d] || d!=row[%d] || bad!=0 { panic("real private P256 register helper mismatch") }
  }
}
`, test.inputs+4, goRows.String(), args.String(), test.inputs, test.inputs+1, test.inputs+2, test.inputs+3), len(runner) != 0)
			pkg := mustGoPackage(t, "test/privatep256", "package privatep256\n"+decl)
			translate := func(target string) string {
				ctx := llvm.NewContext()
				defer ctx.Dispose()
				tr, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{
					GOARCH: "arm64", TargetTriple: target,
					ResolveSym: func(sym string) string { return strings.TrimPrefix(sym, "·") },
				})
				if err != nil {
					t.Fatal(err)
				}
				defer tr.Module.Dispose()
				if tr.Module.Context() != ctx {
					t.Fatal("real P256 helper escaped its owned context")
				}
				ir := tr.Module.String()
				if len(tr.Signatures) != 1 || len(tr.Functions) != 1 {
					t.Fatal("private helper acquired a fake scalar/native entry")
				}
				return ir + arm64P256CheckIR(test.inputs)
			}
			for _, target := range []string{
				"aarch64-apple-darwin", "aarch64-unknown-linux-gnu",
				"aarch64-unknown-freebsd", "aarch64-pc-windows-msvc",
				"aarch64-unknown-linux-musl",
			} {
				compileLLVMToObject(t, llc, target, "p256-private.ll", "p256-private.o", translate(target))
			}
			cParameters := strings.TrimSuffix(strings.Repeat("uint64_t,", test.inputs+4), ",")
			for i := test.inputs; i < test.inputs+4; i++ {
				fmt.Fprintf(&args, ",row[%d]", i)
			}
			main := fmt.Sprintf(`#include <stdint.h>
extern uint64_t Check(%s);
int main(void) {
  uint64_t rows[][%d]={
%s};
  for (unsigned i=0;i<64;i++) {
    uint64_t *row=rows[i];
    if (Check(%s)!=0) return 1;
  }
  return 0;
}
`, cParameters, test.inputs+4, cRows.String(), args.String())
			compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "p256_private", triple, translate(triple), main, runner)
		})
	}
}

// A scalar C boundary is separate from the logical Go tuple return. Both the
// original entry and this wrapper are typed LLVM calls; no Clang aggregate ABI
// or private helper return convention is guessed.
func arm64P256CheckIR(inputs int) string {
	var ir strings.Builder
	ir.WriteString("\ndefine i64 @Check(")
	for i := 0; i < inputs+4; i++ {
		if i != 0 {
			ir.WriteString(", ")
		}
		fmt.Fprintf(&ir, "i64 %%a%d", i)
	}
	ir.WriteString(") {\nentry:\n  %r = call {i64,i64,i64,i64,i64} @Run(")
	for i := 0; i < inputs; i++ {
		if i != 0 {
			ir.WriteString(", ")
		}
		fmt.Fprintf(&ir, "i64 %%a%d", i)
	}
	ir.WriteString(")\n")
	for i := 0; i < 4; i++ {
		fmt.Fprintf(&ir, "  %%v%d = extractvalue {i64,i64,i64,i64,i64} %%r, %d\n  %%bad%d = xor i64 %%v%d, %%a%d\n", i, i, i, i, inputs+i)
	}
	ir.WriteString("  %bad4 = extractvalue {i64,i64,i64,i64,i64} %r, 4\n  %b01 = or i64 %bad0, %bad1\n  %b23 = or i64 %bad2, %bad3\n  %b0123 = or i64 %b01, %b23\n  %all = or i64 %b0123, %bad4\n  ret i64 %all\n}\n")
	return ir.String()
}

// The unchanged public Sqr body stores through its incoming result pointer.
// The complete source has no way to expose this invocation's fresh virtual SP,
// so those heap stores cannot alias its automatically saved caller link.
func TestCrossLinuxRuntimeMatrixARM64PrivateP256PointerUnexposedFrame(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src", "crypto", "internal", "fips140", "nistec", "p256_asm_arm64.s"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	prefix := text[:strings.Index(text, "TEXT ")]
	extract := func(header string) string {
		start := strings.Index(text, header)
		if start < 0 {
			t.Fatalf("missing current Go source %q", header)
		}
		body := text[start:]
		if end := strings.Index(body[1:], "\nTEXT "); end >= 0 {
			body = body[:end+1]
		}
		return body
	}
	source := prefix + strings.Replace(extract("TEXT ·p256Sqr(SB)"), "TEXT ·p256Sqr(SB)", "TEXT ·Public(SB)", 1) + "\n" + extract("TEXT p256SqrInternal<>(SB)") + "\n"
	runARM64LocalRegisterGoOracle(t, source, `package main
import "math/big"
func Public(*[4]uint64,*[4]uint64,int)
func main() {
  p,_:=new(big.Int).SetString("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",16)
  rinv:=new(big.Int).ModInverse(new(big.Int).Lsh(big.NewInt(1),256),p)
  seed:=uint64(0x123456789abcdef0)
  mask:=new(big.Int).SetUint64(^uint64(0))
  for i:=0;i<32;i++ {
    x:=new(big.Int)
    for limb:=0;limb<4;limb++ {
      seed=seed*6364136223846793005+1
      x.Or(x,new(big.Int).Lsh(new(big.Int).SetUint64(seed),uint(limb*64)))
    }
    x.Mod(x,p)
    in:=new([4]uint64)
    words:=new(big.Int).Set(x)
    for limb:=range in { in[limb]=new(big.Int).And(words,mask).Uint64();words.Rsh(words,64) }
    n:=i%4+1
    out:=new([4]uint64)
    Public(out,in,n)
    for j:=0;j<n;j++ { x.Mul(x,x).Mul(x,rinv).Mod(x,p) }
    for limb:=range out {
      if out[limb]!=new(big.Int).And(x,mask).Uint64() { panic("real public P256 Sqr data oracle mismatch") }
      x.Rsh(x,64)
    }
  }
}
`, len(runner) != 0)
	pkg := mustGoPackage(t, "test/privatep256", "package privatep256\nfunc Public(*[4]uint64,*[4]uint64,int)\n")
	translate := func(target string) string {
		ctx := llvm.NewContext()
		defer ctx.Dispose()
		tr, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{
			GOARCH: "arm64", TargetTriple: target,
			ResolveSym: func(sym string) string { return strings.TrimPrefix(sym, "·") },
		})
		if err != nil {
			t.Fatalf("%s: real public P256 Sqr's incoming pointer cannot expose fresh SP: %v", target, err)
		}
		defer tr.Module.Dispose()
		return tr.Module.String()
	}
	for _, target := range append([]string{
		"aarch64-apple-darwin", "aarch64-unknown-linux-gnu",
		"aarch64-unknown-freebsd", "aarch64-pc-windows-msvc",
		"aarch64-unknown-linux-musl",
	}, triple) {
		ir := translate(target)
		compileLLVMToObject(t, llc, target, "p256-public.ll", "p256-public.o", ir)
		if target == triple {
			p, ok := new(big.Int).SetString("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16)
			if !ok {
				t.Fatal("invalid independent P256 modulus")
			}
			rinv := new(big.Int).ModInverse(new(big.Int).Lsh(big.NewInt(1), 256), p)
			var rows strings.Builder
			seed := uint64(0x123456789abcdef0)
			for i := 0; i < 32; i++ {
				x := new(big.Int)
				for limb := 0; limb < 4; limb++ {
					seed = seed*6364136223846793005 + 1
					x.Or(x, new(big.Int).Lsh(new(big.Int).SetUint64(seed), uint(limb*64)))
				}
				x.Mod(x, p)
				input := arm64P256Words(x)
				n := i%4 + 1
				for j := 0; j < n; j++ {
					x.Mul(x, x).Mul(x, rinv).Mod(x, p)
				}
				output := arm64P256Words(x)
				rows.WriteString("{")
				for _, value := range append(input[:], output[:]...) {
					fmt.Fprintf(&rows, "UINT64_C(0x%x),", value)
				}
				fmt.Fprintf(&rows, "%d},\n", n)
			}
			main := fmt.Sprintf(`#include <stdint.h>
extern void Public(uint64_t *,const uint64_t *,uint64_t);
int main(void) {
 uint64_t rows[32][9]={%s};
 for(int i=0;i<32;i++) {
  uint64_t *row=rows[i],out[6]={UINT64_C(0x123456789abcdef0),0,0,0,0,UINT64_C(0xfedcba9876543210)};
  Public(out+1,row,row[8]);
  if(out[0]!=UINT64_C(0x123456789abcdef0)||out[5]!=UINT64_C(0xfedcba9876543210)) return 1;
  for(int j=0;j<4;j++) if(out[j+1]!=row[j+4]) return 2;
 }
 return 0;
}
`, rows.String())
			compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "p256_public", triple, ir, main, runner)
		}
	}
}
