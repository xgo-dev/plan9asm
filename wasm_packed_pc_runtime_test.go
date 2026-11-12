package plan9asm

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func wasmPackedRuntimeFixture(t *testing.T) (string, map[string]FuncSig, string) {
	t.Helper()
	var source, goSource strings.Builder
	source.WriteString(`TEXT ·target(SB),4,$0-0
MOVD $·calls(SB), R1
MOVD 0(R1), R0
Get R0
I64Const $1
I64Add
Set R0
MOVD R0, 0(R1)
RET
GLOBL ·calls(SB),16,$8
TEXT ·dynamicCall(SB),4,$0-0
I64Const $·target(SB)
CALL
RET
TEXT ·dynamicJump(SB),4,$0-0
I64Const $·target(SB)
JMP
TEXT ·readCalls(SB),4,$0-8
MOVD $·calls(SB), R1
MOVD 0(R1), R0
MOVD R0, ret+0(FP)
RET
`)
	sigs := map[string]FuncSig{
		"target": {Name: "target", Ret: Void}, "dynamicCall": {Name: "dynamicCall", Ret: Void}, "dynamicJump": {Name: "dynamicJump", Ret: Void},
		"readCalls": {Name: "readCalls", Ret: I64, Frame: FrameLayout{Results: []FrameSlot{{Offset: 0, Index: 0, Type: I64}}}},
	}
	native, ok := LookupGoWASMNativeFuncSig("runtime.wasmDiv")
	if !ok {
		t.Fatal("actual Go native contract absent")
	}
	sigs["runtime.wasmDiv"] = native
	goSource.WriteString("package main\nimport \"fmt\"\nfunc target()\nfunc dynamicCall()\nfunc dynamicJump()\nfunc readCalls() uint64\n")
	goSource.WriteString("//go:noinline\nfunc nativeDivision(a,b int64)int64{return a/b}\n")
	var addresses []string
	for _, target := range []string{"·target", "runtime·wasmDiv"} {
		for _, addend := range []int64{0, 1, 65535} {
			for _, opcode := range []string{"I64Const", "I32Const", "MOVB", "MOVH", "MOVW", "MOVD"} {
				name := fmt.Sprintf("address%d", len(addresses))
				operand := fmt.Sprintf("$%s%+d(SB)", target, addend)
				body := opcode + " " + operand + "\n"
				if strings.HasPrefix(opcode, "MOV") {
					body = opcode + " " + operand + ", R0\nGet R0\n"
				} else if opcode == "I32Const" {
					body += "I64ExtendI32U\n"
				}
				fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-8\nGet SP\n%sI64Store ret+0(FP)\nRET\n", name, body)
				fmt.Fprintf(&source, "DATA ·holder%d(SB)/1,$0xa5\nDATA ·holder%d+1(SB)/8,%s\nDATA ·holder%d+9(SB)/1,$0x5a\nGLOBL ·holder%d(SB),24,$16\n", len(addresses), len(addresses), operand, len(addresses), len(addresses))
				sigs[name] = FuncSig{Name: name, Ret: I64, Frame: FrameLayout{Results: []FrameSlot{{Offset: 0, Index: 0, Type: I64}}}}
				fmt.Fprintf(&goSource, "func %s() uint64\n", name)
				addresses = append(addresses, name)
			}
		}
	}
	var numeric []string
	var expected []uint64
	for _, op := range []string{"MOVB", "MOVH", "MOVW", "MOVD"} {
		bits := map[string]uint{"MOVB": 8, "MOVH": 16, "MOVW": 32, "MOVD": 64}[op]
		mask := ^uint64(0)
		if bits < 64 {
			mask = (1 << bits) - 1
		}
		for _, form := range []string{"constant", "register", "load", "store_low", "store_high", "memory_copy", "constant_store", "address_store"} {
			name := fmt.Sprintf("numeric%d", len(numeric))
			body := "MOVD $0x88776655fedcba98, 0(SP)\nMOVD $0x1020304050607080, 8(SP)\n"
			want := uint64(0x88776655fedcba98)
			switch form {
			case "constant":
				body += op + " $0x88776655fedcba98, R0\n"
			case "register":
				body += "MOVD $0x88776655fedcba98, R1\n" + op + " R1, R0\n"
			case "load":
				body += op + " 0(SP), R0\n"
				want &= mask
			case "store_low", "store_high":
				body += "MOVD $0xa1b2c3d4e5f60718, R1\n" + op + " R1, 1(SP)\n"
				if form == "store_low" {
					body += "MOVD 0(SP), R0\n"
					want = (want & ^(mask << 8)) | ((uint64(0xa1b2c3d4e5f60718) & mask) << 8)
				} else {
					body += "MOVD 8(SP), R0\n"
					want = 0x1020304050607080
					if bits == 64 {
						want = (want & ^uint64(255)) | 0xa1
					}
				}
			case "memory_copy":
				body += op + " 0(SP), 8(SP)\nMOVD 8(SP), R0\n"
				want = (uint64(0x1020304050607080) & ^mask) | (want & mask)
			case "constant_store":
				body += op + " $0xa1b2c3d4e5f60718, 0(SP)\nMOVD 0(SP), R0\n"
				want = (want & ^mask) | (uint64(0xa1b2c3d4e5f60718) & mask)
			case "address_store":
				body += op + " $·target+65535(SB), 0(SP)\nMOVD 0(SP), R0\n"
				// The actual function index is assigned by each linker; only the
				// non-address bytes are fixed in the independent expected value.
				want &= ^mask
			}
			fmt.Fprintf(&source, "TEXT ·%s(SB),4,$16-8\n%sMOVD R0, ret+0(FP)\nRET\n", name, body)
			sigs[name] = FuncSig{Name: name, Ret: I64, Frame: FrameLayout{Results: []FrameSlot{{Offset: 0, Index: 0, Type: I64}}}}
			fmt.Fprintf(&goSource, "func %s() uint64\n", name)
			numeric, expected = append(numeric, name), append(expected, want)
		}
	}
	goSource.WriteString("func main(){\na:=[]func()uint64{" + strings.Join(addresses, ",") + "}\n")
	goSource.WriteString("for i,f:=range a {b:=a[(i/18)*18]();v:=f();want:=b+[]uint64{0,1,65535}[(i%18)/6];if i%6==1{want=uint64(uint32(want))};if b<0x10000000||b&65535!=0||v!=want{panic(fmt.Sprintf(\"Go address %d: %x != %x\",i,v,want))}}\n")
	goSource.WriteString("n:=[]func()uint64{" + strings.Join(numeric, ",") + "}\nw:=[]uint64{")
	for _, value := range expected {
		fmt.Fprintf(&goSource, "%d,", value)
	}
	goSource.WriteString("}\nfor i,f:=range n{want:=w[i];if i%8==7{bits:=[]uint{8,16,32,64}[i/8];mask:=^uint64(0);if bits<64{mask=(1<<bits)-1};want|=(a[0]()+65535)&mask};if v:=f();v!=want{panic(fmt.Sprintf(\"Go MOV %d: %x != %x\",i,v,want))}}\ndynamicCall();dynamicJump();if readCalls()!=2{panic(\"Go dynamic CALL/JMP count\")};d:=[][2]int64{{81,9},{-81,9},{0,5},{-9223372036854775808,-1}};r:=[]int64{9,-9,0,-9223372036854775808};for i,p:=range d{if nativeDivision(p[0],p[1])!=r[i]{panic(\"actual Go native division\")}};fmt.Println(\"actual Go packed address + complete MOV widths + dynamic calls + native division PASS\")}\n")
	return source.String(), sigs, goSource.String()
}

func TestWASMPackedFunctionAddressFirstLoadAndControlRuntime(t *testing.T) {
	source, sigs, _ := wasmPackedRuntimeFixture(t)
	source += wasmPackedNativeSource(t)
	for _, goos := range wasmPackedGoPlatforms {
		wasmDataGoObject(t, strings.ReplaceAll(source, "NOSPLIT", "4"), goos)
	}
	file, err := Parse(ArchWASM, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, route := range []string{"Translate", "TranslateModule", "TranslateModuleInContext"} {
		t.Run(route, func(t *testing.T) {
			ir, err := wasmPackedTranslate(t, file, wasmPackedOptions(sigs, WASMABIGo), route)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(ir, "llvm.global_ctors") || strings.Contains(ir, "blockaddress") {
				t.Fatal("packed PC translation needs neither constructors nor blockaddress")
			}
			ir = strings.Replace(ir, "@SP = external addrspace(1) global i32", "@SP = addrspace(1) global i32 4096", 1)
			ir += "@target_index = constant i32 ptrtoint (ptr @target to i32)\n@native_index = constant i32 ptrtoint (ptr @\"runtime.wasmDiv\" to i32)\n"
			for name, sig := range sigs {
				if sig.WASMNative || name == "target" {
					continue
				}
				ir += fmt.Sprintf("define i64 @probe_%s(){ store i32 4096, ptr addrspace(1) @SP\n %%u=call i32 @%s(i32 0)\n %%v=load i64, ptr inttoptr(i32 4104 to ptr),align 1\n ret i64 %%v }\n", name, name)
			}
			for _, triple := range []string{"wasm32-unknown-unknown", "wasm32-wasi"} {
				input := strings.Replace(ir, "wasm32-unknown-unknown", triple, 1)
				partial, dir := wasmPackedObject(t, input)
				for _, tableBase := range []int{1, 65536} {
					final := filepath.Join(dir, fmt.Sprintf("final-%d.wasm", tableBase))
					wasmDataCommand(t, wasmDataTool(t, "wasm-ld"), "--no-entry", "--export-all", "--export-memory", "--export-table", fmt.Sprintf("--table-base=%d", tableBase), partial, "-o", final)
					out := wasmDataCommand(t, wasmPackedNode(t), "-e", wasmPackedRuntimeNode, final)
					t.Logf("%s table-base=%d: %s", triple, tableBase, strings.TrimSpace(out))
				}
			}
		})
	}
}

func TestWASMPackedFunctionAddressDirectModelRuntime(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT ·target(SB),4,$0-0\nRET\n")
	source.WriteString(wasmPackedNativeSource(t))
	native, ok := LookupGoWASMNativeFuncSig("runtime.wasmDiv")
	if !ok {
		t.Fatal("actual Go native contract absent")
	}
	sigs := map[string]FuncSig{
		"target": {Name: "target", Ret: Void}, "runtime.wasmDiv": native,
	}
	index := 0
	for _, target := range []string{"·target", "runtime·wasmDiv"} {
		fmt.Fprintf(&source, "DATA ·direct%d(SB)/8,$%s(SB)\nGLOBL ·direct%d(SB),24,$8\n", index/18, target, index/18)
		for _, addend := range []int64{-1, 0, 65535} {
			for _, opcode := range []string{"I64Const", "I32Const", "MOVB", "MOVH", "MOVW", "MOVD"} {
				name := fmt.Sprintf("directAddress%d", index)
				operand := fmt.Sprintf("$%s%+d(SB)", target, addend)
				body := opcode + " " + operand + "\n"
				if strings.HasPrefix(opcode, "MOV") {
					body = opcode + " " + operand + ", R0\n"
				} else {
					if opcode == "I32Const" {
						body += "I64ExtendI32U\n"
					}
					body += "Set R0\n"
				}
				fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-8\n%sMOVD R0, ret+0(FP)\nRET\n", name, body)
				sigs[name] = FuncSig{Name: name, Ret: I64, Frame: FrameLayout{Results: []FrameSlot{{Offset: 0, Index: 0, Type: I64}}}}
				index++
			}
		}
	}
	for _, goos := range wasmPackedGoPlatforms {
		wasmDataGoObject(t, strings.ReplaceAll(source.String(), "NOSPLIT", "4"), goos)
	}
	file, err := Parse(ArchWASM, source.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, route := range []string{"Translate", "TranslateModule", "TranslateModuleInContext"} {
		t.Run(route, func(t *testing.T) {
			ir, err := wasmPackedTranslate(t, file, wasmPackedOptions(sigs, WASMABIDirect), route)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(ir, "shl i64") || strings.Contains(ir, "llvm.global_ctors") {
				t.Fatal("Direct-model function address must remain an unshifted table index")
			}
			ir += "@target_index = constant i32 ptrtoint (ptr @target to i32)\n@native_index = constant i32 ptrtoint (ptr @\"runtime.wasmDiv\" to i32)\n"
			for _, triple := range []string{"wasm32-unknown-unknown", "wasm32-wasi"} {
				partial, dir := wasmPackedObject(t, strings.Replace(ir, "wasm32-unknown-unknown", triple, 1))
				relocs := wasmDataCommand(t, wasmDataTool(t, "llvm-readobj"), "--relocations", partial)
				if !strings.Contains(relocs, "R_WASM_TABLE_INDEX_I64") {
					t.Fatal("Direct DATA lost its original table-index-I64 relocation")
				}
				final := filepath.Join(dir, "direct.wasm")
				wasmDataCommand(t, wasmDataTool(t, "wasm-ld"), "--no-entry", "--export-all", "--export-memory", "--export-table", "--table-base=65536", partial, "-o", final)
				out := wasmDataCommand(t, wasmPackedNode(t), "-e", wasmDirectAddressNode, final)
				t.Logf("%s: %s", triple, strings.TrimSpace(out))
			}
		})
	}
}

const wasmDirectAddressNode = `
const fs=require('fs');
WebAssembly.instantiate(fs.readFileSync(process.argv[1]),{}).then(({instance:{exports:e}})=>{
  const v=new DataView(e.memory.buffer);
  const bases=[BigInt(v.getUint32(e.target_index.value,true)),BigInt(v.getUint32(e.native_index.value,true))];
  for(let i=0;i<2;i++)if(v.getBigUint64(e['direct'+i].value,true)!==bases[i])throw Error('first host Direct DATA index');
  for(let i=0;i<36;i++){
    let want=bases[Math.floor(i/18)]+[-1n,0n,65535n][Math.floor((i%18)/6)];
    if(i%6===1)want=BigInt.asUintN(32,want);
    if(BigInt.asUintN(64,e['directAddress'+i]())!==want)throw Error('unshifted Direct address '+i);
  }
  if(e['runtime.wasmDiv'](81n,9n)!==9n)throw Error('Direct native primitive');
  console.log('first Direct DATA + complete address family + native primitive PASS');
}).catch(e=>{console.error(e);process.exit(1)});
`

const wasmPackedRuntimeNode = `
const fs=require('fs');
WebAssembly.instantiate(fs.readFileSync(process.argv[1]),{}).then(({instance:{exports:e}})=>{
  const v=new DataView(e.memory.buffer);
  const bases=[BigInt(v.getUint32(e.target_index.value,true))<<16n,BigInt(v.getUint32(e.native_index.value,true))<<16n];
  for(let i=0;i<36;i++){
    const a=e['holder'+i].value,want=bases[Math.floor(i/18)]+[0n,1n,65535n][Math.floor((i%18)/6)];
    if(v.getUint8(a)!==165||v.getUint8(a+9)!==90||v.getBigUint64(a+1,true)!==want) throw Error('first host-memory packed DATA '+i);
  }
  for(let i=0;i<36;i++){
    let want=bases[Math.floor(i/18)]+[0n,1n,65535n][Math.floor((i%18)/6)];
    if(i%6===1)want=BigInt.asUintN(32,want);
    if(BigInt.asUintN(64,e['probe_address'+i]())!==want) throw Error('immediate PC '+i);
  }
  const init=0x88776655fedcba98n,high=0x1020304050607080n,value=0xa1b2c3d4e5f60718n;
  for(let i=0;i<32;i++){
    const bits=[8n,16n,32n,64n][Math.floor(i/8)],mask=(1n<<bits)-1n,f=i%8;
    let want=init;
    if(f===2)want=init&mask;
    if(f===3)want=BigInt.asUintN(64,(init&~(mask<<8n))|((value&mask)<<8n));
    if(f===4)want=bits===64n?(high&~255n)|0xa1n:high;
    if(f===5)want=(high&~mask)|(init&mask);
    if(f===6)want=(init&~mask)|(value&mask);
    if(f===7)want=(init&~mask)|((bases[0]+65535n)&mask);
    if(BigInt.asUintN(64,e['probe_numeric'+i]())!==want)throw Error('MOV width/value '+i);
  }
  if(v.getBigUint64(e.calls.value,true)!==0n)throw Error('premature target execution');
  e.probe_dynamicCall();e.probe_dynamicJump();
  if(v.getBigUint64(e.calls.value,true)!==2n)throw Error('Go dynamic CALL/JMP target count');
  for(const [a,b] of [[81n,9n],[-81n,9n],[0n,5n],[-9223372036854775808n,-1n]]){
    const want=BigInt.asIntN(64,a/b);
    if(e['runtime.wasmDiv'](a,b)!==want)throw Error('actual source WASMNative primitive');
  }
  console.log('first host packed DATA + LLVM MOV numeric + CALL/JMP count + native primitive PASS');
}).catch(e=>{console.error(e);process.exit(1)});
`
