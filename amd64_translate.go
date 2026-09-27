package plan9asm

import (
	"fmt"
	"strings"
)

type amd64EmitBr func(target string)
type amd64EmitCondBr func(cond string, target string, fall string) error

func emitAMD64Prelude(b *strings.Builder, goarch string, file *File) {
	b.WriteString("declare i64 @syscall(i64, i64, i64, i64, i64, i64, i64)\n")
	b.WriteString("declare i32 @cliteErrno()\n")
	// Generic LLVM intrinsics used by amd64 lowering.
	b.WriteString("declare i64 @llvm.cttz.i64(i64, i1)\n")
	b.WriteString("declare i32 @llvm.cttz.i32(i32, i1)\n")
	b.WriteString("declare i16 @llvm.cttz.i16(i16, i1)\n")
	b.WriteString("declare i64 @llvm.ctlz.i64(i64, i1)\n")
	b.WriteString("declare i32 @llvm.ctlz.i32(i32, i1)\n")
	b.WriteString("declare i16 @llvm.ctlz.i16(i16, i1)\n")
	b.WriteString("declare i64 @llvm.ctpop.i64(i64)\n")
	b.WriteString("declare i32 @llvm.ctpop.i32(i32)\n")
	b.WriteString("declare i16 @llvm.ctpop.i16(i16)\n")
	b.WriteString("declare i32 @llvm.x86.rdpid()\n")
	b.WriteString("declare i32 @llvm.x86.xbegin()\n")
	b.WriteString("declare void @llvm.x86.xabort(i8 immarg)\n")
	b.WriteString("declare void @llvm.x86.xend()\n")
	b.WriteString("declare i32 @llvm.x86.xtest()\n")
	for _, family := range []string{"rdrand", "rdseed"} {
		for _, bits := range []int{16, 32, 64} {
			fmt.Fprintf(b, "declare { i%d, i32 } @llvm.x86.%s.%d()\n", bits, family, bits)
		}
	}
	for _, laneBits := range []int{8, 16, 32, 64} {
		for _, byteWidth := range []int{16, 32, 64} {
			lanes := byteWidth * 8 / laneBits
			fmt.Fprintf(b, "declare <%d x i%d> @llvm.ctpop.v%di%d(<%d x i%d>)\n", lanes, laneBits, lanes, laneBits, lanes, laneBits)
			fmt.Fprintf(b, "declare <%d x i%d> @llvm.ctlz.v%di%d(<%d x i%d>, i1)\n", lanes, laneBits, lanes, laneBits, lanes, laneBits)
			fmt.Fprintf(b, "declare <%d x i%d> @llvm.experimental.vector.compress.v%di%d(<%d x i%d>, <%d x i1>, <%d x i%d>)\n", lanes, laneBits, lanes, laneBits, lanes, laneBits, lanes, lanes, laneBits)
			fmt.Fprintf(b, "declare void @llvm.masked.compressstore.v%di%d(<%d x i%d>, ptr, <%d x i1>)\n", lanes, laneBits, lanes, laneBits, lanes)
			fmt.Fprintf(b, "declare void @llvm.masked.compressstore.v%di%d.p256(<%d x i%d>, ptr addrspace(256), <%d x i1>)\n", lanes, laneBits, lanes, laneBits, lanes)
			fmt.Fprintf(b, "declare void @llvm.masked.compressstore.v%di%d.p257(<%d x i%d>, ptr addrspace(257), <%d x i1>)\n", lanes, laneBits, lanes, laneBits, lanes)
			fmt.Fprintf(b, "declare <%d x i%d> @llvm.masked.expandload.v%di%d(ptr, <%d x i1>, <%d x i%d>)\n", lanes, laneBits, lanes, laneBits, lanes, lanes, laneBits)
			fmt.Fprintf(b, "declare <%d x i%d> @llvm.masked.expandload.v%di%d.p256(ptr addrspace(256), <%d x i1>, <%d x i%d>)\n", lanes, laneBits, lanes, laneBits, lanes, lanes, laneBits)
			fmt.Fprintf(b, "declare <%d x i%d> @llvm.masked.expandload.v%di%d.p257(ptr addrspace(257), <%d x i1>, <%d x i%d>)\n", lanes, laneBits, lanes, laneBits, lanes, lanes, laneBits)
			if laneBits >= 16 {
				vectorType := fmt.Sprintf("<%d x i%d>", lanes, laneBits)
				fmt.Fprintf(b, "declare %s @llvm.fshl.v%di%d(%s, %s, %s)\n", vectorType, lanes, laneBits, vectorType, vectorType, vectorType)
				fmt.Fprintf(b, "declare %s @llvm.fshr.v%di%d(%s, %s, %s)\n", vectorType, lanes, laneBits, vectorType, vectorType, vectorType)
			}
		}
	}
	b.WriteString("declare i64 @llvm.bswap.i64(i64)\n")
	b.WriteString("declare i32 @llvm.bswap.i32(i32)\n")
	b.WriteString("declare i16 @llvm.bswap.i16(i16)\n")
	b.WriteString("declare float @llvm.sqrt.f32(float)\n")
	b.WriteString("declare double @llvm.sqrt.f64(double)\n")
	b.WriteString("declare <4 x float> @llvm.sqrt.v4f32(<4 x float>)\n")
	b.WriteString("declare <8 x float> @llvm.sqrt.v8f32(<8 x float>)\n")
	b.WriteString("declare <16 x float> @llvm.sqrt.v16f32(<16 x float>)\n")
	b.WriteString("declare <2 x double> @llvm.sqrt.v2f64(<2 x double>)\n")
	b.WriteString("declare <4 x double> @llvm.sqrt.v4f64(<4 x double>)\n")
	b.WriteString("declare <8 x double> @llvm.sqrt.v8f64(<8 x double>)\n")
	b.WriteString("declare <4 x float> @llvm.x86.sse.rcp.ps(<4 x float>)\n")
	b.WriteString("declare <4 x float> @llvm.x86.sse.rsqrt.ps(<4 x float>)\n")
	b.WriteString("declare <8 x float> @llvm.x86.avx.rcp.ps.256(<8 x float>)\n")
	b.WriteString("declare <8 x float> @llvm.x86.avx.rsqrt.ps.256(<8 x float>)\n")
	b.WriteString("declare <2 x double> @llvm.x86.sse41.dppd(<2 x double>, <2 x double>, i8 immarg)\n")
	b.WriteString("declare <4 x float> @llvm.x86.sse41.dpps(<4 x float>, <4 x float>, i8 immarg)\n")
	b.WriteString("declare <8 x float> @llvm.x86.avx.dp.ps.256(<8 x float>, <8 x float>, i8 immarg)\n")
	b.WriteString("declare <8 x i16> @llvm.x86.sse41.mpsadbw(<16 x i8>, <16 x i8>, i8 immarg)\n")
	b.WriteString("declare <16 x i16> @llvm.x86.avx2.mpsadbw(<32 x i8>, <32 x i8>, i8 immarg)\n")
	b.WriteString("declare i32 @llvm.x86.sse42.pcmpestri128(<16 x i8>, i32, <16 x i8>, i32, i8 immarg)\n")
	b.WriteString("declare <16 x i8> @llvm.x86.sse42.pcmpestrm128(<16 x i8>, i32, <16 x i8>, i32, i8 immarg)\n")
	b.WriteString("declare i32 @llvm.x86.sse42.pcmpistri128(<16 x i8>, <16 x i8>, i8 immarg)\n")
	b.WriteString("declare <16 x i8> @llvm.x86.sse42.pcmpistrm128(<16 x i8>, <16 x i8>, i8 immarg)\n")
	for _, family := range []string{"pcmpestri", "pcmpistri"} {
		for _, flag := range []string{"c", "o", "s", "z"} {
			if family == "pcmpestri" {
				fmt.Fprintf(b, "declare i32 @llvm.x86.sse42.%s%s128(<16 x i8>, i32, <16 x i8>, i32, i8 immarg)\n", family, flag)
			} else {
				fmt.Fprintf(b, "declare i32 @llvm.x86.sse42.%s%s128(<16 x i8>, <16 x i8>, i8 immarg)\n", family, flag)
			}
		}
	}
	for _, family := range []string{"rcp14", "rsqrt14"} {
		for _, vector := range []struct {
			kind     string
			bits     int
			lanes    int
			laneType string
			maskType string
		}{
			{kind: "ps", bits: 128, lanes: 4, laneType: "float", maskType: "i8"},
			{kind: "ps", bits: 256, lanes: 8, laneType: "float", maskType: "i8"},
			{kind: "ps", bits: 512, lanes: 16, laneType: "float", maskType: "i16"},
			{kind: "pd", bits: 128, lanes: 2, laneType: "double", maskType: "i8"},
			{kind: "pd", bits: 256, lanes: 4, laneType: "double", maskType: "i8"},
			{kind: "pd", bits: 512, lanes: 8, laneType: "double", maskType: "i8"},
		} {
			typ := fmt.Sprintf("<%d x %s>", vector.lanes, vector.laneType)
			fmt.Fprintf(b, "declare %s @llvm.x86.avx512.%s.%s.%d(%s, %s, %s)\n", typ, family, vector.kind, vector.bits, typ, typ, vector.maskType)
		}
		for _, scalar := range []struct {
			kind     string
			lanes    int
			laneType string
		}{
			{kind: "ss", lanes: 4, laneType: "float"},
			{kind: "sd", lanes: 2, laneType: "double"},
		} {
			typ := fmt.Sprintf("<%d x %s>", scalar.lanes, scalar.laneType)
			fmt.Fprintf(b, "declare %s @llvm.x86.avx512.%s.%s(%s, %s, %s, i8)\n", typ, family, scalar.kind, typ, typ, typ)
		}
	}
	for _, declaration := range []string{
		"float @llvm.fma.f32(float, float, float)",
		"double @llvm.fma.f64(double, double, double)",
		"<4 x float> @llvm.fma.v4f32(<4 x float>, <4 x float>, <4 x float>)",
		"<8 x float> @llvm.fma.v8f32(<8 x float>, <8 x float>, <8 x float>)",
		"<16 x float> @llvm.fma.v16f32(<16 x float>, <16 x float>, <16 x float>)",
		"<2 x double> @llvm.fma.v2f64(<2 x double>, <2 x double>, <2 x double>)",
		"<4 x double> @llvm.fma.v4f64(<4 x double>, <4 x double>, <4 x double>)",
		"<8 x double> @llvm.fma.v8f64(<8 x double>, <8 x double>, <8 x double>)",
	} {
		b.WriteString("declare " + declaration + "\n")
	}
	for _, declaration := range []string{
		"float @llvm.experimental.constrained.fma.f32(float, float, float, metadata, metadata)",
		"double @llvm.experimental.constrained.fma.f64(double, double, double, metadata, metadata)",
		"<16 x float> @llvm.experimental.constrained.fma.v16f32(<16 x float>, <16 x float>, <16 x float>, metadata, metadata)",
		"<8 x double> @llvm.experimental.constrained.fma.v8f64(<8 x double>, <8 x double>, <8 x double>, metadata, metadata)",
	} {
		b.WriteString("declare " + declaration + "\n")
	}
	for _, operation := range []string{"fadd", "fsub", "fmul", "fdiv"} {
		for _, signature := range []string{
			"float @llvm.experimental.constrained.%s.f32(float, float, metadata, metadata)",
			"double @llvm.experimental.constrained.%s.f64(double, double, metadata, metadata)",
			"<16 x float> @llvm.experimental.constrained.%s.v16f32(<16 x float>, <16 x float>, metadata, metadata)",
			"<8 x double> @llvm.experimental.constrained.%s.v8f64(<8 x double>, <8 x double>, metadata, metadata)",
			"<32 x half> @llvm.experimental.constrained.%s.v32f16(<32 x half>, <32 x half>, metadata, metadata)",
		} {
			b.WriteString("declare " + fmt.Sprintf(signature, operation) + "\n")
		}
	}
	b.WriteString("declare double @llvm.rint.f64(double)\n")
	b.WriteString("declare double @llvm.roundeven.f64(double)\n")
	b.WriteString("declare double @llvm.floor.f64(double)\n")
	b.WriteString("declare double @llvm.ceil.f64(double)\n")
	b.WriteString("declare double @llvm.trunc.f64(double)\n")
	b.WriteString("declare double @llvm.sin.f64(double)\n")
	b.WriteString("declare double @llvm.cos.f64(double)\n")
	b.WriteString("declare double @llvm.exp2.f64(double)\n")
	b.WriteString("declare double @llvm.log2.f64(double)\n")
	b.WriteString("declare double @atan2(double, double)\n")
	b.WriteString("declare double @fmod(double, double)\n")
	b.WriteString("declare double @remainder(double, double)\n")
	b.WriteString("declare double @tan(double)\n")
	if goarch == "386" {
		b.WriteString("declare double @llvm.fabs.f64(double)\n")
	}
	b.WriteString("declare <16 x i8> @llvm.x86.ssse3.pshuf.b.128(<16 x i8>, <16 x i8>)\n")
	b.WriteString("declare <2 x i64> @llvm.x86.aesni.aesenc(<2 x i64>, <2 x i64>)\n")
	b.WriteString("declare <2 x i64> @llvm.x86.aesni.aesenclast(<2 x i64>, <2 x i64>)\n")
	b.WriteString("declare <2 x i64> @llvm.x86.aesni.aesdec(<2 x i64>, <2 x i64>)\n")
	b.WriteString("declare <2 x i64> @llvm.x86.aesni.aesdeclast(<2 x i64>, <2 x i64>)\n")
	b.WriteString("declare <2 x i64> @llvm.x86.aesni.aesimc(<2 x i64>)\n")
	b.WriteString("declare <2 x i64> @llvm.x86.aesni.aeskeygenassist(<2 x i64>, i8 immarg)\n")
	b.WriteString("declare void @llvm.x86.sse.ldmxcsr(ptr)\n")
	b.WriteString("declare void @llvm.x86.sse.stmxcsr(ptr)\n")
	b.WriteString("declare <4 x i32> @llvm.x86.sse2.cvtps2dq(<4 x float>)\n")
	b.WriteString("declare <4 x i32> @llvm.x86.sse2.cvttps2dq(<4 x float>)\n")
	b.WriteString("declare <8 x i32> @llvm.x86.avx.cvt.ps2dq.256(<8 x float>)\n")
	b.WriteString("declare <8 x i32> @llvm.x86.avx.cvtt.ps2dq.256(<8 x float>)\n")
	b.WriteString("declare <16 x float> @llvm.experimental.constrained.sitofp.v16f32.v16i32(<16 x i32>, metadata, metadata)\n")
	b.WriteString("declare <8 x float> @llvm.experimental.constrained.fptrunc.v8f32.v8f64(<8 x double>, metadata, metadata)\n")
	for _, lanes := range []int{4, 8, 16} {
		fmt.Fprintf(b, "declare <%d x half> @llvm.experimental.constrained.fptrunc.v%df16.v%df32(<%d x float>, metadata, metadata)\n", lanes, lanes, lanes, lanes)
	}
	b.WriteString("declare float @llvm.rint.f32(float)\n")
	b.WriteString("declare float @llvm.roundeven.f32(float)\n")
	b.WriteString("declare float @llvm.trunc.f32(float)\n")
	b.WriteString("declare float @llvm.floor.f32(float)\n")
	b.WriteString("declare float @llvm.ceil.f32(float)\n")
	b.WriteString("declare <16 x float> @llvm.experimental.constrained.sqrt.v16f32(<16 x float>, metadata, metadata)\n")
	b.WriteString("declare <8 x double> @llvm.experimental.constrained.sqrt.v8f64(<8 x double>, metadata, metadata)\n")
	b.WriteString("declare float @llvm.experimental.constrained.sqrt.f32(float, metadata, metadata)\n")
	b.WriteString("declare double @llvm.experimental.constrained.sqrt.f64(double, metadata, metadata)\n")
	b.WriteString("declare i32 @llvm.fptosi.sat.i32.f32(float)\n")
	b.WriteString("declare i32 @llvm.fptosi.sat.i32.f64(double)\n")
	for _, conversion := range []struct {
		name       string
		resultType string
		sourceType string
	}{
		{name: "fptoui.sat.i32.f32", resultType: "i32", sourceType: "float"},
		{name: "fptoui.sat.i32.f64", resultType: "i32", sourceType: "double"},
		{name: "fptosi.sat.i64.f32", resultType: "i64", sourceType: "float"},
		{name: "fptosi.sat.i64.f64", resultType: "i64", sourceType: "double"},
		{name: "fptoui.sat.i64.f32", resultType: "i64", sourceType: "float"},
		{name: "fptoui.sat.i64.f64", resultType: "i64", sourceType: "double"},
	} {
		fmt.Fprintf(b, "declare %s @llvm.%s(%s)\n", conversion.resultType, conversion.name, conversion.sourceType)
	}
	b.WriteString("\n")
	// x86-64 CRC32 (SSE4.2) and PCLMULQDQ intrinsics.
	b.WriteString("declare i64 @llvm.x86.sse42.crc32.64.64(i64, i64)\n")
	b.WriteString("declare i32 @llvm.x86.sse42.crc32.32.32(i32, i32)\n")
	b.WriteString("declare i32 @llvm.x86.sse42.crc32.32.16(i32, i16)\n")
	b.WriteString("declare i32 @llvm.x86.sse42.crc32.32.8(i32, i8)\n")
	b.WriteString("declare <2 x i64> @llvm.x86.pclmulqdq(<2 x i64>, <2 x i64>, i8 immarg)\n")
	// SSE2 helpers used by stdlib asm (e.g. internal/bytealg).
	b.WriteString("declare i32 @llvm.x86.sse2.pmovmskb.128(<16 x i8>)\n")
	for _, shape := range []struct{ lanes, bits int }{
		{8, 8}, // Legacy MMX MASKMOVQ.
		{16, 8}, {32, 8}, {64, 8}, {8, 16}, {16, 16}, {32, 16},
		{4, 32}, {8, 32}, {16, 32}, {2, 64}, {4, 64}, {8, 64},
	} {
		for _, addressSpace := range []struct {
			suffix, pointer string
		}{{".p0", "ptr"}, {".p256", "ptr addrspace(256)"}, {".p257", "ptr addrspace(257)"}} {
			fmt.Fprintf(b, "declare <%d x i%d> @llvm.masked.load.v%di%d%s(%s, <%d x i1>, <%d x i%d>)\n", shape.lanes, shape.bits, shape.lanes, shape.bits, addressSpace.suffix, addressSpace.pointer, shape.lanes, shape.lanes, shape.bits)
			fmt.Fprintf(b, "declare void @llvm.masked.store.v%di%d%s(<%d x i%d>, %s, <%d x i1>)\n", shape.lanes, shape.bits, addressSpace.suffix, shape.lanes, shape.bits, addressSpace.pointer, shape.lanes)
		}
	}
	b.WriteString("\n")
	b.WriteString("\n")
	emitX86StringHelpers(b, file)
}

func emitX86StringHelpers(b *strings.Builder, file *File) {
	needed := make(map[string]struct{})
	for _, fn := range file.Funcs {
		for _, ins := range fn.Instrs {
			kind, typ, width, ok := x86StringProperties(ins.Op)
			if !ok {
				continue
			}
			name := x86StringHelperName(kind, width)
			if _, ok := needed[name]; ok {
				continue
			}
			needed[name] = struct{}{}
			switch kind {
			case "movs":
				emitX86MOVSHelper(b, name, string(typ), width)
			case "stos":
				emitX86STOSHelper(b, name, string(typ), width)
			case "scas":
				emitX86SCASHelper(b, name, string(typ), width)
			case "cmps":
				emitX86CMPSHelper(b, name, string(typ), width)
			case "lods":
				emitX86LODSHelper(b, name, string(typ), width)
			}
		}
	}
}

func emitX86MOVSHelper(b *strings.Builder, name, ty string, width int) {
	fmt.Fprintf(b, "define internal void @%s(i64 %%dst, i64 %%src, i64 %%count, i1 %%backward) {\n", name)
	b.WriteString(`entry:
  %step = select i1 %backward, i64 `)
	fmt.Fprintf(b, "-%d, i64 %d\n", width, width)
	b.WriteString(`  br label %loop
loop:
  %cur_dst = phi i64 [ %dst, %entry ], [ %next_dst, %body ]
  %cur_src = phi i64 [ %src, %entry ], [ %next_src, %body ]
  %left = phi i64 [ %count, %entry ], [ %remaining, %body ]
  %done = icmp eq i64 %left, 0
  br i1 %done, label %exit, label %body
body:
  %dst_ptr = inttoptr i64 %cur_dst to ptr
  %src_ptr = inttoptr i64 %cur_src to ptr
`)
	fmt.Fprintf(b, "  %%value = load %s, ptr %%src_ptr, align 1\n", ty)
	fmt.Fprintf(b, "  store %s %%value, ptr %%dst_ptr, align 1\n", ty)
	b.WriteString(`  %next_dst = add i64 %cur_dst, %step
  %next_src = add i64 %cur_src, %step
  %remaining = sub i64 %left, 1
  br label %loop
exit:
  ret void
}

`)
}

func emitX86STOSHelper(b *strings.Builder, name, typ string, width int) {
	fmt.Fprintf(b, "define internal void @%s(i64 %%addr, %s %%value, i64 %%count, i1 %%backward) {\n", name, typ)
	b.WriteString(`entry:
  %step = select i1 %backward, i64 `)
	fmt.Fprintf(b, "-%d, i64 %d\n", width, width)
	b.WriteString(`  br label %loop
loop:
  %cur = phi i64 [ %addr, %entry ], [ %next, %body ]
  %left = phi i64 [ %count, %entry ], [ %remaining, %body ]
  %done = icmp eq i64 %left, 0
  br i1 %done, label %exit, label %body
body:
  %ptr = inttoptr i64 %cur to ptr
`)
	fmt.Fprintf(b, "  store %s %%value, ptr %%ptr, align 1\n", typ)
	b.WriteString(`  %next = add i64 %cur, %step
  %remaining = sub i64 %left, 1
  br label %loop
exit:
  ret void
}

`)
}

func emitX86SCASHelper(b *strings.Builder, name, typ string, width int) {
	fmt.Fprintf(b, "define internal { i64, i64, i1 } @%s(i64 %%addr, %s %%needle, i64 %%count, i1 %%backward, i1 %%while_equal) {\n", name, typ)
	b.WriteString(`entry:
  %step = select i1 %backward, i64 `)
	fmt.Fprintf(b, "-%d, i64 %d\n", width, width)
	b.WriteString(`  br label %loop
loop:
  %cur = phi i64 [ %addr, %entry ], [ %scan_next, %scan ]
  %left = phi i64 [ %count, %entry ], [ %scan_remaining, %scan ]
  %empty = icmp eq i64 %left, 0
  br i1 %empty, label %empty_exit, label %scan
scan:
  %ptr = inttoptr i64 %cur to ptr
`)
	fmt.Fprintf(b, "  %%value = load %s, ptr %%ptr, align 1\n", typ)
	fmt.Fprintf(b, "  %%equal = icmp eq %s %%value, %%needle\n", typ)
	b.WriteString(`  %not_equal = xor i1 %equal, true
  %repeat_condition = select i1 %while_equal, i1 %equal, i1 %not_equal
  %scan_next = add i64 %cur, %step
  %scan_remaining = sub i64 %left, 1
  %more = icmp ne i64 %scan_remaining, 0
  %continue = and i1 %repeat_condition, %more
  br i1 %continue, label %loop, label %done
done:
  %done0 = insertvalue { i64, i64, i1 } undef, i64 %scan_next, 0
  %done1 = insertvalue { i64, i64, i1 } %done0, i64 %scan_remaining, 1
  %done2 = insertvalue { i64, i64, i1 } %done1, i1 %equal, 2
  ret { i64, i64, i1 } %done2
empty_exit:
  %empty0 = insertvalue { i64, i64, i1 } undef, i64 %cur, 0
  %empty1 = insertvalue { i64, i64, i1 } %empty0, i64 %left, 1
  %empty2 = insertvalue { i64, i64, i1 } %empty1, i1 false, 2
  ret { i64, i64, i1 } %empty2
}

`)
}

func emitX86CMPSHelper(b *strings.Builder, name, typ string, width int) {
	resultType := fmt.Sprintf("{ i64, i64, i64, %s, %s, i1 }", typ, typ)
	fmt.Fprintf(b, "define internal %s @%s(i64 %%src, i64 %%dst, i64 %%count, i1 %%backward, i1 %%while_equal) {\n", resultType, name)
	b.WriteString(`entry:
  %step = select i1 %backward, i64 `)
	fmt.Fprintf(b, "-%d, i64 %d\n", width, width)
	b.WriteString(`  br label %loop
loop:
  %cur_src = phi i64 [ %src, %entry ], [ %next_src, %scan ]
  %cur_dst = phi i64 [ %dst, %entry ], [ %next_dst, %scan ]
  %left = phi i64 [ %count, %entry ], [ %remaining, %scan ]
  %empty = icmp eq i64 %left, 0
  br i1 %empty, label %empty_exit, label %scan
scan:
  %src_ptr = inttoptr i64 %cur_src to ptr
  %dst_ptr = inttoptr i64 %cur_dst to ptr
`)
	fmt.Fprintf(b, "  %%src_value = load %s, ptr %%src_ptr, align 1\n", typ)
	fmt.Fprintf(b, "  %%dst_value = load %s, ptr %%dst_ptr, align 1\n", typ)
	fmt.Fprintf(b, "  %%equal = icmp eq %s %%src_value, %%dst_value\n", typ)
	b.WriteString(`  %not_equal = xor i1 %equal, true
  %repeat_condition = select i1 %while_equal, i1 %equal, i1 %not_equal
  %next_src = add i64 %cur_src, %step
  %next_dst = add i64 %cur_dst, %step
  %remaining = sub i64 %left, 1
  %more = icmp ne i64 %remaining, 0
  %continue = and i1 %repeat_condition, %more
  br i1 %continue, label %loop, label %done
done:
`)
	fmt.Fprintf(b, "  %%done0 = insertvalue %s undef, i64 %%next_src, 0\n", resultType)
	fmt.Fprintf(b, "  %%done1 = insertvalue %s %%done0, i64 %%next_dst, 1\n", resultType)
	fmt.Fprintf(b, "  %%done2 = insertvalue %s %%done1, i64 %%remaining, 2\n", resultType)
	fmt.Fprintf(b, "  %%done3 = insertvalue %s %%done2, %s %%src_value, 3\n", resultType, typ)
	fmt.Fprintf(b, "  %%done4 = insertvalue %s %%done3, %s %%dst_value, 4\n", resultType, typ)
	fmt.Fprintf(b, "  %%done5 = insertvalue %s %%done4, i1 true, 5\n", resultType)
	fmt.Fprintf(b, "  ret %s %%done5\n", resultType)
	b.WriteString("empty_exit:\n")
	fmt.Fprintf(b, "  %%empty0 = insertvalue %s undef, i64 %%cur_src, 0\n", resultType)
	fmt.Fprintf(b, "  %%empty1 = insertvalue %s %%empty0, i64 %%cur_dst, 1\n", resultType)
	fmt.Fprintf(b, "  %%empty2 = insertvalue %s %%empty1, i64 %%left, 2\n", resultType)
	fmt.Fprintf(b, "  %%empty3 = insertvalue %s %%empty2, %s 0, 3\n", resultType, typ)
	fmt.Fprintf(b, "  %%empty4 = insertvalue %s %%empty3, %s 0, 4\n", resultType, typ)
	fmt.Fprintf(b, "  %%empty5 = insertvalue %s %%empty4, i1 false, 5\n", resultType)
	fmt.Fprintf(b, "  ret %s %%empty5\n}\n\n", resultType)
}

func emitX86LODSHelper(b *strings.Builder, name, typ string, width int) {
	resultType := fmt.Sprintf("{ i64, i64, %s, i1 }", typ)
	fmt.Fprintf(b, "define internal %s @%s(i64 %%src, i64 %%count, i1 %%backward) {\n", resultType, name)
	b.WriteString(`entry:
  %step = select i1 %backward, i64 `)
	fmt.Fprintf(b, "-%d, i64 %d\n", width, width)
	b.WriteString(`  br label %loop
loop:
  %cur = phi i64 [ %src, %entry ], [ %next, %load ]
  %left = phi i64 [ %count, %entry ], [ %remaining, %load ]
  %empty = icmp eq i64 %left, 0
  br i1 %empty, label %empty_exit, label %load
load:
  %ptr = inttoptr i64 %cur to ptr
`)
	fmt.Fprintf(b, "  %%value = load %s, ptr %%ptr, align 1\n", typ)
	b.WriteString(`  %next = add i64 %cur, %step
  %remaining = sub i64 %left, 1
  %more = icmp ne i64 %remaining, 0
  br i1 %more, label %loop, label %done
done:
`)
	fmt.Fprintf(b, "  %%done0 = insertvalue %s undef, i64 %%next, 0\n", resultType)
	fmt.Fprintf(b, "  %%done1 = insertvalue %s %%done0, i64 %%remaining, 1\n", resultType)
	fmt.Fprintf(b, "  %%done2 = insertvalue %s %%done1, %s %%value, 2\n", resultType, typ)
	fmt.Fprintf(b, "  %%done3 = insertvalue %s %%done2, i1 true, 3\n", resultType)
	fmt.Fprintf(b, "  ret %s %%done3\n", resultType)
	b.WriteString("empty_exit:\n")
	fmt.Fprintf(b, "  %%empty0 = insertvalue %s undef, i64 %%cur, 0\n", resultType)
	fmt.Fprintf(b, "  %%empty1 = insertvalue %s %%empty0, i64 %%left, 1\n", resultType)
	fmt.Fprintf(b, "  %%empty2 = insertvalue %s %%empty1, %s 0, 2\n", resultType, typ)
	fmt.Fprintf(b, "  %%empty3 = insertvalue %s %%empty2, i1 false, 3\n", resultType)
	fmt.Fprintf(b, "  ret %s %%empty3\n}\n\n", resultType)
}

func translateFuncAMD64(b *strings.Builder, fn Func, sig FuncSig, resolve func(string) string, sigs map[string]FuncSig, annotateSource bool) error {
	return translateFuncX86(b, fn, sig, resolve, sigs, "amd64", "", X87Auto, annotateSource)
}

// emitX86AddressSensitiveRawText emits an exact raw TEXT body as a naked
// function. Naked inline assembly is intentionally limited to bodies selected
// by preserveAddressSensitiveX86RawText: their byte addresses are observable,
// so semantic IR lowering cannot preserve symbol+offset references. The
// unreachable terminator adds no machine bytes on LLVM 22.
func emitX86AddressSensitiveRawText(b *strings.Builder, fn Func, sig FuncSig) error {
	if len(fn.X86RawText) == 0 {
		return fmt.Errorf("empty address-sensitive raw TEXT body")
	}
	fmt.Fprintf(b, "define %s %s(", sig.Ret, llvmGlobal(sig.Name))
	for index, typ := range sig.Args {
		if index != 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(b, "%s %%arg%d", typ, index)
	}
	b.WriteString(") naked noinline")
	if fn.X86RawAlign != 0 {
		fmt.Fprintf(b, " align %d", fn.X86RawAlign)
	}
	if sig.Attrs != "" {
		b.WriteString(" " + sig.Attrs)
	}
	b.WriteString(" {\nentry:\n")
	var assembly strings.Builder
	assembly.WriteString(".byte ")
	for index, value := range fn.X86RawText {
		if index != 0 {
			assembly.WriteString(", ")
		}
		fmt.Fprintf(&assembly, "%d", value)
	}
	fmt.Fprintf(b, "  call void asm sideeffect %q, %q()\n", assembly.String(), "~{memory}")
	b.WriteString("  unreachable\n}\n")
	return nil
}

// A jump-only TEXT with multiple direct symbol targets is a relocation
// anchor. Only its first jump is reachable, but Go emits every relocation;
// generated ABI0 wrapper keepers use this object-level behavior. Preserve the
// whole sequence in one naked inline-assembly body. Ordinary IR calls would
// invent arguments and LLVM could discard the unreachable jumps.
func amd64IsRelocationAnchor(fn Func, sig FuncSig) bool {
	if sig.Ret != Void || len(sig.Args) != 0 ||
		fn.FrameSize != 0 || fn.ArgSize != 0 || len(fn.Instrs) < 3 ||
		fn.Instrs[0].Op != OpTEXT {
		return false
	}
	for _, ins := range fn.Instrs[1:] {
		if ins.Op != OpJMP || len(ins.Args) != 1 || ins.Args[0].Kind != OpSym ||
			!strings.HasSuffix(strings.TrimSpace(ins.Args[0].Sym), "(SB)") {
			return false
		}
	}
	return true
}

func emitX86RelocationAnchor(b *strings.Builder, fn Func, sig FuncSig, resolve func(string) string, sigs map[string]FuncSig) error {
	assembly := make([]string, 0, len(fn.Instrs)-1)
	constraints := make([]string, 0, len(fn.Instrs))
	args := make([]string, 0, len(fn.Instrs)-1)
	for index, ins := range fn.Instrs[1:] {
		target := strings.TrimSuffix(strings.TrimSpace(ins.Args[0].Sym), "(SB)")
		resolved := resolve(target)
		targetSig, ok := sigs[resolved]
		if !ok {
			return fmt.Errorf("relocation anchor target %q has no signature", resolved)
		}
		assembly = append(assembly, fmt.Sprintf("jmp ${%d:c}", index))
		constraints = append(constraints, "X")
		args = append(args, "ptr "+llvmGlobal(funcSigSymbol(resolved, targetSig)))
	}
	constraints = append(constraints, "~{memory}")
	fmt.Fprintf(b, "define void %s() naked noinline {\nentry:\n", llvmGlobal(sig.Name))
	fmt.Fprintf(b, "  call void asm sideeffect %q, %q(%s)\n",
		strings.Join(assembly, "; "), strings.Join(constraints, ","), strings.Join(args, ", "))
	b.WriteString("  unreachable\n}\n")
	return nil
}

func translateFuncX86(b *strings.Builder, fn Func, sig FuncSig, resolve func(string) string, sigs map[string]FuncSig, goarch, targetTriple string, x87Mode X87Mode, annotateSource bool) error {
	fmt.Fprintf(b, "define %s %s(", sig.Ret, llvmGlobal(sig.Name))
	for i, t := range sig.Args {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(b, "%s %%arg%d", t, i)
	}
	b.WriteString(")")
	if sig.Attrs != "" {
		b.WriteString(" " + sig.Attrs)
	}
	b.WriteString(" {\n")

	c := newX86Ctx(b, fn, sig, resolve, sigs, goarch, targetTriple, annotateSource)
	c.x87Mode = x87Mode
	if err := c.emitEntryAllocas(); err != nil {
		return err
	}
	if err := c.lowerBlocks(); err != nil {
		return err
	}

	b.WriteString("}\n")
	return nil
}

func (c *amd64Ctx) lowerBlocks() error {
	emitBr := func(target string) {
		fmt.Fprintf(c.b, "  br label %%%s\n", amd64LLVMBlockName(target))
	}
	emitCondBr := func(cond string, target string, fall string) error {
		fmt.Fprintf(c.b, "  br i1 %s, label %%%s, label %%%s\n", cond, amd64LLVMBlockName(target), amd64LLVMBlockName(fall))
		return nil
	}

	for bi := 0; bi < len(c.blocks); bi++ {
		blk := c.blocks[bi]
		if bi != 0 {
			fmt.Fprintf(c.b, "\n%s:\n", amd64LLVMBlockName(blk.name))
		}

		terminated := false
		for ii, ins := range blk.instrs {
			c.emitSourceComment(ins)
			term, err := c.lowerInstr(bi, ii, ins, emitBr, emitCondBr)
			if err != nil {
				return fmt.Errorf("%q: %w", ins.Raw, err)
			}
			if term {
				terminated = true
				break
			}
		}
		if terminated {
			continue
		}
		if c.repeatPrefix != "" && bi+1 == len(c.blocks) {
			prefix := c.repeatPrefix
			c.repeatPrefix = ""
			return fmt.Errorf("%s %s prefix has no following string instruction", c.goarch, prefix)
		}
		// Fallthrough.
		if bi+1 < len(c.blocks) {
			emitBr(c.blocks[bi+1].name)
			continue
		}
		c.lowerRetZero()
	}
	return nil
}

func (c *amd64Ctx) lowerInstr(bi int, ii int, ins Instr, emitBr amd64EmitBr, emitCondBr amd64EmitCondBr) (terminated bool, err error) {
	c.allowSPWrite = models386SPWrite(ins)
	defer func() { c.allowSPWrite = false }()
	for i := range ins.Args {
		if ins.Args[i].Kind == OpFP || ins.Args[i].Kind == OpFPAddr {
			ins.Args[i].FPOffset = c.namedFPResultOffset(ins.Args[i].FPName, ins.Args[i].FPOffset)
		}
	}
	op := strings.ToUpper(string(ins.Op))
	_, _, _, regularString := x86StringProperties(Op(op))
	_, _, portString := x86PortStringProperties(Op(op))
	if c.repeatPrefix != "" && !regularString && !portString {
		prefix := c.repeatPrefix
		c.repeatPrefix = ""
		return false, fmt.Errorf("%s %s prefix is unsupported for %s", c.goarch, prefix, op)
	}
	if strings.HasPrefix(op, "GET_TLS(") {
		// Macro-expanded helper from go_tls.h. Keep current simplified model.
		return false, nil
	}
	switch Op(op) {
	case OpTEXT:
		return false, nil
	case OpBYTE, OpWORD, "LONG", "QUAD":
		return false, fmt.Errorf("%s %s cannot be lowered safely as opaque machine code: %q", c.goarch, op, ins.Raw)
	case OpRET:
		if len(ins.Args) == 1 && ins.Args[0].Kind == OpSym && strings.HasSuffix(ins.Args[0].Sym, "(SB)") {
			return true, c.tailCallAndRet(ins.Args[0])
		}
		if len(ins.Args) > 1 {
			return true, fmt.Errorf("amd64 RET expects at most 1 operand: %q", ins.Raw)
		}
		return true, c.lowerRET()
	case "NOPW", "NOPL":
		if len(ins.Args) != 1 {
			return false, fmt.Errorf("%s %s expects one Yml register/memory operand: %q", c.goarch, op, ins.Raw)
		}
		operand := ins.Args[0]
		if operand.Kind == OpReg {
			if !isX86YrlRegisterForArch(operand.Reg, c.goarch) {
				return false, fmt.Errorf("%s %s register is outside Go 1.27's Yml class: %q", c.goarch, op, ins.Raw)
			}
		} else if !isAMD64MemoryOperand(operand) {
			return false, fmt.Errorf("%s %s operand is outside Go 1.27's Yml class: %q", c.goarch, op, ins.Raw)
		}
		return false, nil
	case "PCALIGN", "NO_LOCAL_POINTERS", "PCDATA", "FUNCDATA", "NOP",
		"PUSH_REGS_HOST_TO_ABI0()", "POP_REGS_HOST_TO_ABI0()":
		// Alignment directive emitted by stdlib asm; no semantic effect in our IR.
		return false, nil
	case "LAHF":
		if len(ins.Args) != 0 {
			return false, fmt.Errorf("%s LAHF takes no operands: %q", c.goarch, ins.Raw)
		}
		packed := c.packX86Flags()
		value := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i8\n", value, packed)
		return false, c.storeRegSized(AH, I8, "%"+value)
	case "SAHF":
		if len(ins.Args) != 0 {
			return false, fmt.Errorf("%s SAHF takes no operands: %q", c.goarch, ins.Raw)
		}
		value, err := c.evalIntSized(Operand{Kind: OpReg, Reg: AH}, I8)
		if err != nil {
			return false, err
		}
		flagBit := func(bit uint) string {
			shifted := value
			if bit != 0 {
				tmp := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = lshr i8 %s, %d\n", tmp, value, bit)
				shifted = "%" + tmp
			}
			result := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i8 %s to i1\n", result, shifted)
			return "%" + result
		}
		fmt.Fprintf(c.b, "  store i1 %s, ptr %s\n", flagBit(0), c.flagsCFSlot)
		fmt.Fprintf(c.b, "  store i1 %s, ptr %s\n", flagBit(2), c.flagsPFSlot)
		fmt.Fprintf(c.b, "  store i1 %s, ptr %s\n", flagBit(6), c.flagsZSlot)
		sign := flagBit(7)
		overflow := c.loadFlag(c.flagsOFSlot)
		signedLess := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = xor i1 %s, %s\n", signedLess, sign, overflow)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", signedLess, c.flagsSltSlot)
		return false, nil
	case "CLC", "STC", "CMC":
		if len(ins.Args) != 0 {
			return false, fmt.Errorf("%s %s takes no operands: %q", c.goarch, op, ins.Raw)
		}
		switch op {
		case "CLC":
			fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsCFSlot)
		case "STC":
			fmt.Fprintf(c.b, "  store i1 true, ptr %s\n", c.flagsCFSlot)
		case "CMC":
			oldCarry := c.loadFlag(c.flagsCFSlot)
			newCarry := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = xor i1 %s, true\n", newCarry, oldCarry)
			fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", newCarry, c.flagsCFSlot)
		}
		return false, nil
	case "ADJSP":
		if c.goarch != "386" {
			return false, nil
		}
		if len(ins.Args) != 1 || ins.Args[0].Kind != OpImm {
			return false, fmt.Errorf("386 ADJSP expects an immediate: %q", ins.Raw)
		}
		sp, err := c.loadReg(SP)
		if err != nil {
			return false, err
		}
		next := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sub i64 %s, %d\n", next, sp, int64(ins.Args[0].Imm))
		return false, c.storeRegUnchecked(SP, "%"+next)
	case "CLD":
		if len(ins.Args) != 0 {
			return false, fmt.Errorf("%s CLD takes no operands: %q", c.goarch, ins.Raw)
		}
		if c.directionSlot != "" {
			fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.directionSlot)
		}
		c.b.WriteString("  call void asm sideeffect \"cld\", \"~{dirflag}\"()\n")
		return false, nil
	case "STD":
		if len(ins.Args) != 0 {
			return false, fmt.Errorf("%s STD takes no operands: %q", c.goarch, ins.Raw)
		}
		if c.directionSlot != "" {
			fmt.Fprintf(c.b, "  store i1 true, ptr %s\n", c.directionSlot)
		}
		c.b.WriteString("  call void asm sideeffect \"std\", \"~{dirflag}\"()\n")
		return false, nil
	case "REP", "REPN":
		if len(ins.Args) != 0 {
			return false, fmt.Errorf("%s %s takes no operands: %q", c.goarch, op, ins.Raw)
		}
		c.repeatPrefix = op
		return false, nil
	}
	// Scalar ADD/SUB spellings overlap with vector and generic arithmetic
	// lowerers. Validate the complete Go assembler operand table before those
	// broader handlers get a chance to accept an illegal form.
	if ok, term, err := c.lowerScalarAddSub(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerRTM(bi, ii, Op(op), ins, emitCondBr); ok {
		return term, err
	}
	if ok, term, err := c.lowerFarReturn(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerLeave(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerXLAT(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerBranch(bi, ii, Op(op), ins, emitBr, emitCondBr); ok {
		return term, err
	}
	// Segment-register MOVW shares scalar MOV spellings with broad vector and
	// generic move handlers, so validate its narrow ymovtab forms first.
	if ok, term, err := c.lowerSegmentRegisterMove(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerCmpBt(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerX87(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerDuplicateMove(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerPackedDwordMultiply(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerPackedQwordMultiply(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerDwordToQwordMultiply(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerPackedWordMultiply(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerPackedWordMultiplyAdd(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerPackedDotProduct(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerPackedIntegerMinMax(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerPackedUnsignedAverage(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerHorizontalInteger(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerPackedUnsignedWordMinimumPosition(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerImplicitMaskMove(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerPackedLogicalShift(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerPerLaneVariableShift(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerPackedArithmeticRightShift(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerPackedFloatShuffle(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerShuffle128BitBlocks(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerImmediatePackedBlend(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerVariableBlend(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerMaskBlend(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerPackedUnpack(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerQwordPermute(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerInLaneFloatingPermute(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerIndexedPermute(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerLegacyMMXMove(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerNonTemporalVectorMove(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerUnalignedVectorLoad(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerPackedVectorMove(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerPackedVectorInsert(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerInsertPackedSingle(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerPackedByteShuffle(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerScatter(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerAlternatingFloatingAddSubtract(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerPackedNumericConversion(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerSameWidthPackedConversion(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerPackedHalfConversion(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerBF16Convert(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerPackedDoubleDword(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerPackedAbsSign(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerVectorScalarIntegerMove(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerScalarIntegerToFloat(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerLegacyIntegerToFloat(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerPackedExtendMove(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerParallelBitDepositExtract(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerMXCSR(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerPackedFloatToDword(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerPackedSingleToDouble(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerPackedDoubleToSingle(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerPackedScalarExtract(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerPackedMoveMask(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerMoveHighLowPackedSingle(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerVectorLaneExtract(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerPackedSumAbsoluteDifferences(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerPackedFloatingDot(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerPackedIntegerAdd(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerPackedIntegerSubtract(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerPackedScalarBroadcast(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerMaskRegisterBroadcast(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerPackedBlockBroadcast(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerPackedFloatingLogical(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerFMA3(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerEVEXPackedLogical(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerPackedAndNot(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerPackedIntegerCompare(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerImmediatePackedCompare(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerPackedTestMask(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerFloatingCompare(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerPackedSaturatingNarrow(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerVariableDwordPermute(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerConditionalSet(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerVectorScalarMove(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerVectorScalarFlagCompare(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerConditionalMove(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerFP(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerCrc32(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerVec(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerCompareExchange(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerBound(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerAtomic(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerMSRAccess(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerImplicitSystem(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerDescriptorTable(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerSegmentBase(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerXState(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerSystemAddress(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerCacheLineWriteback(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerFixedSystem(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerSystemTransfer(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerAMDSystemManagement(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerSyscall(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerPortIO(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerString(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerMachineRegisterMove(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerMov(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerScalarShiftRotate(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerScalarIncDec(Op(op), ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerArith(Op(op), ins); ok {
		return term, err
	}
	return false, fmt.Errorf("amd64: unsupported instruction %s", ins.Op)
}

func (c *amd64Ctx) lowerRET() error {
	// Prefer classic Go asm return slots if present.
	if len(c.fpResults) == 0 {
		rax, err := c.loadReg(AX)
		if err != nil {
			return err
		}
		switch c.sig.Ret {
		case Void:
			c.b.WriteString("  ret void\n")
		case I1:
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i1\n", t, rax)
			fmt.Fprintf(c.b, "  ret i1 %%%s\n", t)
		case I8:
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i8\n", t, rax)
			fmt.Fprintf(c.b, "  ret i8 %%%s\n", t)
		case I16:
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i16\n", t, rax)
			fmt.Fprintf(c.b, "  ret i16 %%%s\n", t)
		case I32:
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", t, rax)
			fmt.Fprintf(c.b, "  ret i32 %%%s\n", t)
		default:
			fmt.Fprintf(c.b, "  ret %s %s\n", c.sig.Ret, rax)
		}
		return nil
	}

	if len(c.fpResults) == 1 {
		slot := c.fpResults[0]
		var v string
		var err error
		if c.fpResWritten[slot.Index] || c.fpResAddrTaken[slot.Index] {
			v, err = c.loadFPResult(slot)
		} else {
			v, err = c.loadRetSlotFallback(slot)
		}
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  ret %s %s\n", c.sig.Ret, v)
		return nil
	}

	cur := "undef"
	last := ""
	for _, slot := range c.fpResults {
		var v string
		var err error
		if c.fpResWritten[slot.Index] || c.fpResAddrTaken[slot.Index] {
			v, err = c.loadFPResult(slot)
		} else {
			v, err = c.loadRetSlotFallback(slot)
		}
		if err != nil {
			return err
		}
		name := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertvalue %s %s, %s %s, %d\n", name, c.sig.Ret, cur, slot.Type, v, slot.Index)
		cur = "%" + name
		last = cur
	}
	fmt.Fprintf(c.b, "  ret %s %s\n", c.sig.Ret, last)
	return nil
}

func (c *amd64Ctx) lowerRetZero() {
	switch c.sig.Ret {
	case Void:
		c.b.WriteString("  ret void\n")
	default:
		fmt.Fprintf(c.b, "  ret %s %s\n", c.sig.Ret, llvmZeroValue(c.sig.Ret))
	}
}
