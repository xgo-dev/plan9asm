package plan9asm

import (
	"fmt"
	"strings"
)

type arm64EmitBr func(target string)
type arm64EmitCondBr func(cond string, target string, fall string) error

func emitARM64Prelude(b *strings.Builder) {
	b.WriteString("declare void @llvm.memcpy.p0.p0.i64(ptr, ptr, i64, i1 immarg)\n")
	b.WriteString("declare void @llvm.trap()\n")
	b.WriteString("declare i64 @syscall(i64, i64, i64, i64, i64, i64, i64)\n")
	b.WriteString("declare { i64, i1 } @llvm.aarch64.rndr()\n")
	b.WriteString("declare { i64, i1 } @llvm.aarch64.rndrrs()\n")
	b.WriteString("declare i32 @cliteErrno()\n")
	b.WriteString("declare i64 @llvm.bitreverse.i64(i64)\n")
	b.WriteString("declare i32 @llvm.bitreverse.i32(i32)\n")
	b.WriteString("declare <8 x i8> @llvm.bitreverse.v8i8(<8 x i8>)\n")
	b.WriteString("declare <16 x i8> @llvm.bitreverse.v16i8(<16 x i8>)\n")
	b.WriteString("declare i64 @llvm.ctlz.i64(i64, i1)\n")
	b.WriteString("declare i32 @llvm.ctlz.i32(i32, i1)\n")
	b.WriteString("declare i64 @llvm.bswap.i64(i64)\n")
	b.WriteString("declare i32 @llvm.bswap.i32(i32)\n")
	b.WriteString("declare <8 x i8> @llvm.ctpop.v8i8(<8 x i8>)\n")
	b.WriteString("declare <16 x i8> @llvm.ctpop.v16i8(<16 x i8>)\n")
	for _, intrinsic := range []string{"smmla", "ummla", "usmmla"} {
		fmt.Fprintf(b, "declare <vscale x 4 x i32> @llvm.aarch64.sve.%s.nxv4i32(<vscale x 4 x i32>, <vscale x 16 x i8>, <vscale x 16 x i8>)\n", intrinsic)
	}
	b.WriteString("declare <vscale x 4 x float> @llvm.aarch64.sve.bfmmla(<vscale x 4 x float>, <vscale x 8 x bfloat>, <vscale x 8 x bfloat>)\n")
	b.WriteString("declare <vscale x 4 x float> @llvm.aarch64.sve.fmmla.nxv4f32(<vscale x 4 x float>, <vscale x 4 x float>, <vscale x 4 x float>)\n")
	b.WriteString("declare <vscale x 2 x double> @llvm.aarch64.sve.fmmla.nxv2f64(<vscale x 2 x double>, <vscale x 2 x double>, <vscale x 2 x double>)\n")
	b.WriteString("declare <vscale x 4 x float> @llvm.aarch64.sve.fmmla.nxv4f32.nxv8f16(<vscale x 4 x float>, <vscale x 8 x half>, <vscale x 8 x half>)\n")
	for _, vector := range []struct{ lanes, bits int }{{8, 8}, {16, 8}, {4, 16}, {8, 16}, {2, 32}, {4, 32}} {
		fmt.Fprintf(b, "declare <%d x i%d> @llvm.ctlz.v%di%d(<%d x i%d>, i1)\n", vector.lanes, vector.bits, vector.lanes, vector.bits, vector.lanes, vector.bits)
	}
	b.WriteString("declare <8 x i16> @llvm.aarch64.neon.pmull.v8i16(<8 x i8>, <8 x i8>)\n")
	b.WriteString("declare <16 x i8> @llvm.aarch64.neon.pmull64(i64, i64)\n")
	b.WriteString("declare <2 x float> @llvm.aarch64.neon.bfdot.v2f32.v4bf16(<2 x float>, <4 x bfloat>, <4 x bfloat>)\n")
	b.WriteString("declare <4 x float> @llvm.aarch64.neon.bfdot.v4f32.v8bf16(<4 x float>, <8 x bfloat>, <8 x bfloat>)\n")
	b.WriteString("declare <4 x float> @llvm.aarch64.neon.bfmmla(<4 x float>, <8 x bfloat>, <8 x bfloat>)\n")
	for _, shape := range []struct {
		lanes    int
		typeName string
		suffix   string
	}{{4, "half", "f16"}, {8, "half", "f16"}, {2, "float", "f32"}, {4, "float", "f32"}, {2, "double", "f64"}} {
		vectorType := fmt.Sprintf("<%d x %s>", shape.lanes, shape.typeName)
		for _, intrinsic := range []string{"fabd", "fmulx"} {
			fmt.Fprintf(b, "declare %s @llvm.aarch64.neon.%s.v%d%s(%s, %s)\n",
				vectorType, intrinsic, shape.lanes, shape.suffix, vectorType, vectorType)
		}
	}
	for _, scalar := range []struct{ typeName, suffix string }{{"half", "f16"}, {"float", "f32"}, {"double", "f64"}} {
		fmt.Fprintf(b, "declare %s @llvm.aarch64.sisd.fabd.%s(%s, %s)\n",
			scalar.typeName, scalar.suffix, scalar.typeName, scalar.typeName)
		fmt.Fprintf(b, "declare %s @llvm.aarch64.neon.fmulx.%s(%s, %s)\n",
			scalar.typeName, scalar.suffix, scalar.typeName, scalar.typeName)
	}
	for _, shape := range []struct {
		lanes    int
		typeName string
		suffix   string
	}{
		{1, "half", "f16"},
		{1, "float", "f32"},
		{1, "double", "f64"},
		{4, "half", "v4f16"},
		{8, "half", "v8f16"},
		{2, "float", "v2f32"},
		{4, "float", "v4f32"},
		{2, "double", "v2f64"},
	} {
		typeName := shape.typeName
		if shape.lanes != 1 {
			typeName = fmt.Sprintf("<%d x %s>", shape.lanes, shape.typeName)
		}
		for _, intrinsic := range []string{"frecpe", "frsqrte"} {
			fmt.Fprintf(b, "declare %s @llvm.aarch64.neon.%s.%s(%s)\n",
				typeName, intrinsic, shape.suffix, typeName)
		}
		if shape.lanes == 1 {
			fmt.Fprintf(b, "declare %s @llvm.aarch64.neon.frecpx.%s(%s)\n",
				typeName, shape.suffix, typeName)
		}
		for _, intrinsic := range []string{"frecps", "frsqrts"} {
			fmt.Fprintf(b, "declare %s @llvm.aarch64.neon.%s.%s(%s, %s)\n",
				typeName, intrinsic, shape.suffix, typeName, typeName)
		}
	}
	for _, vector := range []struct{ lanes, bits int }{{8, 8}, {16, 8}, {4, 16}, {8, 16}, {2, 32}, {4, 32}, {2, 64}} {
		vectorType := fmt.Sprintf("<%d x i%d>", vector.lanes, vector.bits)
		for _, intrinsic := range []string{"sshl", "srshl", "ushl", "urshl", "sqshl", "uqshl"} {
			fmt.Fprintf(b, "declare %s @llvm.aarch64.neon.%s.v%di%d(%s, %s)\n", vectorType, intrinsic, vector.lanes, vector.bits, vectorType, vectorType)
		}
	}
	for _, intrinsic := range []string{"sshl", "srshl", "ushl", "urshl"} {
		fmt.Fprintf(b, "declare i64 @llvm.aarch64.neon.%s.i64(i64, i64)\n", intrinsic)
	}
	for _, intrinsic := range []string{"suqadd", "usqadd"} {
		for _, bits := range []int{8, 16, 32, 64} {
			for _, vectorBits := range []int{64, 128} {
				if bits > vectorBits {
					continue
				}
				lanes := vectorBits / bits
				typeName := fmt.Sprintf("<%d x i%d>", lanes, bits)
				fmt.Fprintf(b, "declare %s @llvm.aarch64.neon.%s.v%di%d(%s, %s)\n",
					typeName, intrinsic, lanes, bits, typeName, typeName)
			}
		}
	}
	for _, intrinsic := range []string{"saddlv", "uaddlv"} {
		for _, shape := range []struct{ lanes, bits int }{
			{8, 8}, {16, 8}, {4, 16}, {8, 16}, {4, 32},
		} {
			resultBits := shape.bits * 2
			if resultBits < 32 {
				resultBits = 32
			}
			fmt.Fprintf(b, "declare i%d @llvm.aarch64.neon.%s.i%d.v%di%d(<%d x i%d>)\n",
				resultBits, intrinsic, resultBits, shape.lanes, shape.bits, shape.lanes, shape.bits)
		}
	}
	b.WriteString("declare <16 x i8> @llvm.aarch64.crypto.aese(<16 x i8>, <16 x i8>)\n")
	b.WriteString("declare <16 x i8> @llvm.aarch64.crypto.aesd(<16 x i8>, <16 x i8>)\n")
	b.WriteString("declare <16 x i8> @llvm.aarch64.crypto.aesmc(<16 x i8>)\n")
	b.WriteString("declare <16 x i8> @llvm.aarch64.crypto.aesimc(<16 x i8>)\n")
	for _, spec := range arm64RawSM4Specs {
		fmt.Fprintf(b, "declare <4 x i32> @llvm.aarch64.crypto.%s(<4 x i32>, <4 x i32>)\n", spec.intrinsic)
	}
	for _, spec := range arm64RawRDMASpecs[:2] {
		for _, shape := range []struct{ lanes, bits int }{{4, 16}, {8, 16}, {2, 32}, {4, 32}} {
			vectorType := fmt.Sprintf("<%d x i%d>", shape.lanes, shape.bits)
			fmt.Fprintf(b, "declare %s @llvm.aarch64.neon.%s.v%di%d(%s, %s, %s)\n",
				vectorType, spec.intrinsic, shape.lanes, shape.bits, vectorType, vectorType, vectorType)
		}
	}
	b.WriteString("declare <4 x i32> @llvm.aarch64.crypto.sha1c(<4 x i32>, i32, <4 x i32>)\n")
	b.WriteString("declare <4 x i32> @llvm.aarch64.crypto.sha1p(<4 x i32>, i32, <4 x i32>)\n")
	b.WriteString("declare <4 x i32> @llvm.aarch64.crypto.sha1m(<4 x i32>, i32, <4 x i32>)\n")
	b.WriteString("declare i32 @llvm.aarch64.crypto.sha1h(i32)\n")
	b.WriteString("declare <4 x i32> @llvm.aarch64.crypto.sha1su0(<4 x i32>, <4 x i32>, <4 x i32>)\n")
	b.WriteString("declare <4 x i32> @llvm.aarch64.crypto.sha1su1(<4 x i32>, <4 x i32>)\n")
	b.WriteString("declare <4 x i32> @llvm.aarch64.crypto.sha256h(<4 x i32>, <4 x i32>, <4 x i32>)\n")
	b.WriteString("declare <4 x i32> @llvm.aarch64.crypto.sha256h2(<4 x i32>, <4 x i32>, <4 x i32>)\n")
	b.WriteString("declare <4 x i32> @llvm.aarch64.crypto.sha256su0(<4 x i32>, <4 x i32>)\n")
	b.WriteString("declare <4 x i32> @llvm.aarch64.crypto.sha256su1(<4 x i32>, <4 x i32>, <4 x i32>)\n")
	b.WriteString("declare <2 x i64> @llvm.aarch64.crypto.sha512h(<2 x i64>, <2 x i64>, <2 x i64>)\n")
	b.WriteString("declare <2 x i64> @llvm.aarch64.crypto.sha512h2(<2 x i64>, <2 x i64>, <2 x i64>)\n")
	b.WriteString("declare <2 x i64> @llvm.aarch64.crypto.sha512su0(<2 x i64>, <2 x i64>)\n")
	b.WriteString("declare <2 x i64> @llvm.aarch64.crypto.sha512su1(<2 x i64>, <2 x i64>, <2 x i64>)\n")
	b.WriteString("declare i64 @llvm.vscale.i64()\n")
	b.WriteString("declare <vscale x 2 x i64> @llvm.masked.load.nxv2i64.p0(ptr, <vscale x 2 x i1>, <vscale x 2 x i64>)\n")
	b.WriteString("declare void @llvm.masked.store.nxv2i64.p0(<vscale x 2 x i64>, ptr, <vscale x 2 x i1>)\n")
	for _, bits := range []int{8, 16, 32, 64} {
		lanes := 128 / bits
		vectorType := fmt.Sprintf("<vscale x %d x i%d>", lanes, bits)
		for _, intrinsic := range []string{"eorbt", "eortb"} {
			fmt.Fprintf(b, "declare %s @llvm.aarch64.sve.%s.nxv%di%d(%s, %s, %s)\n", vectorType, intrinsic, lanes, bits, vectorType, vectorType, vectorType)
		}
		predicateType := fmt.Sprintf("<vscale x %d x i1>", lanes)
		fmt.Fprintf(b, "declare %s @llvm.aarch64.sve.ld1ro.nxv%di%d(%s, ptr)\n", vectorType, lanes, bits, predicateType)
		fmt.Fprintf(b, "declare %s @llvm.aarch64.sve.ld1rq.nxv%di%d(%s, ptr)\n", vectorType, lanes, bits, predicateType)
		fmt.Fprintf(b, "declare %s @llvm.aarch64.sve.ldnt1.nxv%di%d(%s, ptr)\n", vectorType, lanes, bits, predicateType)
		fmt.Fprintf(b, "declare void @llvm.aarch64.sve.stnt1.nxv%di%d(%s, %s, ptr)\n", lanes, bits, vectorType, predicateType)
		fmt.Fprintf(b, "declare { %s, %s } @llvm.aarch64.sve.ldnt1.pn.x2.nxv%di%d(target(\"aarch64.svcount\"), ptr)\n", vectorType, vectorType, lanes, bits)
		fmt.Fprintf(b, "declare { %s, %s, %s, %s } @llvm.aarch64.sve.ldnt1.pn.x4.nxv%di%d(target(\"aarch64.svcount\"), ptr)\n", vectorType, vectorType, vectorType, vectorType, lanes, bits)
		fmt.Fprintf(b, "declare void @llvm.aarch64.sve.stnt1.pn.x2.nxv%di%d(%s, %s, target(\"aarch64.svcount\"), ptr)\n", lanes, bits, vectorType, vectorType)
		fmt.Fprintf(b, "declare void @llvm.aarch64.sve.stnt1.pn.x4.nxv%di%d(%s, %s, %s, %s, target(\"aarch64.svcount\"), ptr)\n", lanes, bits, vectorType, vectorType, vectorType, vectorType)
	}
	for _, destinationBits := range []int{32, 64} {
		lanes := 128 / destinationBits
		baseType := fmt.Sprintf("<vscale x %d x i%d>", lanes, destinationBits)
		predicateType := fmt.Sprintf("<vscale x %d x i1>", lanes)
		for _, memoryBits := range []int{8, 16, 32, 64} {
			if memoryBits > destinationBits {
				continue
			}
			memoryType := fmt.Sprintf("<vscale x %d x i%d>", lanes, memoryBits)
			fmt.Fprintf(b, "declare %s @llvm.aarch64.sve.ldnt1.gather.scalar.offset.nxv%di%d.nxv%di%d(%s, %s, i64)\n", memoryType, lanes, memoryBits, lanes, destinationBits, predicateType, baseType)
			fmt.Fprintf(b, "declare void @llvm.aarch64.sve.stnt1.scatter.scalar.offset.nxv%di%d.nxv%di%d(%s, %s, %s, i64)\n", lanes, memoryBits, lanes, destinationBits, memoryType, predicateType, baseType)
		}
	}
	for _, destinationBits := range []int{8, 16, 32, 64} {
		lanes := 128 / destinationBits
		indexType := fmt.Sprintf("<vscale x %d x i%d>", lanes, destinationBits)
		predicateType := fmt.Sprintf("<vscale x %d x i1>", lanes)
		for _, memoryBits := range []int{8, 16, 32, 64} {
			if memoryBits > destinationBits {
				continue
			}
			memoryType := fmt.Sprintf("<vscale x %d x i%d>", lanes, memoryBits)
			fmt.Fprintf(b, "declare %s @llvm.aarch64.sve.ldff1.nxv%di%d(%s, ptr)\n", memoryType, lanes, memoryBits, predicateType)
			fmt.Fprintf(b, "declare %s @llvm.aarch64.sve.ldnf1.nxv%di%d(%s, ptr)\n", memoryType, lanes, memoryBits, predicateType)
			if destinationBits != 32 && destinationBits != 64 {
				continue
			}
			suffixes := []string{"", ".index"}
			if destinationBits == 32 {
				suffixes = append(suffixes, ".uxtw", ".uxtw.index", ".sxtw", ".sxtw.index")
			}
			for _, suffix := range suffixes {
				fmt.Fprintf(b, "declare %s @llvm.aarch64.sve.ldff1.gather%s.nxv%di%d(%s, ptr, %s)\n", memoryType, suffix, lanes, memoryBits, predicateType, indexType)
			}
			fmt.Fprintf(b, "declare %s @llvm.aarch64.sve.ldff1.gather.scalar.offset.nxv%di%d.nxv%di%d(%s, %s, i64)\n",
				memoryType, lanes, memoryBits, lanes, destinationBits, predicateType, indexType)
		}
	}
	for _, destinationBits := range []int{8, 16, 32, 64} {
		lanes := 128 / destinationBits
		indexType := fmt.Sprintf("<vscale x %d x i%d>", lanes, destinationBits)
		predicateType := fmt.Sprintf("<vscale x %d x i1>", lanes)
		for _, memoryBits := range []int{8, 16, 32, 64} {
			if memoryBits > destinationBits {
				continue
			}
			memoryType := fmt.Sprintf("<vscale x %d x i%d>", lanes, memoryBits)
			fmt.Fprintf(b, "declare %s @llvm.aarch64.sve.ld1.nxv%di%d(%s, ptr)\n", memoryType, lanes, memoryBits, predicateType)
			fmt.Fprintf(b, "declare void @llvm.aarch64.sve.st1.nxv%di%d(%s, %s, ptr)\n", lanes, memoryBits, memoryType, predicateType)
			if destinationBits != 32 && destinationBits != 64 {
				continue
			}
			suffixes := []string{"", ".index"}
			if destinationBits == 32 {
				suffixes = append(suffixes, ".uxtw", ".uxtw.index", ".sxtw", ".sxtw.index")
			}
			for _, suffix := range suffixes {
				fmt.Fprintf(b, "declare %s @llvm.aarch64.sve.ld1.gather%s.nxv%di%d(%s, ptr, %s)\n", memoryType, suffix, lanes, memoryBits, predicateType, indexType)
				fmt.Fprintf(b, "declare void @llvm.aarch64.sve.st1.scatter%s.nxv%di%d(%s, %s, ptr, %s)\n", suffix, lanes, memoryBits, memoryType, predicateType, indexType)
			}
			fmt.Fprintf(b, "declare %s @llvm.aarch64.sve.ld1.gather.scalar.offset.nxv%di%d.nxv%di%d(%s, %s, i64)\n",
				memoryType, lanes, memoryBits, lanes, destinationBits, predicateType, indexType)
			fmt.Fprintf(b, "declare void @llvm.aarch64.sve.st1.scatter.scalar.offset.nxv%di%d.nxv%di%d(%s, %s, %s, i64)\n",
				lanes, memoryBits, lanes, destinationBits, memoryType, predicateType, indexType)
		}
	}
	for _, bits := range []int{8, 16, 32, 64} {
		lanes := 128 / bits
		vectorType := fmt.Sprintf("<vscale x %d x i%d>", lanes, bits)
		fmt.Fprintf(b, "declare { %s, %s } @llvm.aarch64.sve.ld1.pn.x2.nxv%di%d(target(\"aarch64.svcount\"), ptr)\n", vectorType, vectorType, lanes, bits)
		fmt.Fprintf(b, "declare { %s, %s, %s, %s } @llvm.aarch64.sve.ld1.pn.x4.nxv%di%d(target(\"aarch64.svcount\"), ptr)\n", vectorType, vectorType, vectorType, vectorType, lanes, bits)
		fmt.Fprintf(b, "declare void @llvm.aarch64.sve.st1.pn.x2.nxv%di%d(%s, %s, target(\"aarch64.svcount\"), ptr)\n", lanes, bits, vectorType, vectorType)
		fmt.Fprintf(b, "declare void @llvm.aarch64.sve.st1.pn.x4.nxv%di%d(%s, %s, %s, %s, target(\"aarch64.svcount\"), ptr)\n", lanes, bits, vectorType, vectorType, vectorType, vectorType)
	}
	b.WriteString("declare <vscale x 1 x i1> @llvm.aarch64.sve.convert.from.svbool.nxv1i1(<vscale x 16 x i1>)\n")
	b.WriteString("declare <vscale x 4 x i32> @llvm.aarch64.sve.ld1uwq.nxv4i32(<vscale x 1 x i1>, ptr)\n")
	b.WriteString("declare <vscale x 2 x i64> @llvm.aarch64.sve.ld1udq.nxv2i64(<vscale x 1 x i1>, ptr)\n")
	b.WriteString("declare void @llvm.aarch64.sve.st1wq.nxv4i32(<vscale x 4 x i32>, <vscale x 1 x i1>, ptr)\n")
	b.WriteString("declare void @llvm.aarch64.sve.st1dq.nxv2i64(<vscale x 2 x i64>, <vscale x 1 x i1>, ptr)\n")
	b.WriteString("declare <vscale x 2 x i64> @llvm.aarch64.sve.ld1q.gather.scalar.offset.nxv2i64.nxv2i64(<vscale x 1 x i1>, <vscale x 2 x i64>, i64)\n")
	b.WriteString("declare void @llvm.aarch64.sve.st1q.scatter.scalar.offset.nxv2i64.nxv2i64(<vscale x 2 x i64>, <vscale x 1 x i1>, <vscale x 2 x i64>, i64)\n")
	for _, count := range []int{2, 3, 4} {
		for _, bits := range []int{8, 16, 32, 64} {
			lanes := 128 / bits
			vectorType := fmt.Sprintf("<vscale x %d x i%d>", lanes, bits)
			predicateType := fmt.Sprintf("<vscale x %d x i1>", lanes)
			aggregateType := arm64SVEAggregateType(vectorType, count)
			fmt.Fprintf(b, "declare %s @llvm.aarch64.sve.ld%d.sret.nxv%di%d(%s, ptr)\n", aggregateType, count, lanes, bits, predicateType)
			values := make([]string, count)
			for i := range values {
				values[i] = vectorType
			}
			fmt.Fprintf(b, "declare void @llvm.aarch64.sve.st%d.nxv%di%d(%s, %s, ptr)\n", count, lanes, bits, strings.Join(values, ", "), predicateType)
		}
		vectorType := "<vscale x 2 x i64>"
		predicateType := "<vscale x 2 x i1>"
		aggregateType := arm64SVEAggregateType(vectorType, count)
		fmt.Fprintf(b, "declare %s @llvm.aarch64.sve.ld%dq.sret.nxv2i64(%s, ptr)\n", aggregateType, count, predicateType)
		values := make([]string, count)
		for i := range values {
			values[i] = vectorType
		}
		fmt.Fprintf(b, "declare void @llvm.aarch64.sve.st%dq.nxv2i64(%s, %s, ptr)\n", count, strings.Join(values, ", "), predicateType)
	}
	for _, suffix := range []string{"b", "h", "w", "d"} {
		fmt.Fprintf(b, "declare i64 @llvm.aarch64.sve.cnt%s(i32 immarg)\n", suffix)
	}
	for _, elementBits := range []int{8, 16, 32, 64} {
		fmt.Fprintf(b, "declare target(\"aarch64.svcount\") @llvm.aarch64.sve.ptrue.c%d()\n", elementBits)
		fmt.Fprintf(b, "declare i64 @llvm.aarch64.sve.cntp.c%d(target(\"aarch64.svcount\"), i32 immarg)\n", elementBits)
		lanes := 128 / elementBits
		fmt.Fprintf(b, "declare i64 @llvm.aarch64.sve.cntp.nxv%di1(<vscale x %d x i1>, <vscale x %d x i1>)\n", lanes, lanes, lanes)
		predicateType := fmt.Sprintf("<vscale x %d x i1>", lanes)
		fmt.Fprintf(b, "declare %s @llvm.aarch64.sve.pext.nxv%di1(target(\"aarch64.svcount\"), i32 immarg)\n", predicateType, lanes)
		fmt.Fprintf(b, "declare { %s, %s } @llvm.aarch64.sve.pext.x2.nxv%di1(target(\"aarch64.svcount\"), i32 immarg)\n", predicateType, predicateType, lanes)
		for _, condition := range []string{"whilege", "whilegt", "whilehi", "whilehs", "whilele", "whilelo", "whilels", "whilelt"} {
			fmt.Fprintf(b, "declare %s @llvm.aarch64.sve.%s.nxv%di1.i64(i64, i64)\n", predicateType, condition, lanes)
			fmt.Fprintf(b, "declare %s @llvm.aarch64.sve.%s.nxv%di1.i32(i32, i32)\n", predicateType, condition, lanes)
			fmt.Fprintf(b, "declare { %s, %s } @llvm.aarch64.sve.%s.x2.nxv%di1(i64, i64)\n", predicateType, predicateType, condition, lanes)
			fmt.Fprintf(b, "declare target(\"aarch64.svcount\") @llvm.aarch64.sve.%s.c%d(i64, i64, i32 immarg)\n", condition, elementBits)
		}
		letter := strings.ToLower(map[int]string{8: "B", 16: "H", 32: "S", 64: "D"}[elementBits])
		for _, condition := range []string{"whilerw", "whilewr"} {
			fmt.Fprintf(b, "declare %s @llvm.aarch64.sve.%s.%s.nxv%di1.p0(ptr, ptr)\n", predicateType, condition, letter, lanes)
		}
		for _, intrinsic := range []string{"sqdecp", "sqincp", "uqdecp", "uqincp"} {
			fmt.Fprintf(b, "declare i32 @llvm.aarch64.sve.%s.n32.nxv%di1(i32, %s)\n", intrinsic, lanes, predicateType)
			fmt.Fprintf(b, "declare i64 @llvm.aarch64.sve.%s.n64.nxv%di1(i64, %s)\n", intrinsic, lanes, predicateType)
		}
		fmt.Fprintf(b, "declare void @llvm.aarch64.sve.prf.nxv%di1(%s, ptr, i32 immarg)\n", lanes, predicateType)
		vectorType := fmt.Sprintf("<vscale x %d x i%d>", lanes, elementBits)
		fmt.Fprintf(b, "declare %s @llvm.aarch64.sve.index.nxv%di%d(i%d, i%d)\n", vectorType, lanes, elementBits, elementBits, elementBits)
		fmt.Fprintf(b, "declare %s @llvm.aarch64.sve.insr.nxv%di%d(%s, i%d)\n", vectorType, lanes, elementBits, vectorType, elementBits)
		for _, intrinsic := range []string{"lasta", "lastb"} {
			fmt.Fprintf(b, "declare i%d @llvm.aarch64.sve.%s.nxv%di%d(%s, %s)\n", elementBits, intrinsic, lanes, elementBits, predicateType, vectorType)
		}
		for _, intrinsic := range []string{"clasta", "clastb"} {
			fmt.Fprintf(b, "declare i%d @llvm.aarch64.sve.%s.n.nxv%di%d(%s, i%d, %s)\n", elementBits, intrinsic, lanes, elementBits, predicateType, elementBits, vectorType)
			fmt.Fprintf(b, "declare %s @llvm.aarch64.sve.%s.nxv%di%d(%s, %s, %s)\n", vectorType, intrinsic, lanes, elementBits, predicateType, vectorType, vectorType)
		}
		fmt.Fprintf(b, "declare %s @llvm.aarch64.sve.compact.nxv%di%d(%s, %s)\n", vectorType, lanes, elementBits, predicateType, vectorType)
		fmt.Fprintf(b, "declare %s @llvm.aarch64.sve.expand.nxv%di%d(%s, %s)\n", vectorType, lanes, elementBits, predicateType, vectorType)
		fmt.Fprintf(b, "declare %s @llvm.aarch64.sve.splice.nxv%di%d(%s, %s, %s)\n", vectorType, lanes, elementBits, predicateType, vectorType, vectorType)
		fmt.Fprintf(b, "declare %s @llvm.aarch64.sve.pmov.to.pred.lane.zero.nxv%di%d(%s)\n", predicateType, lanes, elementBits, vectorType)
		fmt.Fprintf(b, "declare %s @llvm.aarch64.sve.pmov.to.pred.lane.nxv%di%d(%s, i32 immarg)\n", predicateType, lanes, elementBits, vectorType)
		fmt.Fprintf(b, "declare %s @llvm.aarch64.sve.pmov.to.vector.lane.zeroing.nxv%di%d(%s)\n", vectorType, lanes, elementBits, predicateType)
		fmt.Fprintf(b, "declare %s @llvm.aarch64.sve.pmov.to.vector.lane.merging.nxv%di%d(%s, %s, i32 immarg)\n", vectorType, lanes, elementBits, vectorType, predicateType)
	}
	for _, destinationBits := range []int{16, 32, 64} {
		destinationLanes := 128 / destinationBits
		sourceBits := destinationBits / 2
		sourceLanes := 128 / sourceBits
		destinationType := fmt.Sprintf("<vscale x %d x i%d>", destinationLanes, destinationBits)
		sourceType := fmt.Sprintf("<vscale x %d x i%d>", sourceLanes, sourceBits)
		for _, intrinsic := range []string{"saddlb", "saddlbt", "saddlt", "ssublb", "ssublbt", "ssublt", "ssubltb", "uaddlb", "uaddlt", "usublb", "usublt"} {
			fmt.Fprintf(b, "declare %s @llvm.aarch64.sve.%s.nxv%di%d(%s, %s)\n", destinationType, intrinsic, destinationLanes, destinationBits, sourceType, sourceType)
		}
		for _, intrinsic := range []string{"sshllb", "sshllt", "ushllb", "ushllt"} {
			fmt.Fprintf(b, "declare %s @llvm.aarch64.sve.%s.nxv%di%d(%s, i32 immarg)\n", destinationType, intrinsic, destinationLanes, destinationBits, sourceType)
		}
		for _, intrinsic := range []string{"saddwb", "saddwt", "ssubwb", "ssubwt", "uaddwb", "uaddwt", "usubwb", "usubwt"} {
			fmt.Fprintf(b, "declare %s @llvm.aarch64.sve.%s.nxv%di%d(%s, %s)\n", destinationType, intrinsic, destinationLanes, destinationBits, destinationType, sourceType)
		}
		for _, intrinsic := range []string{"sabdlb", "sabdlt", "uabdlb", "uabdlt"} {
			fmt.Fprintf(b, "declare %s @llvm.aarch64.sve.%s.nxv%di%d(%s, %s)\n", destinationType, intrinsic, destinationLanes, destinationBits, sourceType, sourceType)
		}
		for _, intrinsic := range []string{"sabalb", "sabalt", "uabalb", "uabalt"} {
			fmt.Fprintf(b, "declare %s @llvm.aarch64.sve.%s.nxv%di%d(%s, %s, %s)\n", destinationType, intrinsic, destinationLanes, destinationBits, destinationType, sourceType, sourceType)
		}
		for _, intrinsic := range []string{"sadalp", "uadalp"} {
			fmt.Fprintf(b, "declare %s @llvm.aarch64.sve.%s.nxv%di%d(<vscale x %d x i1>, %s, %s)\n", destinationType, intrinsic, destinationLanes, destinationBits, destinationLanes, destinationType, sourceType)
		}
	}
	for _, sourceBits := range []int{16, 32, 64} {
		sourceLanes := 128 / sourceBits
		destinationBits := sourceBits / 2
		destinationLanes := 128 / destinationBits
		sourceType := fmt.Sprintf("<vscale x %d x i%d>", sourceLanes, sourceBits)
		destinationType := fmt.Sprintf("<vscale x %d x i%d>", destinationLanes, destinationBits)
		for _, intrinsic := range []string{"addhnb", "raddhnb", "rsubhnb", "subhnb"} {
			fmt.Fprintf(b, "declare %s @llvm.aarch64.sve.%s.nxv%di%d(%s, %s)\n", destinationType, intrinsic, sourceLanes, sourceBits, sourceType, sourceType)
		}
		for _, intrinsic := range []string{"addhnt", "raddhnt", "rsubhnt", "subhnt"} {
			fmt.Fprintf(b, "declare %s @llvm.aarch64.sve.%s.nxv%di%d(%s, %s, %s)\n", destinationType, intrinsic, sourceLanes, sourceBits, destinationType, sourceType, sourceType)
		}
	}
	for _, intrinsic := range []string{"bcax", "bsl", "bsl1n", "bsl2n", "eor3", "nbsl"} {
		fmt.Fprintf(b, "declare <vscale x 2 x i64> @llvm.aarch64.sve.%s.nxv2i64(<vscale x 2 x i64>, <vscale x 2 x i64>, <vscale x 2 x i64>)\n", intrinsic)
	}
	for _, bits := range []int{8, 16, 32, 64} {
		lanes := 128 / bits
		vectorType := fmt.Sprintf("<vscale x %d x i%d>", lanes, bits)
		for _, intrinsic := range []string{"bdep.x", "bext.x", "bgrp.x"} {
			fmt.Fprintf(b, "declare %s @llvm.aarch64.sve.%s.nxv%di%d(%s, %s)\n", vectorType, intrinsic, lanes, bits, vectorType, vectorType)
		}
	}
	for _, bits := range []int{32, 64} {
		lanes := 128 / bits
		vectorType := fmt.Sprintf("<vscale x %d x i%d>", lanes, bits)
		for _, intrinsic := range []string{"adclb", "adclt", "sbclb", "sbclt"} {
			fmt.Fprintf(b, "declare %s @llvm.aarch64.sve.%s.nxv%di%d(%s, %s, %s)\n", vectorType, intrinsic, lanes, bits, vectorType, vectorType, vectorType)
		}
	}
	for _, bits := range []int{8, 16, 32, 64} {
		lanes := 128 / bits
		vectorType := fmt.Sprintf("<vscale x %d x i%d>", lanes, bits)
		for _, intrinsic := range []string{"sclamp", "uclamp"} {
			fmt.Fprintf(b, "declare %s @llvm.aarch64.sve.%s.nxv%di%d(%s, %s, %s)\n", vectorType, intrinsic, lanes, bits, vectorType, vectorType, vectorType)
		}
	}
	for _, bits := range []int{16, 32, 64} {
		_, vectorType, lanes, _ := arm64SVEFloatType(bits)
		suffix := map[int]string{16: "f16", 32: "f32", 64: "f64"}[bits]
		fmt.Fprintf(b, "declare %s @llvm.aarch64.sve.fclamp.nxv%d%s(%s, %s, %s)\n", vectorType, lanes, suffix, vectorType, vectorType, vectorType)
	}
	b.WriteString("declare <vscale x 8 x bfloat> @llvm.aarch64.sve.fclamp.nxv8bf16(<vscale x 8 x bfloat>, <vscale x 8 x bfloat>, <vscale x 8 x bfloat>)\n")
	b.WriteString("declare <vscale x 4 x float> @llvm.aarch64.sve.bfdot(<vscale x 4 x float>, <vscale x 8 x bfloat>, <vscale x 8 x bfloat>)\n")
	b.WriteString("declare <vscale x 4 x float> @llvm.aarch64.sve.bfdot.lane.v2(<vscale x 4 x float>, <vscale x 8 x bfloat>, <vscale x 8 x bfloat>, i32 immarg)\n")
	b.WriteString("declare <vscale x 8 x half> @llvm.aarch64.sve.fp8.fdot.nxv8f16(<vscale x 8 x half>, <vscale x 16 x i8>, <vscale x 16 x i8>)\n")
	b.WriteString("declare <vscale x 8 x half> @llvm.aarch64.sve.fp8.fdot.lane.nxv8f16(<vscale x 8 x half>, <vscale x 16 x i8>, <vscale x 16 x i8>, i32 immarg)\n")
	b.WriteString("declare <vscale x 4 x float> @llvm.aarch64.sve.fp8.fdot.nxv4f32(<vscale x 4 x float>, <vscale x 16 x i8>, <vscale x 16 x i8>)\n")
	b.WriteString("declare <vscale x 4 x float> @llvm.aarch64.sve.fp8.fdot.lane.nxv4f32(<vscale x 4 x float>, <vscale x 16 x i8>, <vscale x 16 x i8>, i32 immarg)\n")
	b.WriteString("declare <vscale x 4 x float> @llvm.aarch64.sve.fdot.x2.nxv4f32(<vscale x 4 x float>, <vscale x 8 x half>, <vscale x 8 x half>)\n")
	b.WriteString("declare <vscale x 4 x float> @llvm.aarch64.sve.fdot.lane.x2.nxv4f32(<vscale x 4 x float>, <vscale x 8 x half>, <vscale x 8 x half>, i32 immarg)\n")
	b.WriteString("declare <vscale x 4 x i32> @llvm.aarch64.sve.cdot.nxv4i32(<vscale x 4 x i32>, <vscale x 16 x i8>, <vscale x 16 x i8>, i32 immarg)\n")
	b.WriteString("declare <vscale x 4 x i32> @llvm.aarch64.sve.cdot.lane.nxv4i32(<vscale x 4 x i32>, <vscale x 16 x i8>, <vscale x 16 x i8>, i32 immarg, i32 immarg)\n")
	b.WriteString("declare <vscale x 2 x i64> @llvm.aarch64.sve.cdot.nxv2i64(<vscale x 2 x i64>, <vscale x 8 x i16>, <vscale x 8 x i16>, i32 immarg)\n")
	b.WriteString("declare <vscale x 2 x i64> @llvm.aarch64.sve.cdot.lane.nxv2i64(<vscale x 2 x i64>, <vscale x 8 x i16>, <vscale x 8 x i16>, i32 immarg, i32 immarg)\n")
	b.WriteString("declare <vscale x 16 x i8> @llvm.aarch64.sve.luti2.lane.nxv16i8(<vscale x 16 x i8>, <vscale x 16 x i8>, i32 immarg)\n")
	b.WriteString("declare <vscale x 8 x i16> @llvm.aarch64.sve.luti2.lane.nxv8i16(<vscale x 8 x i16>, <vscale x 16 x i8>, i32 immarg)\n")
	b.WriteString("declare <vscale x 16 x i8> @llvm.aarch64.sve.luti4.lane.nxv16i8(<vscale x 16 x i8>, <vscale x 16 x i8>, i32 immarg)\n")
	b.WriteString("declare <vscale x 8 x i16> @llvm.aarch64.sve.luti4.lane.nxv8i16(<vscale x 8 x i16>, <vscale x 16 x i8>, i32 immarg)\n")
	b.WriteString("declare <vscale x 8 x i16> @llvm.aarch64.sve.luti4.lane.x2.nxv8i16(<vscale x 8 x i16>, <vscale x 8 x i16>, <vscale x 16 x i8>, i32 immarg)\n")
	for _, intrinsic := range []string{"fmlalb", "fmlalt", "fmlslb", "fmlslt"} {
		fmt.Fprintf(b, "declare <vscale x 4 x float> @llvm.aarch64.sve.%s.nxv4f32(<vscale x 4 x float>, <vscale x 8 x half>, <vscale x 8 x half>)\n", intrinsic)
		fmt.Fprintf(b, "declare <vscale x 4 x float> @llvm.aarch64.sve.%s.lane.nxv4f32(<vscale x 4 x float>, <vscale x 8 x half>, <vscale x 8 x half>, i32 immarg)\n", intrinsic)
	}
	for _, intrinsic := range []string{"fmlalb", "fmlalt"} {
		fmt.Fprintf(b, "declare <vscale x 8 x half> @llvm.aarch64.sve.fp8.%s.nxv8f16(<vscale x 8 x half>, <vscale x 16 x i8>, <vscale x 16 x i8>)\n", intrinsic)
		fmt.Fprintf(b, "declare <vscale x 8 x half> @llvm.aarch64.sve.fp8.%s.lane.nxv8f16(<vscale x 8 x half>, <vscale x 16 x i8>, <vscale x 16 x i8>, i32 immarg)\n", intrinsic)
	}
	for _, intrinsic := range []string{"fmlallbb", "fmlallbt", "fmlalltb", "fmlalltt"} {
		fmt.Fprintf(b, "declare <vscale x 4 x float> @llvm.aarch64.sve.fp8.%s.nxv4f32(<vscale x 4 x float>, <vscale x 16 x i8>, <vscale x 16 x i8>)\n", intrinsic)
		fmt.Fprintf(b, "declare <vscale x 4 x float> @llvm.aarch64.sve.fp8.%s.lane.nxv4f32(<vscale x 4 x float>, <vscale x 16 x i8>, <vscale x 16 x i8>, i32 immarg)\n", intrinsic)
	}
	for _, intrinsic := range []string{"sqcvtn", "sqcvtun", "uqcvtn"} {
		fmt.Fprintf(b, "declare <vscale x 8 x i16> @llvm.aarch64.sve.%s.x2.nxv4i32(<vscale x 4 x i32>, <vscale x 4 x i32>)\n", intrinsic)
	}
	for _, intrinsic := range []string{"sqrshrn", "sqrshrun", "uqrshrn"} {
		fmt.Fprintf(b, "declare <vscale x 8 x i16> @llvm.aarch64.sve.%s.x2.nxv4i32(<vscale x 4 x i32>, <vscale x 4 x i32>, i32 immarg)\n", intrinsic)
	}
	b.WriteString("declare <vscale x 16 x i8> @llvm.vector.interleave2.nxv16i8(<vscale x 8 x i8>, <vscale x 8 x i8>)\n")
	b.WriteString("declare <vscale x 16 x i8> @llvm.aarch64.sve.aesimc(<vscale x 16 x i8>)\n")
	b.WriteString("declare <vscale x 16 x i8> @llvm.aarch64.sve.aesmc(<vscale x 16 x i8>)\n")
	b.WriteString("declare <vscale x 16 x i8> @llvm.aarch64.sve.aesd(<vscale x 16 x i8>, <vscale x 16 x i8>)\n")
	b.WriteString("declare <vscale x 16 x i8> @llvm.aarch64.sve.aese(<vscale x 16 x i8>, <vscale x 16 x i8>)\n")
	b.WriteString("declare <vscale x 2 x i64> @llvm.aarch64.sve.rax1(<vscale x 2 x i64>, <vscale x 2 x i64>)\n")
	b.WriteString("declare <vscale x 4 x i32> @llvm.aarch64.sve.sm4e(<vscale x 4 x i32>, <vscale x 4 x i32>)\n")
	b.WriteString("declare <vscale x 4 x i32> @llvm.aarch64.sve.sm4ekey(<vscale x 4 x i32>, <vscale x 4 x i32>)\n")
	for _, count := range []int{2, 4} {
		types := make([]string, count)
		arguments := make([]string, count+2)
		for i := 0; i < count; i++ {
			types[i] = "<vscale x 16 x i8>"
			arguments[i] = "<vscale x 16 x i8>"
		}
		arguments[count] = "<vscale x 16 x i8>"
		arguments[count+1] = "i32 immarg"
		aggregateType := "{ " + strings.Join(types, ", ") + " }"
		for _, intrinsic := range []string{"aesd", "aesdimc", "aese", "aesemc"} {
			fmt.Fprintf(b, "declare %s @llvm.aarch64.sve.%s.lane.x%d(%s)\n", aggregateType, intrinsic, count, strings.Join(arguments, ", "))
		}
	}
	b.WriteString("declare <vscale x 2 x i64> @llvm.aarch64.sve.revd.nxv2i64(<vscale x 2 x i64>, <vscale x 2 x i1>, <vscale x 2 x i64>)\n")
	b.WriteString("declare <vscale x 16 x i8> @llvm.aarch64.sve.pmul.nxv16i8(<vscale x 16 x i8>, <vscale x 16 x i8>)\n")
	for _, bits := range []int{8, 32, 64} {
		lanes := 128 / bits
		vectorType := fmt.Sprintf("<vscale x %d x i%d>", lanes, bits)
		for _, intrinsic := range []string{"pmullb.pair", "pmullt.pair"} {
			fmt.Fprintf(b, "declare %s @llvm.aarch64.sve.%s.nxv%di%d(%s, %s)\n", vectorType, intrinsic, lanes, bits, vectorType, vectorType)
		}
	}
	b.WriteString("declare { <vscale x 2 x i64>, <vscale x 2 x i64> } @llvm.aarch64.sve.pmull.pair.x2(<vscale x 2 x i64>, <vscale x 2 x i64>)\n")
	b.WriteString("declare { <vscale x 2 x i64>, <vscale x 2 x i64> } @llvm.aarch64.sve.pmlal.pair.x2(<vscale x 2 x i64>, <vscale x 2 x i64>, <vscale x 2 x i64>, <vscale x 2 x i64>)\n")
	for _, form := range []struct{ destinationBits, sourceBits int }{{16, 8}, {32, 16}, {32, 8}, {64, 16}} {
		destinationLanes := 128 / form.destinationBits
		sourceLanes := 128 / form.sourceBits
		destinationType := fmt.Sprintf("<vscale x %d x i%d>", destinationLanes, form.destinationBits)
		sourceType := fmt.Sprintf("<vscale x %d x i%d>", sourceLanes, form.sourceBits)
		x2 := ""
		if form.destinationBits == form.sourceBits*2 {
			x2 = ".x2"
		}
		for _, intrinsic := range []string{"sdot", "udot"} {
			fmt.Fprintf(b, "declare %s @llvm.aarch64.sve.%s%s.nxv%di%d(%s, %s, %s)\n", destinationType, intrinsic, x2, destinationLanes, form.destinationBits, destinationType, sourceType, sourceType)
			fmt.Fprintf(b, "declare %s @llvm.aarch64.sve.%s.lane%s.nxv%di%d(%s, %s, %s, i32 immarg)\n", destinationType, intrinsic, x2, destinationLanes, form.destinationBits, destinationType, sourceType, sourceType)
		}
	}
	for _, intrinsic := range []string{"usdot", "usdot.lane", "sudot.lane"} {
		fmt.Fprintf(b, "declare <vscale x 4 x i32> @llvm.aarch64.sve.%s.nxv4i32(<vscale x 4 x i32>, <vscale x 16 x i8>, <vscale x 16 x i8>", intrinsic)
		if strings.Contains(intrinsic, ".lane") {
			b.WriteString(", i32 immarg")
		}
		b.WriteString(")\n")
	}
	for _, sourceBits := range []int{8, 16, 32} {
		destinationBits := sourceBits * 2
		sourceLanes := 128 / sourceBits
		destinationLanes := 128 / destinationBits
		sourceType := fmt.Sprintf("<vscale x %d x i%d>", sourceLanes, sourceBits)
		destinationType := fmt.Sprintf("<vscale x %d x i%d>", destinationLanes, destinationBits)
		for _, intrinsic := range []string{"sunpkhi", "sunpklo", "uunpkhi", "uunpklo"} {
			fmt.Fprintf(b, "declare %s @llvm.aarch64.sve.%s.nxv%di%d(%s)\n", destinationType, intrinsic, destinationLanes, destinationBits, sourceType)
		}
	}
	for _, sourceBits := range []int{16, 32, 64} {
		destinationBits := sourceBits / 2
		sourceLanes := 128 / sourceBits
		destinationLanes := 128 / destinationBits
		sourceType := fmt.Sprintf("<vscale x %d x i%d>", sourceLanes, sourceBits)
		destinationType := fmt.Sprintf("<vscale x %d x i%d>", destinationLanes, destinationBits)
		for _, intrinsic := range []string{"sqxtnb", "sqxtunb", "uqxtnb"} {
			fmt.Fprintf(b, "declare %s @llvm.aarch64.sve.%s.nxv%di%d(%s)\n", destinationType, intrinsic, sourceLanes, sourceBits, sourceType)
		}
		for _, intrinsic := range []string{"sqxtnt", "sqxtunt", "uqxtnt"} {
			fmt.Fprintf(b, "declare %s @llvm.aarch64.sve.%s.nxv%di%d(%s, %s)\n", destinationType, intrinsic, sourceLanes, sourceBits, destinationType, sourceType)
		}
	}
	for _, sourceBits := range []int{16, 32, 64} {
		destinationBits := sourceBits / 2
		sourceLanes := 128 / sourceBits
		destinationLanes := 128 / destinationBits
		sourceType := fmt.Sprintf("<vscale x %d x i%d>", sourceLanes, sourceBits)
		destinationType := fmt.Sprintf("<vscale x %d x i%d>", destinationLanes, destinationBits)
		for _, intrinsic := range []string{"shrnb", "rshrnb"} {
			fmt.Fprintf(b, "declare %s @llvm.aarch64.sve.%s.nxv%di%d(%s, i32 immarg)\n", destinationType, intrinsic, sourceLanes, sourceBits, sourceType)
		}
		for _, intrinsic := range []string{"shrnt", "rshrnt"} {
			fmt.Fprintf(b, "declare %s @llvm.aarch64.sve.%s.nxv%di%d(%s, %s, i32 immarg)\n", destinationType, intrinsic, sourceLanes, sourceBits, destinationType, sourceType)
		}
	}
	for _, sourceBits := range []int{16, 32, 64} {
		destinationBits := sourceBits / 2
		sourceLanes := 128 / sourceBits
		destinationLanes := 128 / destinationBits
		sourceType := fmt.Sprintf("<vscale x %d x i%d>", sourceLanes, sourceBits)
		destinationType := fmt.Sprintf("<vscale x %d x i%d>", destinationLanes, destinationBits)
		for _, intrinsic := range []string{"sqshrnb", "sqrshrnb", "sqshrunb", "sqrshrunb", "uqshrnb", "uqrshrnb"} {
			fmt.Fprintf(b, "declare %s @llvm.aarch64.sve.%s.nxv%di%d(%s, i32 immarg)\n", destinationType, intrinsic, sourceLanes, sourceBits, sourceType)
		}
		for _, intrinsic := range []string{"sqshrnt", "sqrshrnt", "sqshrunt", "sqrshrunt", "uqshrnt", "uqrshrnt"} {
			fmt.Fprintf(b, "declare %s @llvm.aarch64.sve.%s.nxv%di%d(%s, %s, i32 immarg)\n", destinationType, intrinsic, sourceLanes, sourceBits, destinationType, sourceType)
		}
	}
	b.WriteString("declare <vscale x 16 x i8> @llvm.aarch64.sve.ext.nxv16i8(<vscale x 16 x i8>, <vscale x 16 x i8>, i32 immarg)\n")
	b.WriteString("declare <vscale x 16 x i8> @llvm.aarch64.sve.extq.nxv16i8(<vscale x 16 x i8>, <vscale x 16 x i8>, i32 immarg)\n")
	emitARM64SVEConvertDeclarations(b)
	emitARM64SVEFloatNarrowConversionDeclarations(b)
	emitARM64SVEBFloatArithmeticDeclarations(b)
	emitARM64SVEBFloatMLADeclarations(b)
	for _, elementBits := range []int{16, 32, 64} {
		_, vectorType, lanes, _ := arm64SVEFloatType(elementBits)
		code := map[int]string{16: "f16", 32: "f32", 64: "f64"}[elementBits]
		fmt.Fprintf(b, "declare %s @llvm.aarch64.sve.fmul.lane.nxv%d%s(%s, %s, i32 immarg)\n", vectorType, lanes, code, vectorType, vectorType)
		predicateType := fmt.Sprintf("<vscale x %d x i1>", lanes)
		fmt.Fprintf(b, "declare %s @llvm.aarch64.sve.fmulx.nxv%d%s(%s, %s, %s)\n", vectorType, lanes, code, predicateType, vectorType, vectorType)
		for _, intrinsic := range []string{"ftsmul", "ftssel"} {
			fmt.Fprintf(b, "declare %s @llvm.aarch64.sve.%s.x.nxv%d%s(%s, <vscale x %d x i%d>)\n", vectorType, intrinsic, lanes, code, vectorType, lanes, elementBits)
		}
		fmt.Fprintf(b, "declare %s @llvm.aarch64.sve.ftmad.x.nxv%d%s(%s, %s, i32 immarg)\n", vectorType, lanes, code, vectorType, vectorType)
		fmt.Fprintf(b, "declare %s @llvm.aarch64.sve.fcmla.nxv%d%s(%s, %s, %s, %s, i32 immarg)\n", vectorType, lanes, code, predicateType, vectorType, vectorType, vectorType)
		if elementBits != 64 {
			fmt.Fprintf(b, "declare %s @llvm.aarch64.sve.fcmla.lane.nxv%d%s(%s, %s, %s, i32 immarg, i32 immarg)\n", vectorType, lanes, code, vectorType, vectorType, vectorType)
		}
		for _, intrinsic := range []string{"fmla", "fmls", "fmad", "fmsb", "fnmla", "fnmls", "fnmad", "fnmsb"} {
			fmt.Fprintf(b, "declare %s @llvm.aarch64.sve.%s.nxv%d%s(%s, %s, %s, %s)\n", vectorType, intrinsic, lanes, code, predicateType, vectorType, vectorType, vectorType)
		}
		for _, intrinsic := range []string{"fmla", "fmls"} {
			fmt.Fprintf(b, "declare %s @llvm.aarch64.sve.%s.lane.nxv%d%s(%s, %s, %s, i32 immarg)\n", vectorType, intrinsic, lanes, code, vectorType, vectorType, vectorType)
		}
	}
	for _, vectorBits := range []int{32, 64} {
		lanes := 128 / vectorBits
		predicateType := fmt.Sprintf("<vscale x %d x i1>", lanes)
		vectorType := fmt.Sprintf("<vscale x %d x i%d>", lanes, vectorBits)
		for _, letter := range []string{"b", "h", "w", "d"} {
			fmt.Fprintf(b, "declare void @llvm.aarch64.sve.prf%s.gather.index.nxv%di%d(%s, ptr, %s, i32 immarg)\n", letter, lanes, vectorBits, predicateType, vectorType)
			fmt.Fprintf(b, "declare void @llvm.aarch64.sve.prf%s.gather.uxtw.index.nxv%di%d(%s, ptr, %s, i32 immarg)\n", letter, lanes, vectorBits, predicateType, vectorType)
			fmt.Fprintf(b, "declare void @llvm.aarch64.sve.prf%s.gather.sxtw.index.nxv%di%d(%s, ptr, %s, i32 immarg)\n", letter, lanes, vectorBits, predicateType, vectorType)
			fmt.Fprintf(b, "declare void @llvm.aarch64.sve.prf%s.gather.scalar.offset.nxv%di%d(%s, %s, i64, i32 immarg)\n", letter, lanes, vectorBits, predicateType, vectorType)
		}
	}
	for _, lanes := range []int{16, 8, 4, 2} {
		for _, intrinsic := range []string{"any", "first", "last"} {
			fmt.Fprintf(b, "declare i1 @llvm.aarch64.sve.ptest.%s.nxv%di1(<vscale x %d x i1>, <vscale x %d x i1>)\n", intrinsic, lanes, lanes, lanes)
		}
	}
	b.WriteString("declare <vscale x 16 x i1> @llvm.aarch64.sve.rdffr()\n")
	b.WriteString("declare <vscale x 16 x i1> @llvm.aarch64.sve.rdffr.z(<vscale x 16 x i1>)\n")
	b.WriteString("declare void @llvm.aarch64.sve.setffr()\n")
	b.WriteString("declare void @llvm.aarch64.sve.wrffr(<vscale x 16 x i1>)\n")
	for _, intrinsic := range []string{"brka", "brkb"} {
		fmt.Fprintf(b, "declare <vscale x 16 x i1> @llvm.aarch64.sve.%s.nxv16i1(<vscale x 16 x i1>, <vscale x 16 x i1>, <vscale x 16 x i1>)\n", intrinsic)
		fmt.Fprintf(b, "declare <vscale x 16 x i1> @llvm.aarch64.sve.%s.z.nxv16i1(<vscale x 16 x i1>, <vscale x 16 x i1>)\n", intrinsic)
	}
	for _, intrinsic := range []string{"brkn.z", "brkpa.z", "brkpb.z"} {
		fmt.Fprintf(b, "declare <vscale x 16 x i1> @llvm.aarch64.sve.%s.nxv16i1(<vscale x 16 x i1>, <vscale x 16 x i1>, <vscale x 16 x i1>)\n", intrinsic)
	}
	b.WriteString("declare <vscale x 16 x i1> @llvm.vector.reverse.nxv16i1(<vscale x 16 x i1>)\n")
	for _, elementBits := range []int{16, 32, 64} {
		fmt.Fprintf(b, "declare <vscale x 16 x i1> @llvm.aarch64.sve.rev.b%d(<vscale x 16 x i1>)\n", elementBits)
	}
	for _, intrinsic := range []string{"trn1", "trn2", "uzp1", "uzp2", "zip1", "zip2"} {
		fmt.Fprintf(b, "declare <vscale x 16 x i1> @llvm.aarch64.sve.%s.nxv16i1(<vscale x 16 x i1>, <vscale x 16 x i1>)\n", intrinsic)
		for _, elementBits := range []int{16, 32, 64} {
			fmt.Fprintf(b, "declare <vscale x 16 x i1> @llvm.aarch64.sve.%s.b%d(<vscale x 16 x i1>, <vscale x 16 x i1>)\n", intrinsic, elementBits)
		}
	}
	for _, intrinsic := range []string{"punpkhi", "punpklo"} {
		fmt.Fprintf(b, "declare <vscale x 8 x i1> @llvm.aarch64.sve.%s.nxv16i1(<vscale x 16 x i1>)\n", intrinsic)
	}
	b.WriteString("declare <vscale x 16 x i1> @llvm.aarch64.sve.pfirst.nxv16i1(<vscale x 16 x i1>, <vscale x 16 x i1>)\n")
	for _, lanes := range []int{16, 8, 4, 2} {
		fmt.Fprintf(b, "declare <vscale x %d x i1> @llvm.aarch64.sve.pnext.nxv%di1(<vscale x %d x i1>, <vscale x %d x i1>)\n", lanes, lanes, lanes, lanes)
		for _, intrinsic := range []string{"firstp", "lastp"} {
			fmt.Fprintf(b, "declare i64 @llvm.aarch64.sve.%s.nxv%di1(<vscale x %d x i1>, <vscale x %d x i1>)\n", intrinsic, lanes, lanes, lanes)
		}
	}
	for _, lanes := range []int{16, 8, 4, 2} {
		bits := 128 / lanes
		fmt.Fprintf(b, "declare <vscale x %d x i1> @llvm.aarch64.sve.ptrue.nxv%di1(i32 immarg)\n", lanes, lanes)
		fmt.Fprintf(b, "declare <vscale x %d x i%d> @llvm.aarch64.sve.dupq.lane.nxv%di%d(<vscale x %d x i%d>, i64)\n", lanes, bits, lanes, bits, lanes, bits)
		for _, intrinsic := range []string{"asr", "lsl", "lsr"} {
			fmt.Fprintf(b, "declare <vscale x %d x i%d> @llvm.aarch64.sve.%s.nxv%di%d(<vscale x %d x i1>, <vscale x %d x i%d>, <vscale x %d x i%d>)\n", lanes, bits, intrinsic, lanes, bits, lanes, lanes, bits, lanes, bits)
		}
		for _, intrinsic := range []string{"suqadd", "usqadd"} {
			fmt.Fprintf(b, "declare <vscale x %d x i%d> @llvm.aarch64.sve.%s.nxv%di%d(<vscale x %d x i1>, <vscale x %d x i%d>, <vscale x %d x i%d>)\n", lanes, bits, intrinsic, lanes, bits, lanes, lanes, bits, lanes, bits)
		}
		fmt.Fprintf(b, "declare <vscale x %d x i%d> @llvm.aarch64.sve.addp.nxv%di%d(<vscale x %d x i1>, <vscale x %d x i%d>, <vscale x %d x i%d>)\n", lanes, bits, lanes, bits, lanes, lanes, bits, lanes, bits)
		if bits != 8 {
			for _, intrinsic := range []string{"sqdecp", "sqincp", "uqdecp", "uqincp"} {
				fmt.Fprintf(b, "declare <vscale x %d x i%d> @llvm.aarch64.sve.%s.nxv%di%d(<vscale x %d x i%d>, <vscale x %d x i1>)\n", lanes, bits, intrinsic, lanes, bits, lanes, bits, lanes)
			}
		}
		for _, intrinsic := range []string{"asrd", "sqshlu", "srshr", "urshr"} {
			fmt.Fprintf(b, "declare <vscale x %d x i%d> @llvm.aarch64.sve.%s.nxv%di%d(<vscale x %d x i1>, <vscale x %d x i%d>, i32 immarg)\n", lanes, bits, intrinsic, lanes, bits, lanes, lanes, bits)
		}
		for _, intrinsic := range []string{"sli", "sri", "srsra", "ssra", "ursra", "usra"} {
			fmt.Fprintf(b, "declare <vscale x %d x i%d> @llvm.aarch64.sve.%s.nxv%di%d(<vscale x %d x i%d>, <vscale x %d x i%d>, i32 immarg)\n", lanes, bits, intrinsic, lanes, bits, lanes, bits, lanes, bits)
		}
		fmt.Fprintf(b, "declare <vscale x %d x i%d> @llvm.aarch64.sve.mul.nxv%di%d(<vscale x %d x i1>, <vscale x %d x i%d>, <vscale x %d x i%d>)\n", lanes, bits, lanes, bits, lanes, lanes, bits, lanes, bits)
		for _, intrinsic := range []string{"mad", "mla", "mls", "msb"} {
			fmt.Fprintf(b, "declare <vscale x %d x i%d> @llvm.aarch64.sve.%s.nxv%di%d(<vscale x %d x i1>, <vscale x %d x i%d>, <vscale x %d x i%d>, <vscale x %d x i%d>)\n", lanes, bits, intrinsic, lanes, bits, lanes, lanes, bits, lanes, bits, lanes, bits)
		}
		for _, intrinsic := range []string{"smulh", "smulh.u", "umulh", "umulh.u"} {
			fmt.Fprintf(b, "declare <vscale x %d x i%d> @llvm.aarch64.sve.%s.nxv%di%d(<vscale x %d x i1>, <vscale x %d x i%d>, <vscale x %d x i%d>)\n", lanes, bits, intrinsic, lanes, bits, lanes, lanes, bits, lanes, bits)
		}
		for _, intrinsic := range []string{"sqshl", "uqshl", "sqrshl", "uqrshl", "srshl", "urshl"} {
			fmt.Fprintf(b, "declare <vscale x %d x i%d> @llvm.aarch64.sve.%s.nxv%di%d(<vscale x %d x i1>, <vscale x %d x i%d>, <vscale x %d x i%d>)\n", lanes, bits, intrinsic, lanes, bits, lanes, lanes, bits, lanes, bits)
		}
		for _, intrinsic := range []string{"sqdmulh", "sqrdmulh"} {
			fmt.Fprintf(b, "declare <vscale x %d x i%d> @llvm.aarch64.sve.%s.nxv%di%d(<vscale x %d x i%d>, <vscale x %d x i%d>)\n", lanes, bits, intrinsic, lanes, bits, lanes, bits, lanes, bits)
		}
		for _, intrinsic := range []string{"saba", "uaba"} {
			fmt.Fprintf(b, "declare <vscale x %d x i%d> @llvm.aarch64.sve.%s.nxv%di%d(<vscale x %d x i%d>, <vscale x %d x i%d>, <vscale x %d x i%d>)\n", lanes, bits, intrinsic, lanes, bits, lanes, bits, lanes, bits, lanes, bits)
		}
		for _, intrinsic := range []string{"sabd", "uabd"} {
			fmt.Fprintf(b, "declare <vscale x %d x i%d> @llvm.aarch64.sve.%s.nxv%di%d(<vscale x %d x i1>, <vscale x %d x i%d>, <vscale x %d x i%d>)\n", lanes, bits, intrinsic, lanes, bits, lanes, lanes, bits, lanes, bits)
		}
		for _, intrinsic := range []string{"shadd", "shsub", "shsubr", "srhadd", "uhadd", "uhsub", "uhsubr", "urhadd"} {
			fmt.Fprintf(b, "declare <vscale x %d x i%d> @llvm.aarch64.sve.%s.nxv%di%d(<vscale x %d x i1>, <vscale x %d x i%d>, <vscale x %d x i%d>)\n", lanes, bits, intrinsic, lanes, bits, lanes, lanes, bits, lanes, bits)
		}
		if bits >= 32 {
			for _, intrinsic := range []string{"sdiv", "sdivr", "udiv", "udivr"} {
				fmt.Fprintf(b, "declare <vscale x %d x i%d> @llvm.aarch64.sve.%s.nxv%di%d(<vscale x %d x i1>, <vscale x %d x i%d>, <vscale x %d x i%d>)\n", lanes, bits, intrinsic, lanes, bits, lanes, lanes, bits, lanes, bits)
			}
		}
		for _, intrinsic := range []string{"cmla", "sqrdcmlah"} {
			fmt.Fprintf(b, "declare <vscale x %d x i%d> @llvm.aarch64.sve.%s.x.nxv%di%d(<vscale x %d x i%d>, <vscale x %d x i%d>, <vscale x %d x i%d>, i32 immarg)\n", lanes, bits, intrinsic, lanes, bits, lanes, bits, lanes, bits, lanes, bits)
		}
		for _, intrinsic := range []string{"sqrdmlah", "sqrdmlsh"} {
			fmt.Fprintf(b, "declare <vscale x %d x i%d> @llvm.aarch64.sve.%s.nxv%di%d(<vscale x %d x i%d>, <vscale x %d x i%d>, <vscale x %d x i%d>)\n", lanes, bits, intrinsic, lanes, bits, lanes, bits, lanes, bits, lanes, bits)
		}
		for _, intrinsic := range []string{"smax", "smin", "umax", "umin", "smaxp", "sminp", "umaxp", "uminp"} {
			fmt.Fprintf(b, "declare <vscale x %d x i%d> @llvm.aarch64.sve.%s.nxv%di%d(<vscale x %d x i1>, <vscale x %d x i%d>, <vscale x %d x i%d>)\n", lanes, bits, intrinsic, lanes, bits, lanes, lanes, bits, lanes, bits)
		}
		for _, intrinsic := range []string{"cadd.x", "sqcadd.x"} {
			fmt.Fprintf(b, "declare <vscale x %d x i%d> @llvm.aarch64.sve.%s.nxv%di%d(<vscale x %d x i%d>, <vscale x %d x i%d>, i32 immarg)\n", lanes, bits, intrinsic, lanes, bits, lanes, bits, lanes, bits)
		}
		fmt.Fprintf(b, "declare <vscale x %d x i%d> @llvm.aarch64.sve.xar.nxv%di%d(<vscale x %d x i%d>, <vscale x %d x i%d>, i32 immarg)\n", lanes, bits, lanes, bits, lanes, bits, lanes, bits)
		if bits == 8 || bits == 16 {
			for _, intrinsic := range []string{"match", "nmatch"} {
				fmt.Fprintf(b, "declare <vscale x %d x i1> @llvm.aarch64.sve.%s.nxv%di%d(<vscale x %d x i1>, <vscale x %d x i%d>, <vscale x %d x i%d>)\n", lanes, intrinsic, lanes, bits, lanes, lanes, bits, lanes, bits)
			}
		}
		if bits == 8 {
			fmt.Fprintf(b, "declare <vscale x 16 x i8> @llvm.aarch64.sve.histseg.nxv16i8(<vscale x 16 x i8>, <vscale x 16 x i8>)\n")
		}
		if bits == 32 || bits == 64 {
			fmt.Fprintf(b, "declare <vscale x %d x i%d> @llvm.aarch64.sve.histcnt.nxv%di%d(<vscale x %d x i1>, <vscale x %d x i%d>, <vscale x %d x i%d>)\n", lanes, bits, lanes, bits, lanes, lanes, bits, lanes, bits)
		}
		for _, intrinsic := range []string{"abs", "cls", "clz", "cnot", "cnt", "neg", "not", "rbit", "revb", "revh", "revw", "sqabs", "sqneg", "sxtb", "sxth", "sxtw", "uxtb", "uxth", "uxtw", "urecpe", "ursqrte"} {
			fmt.Fprintf(b, "declare <vscale x %d x i%d> @llvm.aarch64.sve.%s.nxv%di%d(<vscale x %d x i%d>, <vscale x %d x i1>, <vscale x %d x i%d>)\n", lanes, bits, intrinsic, lanes, bits, lanes, bits, lanes, lanes, bits)
		}
		fmt.Fprintf(b, "declare <vscale x %d x i%d> @llvm.vector.reverse.nxv%di%d(<vscale x %d x i%d>)\n", lanes, bits, lanes, bits, lanes, bits)
		for _, intrinsic := range []string{"andv", "eorv", "orv", "smaxv", "sminv", "umaxv", "uminv"} {
			fmt.Fprintf(b, "declare i%d @llvm.aarch64.sve.%s.nxv%di%d(<vscale x %d x i1>, <vscale x %d x i%d>)\n", bits, intrinsic, lanes, bits, lanes, lanes, bits)
		}
		for _, intrinsic := range []string{"saddv", "uaddv"} {
			fmt.Fprintf(b, "declare i64 @llvm.aarch64.sve.%s.nxv%di%d(<vscale x %d x i1>, <vscale x %d x i%d>)\n", intrinsic, lanes, bits, lanes, lanes, bits)
		}
		for _, intrinsic := range []string{"addqv", "andqv", "eorqv", "orqv", "smaxqv", "sminqv", "umaxqv", "uminqv"} {
			fmt.Fprintf(b, "declare <%d x i%d> @llvm.aarch64.sve.%s.v%di%d.nxv%di%d(<vscale x %d x i1>, <vscale x %d x i%d>)\n", lanes, bits, intrinsic, lanes, bits, lanes, bits, lanes, lanes, bits)
		}
		fmt.Fprintf(b, "declare <vscale x %d x i%d> @llvm.aarch64.sve.tbl.nxv%di%d(<vscale x %d x i%d>, <vscale x %d x i%d>)\n", lanes, bits, lanes, bits, lanes, bits, lanes, bits)
		fmt.Fprintf(b, "declare <vscale x %d x i%d> @llvm.aarch64.sve.tbl2.nxv%di%d(<vscale x %d x i%d>, <vscale x %d x i%d>, <vscale x %d x i%d>)\n", lanes, bits, lanes, bits, lanes, bits, lanes, bits, lanes, bits)
		fmt.Fprintf(b, "declare <vscale x %d x i%d> @llvm.aarch64.sve.tblq.nxv%di%d(<vscale x %d x i%d>, <vscale x %d x i%d>)\n", lanes, bits, lanes, bits, lanes, bits, lanes, bits)
		for _, intrinsic := range []string{"tbx", "tbxq"} {
			fmt.Fprintf(b, "declare <vscale x %d x i%d> @llvm.aarch64.sve.%s.nxv%di%d(<vscale x %d x i%d>, <vscale x %d x i%d>, <vscale x %d x i%d>)\n", lanes, bits, intrinsic, lanes, bits, lanes, bits, lanes, bits, lanes, bits)
		}
		if bits != 8 {
			fmt.Fprintf(b, "declare <vscale x %d x i%d> @llvm.aarch64.sve.mul.lane.nxv%di%d(<vscale x %d x i%d>, <vscale x %d x i%d>, i32 immarg)\n", lanes, bits, lanes, bits, lanes, bits, lanes, bits)
			for _, intrinsic := range []string{"mla", "mls"} {
				fmt.Fprintf(b, "declare <vscale x %d x i%d> @llvm.aarch64.sve.%s.lane.nxv%di%d(<vscale x %d x i%d>, <vscale x %d x i%d>, <vscale x %d x i%d>, i32 immarg)\n", lanes, bits, intrinsic, lanes, bits, lanes, bits, lanes, bits, lanes, bits)
			}
			for _, intrinsic := range []string{"sqdmulh", "sqrdmulh"} {
				fmt.Fprintf(b, "declare <vscale x %d x i%d> @llvm.aarch64.sve.%s.lane.nxv%di%d(<vscale x %d x i%d>, <vscale x %d x i%d>, i32 immarg)\n", lanes, bits, intrinsic, lanes, bits, lanes, bits, lanes, bits)
			}
			if bits != 64 {
				for _, intrinsic := range []string{"cmla", "sqrdcmlah"} {
					fmt.Fprintf(b, "declare <vscale x %d x i%d> @llvm.aarch64.sve.%s.lane.x.nxv%di%d(<vscale x %d x i%d>, <vscale x %d x i%d>, <vscale x %d x i%d>, i32 immarg, i32 immarg)\n", lanes, bits, intrinsic, lanes, bits, lanes, bits, lanes, bits, lanes, bits)
				}
			}
			for _, intrinsic := range []string{"sqrdmlah", "sqrdmlsh"} {
				fmt.Fprintf(b, "declare <vscale x %d x i%d> @llvm.aarch64.sve.%s.lane.nxv%di%d(<vscale x %d x i%d>, <vscale x %d x i%d>, <vscale x %d x i%d>, i32 immarg)\n", lanes, bits, intrinsic, lanes, bits, lanes, bits, lanes, bits, lanes, bits)
			}
		}
		if bits != 64 {
			for _, intrinsic := range []string{"asr", "lsl", "lsr"} {
				fmt.Fprintf(b, "declare <vscale x %d x i%d> @llvm.aarch64.sve.%s.wide.nxv%di%d(<vscale x %d x i1>, <vscale x %d x i%d>, <vscale x 2 x i64>)\n", lanes, bits, intrinsic, lanes, bits, lanes, lanes, bits)
			}
		}
		if bits != 64 {
			for _, intrinsic := range []string{"cmpeq", "cmpge", "cmpgt", "cmphi", "cmphs", "cmpne"} {
				fmt.Fprintf(b, "declare <vscale x %d x i1> @llvm.aarch64.sve.%s.wide.nxv%di%d(<vscale x %d x i1>, <vscale x %d x i%d>, <vscale x 2 x i64>)\n", lanes, intrinsic, lanes, bits, lanes, lanes, bits)
			}
		}
		if lanes != 16 {
			fmt.Fprintf(b, "declare <vscale x 16 x i1> @llvm.aarch64.sve.convert.to.svbool.nxv%di1(<vscale x %d x i1>)\n", lanes, lanes)
			fmt.Fprintf(b, "declare <vscale x %d x i1> @llvm.aarch64.sve.convert.from.svbool.nxv%di1(<vscale x 16 x i1>)\n", lanes, lanes)
		}
	}
	for _, sourceBits := range []int{8, 16, 32} {
		sourceLanes := 128 / sourceBits
		destinationBits := sourceBits * 2
		destinationLanes := 128 / destinationBits
		for _, op := range arm64SVEMultiplyLongOps {
			spec := arm64SVEMultiplyLongSpecs[op]
			if spec.accumulate {
				fmt.Fprintf(b, "declare <vscale x %d x i%d> @llvm.aarch64.sve.%s.nxv%di%d(<vscale x %d x i%d>, <vscale x %d x i%d>, <vscale x %d x i%d>)\n", destinationLanes, destinationBits, spec.intrinsic, destinationLanes, destinationBits, destinationLanes, destinationBits, sourceLanes, sourceBits, sourceLanes, sourceBits)
			} else {
				fmt.Fprintf(b, "declare <vscale x %d x i%d> @llvm.aarch64.sve.%s.nxv%di%d(<vscale x %d x i%d>, <vscale x %d x i%d>)\n", destinationLanes, destinationBits, spec.intrinsic, destinationLanes, destinationBits, sourceLanes, sourceBits, sourceLanes, sourceBits)
			}
		}
		for _, op := range arm64SVEMultiplyAccumulateLongOpsBySelector {
			intrinsic := arm64SVEMultiplyAccumulateLongIntrinsics[op]
			fmt.Fprintf(b, "declare <vscale x %d x i%d> @llvm.aarch64.sve.%s.nxv%di%d(<vscale x %d x i%d>, <vscale x %d x i%d>, <vscale x %d x i%d>)\n", destinationLanes, destinationBits, intrinsic, destinationLanes, destinationBits, destinationLanes, destinationBits, sourceLanes, sourceBits, sourceLanes, sourceBits)
		}
		if sourceBits != 8 {
			for _, op := range arm64SVEMultiplyLongOps {
				spec := arm64SVEMultiplyLongSpecs[op]
				if spec.laneHBase == 0 {
					continue
				}
				if spec.accumulate {
					fmt.Fprintf(b, "declare <vscale x %d x i%d> @llvm.aarch64.sve.%s.lane.nxv%di%d(<vscale x %d x i%d>, <vscale x %d x i%d>, <vscale x %d x i%d>, i32 immarg)\n", destinationLanes, destinationBits, spec.intrinsic, destinationLanes, destinationBits, destinationLanes, destinationBits, sourceLanes, sourceBits, sourceLanes, sourceBits)
				} else {
					fmt.Fprintf(b, "declare <vscale x %d x i%d> @llvm.aarch64.sve.%s.lane.nxv%di%d(<vscale x %d x i%d>, <vscale x %d x i%d>, i32 immarg)\n", destinationLanes, destinationBits, spec.intrinsic, destinationLanes, destinationBits, sourceLanes, sourceBits, sourceLanes, sourceBits)
				}
			}
			for _, op := range arm64SVEMultiplyAccumulateLongOpsBySelector {
				intrinsic := arm64SVEMultiplyAccumulateLongIntrinsics[op]
				fmt.Fprintf(b, "declare <vscale x %d x i%d> @llvm.aarch64.sve.%s.lane.nxv%di%d(<vscale x %d x i%d>, <vscale x %d x i%d>, <vscale x %d x i%d>, i32 immarg)\n", destinationLanes, destinationBits, intrinsic, destinationLanes, destinationBits, destinationLanes, destinationBits, sourceLanes, sourceBits, sourceLanes, sourceBits)
			}
		}
	}
	for _, elementBits := range []int{8, 16, 32, 64} {
		lanes := 128 / elementBits
		for _, op := range arm64SVEPermuteOpsByIndex {
			intrinsic := arm64SVEPermuteIntrinsics[op]
			fmt.Fprintf(b, "declare <vscale x %d x i%d> @llvm.aarch64.sve.%s.nxv%di%d(<vscale x %d x i%d>, <vscale x %d x i%d>)\n", lanes, elementBits, intrinsic, lanes, elementBits, lanes, elementBits, lanes, elementBits)
		}
		for _, op := range arm64SVEQPermuteOpsByIndex {
			intrinsic := arm64SVEPermuteIntrinsics[op]
			fmt.Fprintf(b, "declare <vscale x %d x i%d> @llvm.aarch64.sve.%s.nxv%di%d(<vscale x %d x i%d>, <vscale x %d x i%d>)\n", lanes, elementBits, intrinsic, lanes, elementBits, lanes, elementBits, lanes, elementBits)
		}
	}
	for _, elementBits := range []int{16, 32, 64} {
		lanes := 128 / elementBits
		scalarType := map[int]string{16: "half", 32: "float", 64: "double"}[elementBits]
		vectorType := fmt.Sprintf("<vscale x %d x %s>", lanes, scalarType)
		predicateType := fmt.Sprintf("<vscale x %d x i1>", lanes)
		mangle := fmt.Sprintf("nxv%d%s", lanes, map[int]string{16: "f16", 32: "f32", 64: "f64"}[elementBits])
		for _, intrinsic := range []string{"fabd", "faddp", "famax", "famin", "fmax", "fmin", "fmaxnm", "fminnm", "fmaxp", "fminp", "fmaxnmp", "fminnmp"} {
			fmt.Fprintf(b, "declare %s @llvm.aarch64.sve.%s.%s(%s, %s, %s)\n", vectorType, intrinsic, mangle, predicateType, vectorType, vectorType)
		}
		for _, intrinsic := range []string{"fmaxv", "fminv", "fmaxnmv", "fminnmv"} {
			fmt.Fprintf(b, "declare %s @llvm.aarch64.sve.%s.%s(%s, %s)\n", scalarType, intrinsic, mangle, predicateType, vectorType)
		}
		fmt.Fprintf(b, "declare %s @llvm.aarch64.sve.fadda.%s(%s, %s, %s)\n", scalarType, mangle, predicateType, scalarType, vectorType)
		fmt.Fprintf(b, "declare %s @llvm.aarch64.sve.faddv.%s(%s, %s)\n", scalarType, mangle, predicateType, vectorType)
		for _, intrinsic := range []string{"faddqv", "fmaxqv", "fminqv", "fmaxnmqv", "fminnmqv"} {
			fmt.Fprintf(b, "declare <%d x %s> @llvm.aarch64.sve.%s.v%d%s.%s(%s, %s)\n", lanes, scalarType, intrinsic, lanes, map[int]string{16: "f16", 32: "f32", 64: "f64"}[elementBits], mangle, predicateType, vectorType)
		}
		for _, intrinsic := range []string{"fabs", "fneg", "frecpx", "frint32x", "frint32z", "frint64x", "frint64z", "frinta", "frinti", "frintm", "frintn", "frintp", "frintx", "frintz", "fsqrt"} {
			fmt.Fprintf(b, "declare %s @llvm.aarch64.sve.%s.%s(%s, %s, %s)\n", vectorType, intrinsic, mangle, vectorType, predicateType, vectorType)
		}
		for _, intrinsic := range []string{"frecpe.x", "frsqrte.x"} {
			fmt.Fprintf(b, "declare %s @llvm.aarch64.sve.%s.%s(%s)\n", vectorType, intrinsic, mangle, vectorType)
		}
		fmt.Fprintf(b, "declare %s @llvm.aarch64.sve.fexpa.x.%s(<vscale x %d x i%d>)\n", vectorType, mangle, lanes, elementBits)
		fmt.Fprintf(b, "declare <vscale x %d x i%d> @llvm.aarch64.sve.flogb.%s(<vscale x %d x i%d>, %s, %s)\n", lanes, elementBits, mangle, lanes, elementBits, predicateType, vectorType)
		for _, intrinsic := range []string{"fdiv", "fdivr"} {
			fmt.Fprintf(b, "declare %s @llvm.aarch64.sve.%s.%s(%s, %s, %s)\n", vectorType, intrinsic, mangle, predicateType, vectorType, vectorType)
		}
		fmt.Fprintf(b, "declare %s @llvm.aarch64.sve.fscale.%s(%s, %s, <vscale x %d x i%d>)\n", vectorType, mangle, predicateType, vectorType, lanes, elementBits)
		fmt.Fprintf(b, "declare %s @llvm.aarch64.sve.fcadd.%s(%s, %s, %s, i32 immarg)\n", vectorType, mangle, predicateType, vectorType, vectorType)
		for _, intrinsic := range []string{"frecps.x", "frsqrts.x"} {
			fmt.Fprintf(b, "declare %s @llvm.aarch64.sve.%s.%s(%s, %s)\n", vectorType, intrinsic, mangle, vectorType, vectorType)
		}
		for _, intrinsic := range []string{"rint", "trunc"} {
			fmt.Fprintf(b, "declare %s @llvm.%s.%s(%s)\n", vectorType, intrinsic, mangle, vectorType)
		}
		if elementBits != 16 {
			for _, integerBits := range []int{32, 64} {
				fmt.Fprintf(b, "declare <vscale x %d x i%d> @llvm.fptosi.sat.nxv%di%d.%s(%s)\n", lanes, integerBits, lanes, integerBits, mangle, vectorType)
			}
		}
	}
	for _, op := range arm64SVEPermuteOpsByIndex {
		intrinsic := arm64SVEPermuteIntrinsics[op] + "q"
		fmt.Fprintf(b, "declare <vscale x 2 x i64> @llvm.aarch64.sve.%s.nxv2i64(<vscale x 2 x i64>, <vscale x 2 x i64>)\n", intrinsic)
	}
	b.WriteString("declare float @llvm.sqrt.f32(float)\n")
	b.WriteString("declare double @llvm.sqrt.f64(double)\n")
	b.WriteString("declare float @llvm.fma.f32(float, float, float)\n")
	b.WriteString("declare double @llvm.fma.f64(double, double, double)\n")
	b.WriteString("declare half @llvm.fma.f16(half, half, half)\n")
	for _, intrinsic := range []string{"fabs", "roundeven", "ceil", "floor", "trunc", "round", "rint", "nearbyint"} {
		b.WriteString("declare float @llvm." + intrinsic + ".f32(float)\n")
		b.WriteString("declare double @llvm." + intrinsic + ".f64(double)\n")
	}
	b.WriteString("declare <2 x float> @llvm.fma.v2f32(<2 x float>, <2 x float>, <2 x float>)\n")
	b.WriteString("declare <4 x float> @llvm.fma.v4f32(<4 x float>, <4 x float>, <4 x float>)\n")
	b.WriteString("declare <2 x double> @llvm.fma.v2f64(<2 x double>, <2 x double>, <2 x double>)\n")
	b.WriteString("declare <4 x half> @llvm.fma.v4f16(<4 x half>, <4 x half>, <4 x half>)\n")
	b.WriteString("declare <8 x half> @llvm.fma.v8f16(<8 x half>, <8 x half>, <8 x half>)\n")
	for _, intrinsic := range []string{"fabs", "sqrt", "roundeven", "round", "rint", "nearbyint", "ceil", "floor", "trunc"} {
		b.WriteString("declare <4 x half> @llvm." + intrinsic + ".v4f16(<4 x half>)\n")
		b.WriteString("declare <8 x half> @llvm." + intrinsic + ".v8f16(<8 x half>)\n")
		b.WriteString("declare <2 x float> @llvm." + intrinsic + ".v2f32(<2 x float>)\n")
		b.WriteString("declare <4 x float> @llvm." + intrinsic + ".v4f32(<4 x float>)\n")
		b.WriteString("declare <2 x double> @llvm." + intrinsic + ".v2f64(<2 x double>)\n")
	}
	for _, intrinsic := range []string{"fptosi.sat", "fptoui.sat"} {
		for _, destination := range []string{"i32", "i64"} {
			b.WriteString("declare " + destination + " @llvm." + intrinsic + "." + destination + ".f32(float)\n")
			b.WriteString("declare " + destination + " @llvm." + intrinsic + "." + destination + ".f64(double)\n")
		}
		b.WriteString("declare <2 x i32> @llvm." + intrinsic + ".v2i32.v2f32(<2 x float>)\n")
		b.WriteString("declare <4 x i32> @llvm." + intrinsic + ".v4i32.v4f32(<4 x float>)\n")
		b.WriteString("declare <2 x i64> @llvm." + intrinsic + ".v2i64.v2f64(<2 x double>)\n")
	}
	for _, intrinsic := range []string{"maximum", "minimum", "maxnum", "minnum"} {
		b.WriteString("declare half @llvm." + intrinsic + ".f16(half, half)\n")
		b.WriteString("declare float @llvm." + intrinsic + ".f32(float, float)\n")
		b.WriteString("declare double @llvm." + intrinsic + ".f64(double, double)\n")
		b.WriteString("declare <4 x half> @llvm." + intrinsic + ".v4f16(<4 x half>, <4 x half>)\n")
		b.WriteString("declare <8 x half> @llvm." + intrinsic + ".v8f16(<8 x half>, <8 x half>)\n")
		b.WriteString("declare <2 x float> @llvm." + intrinsic + ".v2f32(<2 x float>, <2 x float>)\n")
		b.WriteString("declare <4 x float> @llvm." + intrinsic + ".v4f32(<4 x float>, <4 x float>)\n")
		b.WriteString("declare <2 x double> @llvm." + intrinsic + ".v2f64(<2 x double>, <2 x double>)\n")
	}
	for _, intrinsic := range []string{"sadd.sat", "uadd.sat", "ssub.sat", "usub.sat"} {
		for _, vector := range []struct {
			lanes int
			bits  int
		}{
			{8, 8}, {16, 8}, {4, 16}, {8, 16}, {2, 32}, {4, 32}, {2, 64},
		} {
			vectorType := fmt.Sprintf("<%d x i%d>", vector.lanes, vector.bits)
			fmt.Fprintf(b, "declare %s @llvm.%s.v%di%d(%s, %s)\n", vectorType, intrinsic, vector.lanes, vector.bits, vectorType, vectorType)
		}
	}
	for _, intrinsic := range []string{"sqadd.x", "uqadd.x", "sqsub.x", "uqsub.x"} {
		for _, bits := range []int{8, 16, 32, 64} {
			lanes := 128 / bits
			vectorType := fmt.Sprintf("<vscale x %d x i%d>", lanes, bits)
			fmt.Fprintf(b, "declare %s @llvm.aarch64.sve.%s.nxv%di%d(%s, %s)\n", vectorType, intrinsic, lanes, bits, vectorType, vectorType)
		}
	}
	// AArch64 CRC32 and CRC32C intrinsics.
	// Note: B/H forms take the data operand as i32 (low bits used).
	b.WriteString("declare i32 @llvm.aarch64.crc32b(i32, i32)\n")
	b.WriteString("declare i32 @llvm.aarch64.crc32h(i32, i32)\n")
	b.WriteString("declare i32 @llvm.aarch64.crc32w(i32, i32)\n")
	b.WriteString("declare i32 @llvm.aarch64.crc32x(i32, i64)\n")
	b.WriteString("declare i32 @llvm.aarch64.crc32cb(i32, i32)\n")
	b.WriteString("declare i32 @llvm.aarch64.crc32ch(i32, i32)\n")
	b.WriteString("declare i32 @llvm.aarch64.crc32cw(i32, i32)\n")
	b.WriteString("declare i32 @llvm.aarch64.crc32cx(i32, i64)\n")
	b.WriteString("\n")
	// Attribute group used by some functions to enable optional ISA features.
	// (Example: "+crc" for hash/crc32 arm64 fast paths.)
	b.WriteString("\n")
}

func translateFuncARM64(b *strings.Builder, fn Func, sig FuncSig, resolve func(string) string, sigs map[string]FuncSig, annotateSource bool) error {
	var err error
	var rawData []arm64RawDataBlob
	fn, rawData, err = prepareARM64RawPCRelativeWithReturnClobbers(fn, arm64RawPoolReturnClobbers(fn, sig))
	if err != nil {
		return err
	}
	rawDataGlobals := make(map[string]string, len(rawData))
	rawDataOffsets := make(map[string]int64)
	for _, data := range rawData {
		name := sig.Name + "." + data.label + ".raw_data"
		rawDataGlobals[data.label] = name
		for label, offset := range data.aliases {
			rawDataGlobals[label] = name
			rawDataOffsets[label] = offset
		}
		fmt.Fprintf(b, "%s = private constant [%d x i8] %s, align %d\n", llvmGlobal(name), len(data.bytes), llvmI8ArrayInit(data.bytes), bestAlign(int64(len(data.bytes))))
	}
	if len(rawData) != 0 {
		b.WriteString("\n")
	}
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

	c := newARM64Ctx(b, fn, sig, resolve, sigs, annotateSource)
	c.rawDataGlobals = rawDataGlobals
	c.rawDataOffsets = rawDataOffsets
	if err := c.emitEntryAllocasAndArgInit(); err != nil {
		return err
	}
	fmt.Fprintf(b, "  br label %%%s\n", arm64LLVMBlockName(c.blocks[0].name))
	if err := c.lowerBlocks(); err != nil {
		return err
	}

	b.WriteString("}\n")
	return nil
}

func (c *arm64Ctx) lowerBlocks() error {
	c.flagFlow = newARM64FlagFlow(c.blocks)
	defer func() { c.flagFlow = nil }()
	emitBr := func(target string) {
		c.recordARM64FlagFlowEdges(target)
		fmt.Fprintf(c.b, "  br label %%%s\n", arm64LLVMBlockName(target))
	}
	emitCondBr := func(cond string, target string, fall string) error {
		cv, err := c.condValue(cond)
		if err != nil {
			return err
		}
		c.emitPredicateBranch(cv, target, fall)
		return nil
	}

	for bi := 0; bi < len(c.blocks); bi++ {
		blk := c.blocks[bi]
		c.flagFlow.current = bi
		c.flagsWritten = false
		fmt.Fprintf(c.b, "\n%s:\n", arm64LLVMBlockName(blk.name))

		terminated := false
		for _, ins := range blk.instrs {
			c.emitSourceComment(ins)
			term, err := c.lowerInstr(bi, ins, emitBr, emitCondBr)
			if err != nil {
				return err
			}
			if term {
				terminated = true
				break
			}
		}
		c.flagFlow.blocks[bi].writes = c.flagsWritten

		if terminated {
			continue
		}
		// Fallthrough to next block.
		if bi+1 < len(c.blocks) {
			emitBr(c.blocks[bi+1].name)
			continue
		}
		// Last block: implicit return zero.
		c.lowerRetZero()
	}
	return c.flagFlow.validate()
}

func (c *arm64Ctx) lowerInstr(bi int, ins Instr, emitBr arm64EmitBr, emitCondBr arm64EmitCondBr) (terminated bool, err error) {
	rawOp := strings.ToUpper(string(ins.Op))
	postInc := strings.Contains(rawOp, ".P")
	baseOp := rawOp
	if dot := strings.IndexByte(baseOp, '.'); dot >= 0 {
		baseOp = baseOp[:dot]
	}
	op := Op(baseOp)
	switch op {
	case OpTEXT:
		return false, nil
	case OpBYTE:
		return false, fmt.Errorf("arm64 BYTE cannot be lowered safely as a partial machine instruction: %q", ins.Raw)
	case OpRET:
		if c.flagFlow != nil {
			c.flagFlow.blocks[c.flagFlow.current].returns = true
		}
		if len(ins.Args) == 1 && ins.Args[0].Kind == OpSym && strings.HasSuffix(ins.Args[0].Sym, "(SB)") {
			return true, c.tailCallAndRet(ins.Args[0])
		}
		if len(ins.Args) > 1 {
			return true, fmt.Errorf("arm64 RET expects at most 1 operand: %q", ins.Raw)
		}
		return true, c.lowerRET()
	case OpWORD:
		rawErr := c.lowerRawWord(ins)
		if rawErr == nil {
			return false, nil
		} else if !strings.Contains(rawErr.Error(), "unsupported ARM64 WORD encoding") {
			return false, rawErr
		}
		decoded, err := decodeARM64RawWordInstruction(ins)
		if err != nil {
			if strings.Contains(err.Error(), "PC-relative") {
				return false, err
			}
			return false, rawErr
		}
		return c.lowerInstr(bi, decoded, emitBr, emitCondBr)
	case arm64RawDataOp:
		return false, nil
	case "END":
		// Go's assembler end-of-file directive emits no instruction.
		return false, nil
	case "PCALIGN", "NO_LOCAL_POINTERS", "PCDATA", "FUNCDATA":
		return false, nil
	}
	if ok, term, err := c.lowerARM64Barrier(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64CacheMaintenance(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SYS(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64TLBI(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64Prefetch(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64Exception(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64Hint(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEAddress(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEAddressGeneration(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVECnt(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEDupImmediate(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEAdd(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEAddSub(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEFloatAddSub(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEFloatMultiply(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEFloatMultiplyExtended(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEFloatTrigMultiply(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEFloatTrigMultiplyAdd(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEFloatComplexMultiplyAccumulate(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEFloatMultiplyAccumulate(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEMultiplyAccumulate(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEBFDOT(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEIntegerDot(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEAESMix(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEAESRound(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEOptionalCrypto(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVERevd(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEPMUL(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEPMULL(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEPMULLPair(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVESaturatingMultiplyHigh(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEComplexMultiplyAccumulate(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEComplexAdd(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEXAR(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVESaturatingRoundingMultiplyAccumulateHigh(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEFloatMinMax(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEFloatPredicatedPairwise(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEFloatReciprocalStep(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEFloatExponent(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEFloatImmediate(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEFloatDivideScale(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEMixedSaturatingAdd(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEFloatComplexAdd(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEDupW(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEDupQ(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEDupM(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEFDOT(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVECDOT(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVELUTI(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEWideningFloatMLA(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEMultiNarrow(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEFloatNarrowConversion(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEBFloatArithmetic(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEBFloatMLA(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEFloatUnary(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEIntegerUnary(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEPredicateLogical(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEPredicateBreak(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEPredicatePermute(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEPredicateState(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEPredicateIterate(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEPredicatePosition(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEPredicateCounter(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEPredicateWhile(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEPredicateIncDec(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEPredicateMemory(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEWholeVectorMemory(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEVectorPrefetch(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVENonTemporalMemory(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEOrdinaryMemory(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEStructuredMemory(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEFirstFaultMemory(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVENonFaultingMemory(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEReplicateMemory(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64CTERM(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEPMOV(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEIndex(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEInsert(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVELast(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVECLast(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVECompact(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEExpand(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEMOVPRFX(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEEXT(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVESplice(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVECopy(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEConvert(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVECompare(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVECharacterMatch(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEHistogram(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEMinMax(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEIntegerReduction(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEAddReduction(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEWideningAddSub(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEShiftLong(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEAbsoluteDifference(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEHalvingAddSub(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEDivide(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVETernaryBitwise(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEEORInterleave(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEBitPermute(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVECarryLong(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEClamp(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEUnpack(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVESaturatingNarrow(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEShiftNarrow(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVESaturatingShiftNarrow(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVELSR(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEExtraShift(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEMatrixMultiply(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEPairwiseTail(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEMultiplyAddTail(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEVectorPredicateIncDec(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVESelect(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEMultiply(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEMultiplyHigh(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVESaturatingShift(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEEOR(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVETable(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVETableExtension(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEUMULLB(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEMultiplyAccumulateLong(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerARM64SVEPermute(op, ins); ok {
		return term, err
	}

	if ok, term, err := c.lowerPCRelativeAddress(bi, op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerData(op, postInc, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerAtomic(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerVec(op, postInc, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerArith(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerFP(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerSyscall(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerCond(op, ins); ok {
		return term, err
	}
	if ok, term, err := c.lowerBranch(bi, op, ins, emitBr, emitCondBr); ok {
		return term, err
	}
	return false, fmt.Errorf("arm64: unsupported instruction %s", ins.Op)
}

func (c *arm64Ctx) lowerRET() error {
	// Prefer classic Go asm return slots if present; many stdlib asm functions
	// never materialize the return value in R0 and only store to ret+off(FP).
	if len(c.fpResults) == 0 {
		if c.sig.Ret == Void {
			c.b.WriteString("  ret void\n")
			return nil
		}
		cursor := arm64ABIRegisterCursor{}
		if fields, aggregate := parseLiteralStructFields(c.sig.Ret); aggregate {
			result := "undef"
			for fieldIndex, fieldType := range fields {
				reg, err := cursor.next(fieldType)
				if err != nil {
					return fmt.Errorf("arm64 RET result field %d: %w", fieldIndex, err)
				}
				value, err := c.loadABIRegisterValue(reg, fieldType)
				if err != nil {
					return err
				}
				inserted := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = insertvalue %s %s, %s %s, %d\n", inserted, c.sig.Ret, result, fieldType, value, fieldIndex)
				result = "%" + inserted
			}
			fmt.Fprintf(c.b, "  ret %s %s\n", c.sig.Ret, result)
			return nil
		}
		reg, err := cursor.next(c.sig.Ret)
		if err != nil {
			return fmt.Errorf("arm64 RET unsupported register result type %s", c.sig.Ret)
		}
		value, err := c.loadABIRegisterValue(reg, c.sig.Ret)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  ret %s %s\n", c.sig.Ret, value)
		return nil
	}

	// Return from stored result slots when they are explicitly written
	// (or their addresses escape). Otherwise fall back to register returns.
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

	// Aggregate return.
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

func (c *arm64Ctx) lowerRetZero() {
	switch c.sig.Ret {
	case Void:
		c.b.WriteString("  ret void\n")
	default:
		fmt.Fprintf(c.b, "  ret %s %s\n", c.sig.Ret, llvmZeroValue(c.sig.Ret))
	}
}
