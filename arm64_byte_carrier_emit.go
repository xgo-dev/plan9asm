package plan9asm

import (
	"fmt"
	"strings"
)

type arm64ByteCarrierEmitter struct {
	output *strings.Builder
	next   int
}

func (emitter *arm64ByteCarrierEmitter) temporary() string {
	emitter.next++
	return fmt.Sprintf("%%carrier%d", emitter.next)
}

func (emitter *arm64ByteCarrierEmitter) pointer(root string, offset int64) string {
	name := emitter.temporary()
	fmt.Fprintf(emitter.output, "  %s = getelementptr inbounds i8, ptr %s, i64 %d\n", name, root, offset)
	return name
}

func (emitter *arm64ByteCarrierEmitter) load(root string, offset, bytes int64, signed bool) string {
	address, value := emitter.pointer(root, offset), emitter.temporary()
	fmt.Fprintf(emitter.output, "  %s = load volatile i%d, ptr %s, align 1\n", value, bytes*8, address)
	if bytes < 8 {
		wide, operation := emitter.temporary(), "zext"
		if signed {
			operation = "sext"
		}
		fmt.Fprintf(emitter.output, "  %s = %s i%d %s to i64\n", wide, operation, bytes*8, value)
		return wide
	}
	return value
}

func (emitter *arm64ByteCarrierEmitter) store(root string, offset, bytes int64, value string) {
	address := emitter.pointer(root, offset)
	if bytes < 8 {
		narrow := emitter.temporary()
		fmt.Fprintf(emitter.output, "  %s = trunc i64 %s to i%d\n", narrow, value, bytes*8)
		value = narrow
	}
	fmt.Fprintf(emitter.output, "  store volatile i%d %s, ptr %s, align 1\n", bytes*8, value, address)
}

func (binding *arm64ByteCarrierBinding) emitIR() (string, error) {
	var output strings.Builder
	fmt.Fprintf(&output, "target triple = %q\n\n", binding.options.TargetTriple)
	for _, source := range binding.file.Funcs {
		if err := binding.source.liveCarrier(); err != nil {
			return "", err
		}
		function := binding.functions[binding.symbols[source.Sym]]
		if !function.proved {
			return "", arm64ByteCarrierContext("missing complete native/defined-byte proof")
		}
		emitter := arm64ByteCarrierEmitter{output: &output}
		fmt.Fprintf(&output, "define internal i64 %s(ptr %%incoming) {\nentry:\n", llvmGlobal(function.privateName))
		if function.allocation != 0 {
			fmt.Fprintf(&output, "  %%outgoing = alloca [%d x i8], align 1\n", function.allocation-16)
		}
		registers := map[Reg]string{ZR: "0"}
		for _, operation := range function.operations {
			if err := binding.source.liveCarrier(); err != nil {
				return "", err
			}
			root := "%outgoing"
			if operation.incoming {
				root = "%incoming"
			}
			switch operation.kind {
			case "constant":
				if operation.register != ZR {
					registers[operation.register] = fmt.Sprintf("%d", operation.constant)
				}
			case "move":
				if operation.register != ZR {
					registers[operation.register] = registers[operation.from]
				}
			case "load":
				value := emitter.load(root, operation.offset, operation.bytes, operation.signed)
				if operation.register != ZR {
					registers[operation.register] = value
				}
			case "store":
				emitter.store(root, operation.offset, operation.bytes, registers[operation.register])
			case "call":
				callee, value := binding.functions[operation.callee], emitter.temporary()
				// This is the same existing outgoing root, not a return-field
				// alloca or a fresh cell. The complete proof retains full R0.
				fmt.Fprintf(&output, "  %s = call i64 %s(ptr %%outgoing)\n", value, llvmGlobal(callee.privateName))
				registers["R0"] = value
			case "return":
				fmt.Fprintf(&output, "  ret i64 %s\n", registers["R0"])
			}
		}
		output.WriteString("}\n\n")
		if err := binding.emitTypedAdapter(&output, function); err != nil {
			return "", err
		}
	}
	return output.String(), nil
}

func (binding *arm64ByteCarrierBinding) emitTypedAdapter(output *strings.Builder, function *arm64ByteCarrierFunction) error {
	if err := binding.source.liveCarrier(); err != nil {
		return err
	}
	signature := function.signature
	emitter := arm64ByteCarrierEmitter{output: output}
	fmt.Fprintf(output, "define %s %s(", signature.Ret, llvmGlobal(signature.Name))
	for index, argument := range signature.Args {
		if index != 0 {
			output.WriteString(", ")
		}
		fmt.Fprintf(output, "%s %%arg%d", argument, index)
	}
	output.WriteString(") {\nentry:\n")
	// Actual complete compiler wrapper allocation, not rounded ArgWidth.
	fmt.Fprintf(output, "  %%carrier = alloca [%d x i8], align 1\n", function.entry.dataBytes)
	for _, parameter := range signature.Frame.Params {
		address := emitter.pointer("%carrier", parameter.Offset)
		fmt.Fprintf(output, "  store volatile %s %%arg%d, ptr %s, align 1\n", parameter.Type, parameter.Index, address)
	}
	fmt.Fprintf(output, "  %%post_r0 = call i64 %s(ptr %%carrier)\n", llvmGlobal(function.privateName))
	_, aggregate := parseLiteralStructFields(signature.Ret)
	result := "poison"
	for _, field := range signature.Frame.Results {
		value := emitter.load("%carrier", field.Offset, frameTypeSize(field.Type, 8), false)
		if field.Type != I64 {
			narrow := emitter.temporary()
			fmt.Fprintf(output, "  %s = trunc i64 %s to %s\n", narrow, value, field.Type)
			value = narrow
		}
		if aggregate {
			inserted := emitter.temporary()
			fmt.Fprintf(output, "  %s = insertvalue %s %s, %s %s, %d\n", inserted, signature.Ret, result, field.Type, value, field.Index)
			result = inserted
		} else {
			result = value
		}
	}
	fmt.Fprintf(output, "  ret %s %s\n}\n\n", signature.Ret, result)
	return nil
}
