# Reflect's dynamic assembly entries

This is a missing physical-entry contract, not permission to extend an ordinary
zero-argument `FuncSig.Frame`. The original `reflect/asm_{386,amd64,arm}.s`
files remain translation failures. No corpus, benchmark, CI or ledger result is
upgraded by the contract regression described below.

## Independent source and object evidence

In the selected Go toolchain, `reflect/makefunc.go` declares `makeFuncStub()`
and `methodValueCall()` with no parameters or results. `MakeFunc` installs
`abi.FuncPCABI0(makeFuncStub)` in a function value whose *actual* argument and
result layout comes from `funcLayout(ftyp, nil)`. A method value follows the
same construction. The closure context supplies the type, stack map and
argument length; none is a third explicit Go parameter.

The original TEXT declarations deliberately omit their argument size. Go's
assembler objects record `internal/abi.ArgsSizeUnknown`, not zero. The runtime
handles these entries specially in `runtime/stkframe.go`: it obtains the dynamic
argument bitmap and length from the saved closure and uses `retValid` to decide
whether the result region is initialized. `NO_LOCAL_POINTERS` is explicitly
described as a lie in the amd64 source: its local `abi.RegArgs` needs special
runtime stack-object handling.

The source contract is larger than `argframe+0(FP)`:

| Architecture | Incoming context | Argument/result state | Original locals |
| --- | --- | --- | --- |
| 386 | DX | Dynamic caller stack frame | Outgoing helper arguments and retValid |
| amd64 | DX | Caller frame plus AX/BX/CX/DI/SI/R8–R11 and X0–X14 | retValid and abi.RegArgs |
| arm | R7 | Dynamic caller stack frame | Outgoing helper arguments and retValid |

On amd64, `runtime.spillArgs` and `runtime.unspillArgs` use R12 for their
`abi.RegArgs` pointer and preserve/restore a *whole register bank*. The empty
Go declaration of a helper is not evidence for a plain `call void helper()`.
The normal `callReflect`/`callMethod` declarations are typed, but their pointer
parameters still require distinct region, lifetime and memory-effect proofs.

## Reproduce the boundary

After selecting current Go 1.27 and LLVM 22 as documented in [validation](validation.md):

```sh
(cd cmd/plan9asmll && go test . \
  -run '^TestReflectDynamicStubNativeObjectsRetainContext$' -count=1 -v)

go test . -run '^(TestX86LEAFPAddressesRequireBoundStorage|TestX86LEAFPAddressCannotInventScalarBacking|TestTranslateARMFPAddressesTypedStorageLLVM22Objects)$' \
  -count=1 -v
```

The first test loads actual selected Go declarations, derives the full typed
`go_asm.h`, obtains `symabis` from the original assembly, and feeds those ABI0
definitions to the real Go compiler's `-asmhdr`. Every header definition must
match. It then assembles each original source to a nonempty Go object and checks
the native `ArgsSizeUnknown` metadata for both entries. It requires isolated and
whole-file LLVM translation to retain `ErrProbeNeedsContext`, with no output IR
or source-N/A conversion. This is a passing *guard test*, not successful
translation of reflect. The second command exercises real bound FP positives
and LLVM 22 objects independently; it does not supply the missing dynamic entry.

LLGo replaces its reflect package (`runtime/build.go`, `altPkgReplace`) and
implements dynamic functions through its provider/FFI bridge
(`runtime/internal/lib/reflect/makefunc*.go`). That replacement does not consume
these gc assembly entries and cannot establish their translation coverage.

## Proposed next layer, not implemented

Start with one architecture, not a name-triggered cross-architecture special
case. A possible x86 physical-entry option would be address-only, like the
existing explicit `ARMMachineEntry`, with an internal typed state carrier.
The native shim must capture incoming SP/continuation, DX, GP/FP registers and
the real caller-frame base before any LLVM prologue. An ordinary LLVM argument
list or a fabricated `argframe` alloca cannot replace that capture.

Keep source local backing and private carrier storage distinct from the borrowed
caller frame. Preserve every original instruction and PC ordinal. An explicit
caller bridge must supply the dynamic frame extent/lifetime and closure layout;
reject missing, inconsistent or escaping context. Ordinary FP lookups retain
their existing slot and span checks. The private carrier must not be writable
through source pointers or arbitrary callees.

The amd64 spill/unspill family needs an explicit shared-state call contract,
checked against the actual source's register reads/writes and RegArgs layout.
Typed Go declarations alone do not describe this family. `callReflect` and
`callMethod` require bounded effects on caller arguments/results, retValid and
RegArgs, with an actual callee/ABI bridge rather than guessed native register
arguments. Unknown helper, indirect call, frame escape or continuation fails
closed.

Object acceptance alone leaves GC, stack relocation, panic/recover wrappers
and native unwind unresolved. A replay harness with independent typed C helpers
can prove caller-frame/register transport but cannot prove gc's special stack
maps. Binding the real Go runtime requires a separate source-derived roots and
stack-map contract; the LLGo FFI replacement is a different implementation.
Neither must be silently claimed by the other.

The first implementation batch should therefore cover one x86 carrier/shim,
explicit bounded frame and helper contracts, source replay plus a real caller
bridge, and positive/negative LLVM 22 objects on that architecture's supported
targets. Add independent runtime register/frame oracles where authorized.
Mixed integer/float/stack arguments, multiple results, closure distinction,
GC-visible pointers, conditional/helper effects and unknown-contract rejection
are required before expanding to reflect runtime claims or other architectures.
