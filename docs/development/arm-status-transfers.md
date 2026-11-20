# ARM status transfer boundary

Go's ARM `asm5` types 35/36/37 encode `MOVW{cond} CPSR,Rn`,
`MOVW{cond} Rn,CPSR`, and rotated-eight-bit immediate writes. The write
field mask is `fs` (`0xc`), not `fsxc`. The source frontend excludes the
`SPSR` register spelling; `checkSuffix` rejects `.S/.P/.W/.U/.F` for these
forms, even though an internal encoder branch mentions `.F`.

The shared typed grammar covers source spelling and A32 MRS/MSR encodings.
Raw writes to CPSR `f` and `fs` preserve their distinct fields. Source and
raw predicates use the same source NZCV state, not LLVM's incidental flags.
Uninitialized saved status, a conditionally defined GP value, PC operands,
SPSR, and other CPSR field masks fail closed. Unknown bare status/value names
cannot become a literal zero. Invalid source operands are checked even in
source-dead blocks; dead writers never prove live flags.

`arm_status_move_test.go` checks actual Go accepted/rejected forms, Go object
bytes against LLVM22 MC, and LLVM22 objects for ARMv5 Linux, ARMv7 Linux, and
Windows Thumb. `TestCrossLinuxRuntimeMatrixARMStatusSaveRestore` independently
executes native Go and LLVM22/GCC ARM objects under QEMU: 2048 NZCV/Q/GE and
selector inputs across 105 source/raw conditional lanes. SPSR is encoded by
the independent LLVM MC oracle but is never executed in user mode.

```sh
go test . -run 'TestARMStatusMove|TestARMPreemptOriginalSource' -count=1
PLAN9ASM_CROSS_EXEC=1 go test . \
  -run TestCrossLinuxRuntimeMatrixARMStatusSaveRestore -count=1 -v
```

The cross-runtime command requires a Linux driver, Go 1.27, LLVM22,
`arm-linux-gnueabihf-gcc`, `qemu-arm`, and the ARM sysroot. Missing required
tools fail the enabled runtime test.

## Original asyncPreempt remains a missing contract

The actual selected Go `preempt_arm.o` witnesses MRS `e10f0000`, MSR
`e12cf000`, and the source stack-PC resumption. The original first CPSR read
has no preceding source-defined NZCV. The zero-argument Go declaration is not
an ordinary LLVM C entry signature. The original source therefore still
returns `ErrProbeNeedsContext`; this repair does not make the file a pass.

A sufficient extension needs explicit incoming GP/VFP/CPSR/FPSCR state,
source-owned stack storage and saved-status provenance, and the caller's
resume-PC/continuation contract. It also needs the real `asyncPreempt2` Go
call/GC/stack-relocation effects. The current unchanged-LR `ARMMachineEntry`
cannot justify its SP/LR writes, native Go call, or `MOVW.P 192(R13),R15`.
Neither function-name guessing, invented ordinary parameters, nor a generic
late MRS closes that boundary.

Encoding references: Go `cmd/internal/obj/arm/asm5.go`,
`cmd/asm/internal/arch/arch.go`, and LLVM22
[`ARMInstrInfo.td`](https://github.com/llvm/llvm-project/blob/llvmorg-22.1.8/llvm/lib/Target/ARM/ARMInstrInfo.td)
and
[`basic-arm-instructions.s`](https://github.com/llvm/llvm-project/blob/llvmorg-22.1.8/llvm/test/MC/ARM/basic-arm-instructions.s).
