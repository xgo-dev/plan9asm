# ASM source TEXT and physical object order

Go's assembler `NumberSyms` groups static definitions in the indexed Self bank
and nonstatic ASM definitions in NonpkgDef. Source TEXT ordinal is therefore not
the ordinal of the physical TEXT-record array. The observer keeps the original
namespace/index/relative index, code, PC metadata and relocations unchanged.

`ASMSourceTextOrder` associates every source TEXT exactly once by its normalized
Go symbol, explicit ABI and registered static/nonstatic namespace role. It
retains source ordinal separately from physical object ordinal and requires
unchanged declaration order inside each bank. Unknown namespaces, ABI/kind,
duplicate/missing records and exchanged physical indices are Context. This is
metadata only, not entry, caller, register, result or memory authority. Complete
original/expanded/compiler object and code/PC/relocation equality is still required.

The native listing producer and SDK numerical listing consumer use this mapping
rather than reordering original records. The numerical consumer replays both
complete source/member associations, checks the sealed tuple inventory and keeps
all code, PC and relocation evidence equal before selecting `ObjectOrdinal`.
Mutation permanently revokes the original numerical source; metadata supplies no
static-helper or foreign-entry declaration. A downstream frame consumer must
also use `ObjectOrdinal`;
its existing ABI0/no-private/no-static declaration restrictions are not relaxed.
Mixed-namespace/private/ABI-selector frame binding still needs its own complete
entry and signature model.

The original `equal_amd64.s` has source TEXT order `runtime.memequal`,
`runtime.memequal_varlen`, `memeqbody<>`, but its physical helper is first. Their
source-to-object ordinals are `[1,2,0]`. The metadata observation now closes, not
the complete file translation: the canonical bool must-fact requires a closed
same-file tail-summary graph, and varlen's real `8(DX)` read needs a separate
native closure carrier. Numerical capture of a no-DATA source also needs its
own generated-header/source handoff. These remain explicit Context; no package
name, target string, metadata mapping or absent initializer supplies those facts.
