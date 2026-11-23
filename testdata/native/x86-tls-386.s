.text
.globl _start
_start:
    movl $243, %eax                 # set_thread_area
    movl $descriptor, %ebx
    int $0x80
    testl %eax, %eax
    js setup_error
    movl descriptor, %eax
    leal 3(,%eax,8), %eax
.ifdef WINDOWS_SLOT
    movw %ax, %fs
.else
    movw %ax, %gs
.endif

    call Value
    cmpl $37, %eax                  # 2*7 + 23
    jne first_error
.ifdef WINDOWS_SLOT
    movl $4, runtime.tls_g
.else
    movl $41, tls_plus8
.endif
    call Value
    cmpl $55, %eax                  # 2*7 + 41
    jne second_error
.ifdef WINDOWS_SLOT
    movl $19, block_two
.else
    movl $19, tls_value
.endif
    call Value
    cmpl $79, %eax                  # 2*19 + 41
    jne third_error

    movl $4, %eax                   # write
    movl $1, %ebx
    movl $success, %ecx
    movl $success_end-success, %edx
    int $0x80
    xorl %ebx, %ebx
    jmp exit
setup_error:
    movl $11, %ebx
    jmp exit
first_error:
    movl $21, %ebx
    jmp exit
second_error:
    movl $22, %ebx
    jmp exit
third_error:
    movl $23, %ebx
exit:
    movl $1, %eax                   # exit
    int $0x80

.section .rodata
success:
    .ascii "3 TLS states\n"
success_end:

.data
.p2align 2
descriptor:
.ifdef WINDOWS_SLOT
    .long -1, teb, 0xfffff, 0x51
.globl runtime.tls_g
runtime.tls_g:
    .long 12
teb:
    .long 0, block_two, 0, block_one
block_one:
    .long 7, 0, 23
block_two:
    .long 7, 0, 41
.else
    .long -1, thread_pointer, 0xfffff, 0x51
tls_value:
    .long 7
thread_pointer:
    .long thread_pointer
tls_plus8:
    .long 23

.section .tdata,"awT",@progbits
.p2align 2
.globl runtime.tlsg
.type runtime.tlsg,@tls_object
runtime.tlsg:
    .long 0
.size runtime.tlsg,4
.endif
